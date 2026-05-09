"""Cuckoo Sandbox JSON importer.

Mirrors the CAPE importer; the schemas are very similar (CAPE forked Cuckoo)
but a few fields differ — notably the file metadata under ``target.file`` and
the ``behavior.summary`` shape.

Coercion rules:
  * Timestamps in Cuckoo can be ISO-8601 strings (e.g. ``2019-06-14T20:30:58.060Z``)
    relative to ``info.started``, or simple floats. We always rebase to relative
    seconds so the rest of the pipeline (graph layout, timeline, MITRE rules)
    can treat them uniformly.
  * PIDs may be ``int`` or ``str`` — we always emit ``str`` to match
    AnalystBridge's native event schema.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from analystbridge.core.event_schema import (
    Actor,
    ParsedSandboxReport,
    RawEvent,
    SampleMeta,
    Target,
)
from analystbridge.ingestion.parser_base import SandboxParser


def _coerce_ts(value, base: float | None = None) -> float:
    """Return a relative-seconds float for a Cuckoo timestamp value.

    Accepts: float / int / numeric string / ISO-8601 (with or without Z).
    If ``base`` is provided, the returned value is ``ts − base``; otherwise
    the absolute value (or 0 if unparseable) is returned.
    """
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        ts = float(value)
        return ts - base if base is not None else ts
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return 0.0
        try:
            ts = float(value)
            return ts - base if base is not None else ts
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            ts = dt.timestamp()
            return ts - base if base is not None else ts
        except ValueError:
            return 0.0
    return 0.0


def _str_or_none(value) -> str | None:
    """Coerce ints / floats / strings to a clean string, or None."""
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _resolve_base_ts(data: dict, info_started=None) -> float | None:
    """Pick the t=0 origin for a Cuckoo report.

    Real Cuckoo exports frequently have a timezone skew between
    ``info.started`` (analysis-manager UTC) and the per-process
    ``first_seen`` fields (often guest local time, mis-tagged as UTC). If we
    pick ``info.started`` as the base, per-process events end up tens of
    thousands of seconds in the future — useless for the swimlane layout.

    Strategy:
      1. If the report has any per-process ISO timestamps under
         ``behavior.generic[].first_seen`` or ``behavior.processes[].first_seen``,
         use the **minimum of those** as the origin. Every event the analyst
         cares about then sits a small positive offset from it.
      2. Otherwise fall back to ``info.started``.
      3. Otherwise return ``None`` and the rest of the pipeline treats every
         event as ts=0.
    """
    behavior = data.get("behavior") or {}

    proc_candidates: list[float] = []
    for entry in (behavior.get("generic") or []):
        if isinstance(entry, dict):
            v = _coerce_ts(entry.get("first_seen"))
            if v:
                proc_candidates.append(v)
    for entry in (behavior.get("processes") or []):
        if isinstance(entry, dict):
            v = _coerce_ts(entry.get("first_seen"))
            if v:
                proc_candidates.append(v)

    if proc_candidates:
        return min(proc_candidates)

    if info_started:
        v = _coerce_ts(info_started)
        if v:
            return v
    return None


def looks_like_cuckoo(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
    info = data.get("info") or {}
    # Cuckoo writes "version" + "category" inside info; CAPE adds extra keys.
    return "version" in info and "category" in info and "behavior" in data


class CuckooImporter(SandboxParser):
    def parse_file(self, path: Path) -> ParsedSandboxReport:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return self.parse_dict(data)

    def parse_dict(self, data: dict) -> ParsedSandboxReport:
        info = data.get("info") or {}
        target = data.get("target") or {}
        target_file = target.get("file") or {}

        # Pick the t=0 anchor for relative-timestamp calculation. We *can't*
        # blindly trust ``info.started`` — real Cuckoo exports often have a
        # multi-hour timezone skew between info.started (analysis-manager UTC)
        # and behavior.generic[].first_seen (guest local time, mis-tagged as
        # UTC). Strategy: collect every ISO timestamp Cuckoo gives us in this
        # report, take the minimum as the temporal origin. This guarantees
        # the relative offsets fit inside the analysis duration regardless of
        # what timezone any field happens to be in.
        base_ts = _resolve_base_ts(data, info_started=info.get("started"))
        duration = float(info.get("duration") or 0.0)

        sample_id = (
            target_file.get("sha256")
            or _str_or_none(info.get("id"))
            or "cuckoo_sample"
        )
        sample = SampleMeta(
            sample_id=str(sample_id),
            filename=target_file.get("name") or "sample",
            sha256=target_file.get("sha256"),
            sandbox_source="cuckoo",
            platform=info.get("platform") or "windows",
            first_seen=info.get("started"),
        )

        events: list[RawEvent] = []
        events.extend(self._processes(data, base_ts))

        # Prefer the per-process ``behavior.generic[]`` block when present —
        # it gives us per-process first_seen timestamps + per-process summaries
        # so we can spread events temporally instead of stacking everything at
        # ts=0. Fall back to the flat ``behavior.summary`` block otherwise.
        generic = (data.get("behavior") or {}).get("generic") or []
        used_generic = False
        if isinstance(generic, list) and generic:
            spread = self._events_from_generic(generic, base_ts, duration)
            if spread:
                events.extend(spread)
                used_generic = True
        if not used_generic:
            events.extend(self._summary_files(data))
            events.extend(self._summary_keys(data))

        events.extend(self._network(data))
        events.extend(self._signatures(data))
        events.sort(key=lambda e: e.timestamp)

        return ParsedSandboxReport(sample=sample, events=events)

    # ------------------------------------------------------------------
    @staticmethod
    def _events_from_generic(
        generic: list,
        base_ts: float | None,
        duration: float,
    ) -> list[RawEvent]:
        """Walk ``behavior.generic[]`` — Cuckoo's per-process behaviour summary.

        Each generic entry has ``first_seen`` (ISO) and a ``summary`` block
        with bucketed file / registry / module / DNS actions. We use the
        process's first_seen as the anchor and **spread** the actions across
        a 0.4-second window after that anchor so the swimlane shows them as
        a temporal sequence rather than collapsing everything onto one X.
        """
        SPREAD_WINDOW = 0.40   # seconds — how far apart sibling events sit
        out: list[RawEvent] = []

        # Map of (bucket → (event_type, action))
        FILE_BUCKETS = {
            "file_written":  ("file", "wrote_file"),
            "file_created":  ("file", "created_file"),
            "file_modified": ("file", "modified_file"),
            "file_deleted":  ("file", "deleted_file"),
            "file_opened":   ("file", "opened_file"),
            "file_read":     ("file", "read_file"),
            "file_exists":   ("file", "checked_file"),
            "file_failed":   ("file", "failed_file"),
        }
        REG_BUCKETS = {
            "regkey_written": ("registry", "set_value"),
            "regkey_opened":  ("registry", "opened_key"),
            "regkey_read":    ("registry", "read_key"),
            "regkey_deleted": ("registry", "deleted_key"),
        }

        for entry in generic:
            if not isinstance(entry, dict):
                continue
            anchor = _coerce_ts(entry.get("first_seen", 0), base=base_ts)
            pid = _str_or_none(entry.get("pid"))
            ppid = _str_or_none(entry.get("ppid"))
            actor = Actor(
                pid=pid,
                name=_str_or_none(entry.get("process_name")),
                path=_str_or_none(entry.get("process_path")),
            )

            summary = entry.get("summary") or {}

            # Collect bucketed items so we can assign spread timestamps.
            tasks: list[tuple[str, str, str, dict]] = []
            for bucket, (et, action) in FILE_BUCKETS.items():
                for fp in summary.get(bucket, []) or []:
                    if isinstance(fp, str) and fp:
                        tasks.append((et, action, fp, {"file_path": fp}))
            for bucket, (et, action) in REG_BUCKETS.items():
                for key in summary.get(bucket, []) or []:
                    if isinstance(key, str) and key:
                        tasks.append((et, action, key, {"key": key}))
            for mod in summary.get("dll_loaded", []) or []:
                if isinstance(mod, str) and mod:
                    tasks.append(("module", "loaded_module", mod,
                                  {"name": mod, "path": mod}))
            for host in summary.get("resolves_host", []) or []:
                if isinstance(host, str) and host:
                    tasks.append(("network", "dns_query", host,
                                  {"domain": host, "protocol": "DNS"}))
            for q in summary.get("wmi_query", []) or []:
                if isinstance(q, str) and q:
                    tasks.append(("api", "wmi_query", q,
                                  {"api": "wmi_query", "module": "wmi"}))

            if not tasks:
                continue

            # Spread timestamps evenly. If the analysis ran for ``duration`` s,
            # use min(SPREAD_WINDOW, duration / 4) as the spread budget — keeps
            # short runs tight, gives long runs room.
            window = min(SPREAD_WINDOW, max(0.05, duration / 4.0)) if duration else SPREAD_WINDOW
            n = len(tasks)
            for idx, (et, action, raw_value, target_kwargs) in enumerate(tasks):
                ts = anchor + (idx / max(1, n - 1)) * window if n > 1 else anchor
                out.append(RawEvent(
                    timestamp=ts,
                    event_type=et,
                    action=action,
                    actor=actor,
                    target=Target(**target_kwargs),
                ))

        return out

    # ------------------------------------------------------------------
    def _processes(self, data: dict, base_ts: float | None) -> list[RawEvent]:
        out: list[RawEvent] = []
        behavior = data.get("behavior") or {}
        for proc in behavior.get("processes", []) or []:
            if not isinstance(proc, dict):
                continue
            ts = _coerce_ts(proc.get("first_seen", 0), base=base_ts)
            actor = Actor(
                pid=_str_or_none(proc.get("ppid")),
                name=_str_or_none(proc.get("parent_name") or proc.get("parent_process_name")),
            )
            target = Target(
                pid=_str_or_none(proc.get("pid") or proc.get("process_id")),
                name=_str_or_none(proc.get("process_name") or proc.get("name")),
                path=_str_or_none(proc.get("module_path") or proc.get("path")),
                command_line=_str_or_none(proc.get("command_line")),
            )
            out.append(RawEvent(
                timestamp=ts,
                event_type="process",
                action="created_process",
                actor=actor,
                target=target,
            ))
        return out

    def _summary_files(self, data: dict) -> list[RawEvent]:
        out: list[RawEvent] = []
        summary = ((data.get("behavior") or {}).get("summary") or {})

        # The Cuckoo "summary" section uses both flat lists ("files":["…"])
        # and per-action lists ("file_written", "file_deleted", "file_opened",
        # "dll_loaded", …). Honour all of them so we don't lose evidence.
        action_buckets = {
            "file_written":     "wrote_file",
            "file_created":     "created_file",
            "file_modified":    "modified_file",
            "file_deleted":     "deleted_file",
            "file_opened":      "opened_file",
            "file_read":        "read_file",
            "files":            "touched_file",
        }
        for bucket, action in action_buckets.items():
            for fp in summary.get(bucket, []) or []:
                if not isinstance(fp, str) or not fp:
                    continue
                out.append(RawEvent(
                    timestamp=0.0,
                    event_type="file",
                    action=action,
                    actor=Actor(),
                    target=Target(file_path=fp),
                ))
        # DLL loads land in lane 2 / Execution as "module" events
        for mod in summary.get("dll_loaded", []) or []:
            if not isinstance(mod, str) or not mod:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="module",
                action="loaded_module",
                actor=Actor(),
                target=Target(name=mod, path=mod),
            ))
        return out

    def _summary_keys(self, data: dict) -> list[RawEvent]:
        out: list[RawEvent] = []
        summary = ((data.get("behavior") or {}).get("summary") or {})
        action_buckets = {
            "regkey_written":   "set_value",
            "regkey_opened":    "opened_key",
            "regkey_read":      "read_key",
            "regkey_deleted":   "deleted_key",
            "keys":             "touched_key",
        }
        for bucket, action in action_buckets.items():
            for key in summary.get(bucket, []) or []:
                if not isinstance(key, str) or not key:
                    continue
                out.append(RawEvent(
                    timestamp=0.0,
                    event_type="registry",
                    action=action,
                    actor=Actor(),
                    target=Target(key=key),
                ))
        return out

    def _network(self, data: dict) -> list[RawEvent]:
        out: list[RawEvent] = []
        network = data.get("network") or {}

        for host in network.get("hosts", []) or []:
            ip = host if isinstance(host, str) else (host or {}).get("ip")
            if not ip:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="contacted_host",
                actor=Actor(),
                target=Target(remote_ip=str(ip), protocol="HTTP"),
            ))

        # Cuckoo's "domains" can live next to "dns".
        for dom in network.get("domains", []) or []:
            d = dom.get("domain") if isinstance(dom, dict) else dom
            if not d:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="resolved_domain",
                actor=Actor(),
                target=Target(domain=str(d), protocol="DNS"),
            ))
        for dns in network.get("dns", []) or []:
            if isinstance(dns, dict):
                req = dns.get("request") or dns.get("name") or dns.get("hostname")
            else:
                req = dns
            if not req:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="dns_query",
                actor=Actor(),
                target=Target(domain=str(req), protocol="DNS"),
            ))

        for http in (network.get("http") or network.get("http_ex") or []):
            if not isinstance(http, dict):
                continue
            url = http.get("uri") or http.get("url")
            if not url:
                # Cuckoo http_ex stores host + path separately.
                host = http.get("host")
                path = http.get("uri") or http.get("path")
                if host and path:
                    url = f"http://{host}{path}"
            if not url:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="http_request",
                actor=Actor(),
                target=Target(url=str(url), domain=_str_or_none(http.get("host")),
                              protocol=str(http.get("method") or "HTTP")),
            ))
        return out

    def _signatures(self, data: dict) -> list[RawEvent]:
        """Cuckoo signatures often look like YARA-style behavioural matches —
        surface them as YARA events so they land in the Detections lane."""
        out: list[RawEvent] = []
        for sig in data.get("signatures", []) or []:
            if not isinstance(sig, dict):
                continue
            name = sig.get("name") or sig.get("description")
            if not name:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="yara",
                action="signature_match",
                actor=Actor(),
                target=Target(
                    rule=str(name),
                    severity=_str_or_none(sig.get("severity") or sig.get("confidence")),
                ),
            ))
        return out
