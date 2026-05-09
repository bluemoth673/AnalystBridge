"""CAPEv2 sandbox JSON importer.

Maps the CAPE report shape (info / target / behavior / network) into
AnalystBridge's native ``ParsedSandboxReport``.

CAPE schema reference: https://github.com/kevoreilly/CAPEv2  →
``cape/processing/json_dump.py`` is the canonical writer; we read what it
produces.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from analystbridge.core.event_schema import (
    Actor,
    ParsedSandboxReport,
    RawEvent,
    SampleMeta,
    Target,
)
from analystbridge.ingestion.cuckoo_importer import _coerce_ts, _str_or_none
from analystbridge.ingestion.parser_base import SandboxParser


def looks_like_cape(data: dict) -> bool:
    """Cheap heuristic — accept anything with CAPE's ``info.id`` + ``behavior``."""
    if not isinstance(data, dict):
        return False
    info = data.get("info") or {}
    return "id" in info and ("behavior" in data or "CAPE" in data)


class CapeImporter(SandboxParser):
    def parse_file(self, path: Path) -> ParsedSandboxReport:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return self.parse_dict(data)

    def parse_dict(self, data: dict) -> ParsedSandboxReport:
        info = data.get("info") or {}
        target = data.get("target") or {}
        target_file = target.get("file") or {}

        sample_id = (
            target_file.get("sha256")
            or str(info.get("id") or "cape_sample")
        )
        sample = SampleMeta(
            sample_id=sample_id,
            filename=target_file.get("name") or info.get("category") or "sample",
            sha256=target_file.get("sha256"),
            sandbox_source="cape",
            platform=info.get("machine", {}).get("platform") if isinstance(info.get("machine"), dict) else "windows",
            first_seen=info.get("started"),
        )

        events: list[RawEvent] = []
        events.extend(self._process_events(data))
        events.extend(self._network_events(data))
        events.extend(self._signature_events(data))
        events.sort(key=lambda e: e.timestamp)

        return ParsedSandboxReport(sample=sample, events=events)

    # ------------------------------------------------------------------
    def _process_events(self, data: dict) -> list[RawEvent]:
        out: list[RawEvent] = []
        info = data.get("info") or {}
        base_ts = _coerce_ts(info.get("started")) or None
        behavior = data.get("behavior") or {}
        processes = behavior.get("processes") or behavior.get("processtree") or []
        for proc in processes:
            if not isinstance(proc, dict):
                continue
            ts_raw = proc.get("first_seen", 0) or proc.get("start_time", 0) or 0
            ts = _coerce_ts(ts_raw, base=base_ts)
            actor = Actor(
                pid=_str_or_none(proc.get("parent_id") or proc.get("ppid")),
                name=_str_or_none(proc.get("parent_name") or proc.get("parent_process_name")),
            )
            target = Target(
                pid=_str_or_none(proc.get("process_id") or proc.get("pid")),
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

    def _network_events(self, data: dict) -> list[RawEvent]:
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
                target=Target(remote_ip=ip, protocol="HTTP"),
            ))
        for dns in network.get("dns", []) or []:
            request = (dns or {}).get("request") if isinstance(dns, dict) else None
            if not request:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="dns_query",
                actor=Actor(),
                target=Target(domain=request, protocol="DNS"),
            ))
        for http in (network.get("http") or network.get("http_ex") or []):
            if not isinstance(http, dict):
                continue
            url = http.get("uri") or http.get("url")
            if not url:
                continue
            out.append(RawEvent(
                timestamp=0.0,
                event_type="network",
                action="http_request",
                actor=Actor(),
                target=Target(
                    url=url,
                    domain=http.get("host"),
                    protocol=http.get("method") or "HTTP",
                ),
            ))
        return out

    def _signature_events(self, data: dict) -> list[RawEvent]:
        """CAPE 'signatures' often contain YARA hits and behaviour summaries."""
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
                target=Target(rule=name, severity=str(sig.get("severity", ""))),
            ))
        return out
