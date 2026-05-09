"""Sysmon EVTX → JSON importer.

Reads a JSON-line or JSON-array dump of Sysmon events (the standard format
produced by ``Get-WinEvent | ConvertTo-Json`` or ``EvtxECmd``). Recognises:

  EventID 1   Process create
  EventID 3   Network connection
  EventID 11  File create
  EventID 12  Registry object create / delete
  EventID 13  Registry value set

Output is a single ``ParsedSandboxReport`` matching AnalystBridge's schema.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from analystbridge.core.event_schema import (
    Actor,
    ParsedSandboxReport,
    RawEvent,
    SampleMeta,
    Target,
)
from analystbridge.ingestion.parser_base import SandboxParser


def looks_like_sysmon(data) -> bool:
    """Accepts either a list of records or a dict with a Sysmon-shaped record."""
    if isinstance(data, dict):
        records = data.get("Events") or [data]
    elif isinstance(data, list):
        records = data
    else:
        return False
    if not records:
        return False
    sample = records[0] if isinstance(records[0], dict) else None
    if not sample:
        return False
    provider = (
        (sample.get("System") or {}).get("Provider", {}).get("Name")
        or sample.get("ProviderName")
    )
    return provider == "Microsoft-Windows-Sysmon"


def _record_eventid(rec: dict) -> int:
    sys = rec.get("System") or {}
    eid = sys.get("EventID") or rec.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("Value")
    try:
        return int(eid)
    except (TypeError, ValueError):
        return 0


def _record_data(rec: dict) -> dict:
    """Sysmon EventData → dict. Tolerates EvtxECmd / Get-WinEvent shapes."""
    data = rec.get("EventData")
    if isinstance(data, dict):
        # EvtxECmd shape: {"Data": [{"@Name":"Image","#text":"..."}]} or already flat
        if "Data" in data and isinstance(data["Data"], list):
            return {
                str(d.get("@Name") or d.get("Name")): d.get("#text") or d.get("Text")
                for d in data["Data"]
                if isinstance(d, dict)
            }
        return {k: v for k, v in data.items() if not k.startswith("@")}
    return {k: v for k, v in rec.items() if k not in ("System", "EventData")}


def _ts(rec: dict) -> float:
    """Convert ISO-8601 TimeCreated to seconds-since-epoch (float)."""
    sys = rec.get("System") or {}
    tc = sys.get("TimeCreated")
    if isinstance(tc, dict):
        tc = tc.get("@SystemTime") or tc.get("SystemTime")
    if isinstance(tc, str):
        try:
            return datetime.fromisoformat(tc.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    if isinstance(tc, (int, float)):
        return float(tc)
    return 0.0


class SysmonImporter(SandboxParser):
    def parse_file(self, path: Path) -> ParsedSandboxReport:
        with Path(path).open("r", encoding="utf-8") as f:
            text = f.read().strip()
        if not text:
            data: list[dict] = []
        elif text.startswith("["):
            data = json.loads(text)
        else:
            # Newline-delimited JSON (one record per line)
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        return self.parse_records(data, source_path=path)

    def parse_records(self, records: list[dict], source_path: Path | None = None) -> ParsedSandboxReport:
        # Use first record's host (Computer) as the sample identity, since Sysmon
        # streams aren't sample-bound; or fall back to the file name.
        first = records[0] if records else {}
        host = (first.get("System") or {}).get("Computer") or "sysmon_host"
        sample_id = f"sysmon_{host}"

        sample = SampleMeta(
            sample_id=sample_id,
            filename=source_path.name if source_path else "sysmon_stream.json",
            sandbox_source="sysmon",
            platform="windows",
        )

        events: list[RawEvent] = []
        # Track ts0 so we can rebase to relative seconds (matches our demo schema).
        ts0 = min((_ts(r) for r in records), default=0.0)

        for rec in records:
            if not isinstance(rec, dict):
                continue
            eid = _record_eventid(rec)
            ed = _record_data(rec)
            ts = _ts(rec) - ts0

            ev = self._build_event(eid, ed, ts)
            if ev is not None:
                events.append(ev)

        events.sort(key=lambda e: e.timestamp)
        return ParsedSandboxReport(sample=sample, events=events)

    # ------------------------------------------------------------------
    @staticmethod
    def _build_event(eid: int, ed: dict, ts: float) -> RawEvent | None:
        if eid == 1:  # Process create
            return RawEvent(
                timestamp=ts,
                event_type="process",
                action="created_process",
                actor=Actor(
                    pid=str(ed.get("ParentProcessId") or "") or None,
                    name=ed.get("ParentImage", "").split("\\")[-1] if ed.get("ParentImage") else None,
                    path=ed.get("ParentImage"),
                ),
                target=Target(
                    pid=str(ed.get("ProcessId") or "") or None,
                    name=ed.get("Image", "").split("\\")[-1] if ed.get("Image") else None,
                    path=ed.get("Image"),
                    command_line=ed.get("CommandLine"),
                ),
            )
        if eid == 3:  # Network connect
            return RawEvent(
                timestamp=ts,
                event_type="network",
                action="connect",
                actor=Actor(
                    pid=str(ed.get("ProcessId") or "") or None,
                    name=ed.get("Image", "").split("\\")[-1] if ed.get("Image") else None,
                ),
                target=Target(
                    remote_ip=ed.get("DestinationIp"),
                    remote_port=int(ed.get("DestinationPort") or 0) or None,
                    domain=ed.get("DestinationHostname"),
                    protocol=ed.get("Protocol") or "TCP",
                ),
            )
        if eid == 11:  # File create
            return RawEvent(
                timestamp=ts,
                event_type="file",
                action="wrote_file",
                actor=Actor(
                    pid=str(ed.get("ProcessId") or "") or None,
                    name=ed.get("Image", "").split("\\")[-1] if ed.get("Image") else None,
                ),
                target=Target(file_path=ed.get("TargetFilename")),
            )
        if eid in (12, 13):  # Registry value set / key created
            return RawEvent(
                timestamp=ts,
                event_type="registry",
                action="set_value" if eid == 13 else "create_key",
                actor=Actor(
                    pid=str(ed.get("ProcessId") or "") or None,
                    name=ed.get("Image", "").split("\\")[-1] if ed.get("Image") else None,
                ),
                target=Target(
                    key=ed.get("TargetObject"),
                    value_data=ed.get("Details"),
                ),
            )
        return None
