"""Rule-based MITRE ATT&CK mapper.

Every rule examines the event stream for one technique and returns zero or
more `MitreMapping` records. Each mapping carries the event_ids that triggered
it so the UI can highlight evidence.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Callable, List

from analystbridge.core.event_row import EventRow

ATTACK_VERSION = "v15"

POWERSHELL_SUSPICIOUS_FLAGS = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "iex",
    "downloadstring",
)

RUN_KEY_FRAGMENTS = (
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
)

PAYLOAD_EXTENSIONS = (".ps1", ".exe", ".dll", ".bat", ".js", ".vbs", ".hta", ".zip")
ENCRYPTED_FILE_MARKERS = (".locked", ".crypt", ".encrypted", ".enc", ".lock")
RANSOM_NOTE_MARKERS = ("read_me", "readme_to", "restore", "decrypt", "how_to")


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence_event_ids: List[int]
    reason: str
    attack_version: str = ATTACK_VERSION

    def to_db_row(self, sample_id: str) -> tuple:
        return (
            None,  # event_id (we store evidence_json instead since multiple events back one mapping)
            sample_id,
            self.technique_id,
            self.technique_name,
            self.tactic,
            self.confidence,
            json.dumps(self.evidence_event_ids),
            self.reason,
            self.attack_version,
        )

    def to_dict(self) -> dict:
        return asdict(self)


Rule = Callable[[List[EventRow]], List[MitreMapping]]


def _cmd(event: EventRow) -> str:
    return (event.target.get("command_line") or "").lower()


def _target_name(event: EventRow) -> str:
    return (event.target.get("name") or "").lower()


def rule_t1059_001_powershell(events: List[EventRow]) -> List[MitreMapping]:
    evidence: List[int] = []
    for e in events:
        if e.event_type != "process":
            continue
        if _target_name(e) != "powershell.exe":
            continue
        cmd = _cmd(e)
        if any(flag in cmd for flag in POWERSHELL_SUSPICIOUS_FLAGS):
            evidence.append(e.event_id)
    if not evidence:
        return []
    return [
        MitreMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            confidence=0.95,
            evidence_event_ids=evidence,
            reason="powershell.exe launched with suspicious flags (encoded / hidden / DownloadString)",
        )
    ]


def rule_t1547_001_run_keys(events: List[EventRow]) -> List[MitreMapping]:
    evidence: List[int] = []
    for e in events:
        if e.event_type == "registry":
            key = (e.target.get("key") or "").lower()
            if any(frag in key for frag in RUN_KEY_FRAGMENTS):
                evidence.append(e.event_id)
        elif e.event_type == "process":
            cmd = _cmd(e)
            if "reg add" in cmd and any(frag in cmd for frag in RUN_KEY_FRAGMENTS):
                evidence.append(e.event_id)
    if not evidence:
        return []
    return [
        MitreMapping(
            technique_id="T1547.001",
            technique_name="Registry Run Keys / Startup Folder",
            tactic="Persistence",
            confidence=0.9,
            evidence_event_ids=evidence,
            reason="Autorun registry key was created or modified",
        )
    ]


def rule_t1071_001_web_protocols(events: List[EventRow]) -> List[MitreMapping]:
    evidence: List[int] = []
    for e in events:
        if e.event_type != "network":
            continue
        protocol = (e.target.get("protocol") or "").upper()
        if protocol in ("HTTP", "HTTPS"):
            evidence.append(e.event_id)
    if not evidence:
        return []
    return [
        MitreMapping(
            technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            tactic="Command and Control",
            confidence=0.8,
            evidence_event_ids=evidence,
            reason="Process communicated over HTTP / HTTPS to external infrastructure",
        )
    ]


def rule_t1105_ingress_tool_transfer(events: List[EventRow]) -> List[MitreMapping]:
    http_events = [e for e in events if e.event_type == "network" and (e.target.get("url") or "")]
    if not http_events:
        return []
    download_evidence: List[int] = []
    for e in http_events:
        url = (e.target.get("url") or "").lower()
        if any(url.endswith(ext) or f"{ext}?" in url for ext in PAYLOAD_EXTENSIONS):
            download_evidence.append(e.event_id)

    file_writes = [
        e for e in events
        if e.event_type == "file"
        and e.action in {"wrote_file", "created_file"}
        and (e.target.get("file_path") or "").lower().endswith(PAYLOAD_EXTENSIONS)
    ]

    if not download_evidence and not file_writes:
        return []

    evidence = download_evidence + [e.event_id for e in file_writes]
    return [
        MitreMapping(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic="Command and Control",
            confidence=0.85,
            evidence_event_ids=evidence,
            reason="Suspicious payload was downloaded from external infrastructure and written to disk",
        )
    ]


def rule_t1490_inhibit_recovery(events: List[EventRow]) -> List[MitreMapping]:
    evidence: List[int] = []
    for e in events:
        if e.event_type != "process":
            continue
        cmd = _cmd(e)
        name = _target_name(e)
        if name == "vssadmin.exe" and "delete" in cmd and "shadow" in cmd:
            evidence.append(e.event_id)
        elif name == "wbadmin.exe" and "delete" in cmd:
            evidence.append(e.event_id)
        elif name == "bcdedit.exe" and ("recoveryenabled" in cmd or "bootstatuspolicy" in cmd):
            evidence.append(e.event_id)
    if not evidence:
        return []
    return [
        MitreMapping(
            technique_id="T1490",
            technique_name="Inhibit System Recovery",
            tactic="Impact",
            confidence=0.95,
            evidence_event_ids=evidence,
            reason="Volume shadow copies / backup catalog were deleted (anti-recovery)",
        )
    ]


def rule_t1486_data_encrypted(events: List[EventRow]) -> List[MitreMapping]:
    encrypted_files: List[int] = []
    ransom_notes: List[int] = []
    for e in events:
        if e.event_type != "file":
            continue
        fp = (e.target.get("file_path") or "").lower()
        if any(fp.endswith(m) for m in ENCRYPTED_FILE_MARKERS):
            encrypted_files.append(e.event_id)
        if any(m in fp for m in RANSOM_NOTE_MARKERS):
            ransom_notes.append(e.event_id)
    if len(encrypted_files) < 3 and not ransom_notes:
        return []
    evidence = encrypted_files + ransom_notes
    return [
        MitreMapping(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            confidence=0.9 if encrypted_files and ransom_notes else 0.75,
            evidence_event_ids=evidence,
            reason=(
                f"{len(encrypted_files)} files renamed with encryption-style extensions"
                + (" and a ransom note was dropped" if ransom_notes else "")
            ),
        )
    ]


def rule_t1218_005_mshta(events: List[EventRow]) -> List[MitreMapping]:
    evidence: List[int] = []
    for e in events:
        if e.event_type != "process":
            continue
        if _target_name(e) == "mshta.exe":
            evidence.append(e.event_id)
    if not evidence:
        return []
    return [
        MitreMapping(
            technique_id="T1218.005",
            technique_name="System Binary Proxy Execution: Mshta",
            tactic="Defense Evasion",
            confidence=0.85,
            evidence_event_ids=evidence,
            reason="mshta.exe was launched (used to proxy script execution and evade defenses)",
        )
    ]


@dataclass
class MitreMapper:
    rules: List[Rule] = field(
        default_factory=lambda: [
            rule_t1059_001_powershell,
            rule_t1547_001_run_keys,
            rule_t1071_001_web_protocols,
            rule_t1105_ingress_tool_transfer,
            rule_t1490_inhibit_recovery,
            rule_t1486_data_encrypted,
            rule_t1218_005_mshta,
        ]
    )

    def map_events(self, events: List[EventRow]) -> List[MitreMapping]:
        results: List[MitreMapping] = []
        for rule in self.rules:
            results.extend(rule(events))
        return results
