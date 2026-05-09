"""Explainable Malice Score (0-100) with per-contribution breakdown.

The score is intentionally rule-based so analysts can read every point. Each
contribution carries a reason string ready for the UI's "Score Breakdown" panel.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List

from analystbridge.core.event_row import EventRow
from analystbridge.core.mitre_mapper import (
    ENCRYPTED_FILE_MARKERS,
    POWERSHELL_SUSPICIOUS_FLAGS,
    RANSOM_NOTE_MARKERS,
    RUN_KEY_FRAGMENTS,
)


@dataclass
class ScoreContribution:
    points: int
    reason: str


@dataclass
class MaliceScore:
    score: int
    risk_level: str
    contributions: List[ScoreContribution] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _band(score: int) -> str:
    if score >= 75:
        return "High Risk"
    if score >= 50:
        return "Suspicious"
    if score >= 25:
        return "Medium"
    return "Low"


SUSPICIOUS_PARENTS = {"explorer.exe", "winword.exe", "excel.exe", "outlook.exe", "mshta.exe"}
SCRIPT_LIKE = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


def _has_suspicious_chain(events: List[EventRow]) -> bool:
    spawns: dict[str, str] = {}  # actor_pid -> name (lowered)
    for e in events:
        if e.event_type != "process":
            continue
        actor_name = (e.actor.get("name") or "").lower()
        target_name = (e.target.get("name") or "").lower()
        if actor_name in SUSPICIOUS_PARENTS and target_name in SCRIPT_LIKE:
            return True
        # also catch "office-style → script" two-step chains: parent itself was script-like
        if actor_name in SCRIPT_LIKE and target_name in SCRIPT_LIKE:
            return True
        spawns[(e.actor.get("pid") or "")] = actor_name
    return False


def _has_encoded_powershell(events: List[EventRow]) -> bool:
    for e in events:
        if e.event_type != "process":
            continue
        if (e.target.get("name") or "").lower() != "powershell.exe":
            continue
        cmd = (e.target.get("command_line") or "").lower()
        if any(flag in cmd for flag in POWERSHELL_SUSPICIOUS_FLAGS):
            return True
    return False


def _has_persistence_registry(events: List[EventRow]) -> bool:
    for e in events:
        if e.event_type == "registry":
            key = (e.target.get("key") or "").lower()
            if any(frag in key for frag in RUN_KEY_FRAGMENTS):
                return True
    return False


def _has_c2_connection(events: List[EventRow]) -> bool:
    for e in events:
        if e.event_type != "network":
            continue
        proto = (e.target.get("protocol") or "").upper()
        if proto in ("HTTP", "HTTPS") and (
            e.target.get("domain") or e.target.get("remote_ip") or e.target.get("url")
        ):
            return True
    return False


def _suspicious_dll_loads(events: List[EventRow]) -> int:
    count = 0
    for e in events:
        if e.event_type != "module":
            continue
        path = (e.target.get("path") or "").lower()
        if path.startswith(("c:\\users\\public", "c:\\windows\\temp", "c:\\users\\")) and path.endswith(".dll"):
            # User-writable location loading a DLL is suspicious
            if "\\users\\public" in path or "\\appdata\\local\\temp" in path or "\\windows\\temp" in path:
                count += 1
    return count


def _yara_hits(events: List[EventRow]) -> int:
    return sum(1 for e in events if e.event_type == "yara")


def _has_shadow_copy_deletion(events: List[EventRow]) -> bool:
    for e in events:
        if e.event_type != "process":
            continue
        cmd = (e.target.get("command_line") or "").lower()
        name = (e.target.get("name") or "").lower()
        if name == "vssadmin.exe" and "delete" in cmd and "shadow" in cmd:
            return True
    return False


def _ransomware_file_pattern(events: List[EventRow]) -> int:
    return sum(
        1
        for e in events
        if e.event_type == "file"
        and any((e.target.get("file_path") or "").lower().endswith(m) for m in ENCRYPTED_FILE_MARKERS)
    )


def _has_ransom_note(events: List[EventRow]) -> bool:
    for e in events:
        if e.event_type != "file":
            continue
        fp = (e.target.get("file_path") or "").lower()
        if any(m in fp for m in RANSOM_NOTE_MARKERS):
            return True
    return False


class RiskScorer:
    def score(self, events: List[EventRow]) -> MaliceScore:
        contributions: List[ScoreContribution] = []

        if _has_suspicious_chain(events):
            contributions.append(ScoreContribution(25, "Suspicious parent-child process chain"))
        if _has_encoded_powershell(events):
            contributions.append(ScoreContribution(20, "Encoded PowerShell command"))
        if _has_persistence_registry(events):
            contributions.append(ScoreContribution(15, "Persistence registry key"))
        if _has_c2_connection(events):
            contributions.append(ScoreContribution(15, "C2 connection over HTTPS"))

        dll_count = _suspicious_dll_loads(events)
        if dll_count:
            contributions.append(
                ScoreContribution(10, f"Suspicious DLL load from user-writable path ({dll_count})")
            )

        yara_count = _yara_hits(events)
        if yara_count:
            contributions.append(
                ScoreContribution(min(7 * yara_count, 14), f"YARA hit x {yara_count}")
            )

        if _has_shadow_copy_deletion(events):
            contributions.append(ScoreContribution(15, "Volume shadow copy deletion (anti-recovery)"))

        encrypted = _ransomware_file_pattern(events)
        if encrypted >= 3:
            contributions.append(
                ScoreContribution(20, f"Mass file encryption pattern ({encrypted} files)")
            )

        if _has_ransom_note(events):
            contributions.append(ScoreContribution(10, "Ransom note dropped"))

        total = min(100, sum(c.points for c in contributions))
        return MaliceScore(
            score=total,
            risk_level=_band(total),
            contributions=contributions,
        )
