"""Build a human-readable attack storyline from events + MITRE mappings.

Stages are emitted in the standard kill-chain order. A stage is only emitted
if there is supporting evidence in the events.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List

from analystbridge.core.event_row import EventRow
from analystbridge.core.mitre_mapper import MitreMapping


@dataclass
class StorylineStage:
    title: str
    description: str
    mitre_ids: List[str] = field(default_factory=list)
    supporting_event_ids: List[int] = field(default_factory=list)
    confidence: float = 0.8
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _evidence_for(mappings: List[MitreMapping], technique_id: str) -> List[int]:
    for m in mappings:
        if m.technique_id == technique_id:
            return list(m.evidence_event_ids)
    return []


class StorylineBuilder:
    def build(
        self,
        events: List[EventRow],
        mappings: List[MitreMapping],
    ) -> List[StorylineStage]:
        stages: List[StorylineStage] = []
        techniques = {m.technique_id for m in mappings}

        # --- 1. Initial Execution ---
        first_process = next(
            (e for e in events if e.event_type == "process"),
            None,
        )
        if first_process:
            actor = (first_process.actor.get("name") or "?")
            target = (first_process.target.get("name") or "?")
            stages.append(
                StorylineStage(
                    title="Initial Execution",
                    description=f"{actor} launched {target}.",
                    supporting_event_ids=[first_process.event_id],
                    confidence=0.9,
                    recommended_action="Verify how the dropper reached the host (email attachment? download?).",
                )
            )

        # --- 2. Script Execution (mshta / powershell) ---
        if "T1218.005" in techniques or "T1059.001" in techniques:
            evidence = _evidence_for(mappings, "T1218.005") + _evidence_for(mappings, "T1059.001")
            mitre_ids = [t for t in ("T1218.005", "T1059.001") if t in techniques]
            stages.append(
                StorylineStage(
                    title="Script Execution",
                    description="Scripting host (mshta / powershell) executed with suspicious arguments.",
                    mitre_ids=mitre_ids,
                    supporting_event_ids=evidence,
                    confidence=0.9,
                    recommended_action="Block mshta.exe / restrict PowerShell via constrained language mode and AMSI.",
                )
            )

        # --- 3. Payload Delivery ---
        if "T1105" in techniques or "T1071.001" in techniques:
            evidence = _evidence_for(mappings, "T1105") + _evidence_for(mappings, "T1071.001")
            mitre_ids = [t for t in ("T1105", "T1071.001") if t in techniques]
            stages.append(
                StorylineStage(
                    title="Payload Delivery",
                    description="Process downloaded an additional payload from external infrastructure.",
                    mitre_ids=mitre_ids,
                    supporting_event_ids=evidence,
                    confidence=0.85,
                    recommended_action="Block C2 domain / IP at the proxy and DNS firewall; collect downloaded artifact for review.",
                )
            )

        # --- 4. Persistence ---
        if "T1547.001" in techniques:
            stages.append(
                StorylineStage(
                    title="Persistence",
                    description="Autorun registry key was modified to maintain access across reboots.",
                    mitre_ids=["T1547.001"],
                    supporting_event_ids=_evidence_for(mappings, "T1547.001"),
                    confidence=0.9,
                    recommended_action="Remove the Run-key entry and audit similar autoruns across the fleet.",
                )
            )

        # --- 5. Defense Evasion / Recovery Disabled ---
        if "T1490" in techniques:
            stages.append(
                StorylineStage(
                    title="Defense Evasion: Recovery Disabled",
                    description="Volume shadow copies were deleted to prevent file recovery.",
                    mitre_ids=["T1490"],
                    supporting_event_ids=_evidence_for(mappings, "T1490"),
                    confidence=0.95,
                    recommended_action="Restore backups from out-of-band storage; do not rely on local shadow copies.",
                )
            )

        # --- 6. C2 Communication ---
        # If we already covered web protocols under Payload Delivery, still call
        # out a beacon stage when there is HTTP traffic AFTER persistence/encryption.
        c2_events = [
            e for e in events
            if e.event_type == "network"
            and (e.target.get("protocol") or "").upper() in ("HTTP", "HTTPS")
        ]
        if c2_events and "T1071.001" in techniques and "T1486" in techniques:
            late_c2 = [e for e in c2_events if e.ts >= max((m.ts for m in events if m.event_type == "registry"), default=0)]
            if late_c2:
                stages.append(
                    StorylineStage(
                        title="C2 Communication",
                        description="Malware contacted external infrastructure during / after impact.",
                        mitre_ids=["T1071.001"],
                        supporting_event_ids=[e.event_id for e in late_c2],
                        confidence=0.8,
                        recommended_action="Sinkhole the C2 domain and pivot on the IP for lateral discovery.",
                    )
                )

        # --- 7. Impact ---
        if "T1486" in techniques:
            stages.append(
                StorylineStage(
                    title="Impact",
                    description="Files were renamed with encryption-style extensions; ransomware-like behavior observed.",
                    mitre_ids=["T1486"],
                    supporting_event_ids=_evidence_for(mappings, "T1486"),
                    confidence=0.9,
                    recommended_action="Isolate host, preserve disk image, escalate to IR; do not pay any ransom.",
                )
            )

        return stages
