"""Lightweight event row used by the analysis engine.

The DB has the canonical schema. The engine prefers a small dataclass so rule
functions don't need to know about sqlite3 row factories or JSON columns.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class EventRow:
    event_id: int
    ts: float
    event_type: str
    actor_id: Optional[str]
    actor_name: Optional[str]
    target_id: Optional[str]
    target_type: Optional[str]
    action: Optional[str]
    payload: dict[str, Any]  # parsed normalized_json
    severity: int = 0
    confidence: float = 0.0

    @property
    def actor(self) -> dict[str, Any]:
        return self.payload.get("actor") or {}

    @property
    def target(self) -> dict[str, Any]:
        return self.payload.get("target") or {}

    @classmethod
    def from_sqlite_row(cls, row) -> "EventRow":
        normalized = row["normalized_json"]
        payload = json.loads(normalized) if normalized else {}
        return cls(
            event_id=row["event_id"],
            ts=row["ts"],
            event_type=row["event_type"],
            actor_id=row["actor_id"],
            actor_name=row["actor_name"],
            target_id=row["target_id"],
            target_type=row["target_type"],
            action=row["action"],
            payload=payload,
            severity=row["severity"] if "severity" in row.keys() else 0,
            confidence=row["confidence"] if "confidence" in row.keys() else 0.0,
        )
