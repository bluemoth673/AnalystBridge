"""Convert RawEvent rows into NormalizedEvent rows ready for the database.

The normalizer's job:
  - assign canonical actor_id / target_id strings (used as graph node IDs later)
  - decide a target_type (process / file / domain / ip / url / registry / yara / api / module)
  - serialize raw + normalized payloads to JSON for storage
Severity / confidence are left at 0 here; the analysis engine in Phase 3 fills them.
"""
from __future__ import annotations

import json
from typing import Iterable, Optional, Tuple

from pydantic import BaseModel

from analystbridge.core.event_schema import RawEvent


class NormalizedEvent(BaseModel):
    ts: float
    event_type: str
    actor_id: Optional[str]
    actor_name: Optional[str]
    target_id: Optional[str]
    target_type: Optional[str]
    action: Optional[str]
    raw_json: str
    normalized_json: str
    severity: int = 0
    confidence: float = 0.0


class Normalizer:
    def normalize(self, raw: RawEvent) -> NormalizedEvent:
        actor_id, actor_name = self._actor_id(raw)
        target_id, target_type = self._target_id(raw)

        normalized_payload = {
            "event_type": raw.event_type,
            "action": raw.action,
            "actor": raw.actor.model_dump(exclude_none=True) if raw.actor else None,
            "target": raw.target.model_dump(exclude_none=True) if raw.target else None,
        }

        return NormalizedEvent(
            ts=raw.timestamp,
            event_type=raw.event_type,
            actor_id=actor_id,
            actor_name=actor_name,
            target_id=target_id,
            target_type=target_type,
            action=raw.action,
            raw_json=raw.model_dump_json(exclude_none=True),
            normalized_json=json.dumps(normalized_payload, ensure_ascii=False),
        )

    def normalize_all(self, raws: Iterable[RawEvent]) -> list[NormalizedEvent]:
        return [self.normalize(r) for r in raws]

    @staticmethod
    def _actor_id(raw: RawEvent) -> Tuple[Optional[str], Optional[str]]:
        if not raw.actor:
            return None, None
        actor_id = f"proc:{raw.actor.pid}" if raw.actor.pid else None
        return actor_id, raw.actor.name

    @staticmethod
    def _target_id(raw: RawEvent) -> Tuple[Optional[str], Optional[str]]:
        if not raw.target:
            return None, None
        t = raw.target
        et = raw.event_type

        if et == "process" and t.pid:
            return f"proc:{t.pid}", "process"

        if et == "network":
            if t.url:
                return f"url:{t.url}", "url"
            if t.domain:
                return f"domain:{t.domain}", "domain"
            if t.remote_ip:
                node = f"ip:{t.remote_ip}"
                if t.remote_port:
                    node = f"{node}:{t.remote_port}"
                return node, "ip"

        if et == "file":
            fp = t.file_path or t.path
            if fp:
                return f"file:{fp}", "file"

        if et == "registry" and t.key:
            value_part = t.value_name or ""
            return f"reg:{t.key}\\{value_part}", "registry"

        if et == "yara" and t.rule:
            return f"yara:{t.rule}", "yara"

        if et == "api" and t.api:
            return f"api:{t.api}", "api"

        if et == "module":
            mod = t.path or t.name
            if mod:
                return f"module:{mod}", "module"

        if et == "memory":
            mem = t.path or t.name
            if mem:
                return f"mem:{mem}", "memory"

        return None, None
