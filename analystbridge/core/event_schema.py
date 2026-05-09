"""Pydantic models for sandbox-report ingestion.

These models describe the *raw* shape of the JSON we accept. They tolerate
unknown fields (extra=allow) so future sandbox formats can hand us extra
keys without breaking parsing.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class Actor(BaseModel):
    model_config = ConfigDict(extra="allow")

    pid: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None


class Target(BaseModel):
    model_config = ConfigDict(extra="allow")

    # process target
    pid: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None
    command_line: Optional[str] = None

    # network target
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    protocol: Optional[str] = None

    # file target
    file_path: Optional[str] = None
    sha256: Optional[str] = None

    # registry target
    key: Optional[str] = None
    value_name: Optional[str] = None
    value_data: Optional[str] = None

    # api target
    api: Optional[str] = None
    module: Optional[str] = None
    result: Optional[str] = None

    # yara target
    rule: Optional[str] = None
    severity: Optional[str] = None


class RawEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: float
    event_type: str
    action: Optional[str] = None
    actor: Optional[Actor] = None
    target: Optional[Target] = None


class SampleMeta(BaseModel):
    model_config = ConfigDict(extra="allow")

    sample_id: str
    filename: Optional[str] = None
    sha256: Optional[str] = None
    sandbox_source: Optional[str] = None
    platform: Optional[str] = None
    first_seen: Optional[str] = None


class ParsedSandboxReport(BaseModel):
    sample: SampleMeta
    events: List[RawEvent]
