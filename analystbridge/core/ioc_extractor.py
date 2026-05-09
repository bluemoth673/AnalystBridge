"""Extract and dedupe Indicators of Compromise from a sample's events.

Output is two-fold per IOC:
  - `value`: canonical machine-readable form (used for exports / hunts)
  - `display_value`: defanged form for safe rendering in the UI / reports
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, List

from analystbridge.core.event_row import EventRow

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)


@dataclass
class Ioc:
    ioc_type: str  # sha256 | sha1 | md5 | ipv4 | domain | url | file_path | registry_key
    value: str
    display_value: str
    source_event_ids: List[int] = field(default_factory=list)
    confidence: float = 0.8
    severity: int = 50
    tags: List[str] = field(default_factory=list)

    def to_db_row(self, sample_id: str) -> tuple:
        first_event = self.source_event_ids[0] if self.source_event_ids else None
        return (
            sample_id,
            self.ioc_type,
            self.value,
            self.display_value,
            first_event,
            self.confidence,
            self.severity,
            json.dumps({"tags": self.tags, "source_event_ids": self.source_event_ids}),
        )

    def to_dict(self) -> dict:
        return asdict(self)


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


PRIVATE_IP_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "0.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_IP_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            return False
    return False


class IocExtractor:
    def extract(self, events: Iterable[EventRow]) -> List[Ioc]:
        index: dict[tuple[str, str], Ioc] = {}

        def _add(ioc_type: str, value: str, display_value: str, event_id: int | None,
                 *, confidence: float = 0.8, severity: int = 50,
                 tags: Iterable[str] = ()) -> None:
            key = (ioc_type, value)
            ioc = index.get(key)
            if ioc is None:
                ioc = Ioc(
                    ioc_type=ioc_type,
                    value=value,
                    display_value=display_value,
                    confidence=confidence,
                    severity=severity,
                    tags=list(tags),
                )
                index[key] = ioc
            if event_id is not None and event_id not in ioc.source_event_ids:
                ioc.source_event_ids.append(event_id)
            for t in tags:
                if t not in ioc.tags:
                    ioc.tags.append(t)

        for e in events:
            target = e.target

            if e.event_type == "network":
                ip = target.get("remote_ip")
                if ip and not _is_private_ip(ip):
                    _add("ipv4", ip, defang_ip(ip), e.event_id, severity=70, tags=["network"])
                domain = target.get("domain")
                if domain:
                    _add("domain", domain.lower(), defang_domain(domain.lower()),
                         e.event_id, severity=70, tags=["network"])
                url = target.get("url")
                if url:
                    _add("url", url, defang_url(url), e.event_id, severity=80,
                         tags=["network"])

            if e.event_type == "file":
                fp = target.get("file_path")
                if fp:
                    _add("file_path", fp, fp, e.event_id, severity=40, tags=["filesystem"])
                sha = target.get("sha256")
                if sha:
                    _add("sha256", sha.lower(), sha.lower(), e.event_id,
                         severity=80, tags=["hash"])

            if e.event_type == "registry":
                key = target.get("key")
                if key:
                    _add("registry_key", key, key, e.event_id, severity=50,
                         tags=["persistence"])

            if e.event_type == "module":
                mod_path = target.get("path")
                if mod_path:
                    _add("file_path", mod_path, mod_path, e.event_id, severity=60,
                         tags=["module"])

        return sorted(
            index.values(),
            key=lambda i: (-i.severity, i.ioc_type, i.value),
        )
