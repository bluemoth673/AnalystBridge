"""Sandbox parser interface. Future CAPE/Cuckoo/Sysmon parsers implement this."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from analystbridge.core.event_schema import ParsedSandboxReport


class SandboxParser(ABC):
    @abstractmethod
    def parse_file(self, path: Path) -> ParsedSandboxReport:
        ...
