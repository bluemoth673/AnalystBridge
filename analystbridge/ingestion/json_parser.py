"""JSON parser for AnalystBridge's native sandbox report format."""
from __future__ import annotations

import json
from pathlib import Path

from analystbridge.core.event_schema import ParsedSandboxReport
from analystbridge.ingestion.parser_base import SandboxParser


class JsonSandboxParser(SandboxParser):
    def parse_file(self, path: Path) -> ParsedSandboxReport:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return ParsedSandboxReport.model_validate(data)
