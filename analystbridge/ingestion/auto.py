"""Format-detecting wrapper — picks the right importer for a given file.

Usage:
    parsed = parse_any(path)             # auto-detect
    parsed = parse_any(path, format="cape")   # force a format

Supported formats: ``analystbridge`` (native), ``cape``, ``cuckoo``, ``sysmon``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from analystbridge.core.event_schema import ParsedSandboxReport
from analystbridge.ingestion.cape_importer import CapeImporter, looks_like_cape
from analystbridge.ingestion.cuckoo_importer import CuckooImporter, looks_like_cuckoo
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.sysmon_importer import SysmonImporter, looks_like_sysmon

_PARSERS = {
    "analystbridge": JsonSandboxParser,
    "cape": CapeImporter,
    "cuckoo": CuckooImporter,
    "sysmon": SysmonImporter,
}


def detect_format(data) -> str:
    """Return one of the keys in _PARSERS based on the loaded JSON.

    Cuckoo is checked before CAPE because Cuckoo's signature is strictly more
    specific (version + category) — CAPE's heuristic is broader and would
    otherwise swallow Cuckoo reports.
    """
    if isinstance(data, dict) and "sample" in data and "events" in data:
        return "analystbridge"
    if looks_like_cuckoo(data):
        return "cuckoo"
    if looks_like_cape(data):
        return "cape"
    if looks_like_sysmon(data):
        return "sysmon"
    return "analystbridge"  # fallback


def parse_any(path: Path | str, format: Optional[str] = None) -> ParsedSandboxReport:
    src = Path(path)
    with src.open("r", encoding="utf-8") as f:
        text = f.read().strip()

    # Sysmon stream may be NDJSON; for everything else expect a single JSON doc.
    if format == "sysmon" or (format is None and text and not text.lstrip().startswith(("{", "["))):
        return SysmonImporter().parse_file(src)

    if not text:
        raise ValueError(f"{src} is empty")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try NDJSON → list of records (typical for Sysmon exports)
        return SysmonImporter().parse_file(src)

    fmt = format or detect_format(data)
    parser_cls = _PARSERS.get(fmt, JsonSandboxParser)
    return parser_cls().parse_file(src)
