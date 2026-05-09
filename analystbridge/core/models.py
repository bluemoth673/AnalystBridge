"""Shared constants and lightweight value types used across the engine."""
from __future__ import annotations

KNOWN_EVENT_TYPES = frozenset(
    {"process", "network", "file", "registry", "api", "yara", "memory", "module"}
)
