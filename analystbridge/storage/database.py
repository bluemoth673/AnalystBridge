"""SQLite database wrapper.

Schema and PRAGMAs match the design in the project brief. We use a single
connection per Database instance; UI threads should each construct their own.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Union

PRAGMAS = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-64000;
PRAGMA foreign_keys=ON;
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    sha256 TEXT,
    filename TEXT,
    first_seen TEXT,
    sandbox_source TEXT,
    platform TEXT,
    analysis_status TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL,
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    target_id TEXT,
    target_type TEXT,
    action TEXT,
    raw_json TEXT,
    normalized_json TEXT,
    severity INTEGER DEFAULT 0,
    confidence REAL DEFAULT 0.0,
    FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
);

CREATE INDEX IF NOT EXISTS idx_events_sample_ts ON events(sample_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    sample_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT,
    tactic TEXT,
    confidence REAL,
    evidence_json TEXT,
    reason TEXT,
    attack_version TEXT,
    FOREIGN KEY(event_id) REFERENCES events(event_id),
    FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    display_value TEXT,
    source_event_id INTEGER,
    confidence REAL,
    severity INTEGER,
    tags_json TEXT,
    FOREIGN KEY(sample_id) REFERENCES samples(sample_id),
    FOREIGN KEY(source_event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL,
    node_id TEXT,
    event_id INTEGER,
    note_text TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sample_id) REFERENCES samples(sample_id)
);
"""


class Database:
    def __init__(self, path: Union[str, Path] = "analystbridge.db"):
        self.path = str(path)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(PRAGMAS)
        return self._conn

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.init_schema()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
