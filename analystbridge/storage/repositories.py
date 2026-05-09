"""Repository helpers for the AnalystBridge SQLite store.

Functions here own the SQL. UI / engine code should call these and never
construct queries directly.
"""
from __future__ import annotations

from typing import Iterable, List

from analystbridge.core.event_row import EventRow
from analystbridge.core.event_schema import SampleMeta
from analystbridge.core.ioc_extractor import Ioc
from analystbridge.core.mitre_mapper import MitreMapping
from analystbridge.ingestion.normalizer import NormalizedEvent
from analystbridge.storage.database import Database


def upsert_sample(db: Database, sample: SampleMeta) -> None:
    db.conn.execute(
        """
        INSERT INTO samples (sample_id, sha256, filename, first_seen,
                             sandbox_source, platform, analysis_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sample_id) DO UPDATE SET
            sha256=excluded.sha256,
            filename=excluded.filename,
            first_seen=excluded.first_seen,
            sandbox_source=excluded.sandbox_source,
            platform=excluded.platform,
            analysis_status=excluded.analysis_status
        """,
        (
            sample.sample_id,
            sample.sha256,
            sample.filename,
            sample.first_seen,
            sample.sandbox_source,
            sample.platform,
            "ingested",
        ),
    )
    db.conn.commit()


def clear_events_for_sample(db: Database, sample_id: str) -> None:
    # mitre_mappings.event_id and iocs.source_event_id both FK to events; with
    # foreign_keys=ON we must drop the dependents before deleting events.
    db.conn.execute("DELETE FROM mitre_mappings WHERE sample_id = ?", (sample_id,))
    db.conn.execute("DELETE FROM iocs WHERE sample_id = ?", (sample_id,))
    db.conn.execute("DELETE FROM events WHERE sample_id = ?", (sample_id,))
    db.conn.commit()


def insert_events(
    db: Database, sample_id: str, events: Iterable[NormalizedEvent]
) -> int:
    rows = [
        (
            sample_id,
            e.ts,
            e.event_type,
            e.actor_id,
            e.actor_name,
            e.target_id,
            e.target_type,
            e.action,
            e.raw_json,
            e.normalized_json,
            e.severity,
            e.confidence,
        )
        for e in events
    ]
    db.conn.executemany(
        """
        INSERT INTO events (sample_id, ts, event_type, actor_id, actor_name,
                            target_id, target_type, action, raw_json,
                            normalized_json, severity, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db.conn.commit()
    return len(rows)


def event_counts(db: Database, sample_id: str) -> dict[str, int]:
    cur = db.conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events "
        "WHERE sample_id = ? GROUP BY event_type",
        (sample_id,),
    )
    return {row["event_type"]: row["n"] for row in cur.fetchall()}


def total_events(db: Database, sample_id: str) -> int:
    cur = db.conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE sample_id = ?", (sample_id,)
    )
    return cur.fetchone()["n"]


def list_samples(db: Database) -> list[dict]:
    cur = db.conn.execute(
        "SELECT sample_id, filename, sha256, platform, sandbox_source, "
        "analysis_status, created_at FROM samples ORDER BY created_at DESC"
    )
    return [dict(row) for row in cur.fetchall()]


def get_sample(db: Database, sample_id: str) -> dict | None:
    cur = db.conn.execute(
        "SELECT sample_id, filename, sha256, platform, sandbox_source, "
        "analysis_status, first_seen, created_at FROM samples WHERE sample_id = ?",
        (sample_id,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def list_events_for_sample(db: Database, sample_id: str) -> List[EventRow]:
    cur = db.conn.execute(
        "SELECT event_id, sample_id, ts, event_type, actor_id, actor_name, "
        "target_id, target_type, action, raw_json, normalized_json, "
        "severity, confidence "
        "FROM events WHERE sample_id = ? ORDER BY ts ASC, event_id ASC",
        (sample_id,),
    )
    return [EventRow.from_sqlite_row(row) for row in cur.fetchall()]


def clear_mitre_mappings_for_sample(db: Database, sample_id: str) -> None:
    db.conn.execute("DELETE FROM mitre_mappings WHERE sample_id = ?", (sample_id,))
    db.conn.commit()


def insert_mitre_mappings(
    db: Database, sample_id: str, mappings: Iterable[MitreMapping]
) -> int:
    rows = [m.to_db_row(sample_id) for m in mappings]
    db.conn.executemany(
        """
        INSERT INTO mitre_mappings (event_id, sample_id, technique_id,
                                    technique_name, tactic, confidence,
                                    evidence_json, reason, attack_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db.conn.commit()
    return len(rows)


def list_mitre_mappings(db: Database, sample_id: str) -> list[dict]:
    cur = db.conn.execute(
        "SELECT mapping_id, technique_id, technique_name, tactic, confidence, "
        "evidence_json, reason, attack_version "
        "FROM mitre_mappings WHERE sample_id = ? ORDER BY tactic, technique_id",
        (sample_id,),
    )
    return [dict(row) for row in cur.fetchall()]


def clear_iocs_for_sample(db: Database, sample_id: str) -> None:
    db.conn.execute("DELETE FROM iocs WHERE sample_id = ?", (sample_id,))
    db.conn.commit()


def insert_iocs(db: Database, sample_id: str, iocs: Iterable[Ioc]) -> int:
    rows = [i.to_db_row(sample_id) for i in iocs]
    db.conn.executemany(
        """
        INSERT INTO iocs (sample_id, ioc_type, value, display_value,
                          source_event_id, confidence, severity, tags_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    db.conn.commit()
    return len(rows)


def list_iocs(db: Database, sample_id: str) -> list[dict]:
    cur = db.conn.execute(
        "SELECT ioc_id, ioc_type, value, display_value, severity, confidence, "
        "tags_json FROM iocs WHERE sample_id = ? "
        "ORDER BY severity DESC, ioc_type, value",
        (sample_id,),
    )
    return [dict(row) for row in cur.fetchall()]
