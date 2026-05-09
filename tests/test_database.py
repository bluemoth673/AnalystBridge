from pathlib import Path

from analystbridge.core.event_schema import Actor, RawEvent, SampleMeta, Target
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


def test_init_creates_all_tables(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    cur = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = {row["name"] for row in cur.fetchall()}
    assert {"samples", "events", "mitre_mappings", "iocs", "analyst_notes"} <= tables
    db.close()


def test_insert_and_count_round_trip(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    sample = SampleMeta(sample_id="t1", filename="x.exe")
    raw = RawEvent(
        timestamp=0.0,
        event_type="process",
        action="spawn",
        actor=Actor(pid="1", name="a.exe"),
        target=Target(pid="2", name="b.exe"),
    )
    norm = Normalizer().normalize_all([raw])
    repo.upsert_sample(db, sample)
    repo.insert_events(db, "t1", norm)

    assert repo.total_events(db, "t1") == 1
    assert repo.event_counts(db, "t1") == {"process": 1}
    db.close()


def test_demo_dataset_round_trip(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)

    counts = repo.event_counts(db, parsed.sample.sample_id)
    assert counts.get("process", 0) >= 4
    assert counts.get("network", 0) >= 3
    assert counts.get("file", 0) >= 5
    assert counts.get("registry", 0) >= 1
    db.close()


def test_reingest_after_analysis_does_not_violate_fk(tmp_path):
    """Regression: re-ingest must work even after analyze has populated
    mitre_mappings and iocs with FKs into events.event_id."""
    from analystbridge.core.analysis import analyze_sample
    from analystbridge.ingestion.json_parser import JsonSandboxParser

    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    analyze_sample(db, parsed.sample.sample_id, persist=True)

    # Before fix this raised sqlite3.IntegrityError: FOREIGN KEY constraint failed.
    repo.clear_events_for_sample(db, parsed.sample.sample_id)
    assert repo.total_events(db, parsed.sample.sample_id) == 0
    assert repo.list_mitre_mappings(db, parsed.sample.sample_id) == []
    assert repo.list_iocs(db, parsed.sample.sample_id) == []
    db.close()


def test_reingest_clears_events(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    sample = SampleMeta(sample_id="r1", filename="x.exe")
    raw = RawEvent(
        timestamp=0.0, event_type="process", action="spawn",
        actor=Actor(pid="1"), target=Target(pid="2"),
    )
    norm = Normalizer().normalize_all([raw])
    repo.upsert_sample(db, sample)
    repo.insert_events(db, "r1", norm)
    repo.insert_events(db, "r1", norm)
    assert repo.total_events(db, "r1") == 2

    repo.clear_events_for_sample(db, "r1")
    repo.insert_events(db, "r1", norm)
    assert repo.total_events(db, "r1") == 1
    db.close()
