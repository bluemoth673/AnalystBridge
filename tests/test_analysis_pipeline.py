"""End-to-end test: ingest → analyze → verify DB persistence."""
from pathlib import Path

from analystbridge.core.analysis import analyze_sample
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


def _ingest(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    return db, parsed.sample.sample_id


def test_analysis_persists_mappings_and_iocs(tmp_path):
    db, sample_id = _ingest(tmp_path)
    result = analyze_sample(db, sample_id, persist=True)

    assert result.mappings, "should have detected at least one technique"
    assert result.iocs, "should have extracted at least one IOC"
    assert result.score.score > 0

    db_mappings = repo.list_mitre_mappings(db, sample_id)
    db_iocs = repo.list_iocs(db, sample_id)
    assert len(db_mappings) == len(result.mappings)
    assert len(db_iocs) == len(result.iocs)
    db.close()


def test_analysis_is_idempotent(tmp_path):
    """Re-running analysis should not duplicate rows in the DB."""
    db, sample_id = _ingest(tmp_path)
    analyze_sample(db, sample_id, persist=True)
    first_mapping_count = len(repo.list_mitre_mappings(db, sample_id))
    first_ioc_count = len(repo.list_iocs(db, sample_id))

    analyze_sample(db, sample_id, persist=True)
    assert len(repo.list_mitre_mappings(db, sample_id)) == first_mapping_count
    assert len(repo.list_iocs(db, sample_id)) == first_ioc_count
    db.close()
