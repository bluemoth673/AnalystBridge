"""Tests for the MITRE rule engine, driven against the demo dataset."""
from pathlib import Path

import pytest

from analystbridge.core.event_row import EventRow
from analystbridge.core.mitre_mapper import MitreMapper
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


@pytest.fixture()
def demo_events(tmp_path) -> list[EventRow]:
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    rows = repo.list_events_for_sample(db, parsed.sample.sample_id)
    db.close()
    return rows


def test_required_techniques_detected(demo_events):
    mappings = MitreMapper().map_events(demo_events)
    detected = {m.technique_id for m in mappings}
    expected = {"T1059.001", "T1547.001", "T1071.001", "T1218.005", "T1490", "T1486", "T1105"}
    assert expected <= detected, f"missing techniques: {expected - detected}"


def test_each_mapping_has_evidence(demo_events):
    for m in MitreMapper().map_events(demo_events):
        assert m.evidence_event_ids, f"{m.technique_id} has no evidence"
        assert 0.0 < m.confidence <= 1.0


def test_no_techniques_on_empty_event_stream():
    assert MitreMapper().map_events([]) == []
