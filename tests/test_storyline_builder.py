from pathlib import Path

import pytest

from analystbridge.core.mitre_mapper import MitreMapper
from analystbridge.core.storyline_builder import StorylineBuilder
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


@pytest.fixture()
def demo_events(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    rows = repo.list_events_for_sample(db, parsed.sample.sample_id)
    db.close()
    return rows


def test_demo_storyline_covers_full_killchain(demo_events):
    mappings = MitreMapper().map_events(demo_events)
    stages = StorylineBuilder().build(demo_events, mappings)
    titles = [s.title for s in stages]
    expected_subset = {
        "Initial Execution",
        "Script Execution",
        "Payload Delivery",
        "Persistence",
        "Defense Evasion: Recovery Disabled",
        "Impact",
    }
    assert expected_subset <= set(titles)


def test_each_stage_has_evidence_or_action(demo_events):
    mappings = MitreMapper().map_events(demo_events)
    stages = StorylineBuilder().build(demo_events, mappings)
    for stage in stages:
        assert stage.description
        assert stage.recommended_action
        assert stage.confidence > 0
