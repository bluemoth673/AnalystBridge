from pathlib import Path

import pytest

from analystbridge.core.risk_scoring import RiskScorer
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


def test_demo_is_high_risk(demo_events):
    score = RiskScorer().score(demo_events)
    assert score.score >= 75
    assert score.risk_level == "High Risk"


def test_score_capped_at_100(demo_events):
    score = RiskScorer().score(demo_events)
    assert 0 <= score.score <= 100


def test_contributions_have_reasons(demo_events):
    score = RiskScorer().score(demo_events)
    for c in score.contributions:
        assert c.reason
        assert c.points > 0


def test_demo_includes_expected_contributions(demo_events):
    score = RiskScorer().score(demo_events)
    reasons = " | ".join(c.reason.lower() for c in score.contributions)
    for needle in ("powershell", "registry", "shadow", "encryption", "ransom note", "c2"):
        assert needle in reasons, f"missing contribution covering: {needle}"


def test_empty_events_give_low_score():
    score = RiskScorer().score([])
    assert score.score == 0
    assert score.risk_level == "Low"
