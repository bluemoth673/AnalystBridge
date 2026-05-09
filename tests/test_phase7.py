"""Phase 7 — STIX exporter, offline LLM Assist, NotesStore, dashboard filter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from analystbridge.ai import LLMAssistEngine, LLMConfig, LLMStatus
from analystbridge.ai.llm_assist import build_preview_summary
from analystbridge.exports.stix_exporter import write_stix_bundle
from analystbridge.notes import NotesStore
from analystbridge.ui.services import default_demo_path, load_bundle_from_json


@pytest.fixture(scope="module")
def bundle():
    return load_bundle_from_json(default_demo_path())


# ---------------------------------------------------------------------------
# STIX 2.1 exporter
# ---------------------------------------------------------------------------


def test_stix_bundle_is_valid_json_with_correct_shape(bundle, tmp_path):
    out = write_stix_bundle(bundle, tmp_path / "stix.json")
    data = json.loads(out.read_text(encoding="utf-8"))

    assert data["type"] == "bundle"
    assert data["id"].startswith("bundle--")
    assert isinstance(data["objects"], list) and data["objects"]

    types = [o["type"] for o in data["objects"]]
    assert "identity" in types
    assert "malware" in types
    assert "indicator" in types
    assert "relationship" in types

    # Every indicator has a STIX pattern
    for obj in data["objects"]:
        if obj["type"] == "indicator":
            assert obj["pattern"].startswith("[")
            assert obj["pattern_type"] == "stix"
            assert obj["spec_version"] == "2.1"


def test_stix_bundle_is_deterministic(bundle, tmp_path):
    a = write_stix_bundle(bundle, tmp_path / "a.json").read_text(encoding="utf-8")
    b = write_stix_bundle(bundle, tmp_path / "b.json").read_text(encoding="utf-8")

    # Bundle id and per-IOC indicator ids must be stable across runs of the same sample.
    da, db = json.loads(a), json.loads(b)
    ids_a = {o["id"] for o in da["objects"] if o["type"] == "indicator"}
    ids_b = {o["id"] for o in db["objects"] if o["type"] == "indicator"}
    assert ids_a == ids_b


# ---------------------------------------------------------------------------
# AI Assist — deterministic preview path
# ---------------------------------------------------------------------------


def test_llm_engine_is_unavailable_by_default():
    engine = LLMAssistEngine()
    status = engine.status()
    assert engine.is_available() is False
    assert status.available is False
    assert "gemma" in status.model.lower()


def test_preview_summary_is_deterministic_and_complete(bundle):
    a = build_preview_summary(bundle)
    b = build_preview_summary(bundle)

    # Deterministic: identical narrative on every run.
    assert a.executive_summary == b.executive_summary
    assert a.containment_plan == b.containment_plan
    assert a.suggested_hunts == b.suggested_hunts
    assert a.open_questions == b.open_questions

    # Sanity: real content, not empty placeholders.
    assert len(a.executive_summary) > 50
    assert len(a.containment_plan) >= 4
    assert len(a.suggested_hunts) >= 1
    assert len(a.open_questions) >= 3
    assert a.generated_by_llm is False
    # Confidence scales with malice score
    assert 0.5 <= a.confidence <= 0.95


def test_engine_routes_to_backend_when_available(bundle):
    """If a backend reports available=True, the engine MUST call it."""
    class FakeBackend:
        def __init__(self):
            self.calls = 0

        def status(self):
            return LLMStatus(available=True, backend="fake", model="fake-1b")

        def generate_summary(self, bundle, config):
            self.calls += 1
            from analystbridge.ai.llm_assist import AISummary
            return AISummary(
                executive_summary="from-backend",
                containment_plan=["b1"],
                suggested_hunts=["h1"],
                open_questions=["q1"],
                confidence=0.9,
                model="fake-1b",
                generated_by_llm=True,
            )

    backend = FakeBackend()
    engine = LLMAssistEngine(backend=backend, config=LLMConfig(backend="fake"))
    summary = engine.generate_summary(bundle)
    assert backend.calls == 1
    assert summary.generated_by_llm is True
    assert summary.executive_summary == "from-backend"


# ---------------------------------------------------------------------------
# Notes sidecar
# ---------------------------------------------------------------------------


def test_notes_store_round_trips_per_sample(tmp_path):
    store = NotesStore(root=tmp_path)
    assert store.load("sample_x") == ""
    assert store.has_notes("sample_x") is False

    path = store.save("sample_x", "first triage notes\nsuspect has reused payload")
    assert path.exists()
    assert store.load("sample_x").startswith("first triage notes")
    assert store.has_notes("sample_x") is True

    # A different sample doesn't see another sample's notes.
    assert store.load("sample_y") == ""

    # Saving an empty string clears.
    store.save("sample_x", "")
    assert store.load("sample_x") == ""


def test_notes_store_handles_unsafe_sample_ids(tmp_path):
    store = NotesStore(root=tmp_path)
    store.save("weird/sample:1*?", "note")
    # File must land in tmp_path, not anywhere outside
    files = list(tmp_path.iterdir())
    assert files
    assert all(p.parent == tmp_path for p in files)
