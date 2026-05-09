"""Engine-glue tests — no Qt required."""
from analystbridge.ui.services import default_demo_path, load_bundle_from_json


def test_default_demo_path_exists():
    assert default_demo_path().exists()


def test_load_bundle_returns_complete_result():
    bundle = load_bundle_from_json(default_demo_path())
    assert bundle.sample.get("filename") == "invoice_may_2026.exe"
    assert len(bundle.events) >= 20
    assert bundle.result.mappings, "no MITRE mappings produced"
    assert bundle.result.iocs, "no IOCs produced"
    assert bundle.result.score.score >= 75
    assert bundle.result.storyline, "no storyline stages produced"
    assert bundle.graph.number_of_nodes() > 0
    assert bundle.graph.number_of_edges() > 0
