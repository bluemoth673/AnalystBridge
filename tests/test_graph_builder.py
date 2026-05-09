from pathlib import Path

from analystbridge.graph.graph_builder import GraphBuilder
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


def test_graph_has_expected_node_kinds(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    events = repo.list_events_for_sample(db, parsed.sample.sample_id)

    g = GraphBuilder().build(events)
    stats = GraphBuilder.stats(g)

    assert stats["nodes"] >= 10
    assert stats["edges"] >= len(events) // 2  # not every event creates an edge but many do
    for kind in ("process", "file", "registry"):
        assert kind in stats["by_kind"], f"missing node kind: {kind}"
    db.close()


def test_graph_edges_carry_event_ids(tmp_path):
    db = Database(tmp_path / "t.db")
    db.init_schema()
    parsed = JsonSandboxParser().parse_file(Path("sample_data/ransomware_demo.json"))
    norm = Normalizer().normalize_all(parsed.events)
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    events = repo.list_events_for_sample(db, parsed.sample.sample_id)

    g = GraphBuilder().build(events)
    for _, _, data in g.edges(data=True):
        assert "event_id" in data
        assert "ts" in data
        assert "event_type" in data
    db.close()
