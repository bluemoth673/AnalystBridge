from pathlib import Path

from analystbridge.ingestion.json_parser import JsonSandboxParser


DEMO = Path("sample_data/ransomware_demo.json")


def test_parse_demo_sample_metadata():
    parsed = JsonSandboxParser().parse_file(DEMO)
    assert parsed.sample.sample_id == "sample_ransomware_001"
    assert parsed.sample.filename == "invoice_may_2026.exe"
    assert parsed.sample.sha256 and len(parsed.sample.sha256) == 64


def test_parse_demo_event_types():
    parsed = JsonSandboxParser().parse_file(DEMO)
    types = {e.event_type for e in parsed.events}
    # The demo must cover all the major buckets so Phase 3 has signal to work with.
    assert {"process", "network", "file", "registry", "api", "yara"} <= types
    assert len(parsed.events) >= 20


def test_parse_demo_event_chronology():
    parsed = JsonSandboxParser().parse_file(DEMO)
    timestamps = [e.timestamp for e in parsed.events]
    assert timestamps == sorted(timestamps), "demo events should be in chronological order"
