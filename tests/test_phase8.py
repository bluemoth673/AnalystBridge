"""Phase 8 — CAPE / Cuckoo / Sysmon importers + similarity comparison."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from analystbridge.core.analysis import analyze_sample
from analystbridge.core.similarity import SampleFingerprint, compare, rank_against
from analystbridge.ingestion.auto import detect_format, parse_any
from analystbridge.ingestion.cape_importer import CapeImporter, looks_like_cape
from analystbridge.ingestion.cuckoo_importer import CuckooImporter, looks_like_cuckoo
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.ingestion.sysmon_importer import SysmonImporter, looks_like_sysmon
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database
from analystbridge.ui.services import default_demo_path, load_bundle_from_json


# ---------------------------------------------------------------------------
# CAPE importer
# ---------------------------------------------------------------------------

CAPE_SAMPLE = {
    "info": {"id": 4242, "started": "2026-05-08 09:00:00", "category": "file",
             "machine": {"platform": "windows"}},
    "target": {"file": {
        "name": "invoice_test.exe",
        "sha256": "a" * 64,
    }},
    "behavior": {
        "processes": [
            {"process_id": 1234, "parent_id": 4096,
             "process_name": "invoice_test.exe", "first_seen": 1.0,
             "command_line": "invoice_test.exe /silent"},
            {"process_id": 1300, "parent_id": 1234,
             "process_name": "powershell.exe", "first_seen": 1.5,
             "command_line": "powershell.exe -enc Zm9v"},
        ],
    },
    "network": {
        "hosts": [{"ip": "8.8.8.8"}],
        "dns": [{"request": "evil.example"}],
        "http": [{"uri": "https://evil.example/x.bin", "host": "evil.example", "method": "GET"}],
    },
    "signatures": [{"name": "Suspicious_Encoded_PowerShell", "severity": 3}],
}


def test_looks_like_cape_accepts_cape():
    assert looks_like_cape(CAPE_SAMPLE) is True
    assert looks_like_cape({}) is False


def test_cape_importer_round_trip(tmp_path):
    src = tmp_path / "cape.json"
    src.write_text(json.dumps(CAPE_SAMPLE), encoding="utf-8")
    parsed = CapeImporter().parse_file(src)
    assert parsed.sample.sandbox_source == "cape"
    assert parsed.sample.sha256 == "a" * 64
    types = {e.event_type for e in parsed.events}
    assert "process" in types
    assert "network" in types
    assert "yara" in types


# ---------------------------------------------------------------------------
# Cuckoo importer
# ---------------------------------------------------------------------------

CUCKOO_SAMPLE = {
    "info": {"id": 1, "version": "2.0.7", "category": "file", "platform": "windows"},
    "target": {"file": {"name": "cuckoo_test.exe", "sha256": "b" * 64}},
    "behavior": {
        "processes": [
            {"pid": 9001, "ppid": 4096, "process_name": "wscript.exe",
             "first_seen": 0.5, "command_line": "wscript.exe payload.vbs"},
        ],
        "summary": {
            "files": ["C:\\Users\\Public\\dropper.bin"],
            "keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        },
    },
    "network": {"hosts": [{"ip": "1.2.3.4"}], "dns": [{"request": "c2.cuckoo.test"}]},
}


def test_looks_like_cuckoo_accepts_cuckoo():
    assert looks_like_cuckoo(CUCKOO_SAMPLE) is True
    assert looks_like_cuckoo(CAPE_SAMPLE) is False  # CAPE doesn't have version+category


def test_cuckoo_importer_round_trip(tmp_path):
    src = tmp_path / "cuckoo.json"
    src.write_text(json.dumps(CUCKOO_SAMPLE), encoding="utf-8")
    parsed = CuckooImporter().parse_file(src)
    assert parsed.sample.sandbox_source == "cuckoo"
    assert parsed.sample.sha256 == "b" * 64

    by_type = {}
    for e in parsed.events:
        by_type.setdefault(e.event_type, []).append(e)
    assert {"process", "file", "registry", "network"} <= set(by_type)
    assert any("dropper.bin" in (e.target.file_path or "") for e in by_type["file"])


def test_cuckoo_importer_handles_iso_timestamps(tmp_path):
    """Real Cuckoo reports use ISO-8601 timestamps in ``first_seen`` fields.

    Phase 12 changed the t=0 anchor: instead of trusting ``info.started`` (which
    routinely has timezone skew vs the per-process timestamps in real reports),
    we now rebase relative-time to ``min(behavior.{generic,processes}[*].first_seen)``.

    For this synthetic fixture both timestamps come from the same clock, so the
    earliest first_seen becomes t=0 and the second is +2.75 s.
    """
    iso_sample = {
        "info": {"id": 9, "version": "2.0.6", "category": "file",
                 "platform": "windows",
                 "started": "2019-06-14T20:30:00.000Z"},
        "target": {"file": {"name": "iso_test.exe", "sha256": "c" * 64}},
        "behavior": {
            "processes": [
                {"pid": 1, "ppid": 0, "process_name": "iso_test.exe",
                 "first_seen": "2019-06-14T20:30:01.500Z",
                 "command_line": "iso_test.exe"},
                {"pid": 2, "ppid": 1, "process_name": "child.exe",
                 "first_seen": "2019-06-14T20:30:04.250Z",
                 "command_line": "child.exe /q"},
            ],
            "summary": {"files": [], "keys": []},
        },
        "network": {"hosts": [], "dns": []},
    }
    src = tmp_path / "iso_cuckoo.json"
    src.write_text(json.dumps(iso_sample), encoding="utf-8")

    parsed = CuckooImporter().parse_file(src)
    process_events = [e for e in parsed.events if e.event_type == "process"]
    assert len(process_events) == 2
    # First process is the new t=0 anchor; second process at +2.75 s.
    assert process_events[0].timestamp == pytest.approx(0.0, abs=0.01)
    assert process_events[1].timestamp == pytest.approx(2.75, abs=0.01)


def test_cuckoo_importer_resilient_to_timezone_skew(tmp_path):
    """When info.started has a different timezone from per-process first_seen
    (a real-world Cuckoo MongoDB-export quirk), the importer rebases to the
    per-process minimum so events never end up tens of thousands of seconds
    in the future.
    """
    skew_sample = {
        "info": {"id": 7, "version": "2.0.6", "category": "file",
                 "platform": "windows",
                 # info.started is in a different TZ from generic.first_seen,
                 # 14 hours behind — exactly the pafish-report bug.
                 "started": "2019-06-14T06:30:45.788Z",
                 "duration": 157},
        "target": {"file": {"name": "skew.exe", "sha256": "d" * 64}},
        "behavior": {
            "generic": [
                {"pid": 1008, "ppid": 484,
                 "process_name": "skew.exe",
                 "first_seen": "2019-06-14T20:30:59.792Z",
                 "summary": {
                     "file_written": ["C:\\\\temp\\\\dropped.exe"],
                     "regkey_opened": ["HKLM\\\\Software\\\\Test"],
                 }},
            ],
            "processes": [
                {"pid": 1008, "ppid": 484, "process_name": "skew.exe",
                 "first_seen": "2019-06-14T20:30:59.792Z",
                 "command_line": "skew.exe"},
            ],
            "summary": {},
        },
        "network": {"hosts": [], "dns": []},
    }
    src = tmp_path / "skew_cuckoo.json"
    src.write_text(json.dumps(skew_sample), encoding="utf-8")
    parsed = CuckooImporter().parse_file(src)
    timestamps = [e.timestamp for e in parsed.events]
    assert timestamps, "expected events to be parsed"
    # All timestamps must fit inside the analysis duration (with breathing room).
    assert max(timestamps) < 10.0, (
        f"timezone skew leaked into relative offsets — max ts = {max(timestamps)}"
    )


def test_cuckoo_importer_runs_through_full_pipeline_with_iso_timestamps(tmp_path):
    """End-to-end: ISO-timestamped Cuckoo report should produce a usable bundle."""
    from analystbridge.ui.services import load_bundle_from_json
    iso_sample = {
        "info": {"id": 9, "version": "2.0.6", "category": "file",
                 "platform": "windows",
                 "started": "2019-06-14T20:30:00.000Z"},
        "target": {"file": {"name": "iso_test.exe", "sha256": "c" * 64}},
        "behavior": {
            "processes": [
                {"pid": 1, "ppid": 0, "process_name": "powershell.exe",
                 "first_seen": "2019-06-14T20:30:01.500Z",
                 "command_line": "powershell.exe -enc Zm9v"},
            ],
            "summary": {"files": [], "keys": []},
        },
        "network": {"hosts": [], "dns": []},
    }
    src = tmp_path / "iso_cuckoo_pipeline.json"
    src.write_text(json.dumps(iso_sample), encoding="utf-8")

    bundle = load_bundle_from_json(src)
    assert bundle.sample.get("sandbox_source") == "cuckoo"
    assert len(bundle.events) >= 1
    # PowerShell -enc should fire T1059.001
    assert any(m.technique_id == "T1059.001" for m in bundle.result.mappings)


# ---------------------------------------------------------------------------
# Sysmon importer
# ---------------------------------------------------------------------------

SYSMON_SAMPLE = [
    {
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Sysmon"},
            "EventID": 1,
            "TimeCreated": "2026-05-08T10:00:00Z",
            "Computer": "DESKTOP-A1",
        },
        "EventData": {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ParentImage": r"C:\Windows\explorer.exe",
            "ProcessId": 4096,
            "ParentProcessId": 1024,
            "CommandLine": "powershell.exe -enc Zm9v",
        },
    },
    {
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Sysmon"},
            "EventID": 3,
            "TimeCreated": "2026-05-08T10:00:05Z",
        },
        "EventData": {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ProcessId": 4096,
            "DestinationIp": "9.9.9.9",
            "DestinationPort": 443,
            "Protocol": "tcp",
        },
    },
    {
        "System": {
            "Provider": {"Name": "Microsoft-Windows-Sysmon"},
            "EventID": 13,
            "TimeCreated": "2026-05-08T10:00:08Z",
        },
        "EventData": {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ProcessId": 4096,
            "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AB",
            "Details": "powershell.exe",
        },
    },
]


def test_looks_like_sysmon_accepts_sysmon():
    assert looks_like_sysmon(SYSMON_SAMPLE) is True
    assert looks_like_sysmon([{"foo": 1}]) is False


def test_sysmon_importer_round_trip(tmp_path):
    src = tmp_path / "sysmon.json"
    src.write_text(json.dumps(SYSMON_SAMPLE), encoding="utf-8")
    parsed = SysmonImporter().parse_file(src)
    assert parsed.sample.sandbox_source == "sysmon"
    types = {e.event_type for e in parsed.events}
    assert {"process", "network", "registry"} <= types

    # The first event should be at ts=0.0 (we rebase to relative seconds).
    assert min(e.timestamp for e in parsed.events) == pytest.approx(0.0, abs=0.01)


# ---------------------------------------------------------------------------
# Auto-detection router
# ---------------------------------------------------------------------------


def test_detect_format_picks_correct_importer():
    assert detect_format(CAPE_SAMPLE) == "cape"
    assert detect_format(CUCKOO_SAMPLE) == "cuckoo"
    assert detect_format(SYSMON_SAMPLE) == "sysmon"


def test_parse_any_routes_each_format(tmp_path):
    cape_src = tmp_path / "c.json"; cape_src.write_text(json.dumps(CAPE_SAMPLE))
    cuc_src = tmp_path / "u.json"; cuc_src.write_text(json.dumps(CUCKOO_SAMPLE))
    sys_src = tmp_path / "s.json"; sys_src.write_text(json.dumps(SYSMON_SAMPLE))

    assert parse_any(cape_src).sample.sandbox_source == "cape"
    assert parse_any(cuc_src).sample.sandbox_source == "cuckoo"
    assert parse_any(sys_src).sample.sandbox_source == "sysmon"
    # Native format still works
    assert parse_any(default_demo_path()).sample.sandbox_source == "demo"


# ---------------------------------------------------------------------------
# CAPE → analysis → action pack (the full pipeline)
# ---------------------------------------------------------------------------


def test_cape_runs_through_full_analysis_pipeline(tmp_path):
    src = tmp_path / "cape.json"
    src.write_text(json.dumps(CAPE_SAMPLE), encoding="utf-8")
    parsed = CapeImporter().parse_file(src)
    norm = Normalizer().normalize_all(parsed.events)

    db = Database(":memory:")
    db.init_schema()
    repo.upsert_sample(db, parsed.sample)
    repo.insert_events(db, parsed.sample.sample_id, norm)
    result = analyze_sample(db, parsed.sample.sample_id, persist=True)

    # We expect at least PowerShell + a Web protocol to fire on this CAPE blob.
    techniques = {m.technique_id for m in result.mappings}
    assert "T1059.001" in techniques
    assert "T1071.001" in techniques


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------


def test_similarity_self_compare_is_high():
    bundle = load_bundle_from_json(default_demo_path())
    fp = SampleFingerprint.from_result("a", "a.exe", bundle.result)
    fp2 = SampleFingerprint(
        sample_id="b",
        filename="b.exe",
        techniques=fp.techniques,
        iocs=fp.iocs,
        storyline=fp.storyline,
        malice_score=fp.malice_score,
    )
    report = compare(fp, fp2)
    assert report.composite > 0.95
    assert report.verdict == "near-identical"


def test_similarity_no_overlap_is_zero():
    a = SampleFingerprint(sample_id="a", techniques=frozenset({"T1"}), iocs=frozenset(), storyline=frozenset({"X"}))
    b = SampleFingerprint(sample_id="b", techniques=frozenset({"T2"}), iocs=frozenset(), storyline=frozenset({"Y"}))
    report = compare(a, b)
    assert report.composite == 0.0
    assert report.verdict == "unrelated"


def test_rank_against_orders_by_similarity():
    target = SampleFingerprint(sample_id="t", techniques=frozenset({"T1", "T2"}), iocs=frozenset(), storyline=frozenset({"X"}))
    near = SampleFingerprint(sample_id="near", techniques=frozenset({"T1", "T2"}), iocs=frozenset(), storyline=frozenset({"X"}))
    far = SampleFingerprint(sample_id="far", techniques=frozenset({"T9"}), iocs=frozenset(), storyline=frozenset({"Z"}))
    ranked = rank_against(target, [far, near])
    assert ranked[0].b == "near"
    assert ranked[1].b == "far"
