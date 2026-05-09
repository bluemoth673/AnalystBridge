"""Tests for the SOC Action Pack exporters and the orchestrator."""
import csv
import json
from pathlib import Path

import pytest

from analystbridge.exports.action_pack import export_action_pack
from analystbridge.exports.csv_exporter import write_iocs_csv
from analystbridge.exports.json_exporter import write_iocs_json, write_soc_action_pack_json
from analystbridge.exports.kql_exporter import write_defender_kql
from analystbridge.exports.report_exporter import write_markdown_report
from analystbridge.exports.sigma_exporter import write_sigma_rule
from analystbridge.exports.splunk_exporter import write_splunk_spl
from analystbridge.ui.services import default_demo_path, load_bundle_from_json


@pytest.fixture(scope="module")
def bundle():
    return load_bundle_from_json(default_demo_path())


def test_write_iocs_json_is_valid_json_and_contains_demo_iocs(bundle, tmp_path):
    out = write_iocs_json(bundle, tmp_path / "iocs.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["sample_id"] == "sample_ransomware_001"
    assert data["ioc_count"] == len(bundle.result.iocs) > 0
    assert any(i["type"] == "domain" and "badactor" in i["value"] for i in data["iocs"])


def test_write_iocs_csv_has_correct_header_and_row_count(bundle, tmp_path):
    out = write_iocs_csv(bundle, tmp_path / "iocs.csv")
    with out.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
    assert rows[0][0] == "type" and rows[0][1] == "value"
    assert len(rows) - 1 == len(bundle.result.iocs)


def test_write_soc_action_pack_json_contains_all_sections(bundle, tmp_path):
    out = write_soc_action_pack_json(bundle, tmp_path / "soc_action_pack.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    for key in (
        "schema_version", "tool", "sample", "malice_score",
        "mitre_attack", "iocs", "storyline",
        "containment_recommendations", "graph_summary",
    ):
        assert key in data, f"missing section: {key}"
    assert data["malice_score"]["score"] >= 75
    assert len(data["mitre_attack"]) >= 5
    assert data["graph_summary"]["nodes"] > 0


def test_write_sigma_rule_includes_expected_selectors(bundle, tmp_path):
    out = write_sigma_rule(bundle, tmp_path / "rule.yml")
    text = out.read_text(encoding="utf-8")
    assert "title:" in text and "logsource:" in text and "detection:" in text
    assert "selection_powershell" in text
    assert "selection_mshta" in text
    assert "selection_vssadmin" in text
    assert "attack.t1059.001" in text


def test_write_defender_kql_has_blocks_and_iocs(bundle, tmp_path):
    out = write_defender_kql(bundle, tmp_path / "kql.kql")
    text = out.read_text(encoding="utf-8")
    assert "DeviceProcessEvents" in text
    assert "DeviceRegistryEvents" in text
    assert "DeviceNetworkEvents" in text
    assert "cdn.badactor.com" in text


def test_write_splunk_spl_has_blocks_and_iocs(bundle, tmp_path):
    out = write_splunk_spl(bundle, tmp_path / "hunt.spl")
    text = out.read_text(encoding="utf-8")
    assert "powershell.exe" in text
    assert "vssadmin.exe" in text
    assert "cdn.badactor.com" in text


def test_write_markdown_report_includes_all_sections(bundle, tmp_path):
    out = write_markdown_report(bundle, tmp_path / "report.md")
    text = out.read_text(encoding="utf-8")
    for heading in (
        "# AnalystBridge SOC Action Pack",
        "## Executive Summary",
        "## Malice Score:",
        "## MITRE ATT&CK Mapping",
        "## Indicators of Compromise",
        "## Attack Storyline",
        "## Containment Recommendations",
        "## Detection / Hunting Artifacts",
    ):
        assert heading in text, f"missing heading: {heading}"


def test_export_action_pack_writes_all_artifacts(bundle, tmp_path):
    manifest = export_action_pack(bundle, exports_root=tmp_path)
    expected = {
        "report.md",
        "iocs.json",
        "iocs.csv",
        "detection_sigma.yml",
        "hunting_defender.kql",
        "hunting_splunk.spl",
        "stix2_bundle.json",
        "soc_action_pack.json",
    }
    actual = {p.name for p in manifest.files}
    assert actual == expected
    for p in manifest.files:
        assert p.exists() and p.stat().st_size > 0
    assert manifest.out_dir.name == "sample_ransomware_001"


def test_export_action_pack_honours_subset_selection(bundle, tmp_path):
    manifest = export_action_pack(
        bundle,
        exports_root=tmp_path,
        selected={"report.md", "iocs.csv", "stix2_bundle.json"},
    )
    actual = {p.name for p in manifest.files}
    assert actual == {"report.md", "iocs.csv", "stix2_bundle.json"}
    # Anything not selected must NOT exist on disk
    for unwanted in ("hunting_defender.kql", "hunting_splunk.spl"):
        assert not (manifest.out_dir / unwanted).exists()


def test_export_action_pack_is_idempotent(bundle, tmp_path):
    """Running export twice should overwrite, not duplicate or error."""
    first = export_action_pack(bundle, exports_root=tmp_path)
    second = export_action_pack(bundle, exports_root=tmp_path)
    assert {p.name for p in first.files} == {p.name for p in second.files}


def test_export_dir_name_is_filesystem_safe(tmp_path):
    """If a sample_id contains weird characters, the directory must still be safe."""
    from analystbridge.core.analysis import AnalysisResult
    from analystbridge.core.ioc_extractor import Ioc
    from analystbridge.core.mitre_mapper import MitreMapping
    from analystbridge.core.risk_scoring import MaliceScore
    from analystbridge.ui.services import AnalysisBundle
    import networkx as nx

    bundle = AnalysisBundle(
        sample={"sample_id": "weird/sample:1*?", "filename": "x.exe", "sha256": "0" * 64},
        events=[],
        result=AnalysisResult(
            sample_id="weird/sample:1*?",
            mappings=[],
            iocs=[],
            score=MaliceScore(score=0, risk_level="Low", contributions=[]),
            storyline=[],
        ),
        graph=nx.MultiDiGraph(),
    )
    manifest = export_action_pack(bundle, exports_root=tmp_path)
    assert manifest.out_dir.name == "weird_sample_1"
    assert all(p.exists() for p in manifest.files)
