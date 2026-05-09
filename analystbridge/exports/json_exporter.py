"""IOC JSON + master soc_action_pack.json exporters."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from analystbridge import __version__
from analystbridge.exports.common import CONTAINMENT_RECOMMENDATIONS, utc_now_iso
from analystbridge.ui.services import AnalysisBundle


def write_iocs_json(bundle: AnalysisBundle, out_path: Path) -> Path:
    payload = {
        "sample_id": bundle.sample.get("sample_id"),
        "filename": bundle.sample.get("filename"),
        "sha256": bundle.sample.get("sha256"),
        "generated_at": utc_now_iso(),
        "ioc_count": len(bundle.result.iocs),
        "iocs": [
            {
                "type": ioc.ioc_type,
                "value": ioc.value,
                "display_value": ioc.display_value,
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "tags": list(ioc.tags),
                "source_event_ids": list(ioc.source_event_ids),
            }
            for ioc in bundle.result.iocs
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def write_soc_action_pack_json(bundle: AnalysisBundle, out_path: Path) -> Path:
    payload = {
        "schema_version": "1.0",
        "generated_at": utc_now_iso(),
        "tool": {"name": "AnalystBridge", "version": __version__},
        "sample": {
            "sample_id": bundle.sample.get("sample_id"),
            "filename": bundle.sample.get("filename"),
            "sha256": bundle.sample.get("sha256"),
            "platform": bundle.sample.get("platform"),
            "sandbox_source": bundle.sample.get("sandbox_source"),
            "first_seen": bundle.sample.get("first_seen"),
        },
        "malice_score": asdict(bundle.result.score),
        "mitre_attack": [m.to_dict() for m in bundle.result.mappings],
        "iocs": [
            {
                "type": i.ioc_type,
                "value": i.value,
                "display_value": i.display_value,
                "severity": i.severity,
                "confidence": i.confidence,
                "tags": list(i.tags),
                "source_event_ids": list(i.source_event_ids),
            }
            for i in bundle.result.iocs
        ],
        "storyline": [s.to_dict() for s in bundle.result.storyline],
        "containment_recommendations": CONTAINMENT_RECOMMENDATIONS,
        "detection_artifacts": {
            "sigma": "detection_sigma.yml",
            "defender_kql": "hunting_defender.kql",
            "splunk_spl": "hunting_splunk.spl",
        },
        "report_files": {
            "markdown": "report.md",
            "iocs_json": "iocs.json",
            "iocs_csv": "iocs.csv",
        },
        "graph_summary": {
            "nodes": bundle.graph.number_of_nodes(),
            "edges": bundle.graph.number_of_edges(),
        },
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path
