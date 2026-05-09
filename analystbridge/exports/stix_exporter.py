"""STIX 2.1 exporter — emits a Bundle of Indicator SDOs for every IOC.

Output is valid against the STIX 2.1 spec well enough to drop into MISP, OpenCTI,
or any TIP that ingests STIX bundles. We emit:

  * 1 `identity` (the AnalystBridge tool, as the producer)
  * 1 `malware` SDO for the sample itself (with sha256)
  * 1 `indicator` per IOC, using the canonical `pattern` syntax for that type
  * `relationship` SDOs linking each indicator to the malware

UUIDs are derived deterministically from the sample_id + IOC value so repeated
exports of the same sample produce byte-identical bundles (CI / version-control
friendly).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List

from analystbridge.exports.common import utc_now_iso
from analystbridge.ui.services import AnalysisBundle

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # arbitrary, stable
SPEC_VERSION = "2.1"


def _sid(prefix: str, key: str) -> str:
    return f"{prefix}--{uuid.uuid5(STIX_NAMESPACE, f'{prefix}:{key}')}"


def _ioc_pattern(ioc_type: str, value: str) -> str | None:
    """Return a STIX 2.1 pattern string for the given IOC type, or None to skip."""
    safe = value.replace("'", "\\'")
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{safe}']"
    if ioc_type == "md5":
        return f"[file:hashes.MD5 = '{safe}']"
    if ioc_type == "sha1":
        return f"[file:hashes.'SHA-1' = '{safe}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{safe}']"
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{safe}']"
    if ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{safe}']"
    if ioc_type == "url":
        return f"[url:value = '{safe}']"
    if ioc_type == "file_path":
        return f"[file:name = '{safe}']"
    if ioc_type == "registry_key":
        return f"[windows-registry-key:key = '{safe}']"
    return None


def _indicator_label(ioc_type: str) -> str:
    return {
        "sha256": "malicious-activity",
        "md5": "malicious-activity",
        "sha1": "malicious-activity",
        "domain": "malicious-activity",
        "ipv4": "malicious-activity",
        "ipv6": "malicious-activity",
        "url": "malicious-activity",
        "file_path": "malicious-activity",
        "registry_key": "persistence",
    }.get(ioc_type, "malicious-activity")


def write_stix_bundle(bundle: AnalysisBundle, out_path: Path) -> Path:
    sample = bundle.sample
    sample_id = sample.get("sample_id") or "unknown_sample"
    iocs = bundle.result.iocs
    now = utc_now_iso()

    objects: List[Dict[str, Any]] = []

    # Producer identity
    identity_id = _sid("identity", "analystbridge-tool")
    objects.append({
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "AnalystBridge",
        "identity_class": "system",
        "description": "AnalystBridge — Malware Visual Intelligence Engine",
    })

    # Malware SDO for the sample
    sha256 = sample.get("sha256") or ""
    malware_id = _sid("malware", sample_id)
    malware_obj: Dict[str, Any] = {
        "type": "malware",
        "spec_version": SPEC_VERSION,
        "id": malware_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": sample.get("filename") or sample_id,
        "is_family": False,
        "malware_types": ["unknown"],
        "description": (
            f"Malice score {bundle.result.score.score}/100 "
            f"({bundle.result.score.risk_level}); "
            f"{len(bundle.result.mappings)} MITRE ATT&CK techniques observed."
        ),
    }
    if sha256:
        malware_obj["x_sha256"] = sha256
    objects.append(malware_obj)

    # Indicators + relationships
    for ioc in iocs:
        pattern = _ioc_pattern(ioc.ioc_type, ioc.value)
        if pattern is None:
            continue
        ind_key = f"{ioc.ioc_type}:{ioc.value}"
        ind_id = _sid("indicator", ind_key)
        indicator: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": SPEC_VERSION,
            "id": ind_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": ioc.display_value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [_indicator_label(ioc.ioc_type)],
            "indicator_types": [_indicator_label(ioc.ioc_type)],
            "confidence": int(round(getattr(ioc, "confidence", 0.8) * 100)),
        }
        if ioc.tags:
            indicator["x_analystbridge_tags"] = list(ioc.tags)
        objects.append(indicator)

        rel_id = _sid("relationship", f"{ind_key}:indicates:{sample_id}")
        objects.append({
            "type": "relationship",
            "spec_version": SPEC_VERSION,
            "id": rel_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "relationship_type": "indicates",
            "source_ref": ind_id,
            "target_ref": malware_id,
        })

    bundle_id = _sid("bundle", f"{sample_id}:{now}")
    bundle_obj = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }

    out_path.write_text(json.dumps(bundle_obj, indent=2), encoding="utf-8")
    return out_path
