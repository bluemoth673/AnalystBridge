"""Markdown SOC report exporter."""
from __future__ import annotations

from pathlib import Path

from analystbridge import __version__
from analystbridge.exports.common import CONTAINMENT_RECOMMENDATIONS, utc_now_iso
from analystbridge.ui.services import AnalysisBundle


def _ioc_section(title: str, items: list, formatter) -> str:
    if not items:
        return ""
    lines = [f"### {title}", ""]
    for item in items:
        lines.append(f"- {formatter(item)}")
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(bundle: AnalysisBundle, out_path: Path) -> Path:
    sample = bundle.sample
    score = bundle.result.score
    mappings = bundle.result.mappings
    iocs = bundle.result.iocs
    storyline = bundle.result.storyline

    by_type: dict[str, list] = {}
    for i in iocs:
        by_type.setdefault(i.ioc_type, []).append(i)

    lines: list[str] = []
    lines.append(f"# AnalystBridge SOC Action Pack — {sample.get('filename', '?')}")
    lines.append("")
    lines.append(f"**Sample ID:** `{sample.get('sample_id')}`  ")
    lines.append(f"**SHA256:** `{sample.get('sha256') or '?'}`  ")
    lines.append(f"**Platform:** {sample.get('platform') or '?'}  ")
    lines.append(f"**Sandbox source:** {sample.get('sandbox_source') or '?'}  ")
    lines.append(f"**Generated:** {utc_now_iso()}  ")
    lines.append(f"**Tool:** AnalystBridge v{__version__}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"`{sample.get('filename')}` exhibits behavior consistent with malicious activity. "
        f"AnalystBridge assigns a **Malice Score of {score.score}/100 ({score.risk_level})** "
        f"based on **{len(mappings)} MITRE ATT&CK techniques** and "
        f"**{len(iocs)} unique indicators of compromise** extracted from the behavior log."
    )
    lines.append("")
    if storyline:
        lines.append("Key behaviors observed (in order):")
        lines.append("")
        for idx, stage in enumerate(storyline, start=1):
            lines.append(f"{idx}. **{stage.title}** — {stage.description}")
        lines.append("")

    # Malice Score
    lines.append(f"## Malice Score: {score.score} / {score.risk_level}")
    lines.append("")
    lines.append("| Points | Reason |")
    lines.append("|-------:|--------|")
    for c in score.contributions:
        lines.append(f"| +{c.points} | {c.reason} |")
    lines.append("")

    # MITRE ATT&CK
    lines.append("## MITRE ATT&CK Mapping")
    lines.append("")
    if mappings:
        lines.append("| Technique | Tactic | Confidence | Reason |")
        lines.append("|-----------|--------|-----------:|--------|")
        for m in mappings:
            lines.append(
                f"| `{m.technique_id}` {m.technique_name} | {m.tactic} | "
                f"{m.confidence:.0%} | {m.reason} |"
            )
        lines.append("")
    else:
        lines.append("_No techniques detected._")
        lines.append("")

    # IOCs
    lines.append("## Indicators of Compromise")
    lines.append("")
    lines.append(f"_{len(iocs)} unique indicators. Network indicators are defanged for safe rendering._")
    lines.append("")
    lines.append(_ioc_section("Network — Domains", by_type.get("domain", []),
                              lambda i: f"`{i.display_value}` (raw: `{i.value}`)"))
    lines.append(_ioc_section("Network — IPv4", by_type.get("ipv4", []),
                              lambda i: f"`{i.display_value}` (raw: `{i.value}`)"))
    lines.append(_ioc_section("Network — URLs", by_type.get("url", []),
                              lambda i: f"`{i.display_value}` (raw: `{i.value}`)"))
    lines.append(_ioc_section("File hashes (SHA256)", by_type.get("sha256", []),
                              lambda i: f"`{i.value}`"))
    lines.append(_ioc_section("File paths", by_type.get("file_path", []),
                              lambda i: f"`{i.value}`"))
    lines.append(_ioc_section("Registry keys", by_type.get("registry_key", []),
                              lambda i: f"`{i.value}`"))

    # Storyline
    lines.append("## Attack Storyline")
    lines.append("")
    for idx, stage in enumerate(storyline, start=1):
        ids = ", ".join(stage.mitre_ids) if stage.mitre_ids else "-"
        lines.append(f"### {idx}. {stage.title}  *(MITRE: {ids})*")
        lines.append("")
        lines.append(stage.description)
        lines.append("")
        if stage.recommended_action:
            lines.append(f"**Recommended action:** {stage.recommended_action}")
            lines.append("")

    # Containment
    lines.append("## Containment Recommendations")
    lines.append("")
    for rec in CONTAINMENT_RECOMMENDATIONS:
        lines.append(f"- {rec}")
    lines.append("")

    # Detection artifacts
    lines.append("## Detection / Hunting Artifacts")
    lines.append("")
    lines.append("- Sigma rule: `detection_sigma.yml`")
    lines.append("- Microsoft Defender KQL: `hunting_defender.kql`")
    lines.append("- Splunk SPL: `hunting_splunk.spl`")
    lines.append("- IOC list (JSON): `iocs.json`")
    lines.append("- IOC list (CSV): `iocs.csv`")
    lines.append("- STIX 2.1 bundle (TIP / MISP): `stix2_bundle.json`")
    lines.append("- Master JSON pack: `soc_action_pack.json`")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
