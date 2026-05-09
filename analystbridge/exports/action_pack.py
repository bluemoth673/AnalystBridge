"""SOC Action Pack orchestrator — writes every export file in one call."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from analystbridge.exports.common import safe_dir_name
from analystbridge.exports.csv_exporter import write_iocs_csv
from analystbridge.exports.json_exporter import write_iocs_json, write_soc_action_pack_json
from analystbridge.exports.kql_exporter import write_defender_kql
from analystbridge.exports.report_exporter import write_markdown_report
from analystbridge.exports.sigma_exporter import write_sigma_rule
from analystbridge.exports.splunk_exporter import write_splunk_spl
from analystbridge.exports.stix_exporter import write_stix_bundle
from analystbridge.ui.services import AnalysisBundle


# Canonical filenames the GUI / dialog show as checkboxes. Keep in this order
# so the export dialog and on-disk layout match.
ARTIFACTS = (
    "report.md",
    "iocs.json",
    "iocs.csv",
    "detection_sigma.yml",
    "hunting_defender.kql",
    "hunting_splunk.spl",
    "stix2_bundle.json",
    "soc_action_pack.json",
)


@dataclass
class ExportManifest:
    out_dir: Path
    files: List[Path]


_WRITERS = {
    "report.md": write_markdown_report,
    "iocs.json": write_iocs_json,
    "iocs.csv": write_iocs_csv,
    "detection_sigma.yml": write_sigma_rule,
    "hunting_defender.kql": write_defender_kql,
    "hunting_splunk.spl": write_splunk_spl,
    "stix2_bundle.json": write_stix_bundle,
    "soc_action_pack.json": write_soc_action_pack_json,
}


def export_action_pack(
    bundle: AnalysisBundle,
    exports_root: Path | str = "exports",
    selected: Optional[Iterable[str]] = None,
) -> ExportManifest:
    """Write SOC Action Pack files for `bundle` into
    `<exports_root>/<sample_id>/`. Existing files in that directory are
    overwritten.

    `selected` (optional) restricts the output to a subset of `ARTIFACTS`
    filenames. Unknown names are ignored. By default all artifacts are written.
    """
    sample_id = bundle.sample.get("sample_id") or "unknown_sample"
    out_dir = Path(exports_root) / safe_dir_name(sample_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    if selected is None:
        wanted = list(ARTIFACTS)
    else:
        wanted_set = set(selected)
        wanted = [name for name in ARTIFACTS if name in wanted_set]

    files: List[Path] = []
    for name in wanted:
        writer = _WRITERS.get(name)
        if writer is None:
            continue
        files.append(writer(bundle, out_dir / name))

    return ExportManifest(out_dir=out_dir, files=files)
