"""IOC CSV exporter."""
from __future__ import annotations

import csv
from pathlib import Path

from analystbridge.ui.services import AnalysisBundle


CSV_HEADERS = ("type", "value", "display_value", "severity", "confidence", "tags", "source_event_ids")


def write_iocs_csv(bundle: AnalysisBundle, out_path: Path) -> Path:
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        for i in bundle.result.iocs:
            writer.writerow([
                i.ioc_type,
                i.value,
                i.display_value,
                i.severity,
                f"{i.confidence:.2f}",
                ";".join(i.tags),
                ";".join(str(eid) for eid in i.source_event_ids),
            ])
    return out_path
