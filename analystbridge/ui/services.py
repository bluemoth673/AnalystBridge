"""Engine glue for the GUI.

Loads a sandbox JSON, runs the full analysis pipeline, and returns a single
`AnalysisBundle` the UI panels know how to consume. No Qt imports here so this
module stays unit-testable.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import networkx as nx

from analystbridge.core.analysis import AnalysisResult, analyze_sample
from analystbridge.core.event_row import EventRow
from analystbridge.graph.graph_builder import GraphBuilder
from analystbridge.ingestion.auto import parse_any
from analystbridge.ingestion.json_parser import JsonSandboxParser
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


@dataclass
class AnalysisBundle:
    sample: dict
    events: List[EventRow]
    result: AnalysisResult
    graph: nx.MultiDiGraph


def default_demo_path() -> Path:
    """Path to the bundled demo dataset, anchored at the project root."""
    from analystbridge.paths import SAMPLE_DATA_ROOT
    return SAMPLE_DATA_ROOT / "ransomware_demo.json"


def load_bundle_from_json(
    path: Path | str,
    db_path: str = ":memory:",
    *,
    auto_detect: bool = True,
) -> AnalysisBundle:
    """Load a sandbox report and run it through the full analysis pipeline.

    ``auto_detect=True`` (default) routes through the multi-format importer
    (native AnalystBridge / CAPE / Cuckoo / Sysmon). Pass ``False`` to force
    the native parser only — useful for tests that pin the schema.
    """
    src = Path(path)

    db = Database(db_path)
    db.init_schema()

    if auto_detect:
        parsed = parse_any(src)
    else:
        parsed = JsonSandboxParser().parse_file(src)
    norm = Normalizer().normalize_all(parsed.events)

    repo.upsert_sample(db, parsed.sample)
    repo.clear_events_for_sample(db, parsed.sample.sample_id)
    repo.insert_events(db, parsed.sample.sample_id, norm)

    events = repo.list_events_for_sample(db, parsed.sample.sample_id)
    result = analyze_sample(db, parsed.sample.sample_id, persist=True)
    graph = GraphBuilder().build(events)
    sample = repo.get_sample(db, parsed.sample.sample_id) or {}

    db.close()
    return AnalysisBundle(sample=sample, events=events, result=result, graph=graph)
