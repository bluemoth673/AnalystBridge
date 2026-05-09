"""High-level analysis runner.

Glues together the four engine components against the events stored in the DB.
The CLI and the GUI both call `analyze_sample`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from analystbridge.core.ioc_extractor import Ioc, IocExtractor
from analystbridge.core.mitre_mapper import MitreMapper, MitreMapping
from analystbridge.core.risk_scoring import MaliceScore, RiskScorer
from analystbridge.core.storyline_builder import StorylineBuilder, StorylineStage
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database


@dataclass
class AnalysisResult:
    sample_id: str
    mappings: List[MitreMapping]
    iocs: List[Ioc]
    score: MaliceScore
    storyline: List[StorylineStage]


def analyze_sample(db: Database, sample_id: str, persist: bool = True) -> AnalysisResult:
    events = repo.list_events_for_sample(db, sample_id)

    mappings = MitreMapper().map_events(events)
    iocs = IocExtractor().extract(events)
    score = RiskScorer().score(events)
    storyline = StorylineBuilder().build(events, mappings)

    if persist:
        repo.clear_mitre_mappings_for_sample(db, sample_id)
        repo.insert_mitre_mappings(db, sample_id, mappings)
        repo.clear_iocs_for_sample(db, sample_id)
        repo.insert_iocs(db, sample_id, iocs)

    return AnalysisResult(
        sample_id=sample_id,
        mappings=mappings,
        iocs=iocs,
        score=score,
        storyline=storyline,
    )
