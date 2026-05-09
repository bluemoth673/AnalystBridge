"""Behaviour similarity comparison across previously analysed samples.

Computes a deterministic similarity score between two ``AnalysisResult``
objects (or a fingerprint extracted from one) using Jaccard overlap on three
behavioural axes:

  * MITRE ATT&CK technique set
  * IOC value set (network + file hashes)
  * Action verbs in the storyline

The combined score weights techniques highest (they are the most stable
behavioural signal) and IOCs lowest (they rotate quickly).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from analystbridge.core.analysis import AnalysisResult


# Weights for the composite score — must sum to 1.0
W_TECHNIQUES = 0.55
W_IOCS = 0.20
W_STORYLINE = 0.25


@dataclass(frozen=True)
class SampleFingerprint:
    """The minimal behavioural signature we hash for similarity."""

    sample_id: str
    filename: str = ""
    techniques: frozenset[str] = field(default_factory=frozenset)
    iocs: frozenset[str] = field(default_factory=frozenset)
    storyline: frozenset[str] = field(default_factory=frozenset)
    malice_score: int = 0

    @classmethod
    def from_result(
        cls,
        sample_id: str,
        filename: str,
        result: AnalysisResult,
    ) -> "SampleFingerprint":
        techniques = frozenset(m.technique_id for m in result.mappings)
        iocs = frozenset(f"{i.ioc_type}:{i.value}" for i in result.iocs)
        storyline = frozenset(s.title for s in result.storyline)
        return cls(
            sample_id=sample_id,
            filename=filename or sample_id,
            techniques=techniques,
            iocs=iocs,
            storyline=storyline,
            malice_score=result.score.score,
        )


@dataclass
class SimilarityReport:
    a: str  # sample_id of A
    b: str  # sample_id of B
    technique_overlap: float
    ioc_overlap: float
    storyline_overlap: float
    composite: float
    shared_techniques: list[str]
    shared_iocs: list[str]
    shared_storyline: list[str]
    verdict: str  # "near-identical" | "strong" | "moderate" | "weak" | "unrelated"

    def to_dict(self) -> dict:
        return asdict(self)


def _jaccard(a: Iterable, b: Iterable) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / len(union)


def _verdict(score: float) -> str:
    if score >= 0.85:
        return "near-identical"
    if score >= 0.60:
        return "strong"
    if score >= 0.35:
        return "moderate"
    if score >= 0.15:
        return "weak"
    return "unrelated"


def compare(a: SampleFingerprint, b: SampleFingerprint) -> SimilarityReport:
    t = _jaccard(a.techniques, b.techniques)
    i = _jaccard(a.iocs, b.iocs)
    s = _jaccard(a.storyline, b.storyline)
    composite = W_TECHNIQUES * t + W_IOCS * i + W_STORYLINE * s
    return SimilarityReport(
        a=a.sample_id,
        b=b.sample_id,
        technique_overlap=t,
        ioc_overlap=i,
        storyline_overlap=s,
        composite=composite,
        shared_techniques=sorted(a.techniques & b.techniques),
        shared_iocs=sorted(a.iocs & b.iocs),
        shared_storyline=sorted(a.storyline & b.storyline),
        verdict=_verdict(composite),
    )


def rank_against(
    target: SampleFingerprint,
    candidates: list[SampleFingerprint],
    top_k: int = 10,
) -> list[SimilarityReport]:
    """Return ``candidates`` ranked by similarity to ``target`` (best first)."""
    reports = [compare(target, c) for c in candidates if c.sample_id != target.sample_id]
    reports.sort(key=lambda r: r.composite, reverse=True)
    return reports[:top_k]
