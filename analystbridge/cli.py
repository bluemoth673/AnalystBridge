"""Command-line interface for AnalystBridge.

Lets us drive the data pipeline without booting the GUI:

    python -m analystbridge.cli ingest sample_data/ransomware_demo.json
    python -m analystbridge.cli ingest sample_data/ransomware_demo.json --db custom.db --reingest
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analystbridge.core.analysis import analyze_sample
from analystbridge.core.similarity import SampleFingerprint, compare
from analystbridge.exports.action_pack import export_action_pack
from analystbridge.graph.graph_builder import GraphBuilder
from analystbridge.ingestion.auto import parse_any
from analystbridge.ingestion.normalizer import Normalizer
from analystbridge.storage import repositories as repo
from analystbridge.storage.database import Database
from analystbridge.ui.services import AnalysisBundle


def cmd_ingest(path: str, db_path: str, reingest: bool, fmt: str | None = None) -> int:
    src = Path(path)
    if not src.exists():
        print(f"error: {src} does not exist", file=sys.stderr)
        return 2

    parsed = parse_any(src, format=fmt)
    print(f"Detected format: {parsed.sample.sandbox_source or 'analystbridge'}")
    events = Normalizer().normalize_all(parsed.events)

    db = Database(db_path)
    db.init_schema()
    repo.upsert_sample(db, parsed.sample)
    if reingest:
        repo.clear_events_for_sample(db, parsed.sample.sample_id)
    inserted = repo.insert_events(db, parsed.sample.sample_id, events)

    counts = repo.event_counts(db, parsed.sample.sample_id)
    total = sum(counts.values())

    print(f"Sample      : {parsed.sample.filename}")
    print(f"Sample ID   : {parsed.sample.sample_id}")
    print(f"SHA256      : {parsed.sample.sha256}")
    print(f"Platform    : {parsed.sample.platform}")
    print(f"Sandbox     : {parsed.sample.sandbox_source}")
    print(f"DB          : {db_path}")
    print(f"Inserted    : {inserted} events this run")
    print(f"Total in DB : {total} events for this sample")
    print()
    print("Event type breakdown:")
    for k in sorted(counts):
        print(f"  {k:10s} {counts[k]}")

    db.close()
    return 0


def cmd_analyze(db_path: str, sample_id: str) -> int:
    db = Database(db_path)
    db.init_schema()

    sample = repo.get_sample(db, sample_id)
    if sample is None:
        print(f"error: sample '{sample_id}' not found in {db_path}", file=sys.stderr)
        db.close()
        return 2

    result = analyze_sample(db, sample_id, persist=True)
    events = repo.list_events_for_sample(db, sample_id)
    graph = GraphBuilder().build(events)
    gstats = GraphBuilder.stats(graph)

    print(f"=== Analysis: {sample['filename']} ({sample_id}) ===")
    print()
    print(f"Malice Score : {result.score.score} / {result.score.risk_level}")
    print("Score Breakdown:")
    for c in result.score.contributions:
        sign = "+" if c.points >= 0 else ""
        print(f"  {sign}{c.points:>3}  {c.reason}")
    print()
    print(f"MITRE ATT&CK ({len(result.mappings)} techniques)")
    for m in result.mappings:
        print(f"  {m.technique_id:<12} {m.tactic:<22} {m.technique_name}")
        print(f"               reason     : {m.reason}")
        print(f"               confidence : {m.confidence:.0%}, evidence: {len(m.evidence_event_ids)} events")
    print()
    print(f"IOCs ({len(result.iocs)} unique)")
    for i in result.iocs:
        print(f"  [{i.ioc_type:<13}] sev={i.severity:<3} {i.display_value}")
    print()
    print(f"Attack Storyline ({len(result.storyline)} stages)")
    for idx, stage in enumerate(result.storyline, start=1):
        ids = ", ".join(stage.mitre_ids) if stage.mitre_ids else "-"
        print(f"  {idx}. {stage.title}  [{ids}]")
        print(f"     {stage.description}")
        if stage.recommended_action:
            print(f"     action: {stage.recommended_action}")
    print()
    print(f"Behavior Graph: {gstats['nodes']} nodes / {gstats['edges']} edges")
    for kind, count in sorted(gstats["by_kind"].items()):
        print(f"  {kind:<10} {count}")

    db.close()
    return 0


def cmd_export(db_path: str, sample_id: str, exports_root: str) -> int:
    db = Database(db_path)
    db.init_schema()

    sample = repo.get_sample(db, sample_id)
    if sample is None:
        print(f"error: sample '{sample_id}' not found in {db_path}", file=sys.stderr)
        db.close()
        return 2

    # Re-run analysis to make sure mappings/iocs are current.
    result = analyze_sample(db, sample_id, persist=True)
    events = repo.list_events_for_sample(db, sample_id)
    graph = GraphBuilder().build(events)
    bundle = AnalysisBundle(sample=sample, events=events, result=result, graph=graph)

    manifest = export_action_pack(bundle, exports_root=exports_root)

    print(f"SOC Action Pack written to: {manifest.out_dir}")
    for f in manifest.files:
        print(f"  - {f.name}")
    db.close()
    return 0


def cmd_compare(db_path: str, sample_a: str, sample_b: str) -> int:
    db = Database(db_path)
    db.init_schema()
    sa = repo.get_sample(db, sample_a)
    sb = repo.get_sample(db, sample_b)
    if sa is None or sb is None:
        missing = sample_a if sa is None else sample_b
        print(f"error: sample '{missing}' not found in {db_path}", file=sys.stderr)
        db.close()
        return 2

    ra = analyze_sample(db, sample_a, persist=False)
    rb = analyze_sample(db, sample_b, persist=False)
    fa = SampleFingerprint.from_result(sample_a, sa.get("filename", ""), ra)
    fb = SampleFingerprint.from_result(sample_b, sb.get("filename", ""), rb)
    report = compare(fa, fb)

    print(f"=== Behaviour Similarity ===")
    print(f"  A: {sample_a}  ({sa.get('filename', '')})")
    print(f"  B: {sample_b}  ({sb.get('filename', '')})")
    print()
    print(f"  Technique overlap : {report.technique_overlap:.0%}")
    print(f"  IOC overlap       : {report.ioc_overlap:.0%}")
    print(f"  Storyline overlap : {report.storyline_overlap:.0%}")
    print(f"  Composite score   : {report.composite:.0%}")
    print(f"  Verdict           : {report.verdict}")
    print()
    if report.shared_techniques:
        print("  Shared techniques :", ", ".join(report.shared_techniques))
    if report.shared_storyline:
        print("  Shared stages     :", ", ".join(report.shared_storyline))
    if report.shared_iocs:
        print(f"  Shared IOCs       : {len(report.shared_iocs)} (showing first 10)")
        for ioc in report.shared_iocs[:10]:
            print(f"    - {ioc}")

    db.close()
    return 0


def cmd_samples(db_path: str) -> int:
    db = Database(db_path)
    db.init_schema()
    rows = repo.list_samples(db)
    if not rows:
        print("(no samples in db)")
    else:
        print(f"{'sample_id':30s} {'filename':32s} {'platform':16s} status")
        for r in rows:
            print(
                f"{r['sample_id']:30s} {(r['filename'] or ''):32s} "
                f"{(r['platform'] or ''):16s} {r['analysis_status']}"
            )
    db.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="analystbridge.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ingest = sub.add_parser("ingest", help="Ingest a sandbox JSON report")
    ingest.add_argument("path", help="Path to sandbox JSON file")
    ingest.add_argument("--db", default="analystbridge.db", help="SQLite db path")
    ingest.add_argument(
        "--reingest",
        action="store_true",
        help="Wipe existing events for this sample before inserting",
    )
    ingest.add_argument(
        "--format",
        choices=("analystbridge", "cape", "cuckoo", "sysmon"),
        default=None,
        help="Force a specific input format (auto-detect by default)",
    )

    analyze = sub.add_parser("analyze", help="Run the analysis engine on an ingested sample")
    analyze.add_argument("--sample-id", required=True, help="sample_id to analyze")
    analyze.add_argument("--db", default="analystbridge.db", help="SQLite db path")

    export = sub.add_parser("export", help="Generate the SOC Action Pack export bundle")
    export.add_argument("--sample-id", required=True, help="sample_id to export")
    export.add_argument("--db", default="analystbridge.db", help="SQLite db path")
    export.add_argument("--out", default="exports",
                        help="Root directory for exports (per-sample subdir is created)")

    sub.add_parser("samples", help="List ingested samples").add_argument(
        "--db", default="analystbridge.db", help="SQLite db path"
    )

    compare_p = sub.add_parser(
        "compare",
        help="Compute behavioural similarity between two ingested samples",
    )
    compare_p.add_argument("--a", required=True, dest="sample_a", help="Sample A id")
    compare_p.add_argument("--b", required=True, dest="sample_b", help="Sample B id")
    compare_p.add_argument("--db", default="analystbridge.db", help="SQLite db path")

    args = parser.parse_args(argv)
    if args.cmd == "ingest":
        return cmd_ingest(args.path, args.db, args.reingest, args.format)
    if args.cmd == "analyze":
        return cmd_analyze(args.db, args.sample_id)
    if args.cmd == "export":
        return cmd_export(args.db, args.sample_id, args.out)
    if args.cmd == "samples":
        return cmd_samples(args.db)
    if args.cmd == "compare":
        return cmd_compare(args.db, args.sample_a, args.sample_b)
    return 1


if __name__ == "__main__":
    sys.exit(main())
