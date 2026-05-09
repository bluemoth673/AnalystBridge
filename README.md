# AnalystBridge

**Malware Visual Intelligence Engine** — converts sandbox-style malware behavior logs into a visual, interactive, evidence-backed investigation workspace.

> AnalystBridge does not just show what malware did. It converts sandbox noise into evidence-backed, SOC-actionable intelligence.

## Scope

AnalystBridge is **not** a sandbox. It does **not** execute malware. It imports and analyzes safe, prerecorded sandbox logs (JSON) and renders them as graphs, timelines, MITRE ATT&CK mappings, IOCs, malice scores, attack storylines, and SOC Action Packs.

For the MVP, only safe simulated demo data is used.

## Quickstart

```bash
pip install -r requirements.txt

# Launch GUI (Phase 1 stub — empty window)
python -m analystbridge.app

# Ingest the demo dataset into a SQLite DB (Phase 2)
python -m analystbridge.cli ingest sample_data/ransomware_demo.json

# Analyze the ingested sample (MITRE / IOCs / Malice Score / Storyline)
python -m analystbridge.cli analyze --sample-id sample_ransomware_001

# Run tests
python -m pytest -q
```

## Project layout

```
analystbridge/        Application package
  app.py              GUI entry point
  main_window.py      Main Qt window
  core/               Models, schemas, analysis engine (MITRE, IOCs, scoring)
  ingestion/          Parsers and normalizers for sandbox reports
  storage/            SQLite database + repositories
  graph/              Graph model builder
  ui/                 PySide6 widgets
  exports/            SOC Action Pack exporters

sample_data/          Safe simulated sandbox JSON
exports/              Generated SOC Action Packs
tests/                pytest suite
```

## Status

Currently at end of Phase 2 (core data pipeline). See the phased plan in the project brief for what's next.
