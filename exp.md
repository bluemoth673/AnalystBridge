# Project Name

## AnalystBridge

AnalystBridge is a desktop application that helps security analysts understand malware behavior from log files. It does not run malware itself. Instead, it takes safe JSON reports (from tools like CAPE, Cuckoo, Sysmon, or its own format), organizes the data, and shows it in a way humans can investigate quickly.

Think of it like a "translator" between noisy technical logs and clear investigation outputs. After loading a sample, the app can show a behavior graph, timeline, MITRE ATT&CK mapping, extracted IOCs, risk score, and a storyline of what happened.

It also generates a SOC Action Pack (ready-to-use outputs like report markdown, IOC files, Sigma/KQL/Splunk hunting rules, and STIX JSON). This makes the project useful not only for visual analysis, but also for handing practical outputs to a SOC or incident response team.

The project is built as a local-first tool for education, demos, and analyst workflows. It uses deterministic rule-based logic, so results are explainable and repeatable.

# Main Goal

AnalystBridge was made to solve a common problem: malware/sandbox logs are hard to read directly, especially for beginners or busy SOC analysts.

The project turns raw event data into:

- understandable visual investigation
- structured threat intelligence outputs
- practical response artifacts for defenders

In short: **reduce analysis time and improve clarity** when looking at suspicious behavior data.

# Technologies Used

- PySide6 -> desktop UI framework (all pages, widgets, graph/timeline views).
- Python -> core language for ingestion, analysis logic, exports, and CLI.
- SQLite -> lightweight local database to store samples, events, mappings, and IOCs.
- Pydantic v2 -> validates and structures parsed event data safely.
- NetworkX -> builds behavior graphs (nodes/edges) for visual analysis.
- NumPy -> utility math support used by analysis-related modules.
- Jinja2 -> templating support for report/export generation.
- PyInstaller -> creates Windows standalone app builds.
- Pytest -> automated tests for pipeline, exporters, and UI smoke checks.

# Project Structure

These are the folders that matter most:

- `analystbridge/` -> main application package.
- `analystbridge/app.py` -> GUI entry point (`python -m analystbridge.app`).
- `analystbridge/main_window.py` -> central UI orchestrator; wires all pages and flows.
- `analystbridge/cli.py` -> command-line operations (ingest, analyze, export, compare, list samples).
- `analystbridge/ingestion/` -> parsers/importers and normalization of incoming JSON data.
- `analystbridge/core/` -> core analysis logic (MITRE mapping, IOC extraction, risk scoring, storyline).
- `analystbridge/graph/` -> behavior graph construction.
- `analystbridge/storage/` -> SQLite schema and repository SQL access.
- `analystbridge/ui/` -> dashboard, graph, MITRE, indicators, YARA, compare, reports, settings pages.
- `analystbridge/exports/` -> SOC Action Pack output generators.
- `analystbridge/ai/` -> local AI-assist interface with deterministic fallback summaries.
- `analystbridge/notes/` -> analyst notes persistence (sidecar file style).
- `tests/` -> test coverage for data pipeline, exporters, analysis, and UI smoke tests.
- `sample_data/` -> safe demo JSON data.
- `requirements.txt` -> Python dependencies.
- `analystbridge.spec` + `BUILD.md` -> packaging/build guidance for executable distribution.

# How The Project Works

Step-by-step flow:

1. User opens the app (GUI) or runs CLI commands.
2. User loads a JSON report file (or the bundled demo sample).
3. Format auto-detection chooses the correct importer (`analystbridge`, `cape`, `cuckoo`, or `sysmon`).
4. Imported events are normalized into one consistent event format.
5. Sample + events are stored in SQLite.
6. Analysis engine runs:
   - MITRE ATT&CK mapping
   - IOC extraction
   - risk/malice scoring
   - attack storyline creation
7. Graph builder creates behavior graph data.
8. UI panels receive one unified analysis bundle and display it across pages.
9. User can inspect evidence, filter events, replay timeline, compare samples, and export outputs.
10. Export module writes selected SOC Action Pack files to disk.

# Authentication Flow

There is no authentication system in this project.

- No signup/login
- No JWT/tokens/sessions
- No user-role permission middleware
- No web server auth pipeline

Reason: this is a local desktop + CLI analysis tool, not a multi-user web app.

# Database Explanation

The project uses SQLite with these key tables:

- `samples` -> metadata for each analyzed sample (id, hash, filename, platform, status).
- `events` -> normalized behavioral events linked to a sample.
- `mitre_mappings` -> ATT&CK techniques mapped from behavior evidence.
- `iocs` -> extracted indicators (domain/ip/hash/path/registry/etc) linked to sample/events.
- `analyst_notes` -> note schema exists in DB (but current UI note flow uses sidecar notes store).

Main relationships:

- one `sample` has many `events`
- one `sample` has many `mitre_mappings`
- one `sample` has many `iocs`
- mappings/iocs may reference supporting event IDs

Why this model exists:

- `samples` is the top-level investigation record.
- `events` preserves the timeline and source behavior.
- `mitre_mappings` explains attacker techniques in standardized ATT&CK language.
- `iocs` supports hunting and blocking workflows.

# API Explanation

There is no HTTP REST API in this codebase.

The "API surface" here is the CLI commands in `analystbridge/cli.py`:

- `ingest` -> parse and store a report.
- `analyze` -> run analysis engine and print findings.
- `export` -> generate SOC Action Pack files.
- `samples` -> list ingested sample records.
- `compare` -> compare two samples for behavior similarity.

Input/Output pattern:

- Input: file paths, sample IDs, db path, optional format/output args.
- Output: console summaries and generated files in export directories.

# Frontend Explanation

Frontend is a desktop Qt UI (not web React frontend).

Important pages/components:

- Dashboard page -> overview cards + searchable event table.
- Graph view -> behavior graph visualization and event highlighting.
- MITRE page -> mapped techniques with evidence links.
- Indicators page -> extracted IOC list with context.
- YARA page -> generated/related YARA-style output display.
- Compare page -> compares current sample to session-loaded previous samples.
- Reports page -> shows exported artifact files.
- Settings/About pages -> app info and configuration display.
- Timeline panel -> replay-like temporal control over events.
- Right panel -> node details, score details, and supporting context.

State flow:

- `MainWindow` keeps the current `AnalysisBundle`.
- On load, it pushes the same bundle to relevant pages.
- UI events (clicking node, selecting evidence, selecting storyline stage) update graph highlights and details panels.
- Navigation uses stacked widgets and sidebar buttons.

# Backend Explanation

There is no separate network backend service; backend logic is local Python modules.

Architecture in simple terms:

- Orchestration layer:
  - GUI orchestrator: `main_window.py`
  - CLI orchestrator: `cli.py`
- Service/engine layer:
  - `core/` modules perform analysis logic.
  - `ui/services.py` assembles full bundle from file to analyzed graph.
- Data layer:
  - `storage/database.py` defines schema and connection settings.
  - `storage/repositories.py` handles SQL operations.
- Integration/output layer:
  - `ingestion/` converts external report formats.
  - `exports/` writes SOC action artifacts.

Business logic examples:

- map suspicious behavior to ATT&CK techniques
- compute malice score with explainable contributions
- derive storyline stages and recommended actions
- compare sample fingerprints for similarity verdicts

# Important Features

- Multi-format ingestion (`analystbridge`, CAPE, Cuckoo, Sysmon).
- Event normalization pipeline for consistent downstream analysis.
- MITRE ATT&CK mapping with confidence/reasoning fields.
- IOC extraction and deduplicated indicator outputs.
- Malice/risk scoring with transparent score breakdown.
- Storyline generation that summarizes attack progression.
- Interactive behavior graph + timeline replay controls.
- Sample-to-sample behavior similarity comparison.
- One-click SOC Action Pack export:
  - markdown report
  - IOC JSON/CSV
  - Sigma rule
  - Defender KQL
  - Splunk SPL
  - STIX 2.1 bundle
  - consolidated SOC action JSON
- AI assist architecture with deterministic fallback (works even without model backend).

# How To Run The Project

## 1) Install dependencies

```bash
pip install -r requirements.txt
```

## 2) Launch GUI

```bash
python -m analystbridge.app
```

## 3) CLI workflow (optional, but very useful)

Ingest sample:

```bash
python -m analystbridge.cli ingest sample_data/ransomware_demo.json
```

Run analysis:

```bash
python -m analystbridge.cli analyze --sample-id sample_ransomware_001
```

Generate exports:

```bash
python -m analystbridge.cli export --sample-id sample_ransomware_001
```

List samples in DB:

```bash
python -m analystbridge.cli samples
```

## 4) Run tests

```bash
python -m pytest -q
```

## 5) Build executable (Windows packaging)

```bash
python -m PyInstaller analystbridge.spec --clean --noconfirm
```

## Environment variables

- No mandatory runtime environment variables are required for normal usage.
- For headless UI/test environments, `QT_QPA_PLATFORM=offscreen` can be used.

## Database setup

- SQLite database is auto-created by CLI when needed (default `analystbridge.db`).
- GUI service path often uses in-memory DB for loaded session bundles unless customized.

# Problems & Weaknesses

- GUI default analysis bundle path is in-memory DB, so persistence behavior can differ from CLI workflows.
- Notes storage is split conceptually (DB table exists, but active UI notes are sidecar-based), which may confuse contributors.
- AI integration is scaffolded, but real local model adapter is not fully wired by default.
- Rule-based detection is explainable but limited in ATT&CK/rule coverage compared to production threat platforms.
- Some orchestration responsibilities live in UI-level code, causing tighter coupling between presentation and flow logic.
- No web API or multi-user model (fine for local desktop scope, limiting for team/server deployment).

# Suggested Improvements

- Create one explicit application service layer shared by GUI and CLI to reduce orchestration duplication.
- Unify notes persistence strategy (choose DB or sidecar clearly).
- Add richer configuration management for DB paths, export defaults, and model backend settings.
- Expand mapping/extraction rules and add benchmark-like test fixtures for coverage quality.
- Add schema migration/version tooling for long-term DB evolution.
- Introduce plugin-style registries for importers/exporters for easier extension.
- Improve persistence options in GUI (optional saved workspace/session mode).

# Developer Notes

- Treat this as a local malware-intelligence workbench, not a malware execution sandbox.
- Keep analysis logic deterministic and explainable unless intentionally adding probabilistic ML behavior.
- Prefer adding logic in `core/` + tests before wiring new UI features.
- If adding a new data source format, implement importer + normalization + tests together.
- If adding a new export artifact, keep it wired through `exports/action_pack.py` so GUI and CLI stay consistent.
- Be careful when changing graph/timeline interactions; many UI panels depend on shared event IDs for highlighting.
- Validate changes with both:
  - CLI commands (pipeline correctness)
  - GUI smoke behavior (interaction correctness)

