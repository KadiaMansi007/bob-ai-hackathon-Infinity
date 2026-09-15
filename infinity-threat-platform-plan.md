# Infinity Threat Intelligence Fusion & Prioritisation Platform — Implementation Plan

## Top-Level Overview

**Goal:** Build a working full-stack web application for the IBM Bob AI Innovation Hackathon 2026, addressing Problem D2: Threat Intelligence Correlation & Alert Prioritisation Assistant.

**Team:** Team Infinity (4 members)

**Track:** AI

**Scope:** Ingest simulated multi-source threat feeds (SIEM, cyber sensors, satellite, intelligence reports), normalize and deduplicate alerts, correlate them into incidents, classify genuine threats vs false positives as a **first-class outcome**, calculate explainable risk scores, map to MITRE ATT&CK, generate BLUF summaries, and surface everything through a professional analyst dashboard. IBM Bob is integrated as the AI reasoning and review layer via MCP — reasoning on top of deterministic pipeline outputs, not replacing them.

**Non-Goals:**
- Real military or classified data
- Production-grade authentication (JWT stub is sufficient)
- External threat-feed APIs (all feeds are synthetic/simulated)
- Modifying `.github/workflows/validate.yml`, `CONTRIBUTING.md`, or `submission.yaml` filename

**Stack:**
- Frontend: React 18 + Vite + TypeScript + TailwindCSS + shadcn/ui
- Backend: Python 3.11 + FastAPI + SQLAlchemy + Pydantic v2
- Database: SQLite (file-based, zero-config)
- AI: IBM Bob via MCP (custom MCP server)
- Testing: Pytest (backend) + Vitest (frontend)
- Containerisation: Docker + Docker Compose

---

## Hybrid Architecture — Core Principle

The system operates in two distinct layers that must never be conflated:

**Layer 1 — Deterministic Pipeline (no AI, fully auditable):**
- Feed ingestion, normalisation, fingerprint deduplication
- Rule-based false positive pre-filtering (evidence-based rules, stored with reason codes)
- Correlation engine (rules C0–C5, fired rule stored per incident)
- Numerical risk scoring (weighted formula, every component stored separately)
- MITRE ATT&CK lookup mapping
- **Automated classification**: `auto_classification` field = GENUINE_THREAT | FALSE_POSITIVE | UNCLASSIFIED, set by pipeline rules with `auto_classification_reason` text

**Layer 2 — IBM Bob AI Reasoning (on top of Layer 1 outputs, never replacing them):**
- Bob **reads** incident data, alerts, risk score breakdown, fired correlation rule, and MITRE mappings through MCP tools
- Bob **explains** why the risk score is what it is, in natural language, referencing actual component values
- Bob **states** which correlation rule fired and whether its reasoning agrees or disagrees with that rule's conclusion
- Bob **independently classifies** the incident as GENUINE_THREAT | FALSE_POSITIVE, with confidence (0–1) and a reasoning paragraph
- Bob **stores** an `agreement_status` field: AGREES | DISAGREES | PARTIAL — comparing its classification against `auto_classification`
- Bob **generates** the BLUF summary using structured incident data only (Bob must not invent evidence not present in the data)
- Bob's output is stored as `bob_analysis` record; the UI shows both the automated decision and Bob's assessment side-by-side

**What Bob must never do:**
- Invent IOCs, hostnames, IPs, or alert details not present in the data it received via MCP tools
- Override the deterministic risk score (Bob explains it, the number stays)
- Act as the sole classification authority (both automated and Bob classifications are shown)

## Architecture Diagram (described — use Mermaid in docs/architecture.md)

```
Simulated Feed Generator
  └─► Feed Ingestor (FastAPI background task)
        └─► Normaliser → Deduplicator → FP Pre-filter → Correlator → Incident Builder
              └─► Risk Scorer → MITRE Mapper → Auto-Classifier
                    └─► SQLite (alerts, incidents, risk_scores, mitre_mappings, bob_analyses, bluf_summaries)
                          └─► REST API (FastAPI)
                                ├─► React Dashboard (Vite)
                                └─► Bob MCP Server
                                      └─► IBM Bob AI
                                            ├─► score_explanation (reads RiskScore components)
                                            ├─► correlation_review (reads fired rule + member alerts)
                                            ├─► classify_threat (independent GT/FP + agreement)
                                            └─► generate_bluf (structured summary from evidence only)
```

---

## Sub-Tasks

---

### ST-01 — Repository Scaffold & Submission Artefacts

**Status:** [ ] pending

**Intent:** Set up the `src/` directory layout, fill in all hackathon-required non-code artefacts (submission.yaml, README.md, docs/*.md, demo/ stubs), and verify the GitHub Actions validator goes green. This must be done first so the validator never blocks later work.

**Expected Outcomes:**
- `submission.yaml` has all REQUIRED fields filled with real Team Infinity values
- `README.md` contains no `[placeholder]` brackets
- `docs/problem-statement.md`, `docs/solution-overview.md`, `docs/architecture.md`, `docs/setup-guide.md` are written with real content (not lorem ipsum)
- `demo/demo-video-link.txt` and `demo/live-demo-url.txt` are updated with interim values
- `src/` has the directory skeleton and at least one source file so the validator's "src has code" check passes
- GitHub Actions Validate Submission workflow is green

**Todo List:**
1. Fill `submission.yaml` — team name "Infinity", track "AI", lead name/email, all four members, title, problem_statement, solution_summary, key_features (5 items), tech_stack
2. Rewrite `README.md` — remove all `[placeholder]` text, add team section, problem, solution, features, tech stack table, run commands, demo links, limitations
3. Write `docs/problem-statement.md` — D2 domain context, analyst pain points, cost of slow triage, why existing SIEM tools are insufficient
4. Write `docs/solution-overview.md` — step-by-step how ingestion → normalisation → correlation → Bob analysis works
5. Write `docs/architecture.md` — Mermaid system diagram + component table
6. Write `docs/setup-guide.md` — prerequisites (Python 3.11, Node 20, Docker), env vars table, exact install/run commands, verification steps, troubleshooting table
7. Update `demo/demo-video-link.txt` with placeholder real-looking URL (to be replaced after recording)
8. Update `demo/live-demo-url.txt` with "NOT DEPLOYED — run locally using docs/setup-guide.md"
9. Create `src/README.md` describing the backend/frontend/mcp layout
10. Create `src/.env.example` with all environment variables the application will use
11. Create minimal `src/backend/__init__.py` so the src/ validator check passes
12. Commit and verify GitHub Actions is green

**Relevant Context:**
- Validator file: `.github/workflows/validate.yml`
- Current submission.yaml: `submission.yaml`
- Current README: `README.md`
- Required docs: `docs/problem-statement.md`, `docs/solution-overview.md`, `docs/architecture.md`, `docs/setup-guide.md`
- Demo stubs: `demo/demo-video-link.txt`, `demo/live-demo-url.txt`

---

### ST-02 — Database Schema & SQLAlchemy Models

**Status:** [x] done

**Intent:** Define the complete SQLite schema with SQLAlchemy ORM models. This is the foundation every other backend component depends on.

**Expected Outcomes:**
- All ORM models exist in `src/backend/models/`
- Alembic (or SQLAlchemy `create_all`) initialises the database on first run
- Models are importable and pass a basic pytest smoke test

**Database Tables:**

| Table | Purpose |
|---|---|
| `raw_alerts` | One row per alert as received from any feed source |
| `normalised_alerts` | Normalised, deduplicated version of raw alerts |
| `incidents` | Correlated groups of related normalised alerts |
| `incident_alerts` | Many-to-many join: incident ↔ normalised_alert |
| `risk_scores` | Explainable risk score record per incident |
| `mitre_mappings` | MITRE ATT&CK tactic/technique/sub-technique per normalised alert, with evidence strings and mapping method (full field list defined in ST-07) |
| `bluf_summaries` | Bob-generated BLUF text per incident |
| `feed_runs` | Log of each synthetic feed ingestion run (timestamp, source, count) |

**Key Fields — `normalised_alerts`:**
- `id` (UUID PK)
- `raw_alert_id` (FK → raw_alerts)
- `source_type` (enum: SIEM | CYBER_SENSOR | SATELLITE | INTEL_REPORT)
- `source_name` (string)
- `alert_type` (string — e.g. "port_scan", "anomalous_traffic")
- `severity` (enum: LOW | MEDIUM | HIGH | CRITICAL)
- `confidence` (float 0–1)
- `timestamp` (datetime)
- `target_asset` (string — IP, hostname, region)
- `geo_location` (string)
- `description` (text)
- `raw_payload` (JSON)
- `fingerprint` (string — SHA256 hash used for dedup)
- `is_false_positive` (bool, default False)
- `fp_reason` (string, nullable)
- `created_at` (datetime)

**Key Fields — `incidents`:**
- `id` (UUID PK)
- `title` (string)
- `status` (enum: OPEN | INVESTIGATING | CLOSED | FALSE_POSITIVE)
- `overall_severity` (enum)
- `first_seen` (datetime)
- `last_seen` (datetime)
- `affected_assets` (JSON array)
- `source_types_involved` (JSON array)
- `correlation_reason` (text — human-readable explanation)
- `fired_correlation_rule` (string — rule ID, e.g. "C3", stored at incident creation)
- `auto_classification` (enum: GENUINE_THREAT | FALSE_POSITIVE | UNCLASSIFIED — set by deterministic pipeline)
- `auto_classification_reason` (text — which rule(s) produced this classification and why)
- `created_at`, `updated_at`

**Key Fields — `risk_scores`:**
- `id` (UUID PK)
- `incident_id` (FK → incidents)
- `total_score` (float 0–100)
- `severity_component` (float)
- `confidence_component` (float)
- `source_diversity_component` (float)
- `asset_criticality_component` (float)
- `temporal_component` (float)
- `explanation` (JSON — per-component breakdown with weights and per-component natural-language reason strings)
- `scored_at` (datetime)

**New Table — `bob_analyses`:**
- `id` (UUID PK)
- `incident_id` (FK → incidents, unique — one active analysis per incident)
- `bob_classification` (enum: GENUINE_THREAT | FALSE_POSITIVE)
- `bob_confidence` (float 0–1)
- `bob_reasoning` (text — Bob's full reasoning paragraph, evidence-grounded)
- `score_explanation_text` (text — Bob's natural-language walkthrough of the risk score components)
- `correlation_review_text` (text — Bob's commentary on the fired correlation rule and whether it agrees)
- `agreement_status` (enum: AGREES | DISAGREES | PARTIAL — comparison of bob_classification vs auto_classification)
- `agreement_detail` (text — if DISAGREES/PARTIAL, Bob explains the discrepancy)
- `analysed_at` (datetime)
- `bob_model_version` (string — for auditability)

**Todo List:**
1. Create `src/backend/models/__init__.py`
2. Create `src/backend/models/base.py` — SQLAlchemy `DeclarativeBase`, UUID helper
3. Create `src/backend/models/raw_alert.py` — `RawAlert` ORM model
4. Create `src/backend/models/normalised_alert.py` — `NormalisedAlert` ORM model with all fields above
5. Create `src/backend/models/incident.py` — `Incident` + `IncidentAlert` join table (include `fired_correlation_rule`, `auto_classification`, `auto_classification_reason`)
6. Create `src/backend/models/risk_score.py` — `RiskScore` ORM model
7. Create `src/backend/models/mitre_mapping.py` — `MitreMapping` ORM model
8. Create `src/backend/models/bluf_summary.py` — `BlufSummary` ORM model
9. Create `src/backend/models/bob_analysis.py` — `BobAnalysis` ORM model with all fields from `bob_analyses` table above
10. Create `src/backend/models/feed_run.py` — `FeedRun` ORM model
11. Create `src/backend/database.py` — engine, session factory, `get_db()` dependency
12. Create `src/backend/schemas/` — Pydantic v2 schemas mirroring each model for request/response serialisation; include `BobAnalysisSchema` with all classification + agreement fields
13. Create `src/backend/init_db.py` — script that calls `Base.metadata.create_all()`
14. Write `tests/test_models.py` — smoke test that creates all tables and inserts one row per model

**Relevant Context:**
- No existing models — all created fresh in `src/backend/`
- Use `uuid.uuid4` default for all PKs
- SQLite file path configured via `DATABASE_URL` env var (default: `sqlite:///./infinity_threat.db`)

---

### ST-03 — Synthetic Feed Generator

**Status:** [ ] pending

**Intent:** Build a feed simulator that generates realistic synthetic alert data for all four source types. This is the data engine for the entire demo. No real data is used.

**Expected Outcomes:**
- Running `python -m backend.feeds.generate` (or a FastAPI background endpoint) inserts a configurable batch of raw alerts covering all four source types
- Generated data is varied enough to trigger deduplication, correlation, and multiple MITRE technique mappings
- A seed parameter produces deterministic output for reproducible demos

**Four Feed Types & their simulated alert shapes:**

| Source | Example Alert Types | Unique Fields |
|---|---|---|
| SIEM | failed_login_burst, privilege_escalation, lateral_movement, data_exfil | user_id, hostname, event_count |
| Cyber Sensor | port_scan, c2_beacon, malware_hash_match, dns_tunnelling | src_ip, dst_ip, protocol, packet_count |
| Satellite | anomalous_vessel_movement, rf_signal_anomaly, formation_change | lat, lon, object_id, signal_strength |
| Intel Report | ioc_match, threat_actor_sighting, vulnerability_exploitation | ioc_type, ioc_value, actor_name, cve_id |

**Scenario Packs** (pre-defined correlated attack storylines):
1. **APT Lateral Movement** — SIEM privilege_escalation + Cyber Sensor port_scan + Intel Report ioc_match, all targeting same subnet
2. **Ransomware Pre-Stage** — SIEM failed_login_burst + Cyber Sensor c2_beacon + Intel Report vulnerability_exploitation
3. **Satellite Anomaly + Signals** — Satellite rf_signal_anomaly + Satellite formation_change + Intel Report threat_actor_sighting
4. **Data Exfiltration** — SIEM data_exfil + Cyber Sensor dns_tunnelling + Cyber Sensor c2_beacon
5. **Noise/False Positives** — isolated low-confidence alerts designed to be filtered out

**Todo List:**
1. Create `src/backend/feeds/__init__.py`
2. Create `src/backend/feeds/schemas.py` — Pydantic models for each raw feed format (SiemAlert, CyberSensorAlert, SatelliteAlert, IntelReportAlert)
3. Create `src/backend/feeds/siem_generator.py` — generates SIEM raw alert dicts
4. Create `src/backend/feeds/cyber_sensor_generator.py` — generates cyber sensor alert dicts
5. Create `src/backend/feeds/satellite_generator.py` — generates satellite alert dicts
6. Create `src/backend/feeds/intel_report_generator.py` — generates intel report alert dicts
7. Create `src/backend/feeds/scenario_packs.py` — 5 scenario pack definitions, each a list of correlated alert templates
8. Create `src/backend/feeds/generator.py` — orchestrator that calls all four generators + scenario packs, inserts raw_alerts rows, returns FeedRun record
9. Write `tests/test_feeds.py` — verify each generator produces valid Pydantic objects, verify scenario pack generates expected source diversity

**Relevant Context:**
- Raw alerts stored in `raw_alerts` table (ST-02)
- All timestamps randomised within a configurable window (default: last 24 hours)
- Use Python `faker` and `random` with optional `seed` parameter

---

### ST-04 — Normalisation, Deduplication & Fingerprinting

**Status:** [ ] pending

**Intent:** Transform raw alerts from four different schemas into a single `NormalisedAlert` format, then deduplicate by content fingerprint so re-ingested or near-duplicate alerts do not inflate counts.

**Expected Outcomes:**
- Every raw alert can be normalised to a `NormalisedAlert` without information loss
- Two alerts with identical (source_type, alert_type, target_asset, 5-minute time bucket) produce the same fingerprint and only the first is stored
- Normaliser is a pure function (no DB side-effects) — easy to unit test
- Deduplication is a DB-lookup step separate from normalisation

**Normalisation Rules:**

| Raw Field | Normalised Field | Rule |
|---|---|---|
| Any source severity string | `severity` enum | Map HIGH/CRITICAL/MEDIUM/LOW via lookup dict |
| SIEM hostname / Sensor dst_ip / Satellite object_id / Intel ioc_value | `target_asset` | Source-type specific extraction |
| SIEM geo / Sensor geo / Satellite lat+lon | `geo_location` | Concatenate or pass-through |
| All source timestamps | `timestamp` | Parse to UTC datetime |
| Any free-text field | `description` | Concatenated summary |
| Entire raw dict | `raw_payload` | JSON-serialised verbatim |

**Fingerprint Algorithm:**
SHA256( source_type + alert_type + target_asset + floor(timestamp, 5min) )

**False Positive Pre-filter Rules (applied during normalisation — each rule stores a reason code):**

| Rule | Condition | Classification | Reason Code |
|---|---|---|---|
| FP-01 | confidence < 0.15 | FALSE_POSITIVE | `fp_low_confidence` |
| FP-02 | source=SATELLITE AND alert_type=formation_change AND signal_strength < -90 dBm | FALSE_POSITIVE | `fp_satellite_weak_signal` |
| FP-03 | source=SIEM AND event_count == 1 AND severity == LOW | FALSE_POSITIVE | `fp_siem_single_low_event` |
| FP-04 | Intel Report IOC with no corroboration in other sources within 30 min | FALSE_POSITIVE (soft, confidence penalty -0.3) | `fp_intel_uncorroborated` |
| GT-01 | Multi-source convergence (C3 rule fired) AND confidence >= 0.6 | GENUINE_THREAT | `gt_multi_source_convergence` |
| GT-02 | Scenario pack matched (C4 rule fired) | GENUINE_THREAT | `gt_scenario_pattern_match` |
| GT-03 | IOC Propagation (C5 rule fired) AND confidence >= 0.5 | GENUINE_THREAT | `gt_ioc_cross_source_propagation` |
| UNCLASSIFIED | None of the above | UNCLASSIFIED | `unclassified_insufficient_evidence` |

The `auto_classification` and `auto_classification_reason` fields on the `incidents` table are set by the **Automated Classifier** after correlation runs. This is a deterministic, rule-based decision — no AI involved.

**Todo List:**
1. Create `src/backend/processing/__init__.py`
2. Create `src/backend/processing/normaliser.py` — `normalise(raw_alert: RawAlert) -> NormalisedAlert` pure function
3. Create `src/backend/processing/fingerprint.py` — `compute_fingerprint(...)` function
4. Create `src/backend/processing/deduplicator.py` — `deduplicate(session, normalised: NormalisedAlert) -> NormalisedAlert | None` (returns None if duplicate exists)
5. Create `src/backend/processing/false_positive_filter.py` — `apply_fp_rules(normalised: NormalisedAlert) -> NormalisedAlert` applies FP-01 through FP-04 rules, stores reason code
6. Create `src/backend/processing/auto_classifier.py` — `classify_incident(session, incident: Incident) -> Incident` applies GT-01 through UNCLASSIFIED rules, writes `auto_classification` and `auto_classification_reason` to the incident row
7. Create `src/backend/processing/pipeline.py` — `run_pipeline(session, raw_alert: RawAlert) -> NormalisedAlert | None` orchestrates: normalise → fingerprint → deduplicate → FP-filter → persist → correlate → score → MITRE-map → auto-classify
8. Write `tests/test_normaliser.py` — test each source type normalisation, fingerprint determinism, dedup logic, all FP rules, all GT classification rules, UNCLASSIFIED fallback

**Relevant Context:**
- Input: `RawAlert` ORM model (ST-02)
- Output: `NormalisedAlert` ORM model + `auto_classification` set on `Incident` (ST-02)
- `pipeline.py` is called by the ingestor (ST-03) and by the REST API trigger endpoint (ST-09)
- Auto-classifier runs **after** correlation, so it has access to `fired_correlation_rule` and the full member alert set

---

### ST-05 — Correlation Engine & Incident Builder

**Status:** [ ] pending

**Intent:** Group related normalised alerts into incidents using a rule-based + heuristic correlation engine. Each incident gets a human-readable correlation explanation.

**Expected Outcomes:**
- Alerts sharing target_asset OR time proximity (within 15-min window) OR matching MITRE technique are grouped into the same incident
- Each incident has a `correlation_reason` string explaining which rule triggered grouping
- Existing open incidents are extended (alerts added) rather than new incidents created for every alert
- Incidents are created, updated, or closed correctly
- Incidents with only FP-flagged alerts are auto-classified as FALSE_POSITIVE status

**Correlation Rules (applied in order, first match wins):**

| Rule ID | Name | Condition | Action |
|---|---|---|---|
| C1 | Same Asset | normalised.target_asset matches an open incident's affected_assets | Add to incident |
| C2 | Time & Type Cluster | Same alert_type, same source_type, within 15-min window, count >= 3 | Create/extend incident |
| C3 | Multi-Source Convergence | Same target_asset from >= 2 different source_types within 30 min | Create/extend incident — highest priority |
| C4 | Known Scenario Pattern | Alert set matches a scenario pack template (partial match >= 60%) | Create incident with scenario label |
| C5 | IOC Propagation | Intel Report IOC value appears in any other source's raw_payload within 1 hour | Create/extend incident |
| C0 | Default | No rule matched | Singleton incident (may be merged later) |

**Incident Severity Roll-up:**
`max(severity of all member alerts)` — if any alert is CRITICAL, incident is CRITICAL.

**Todo List:**
1. Create `src/backend/correlation/__init__.py`
2. Create `src/backend/correlation/rules.py` — dataclass definitions for each rule (C0–C5) with match logic as methods; each rule's `match()` method returns `(matched: bool, reason: str)`
3. Create `src/backend/correlation/engine.py` — `correlate(session, normalised_alert: NormalisedAlert) -> Incident` — applies rules in priority order, writes the **first matching rule's ID** to `incident.fired_correlation_rule`, returns matched or newly created incident
4. Create `src/backend/correlation/incident_builder.py` — `create_incident(...)`, `extend_incident(...)`, `update_incident_severity(...)` helpers; `create_incident` must accept `fired_rule_id` and `correlation_reason` string
5. Create `src/backend/correlation/scenario_matcher.py` — compares incoming alert set against scenario_packs definitions, returns match score and matched scenario name
6. Write `tests/test_correlation.py` — test each rule fires correctly and the correct rule ID is written to incident, test multi-source convergence, test scenario matcher, test FP-only incident auto-close

**Relevant Context:**
- Input: `NormalisedAlert` (ST-02), scenario packs (ST-03)
- Output: `Incident` + `IncidentAlert` join rows (ST-02); `incident.fired_correlation_rule` must be populated for auto-classifier (ST-04) and Bob (ST-08)
- Called from `pipeline.py` after deduplication (ST-04)

---

### ST-06 — Risk Scoring Engine

**Status:** [ ] pending

**Intent:** Calculate an explainable 0–100 risk/priority score for each incident. Each score component is stored separately so the frontend and Bob can explain exactly why a score was assigned.

**Expected Outcomes:**
- Every incident has a `RiskScore` record with per-component breakdown
- Score is deterministic given the same inputs
- Explanation JSON is structured enough for the frontend to render a score breakdown card
- Score updates when new alerts are added to an incident

**Scoring Formula:**

```
total_score = (
    severity_component      * 0.35  +   # max severity of member alerts
    confidence_component    * 0.25  +   # mean confidence of member alerts
    source_diversity        * 0.20  +   # (unique source types / 4) * 100
    asset_criticality       * 0.10  +   # lookup: known critical assets get boost
    temporal_recency        * 0.10      # recency: last_seen within 1hr = 100, 24hr = 50, >24hr = 10
) clamped to [0, 100]
```

**Severity → Numeric:**
- CRITICAL = 100, HIGH = 75, MEDIUM = 50, LOW = 25

**Asset Criticality Lookup (simulated):**
- Predefined list of "critical assets" (domain controllers, satellite ground stations, command servers) → multiplier 1.5
- Unknown assets → multiplier 1.0

**Explanation JSON Structure:**
```json
{
  "total_score": 82.5,
  "components": {
    "severity": {"value": 35.0, "weight": 0.35, "raw": 100, "reason": "CRITICAL alert present"},
    "confidence": {"value": 18.75, "weight": 0.25, "raw": 75, "reason": "mean confidence 0.75"},
    "source_diversity": {"value": 15.0, "weight": 0.20, "raw": 75, "reason": "3 of 4 source types"},
    "asset_criticality": {"value": 10.0, "weight": 0.10, "raw": 100, "reason": "target is critical asset"},
    "temporal_recency": {"value": 8.75, "weight": 0.10, "raw": 87.5, "reason": "last seen 22min ago"}
  },
  "priority_label": "P1 — Immediate Action"
}
```

**Priority Labels:**
- 80–100 → P1 — Immediate Action
- 60–79 → P2 — Investigate Today
- 40–59 → P3 — Monitor Closely
- 0–39 → P4 — Low Priority

**Todo List:**
1. Create `src/backend/scoring/__init__.py`
2. Create `src/backend/scoring/asset_registry.py` — `CRITICAL_ASSETS` list + `get_asset_criticality(asset: str) -> float`
3. Create `src/backend/scoring/components.py` — individual component calculation functions
4. Create `src/backend/scoring/scorer.py` — `score_incident(session, incident: Incident) -> RiskScore` assembles all components, persists RiskScore
5. Write `tests/test_scoring.py` — test each component function, test clamping, test explanation JSON structure

**Relevant Context:**
- Input: `Incident` with joined `NormalisedAlert` members (ST-02, ST-05)
- Output: `RiskScore` row (ST-02)
- Called from correlation engine after incident is created/updated (ST-05)

---

### ST-07 — MITRE ATT&CK Mapping (Tactic → Technique → Sub-technique)

**Status:** [ ] pending

**Intent:** Map each normalised alert to the full three-level MITRE ATT&CK hierarchy: Tactic → Technique → Sub-technique. The mapper uses a bundled JSON lookup table. When evidence in the alert's raw payload supports a specific sub-technique, it is resolved. When evidence is insufficient, the parent technique is stored and the sub-technique field is explicitly marked `"not_determined"` — the mapper must never guess or default to a sub-technique without supporting evidence. Confidence and the specific evidence strings that drove the mapping are stored alongside each record.

**Expected Outcomes:**
- Every normalised alert has at least one `MitreMapping` record with tactic, technique, and sub-technique fields all populated (sub-technique may be `"not_determined"` with reason)
- Each mapping stores `confidence` (float 0–1) and an `evidence_strings` list (text fragments from the alert that support the mapping)
- Sub-techniques are resolved when raw_payload keywords, alert_type sub-fields, or cross-source corroboration provide sufficient specificity
- A `mitre_summary` for each incident lists all unique tactic/technique/sub-technique paths across member alerts
- Frontend MITRE page displays the three-level hierarchy clearly and can filter/group by tactic
- No sub-technique is stored unless a concrete evidence string justifies it

**Updated `mitre_mappings` Table Fields (replaces flat technique-only design in ST-02):**
- `id` (UUID PK)
- `normalised_alert_id` (FK → normalised_alerts)
- `incident_id` (FK → incidents, nullable — set when incident is built)
- `tactic_id` (string — e.g. `TA0002`)
- `tactic_name` (string — e.g. `Execution`)
- `technique_id` (string — e.g. `T1059`)
- `technique_name` (string — e.g. `Command and Scripting Interpreter`)
- `subtechnique_id` (string — e.g. `T1059.001`, or `"not_determined"`)
- `subtechnique_name` (string — e.g. `PowerShell`, or `"Not determined"`)
- `confidence` (float 0–1)
- `evidence_strings` (JSON array of strings — direct evidence fragments from alert payload)
- `mapping_method` (string — `"alert_type_lookup"` | `"payload_keyword"` | `"cross_source_corroboration"`)
- `created_at` (datetime)

**Mapping Table — alert_type → full hierarchy with sub-technique evidence rules:**

| Alert Type | Tactic | Tactic ID | Technique | Technique ID | Sub-technique | Sub-tech ID | Sub-tech Evidence Condition |
|---|---|---|---|---|---|---|---|
| failed_login_burst | Credential Access | TA0006 | Brute Force | T1110 | Password Spraying | T1110.003 | payload has `spray=true` or `distinct_usernames > 10` |
| failed_login_burst | Credential Access | TA0006 | Brute Force | T1110 | Password Guessing | T1110.001 | payload has single username, high attempt count |
| failed_login_burst | Credential Access | TA0006 | Brute Force | T1110 | not_determined | — | neither condition met |
| privilege_escalation | Privilege Escalation | TA0004 | Exploitation for Privilege Escalation | T1068 | not_determined | — | no sub-techniques in ATT&CK for T1068 |
| lateral_movement | Lateral Movement | TA0008 | Remote Services | T1021 | SMB/Windows Admin Shares | T1021.002 | payload protocol is SMB or port 445 |
| lateral_movement | Lateral Movement | TA0008 | Remote Services | T1021 | SSH | T1021.004 | payload protocol is SSH or port 22 |
| lateral_movement | Lateral Movement | TA0008 | Remote Services | T1021 | not_determined | — | protocol not identified |
| data_exfil | Exfiltration | TA0010 | Exfiltration Over C2 Channel | T1041 | not_determined | — | no sub-techniques in ATT&CK for T1041 |
| port_scan | Discovery | TA0007 | Network Service Discovery | T1046 | not_determined | — | no sub-techniques in ATT&CK for T1046 |
| c2_beacon | Command and Control | TA0011 | Application Layer Protocol | T1071 | Web Protocols | T1071.001 | payload protocol is HTTP or HTTPS |
| c2_beacon | Command and Control | TA0011 | Application Layer Protocol | T1071 | DNS | T1071.004 | payload protocol is DNS |
| c2_beacon | Command and Control | TA0011 | Application Layer Protocol | T1071 | not_determined | — | protocol not identified |
| malware_hash_match | Execution | TA0002 | User Execution | T1204 | Malicious File | T1204.002 | payload has file_type in executable extensions |
| malware_hash_match | Execution | TA0002 | User Execution | T1204 | Malicious Link | T1204.001 | payload has url_indicator |
| malware_hash_match | Execution | TA0002 | User Execution | T1204 | not_determined | — | neither condition met |
| dns_tunnelling | Command and Control | TA0011 | Application Layer Protocol | T1071 | DNS | T1071.004 | alert_type is dns_tunnelling — always sufficient |
| ioc_match | Reconnaissance | TA0043 | Active Scanning | T1595 | Scanning IP Blocks | T1595.001 | payload ioc_type is ip_range |
| ioc_match | Reconnaissance | TA0043 | Active Scanning | T1595 | Vulnerability Scanning | T1595.002 | payload ioc_type is cve or vuln |
| ioc_match | Reconnaissance | TA0043 | Active Scanning | T1595 | not_determined | — | ioc_type is domain/hash/url |
| threat_actor_sighting | Reconnaissance | TA0043 | Gather Victim Org Information | T1591 | not_determined | — | no payload evidence to narrow further |
| vulnerability_exploitation | Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | not_determined | — | no sub-techniques in ATT&CK for T1190 |
| anomalous_vessel_movement | Collection | TA0009 | Data from Network Device | T1602 | not_determined | — | no sub-techniques applicable to satellite context |
| rf_signal_anomaly | Collection | TA0009 | Data from Network Device | T1602 | not_determined | — | no sub-techniques applicable to satellite context |
| formation_change | Reconnaissance | TA0043 | Gather Victim Org Information | T1591 | not_determined | — | no payload evidence to narrow further |

**Sub-technique Resolution Logic (applied in order):**
1. Check `alert_type` + sub-field values in `raw_payload` against evidence conditions in the table above
2. If condition matches → set `subtechnique_id`, `subtechnique_name`, record the matching payload field as `evidence_strings`, set `mapping_method = "payload_keyword"`, set `confidence` = base confidence × 0.9
3. If no sub-technique condition matches → set `subtechnique_id = "not_determined"`, `subtechnique_name = "Not determined"`, `mapping_method = "alert_type_lookup"`, `confidence` = base confidence × 0.7
4. **Cross-source corroboration** (called from incident_summary.py): if two different source_types produce mappings to the same parent technique and both have payload evidence for the same sub-technique → upgrade confidence, set `mapping_method = "cross_source_corroboration"`

**UI Display Format (per mapping card):**
```
Tactic:        Execution  (TA0002)
Technique:     T1059 — Command and Scripting Interpreter
Sub-technique: T1059.001 — PowerShell          ← shown only when determined
               [Not determined]                 ← shown when not_determined
Confidence:    94%
Evidence:
  • PowerShell execution observed in SIEM alert
  • Matching endpoint sensor event
  • Correlated intelligence report
```

**Todo List:**
1. Update `src/backend/models/mitre_mapping.py` — add `subtechnique_id`, `subtechnique_name`, `tactic_id`, `evidence_strings` (JSON), `mapping_method` fields (replaces flat design from ST-02)
2. Update `src/backend/schemas/` — update `MitreMappingSchema` to include all new fields including `subtechnique_id` and `evidence_strings`
3. Create `src/backend/mitre/mitre_data.json` — hierarchical ATT&CK data: tactic → techniques → sub-techniques, with IDs, names, and descriptions for all entries in the mapping table above
4. Create `src/backend/mitre/__init__.py`
5. Create `src/backend/mitre/evidence_rules.py` — `SUBTECHNIQUE_EVIDENCE_RULES` dict keyed by `(alert_type, subtechnique_id)` → evidence condition function `(raw_payload: dict) -> tuple[bool, list[str]]` returning (matched, evidence_strings)
6. Create `src/backend/mitre/mapper.py` — `map_alert(session, normalised_alert: NormalisedAlert) -> list[MitreMapping]`; applies lookup, then calls evidence_rules to attempt sub-technique resolution; never guesses sub-technique; records mapping_method and evidence_strings
7. Create `src/backend/mitre/incident_summary.py` — `get_incident_mitre_summary(session, incident_id) -> dict`; aggregates all tactic/technique/subtechnique paths, applies cross-source corroboration upgrade, returns structured hierarchy
8. Write `tests/test_mitre.py` — test cases:
   - Each alert_type maps to correct tactic and parent technique
   - Sub-technique resolved when payload evidence condition is met
   - Sub-technique is `"not_determined"` when payload evidence condition is NOT met
   - Mapping never assigns a sub-technique without a matching evidence string
   - Cross-source corroboration upgrade fires correctly
   - `evidence_strings` list is non-empty for every resolved sub-technique

**Relevant Context:**
- Input: `NormalisedAlert` with `raw_payload` dict (ST-02), `Incident` (ST-02)
- Output: `MitreMapping` rows (ST-02, updated schema from this ST)
- Called from pipeline after normalisation (ST-04)
- `incident_summary.py` is called by `get_mitre_summary` MCP tool (ST-08) and by the `/api/v1/mitre/matrix` REST endpoint (ST-09)
- The `mitre_data.json` file is the single source of truth for all IDs and names — mapper never hardcodes strings, always resolves from JSON

---

### ST-08 — IBM Bob MCP Server & Tool Definitions

**Status:** [ ] pending

**Intent:** Build a custom MCP server that exposes the platform's threat data to IBM Bob as callable tools. Bob functions as the AI reasoning layer: it reads deterministic pipeline outputs (risk score breakdown, fired correlation rule, MITRE mappings, member alerts) and produces natural-language explanations, an independent classification, an agreement verdict, and a BLUF summary. Bob never invents evidence.

**Expected Outcomes:**
- MCP server runs as a separate process (stdio or HTTP transport)
- Bob can call all defined data-retrieval tools to gather evidence before reasoning
- Bob's `analyse_incident` tool call produces a fully populated `BobAnalysis` record (ST-02) with all fields: classification, confidence, reasoning, score_explanation_text, correlation_review_text, agreement_status, agreement_detail
- Bob's classification is compared against `auto_classification` — agreement_status is computed and stored
- BLUF summaries are stored in `bluf_summaries` table
- All Bob tool calls are timestamped for auditability
- Bob prompt engineering strictly grounds Bob in the data provided via MCP tools (no hallucinated evidence)

**MCP Tools to Expose:**

| Tool Name | Layer | Description | Parameters | Returns |
|---|---|---|---|---|
| `get_incident_details` | Data | Retrieve full incident with member alerts, risk score, and auto_classification | `incident_id: str` | Incident JSON (includes auto_classification, auto_classification_reason, fired_correlation_rule) |
| `get_alert_context` | Data | Retrieve a normalised alert with raw payload and MITRE mappings | `alert_id: str` | Alert JSON with mappings |
| `list_open_incidents` | Data | List OPEN incidents sorted by risk score with auto_classification | `limit: int = 10` | List of incident summaries |
| `get_risk_score_explanation` | Data | Retrieve the structured score breakdown (all components + reason strings) | `incident_id: str` | RiskScore explanation JSON |
| `get_mitre_summary` | Data | Get full tactic/technique/sub-technique hierarchy for an incident, including confidence and evidence strings per mapping | `incident_id: str` | Structured hierarchy with subtechnique_id, subtechnique_name, confidence, evidence_strings per entry |
| `get_correlation_graph` | Data | Alert correlation graph (nodes + edges) | `incident_id: str` | `{nodes: [], edges: []}` |
| `analyse_incident` | AI | Orchestrates Bob's full reasoning pass: reads score, fired rule, MITRE, alerts → produces BobAnalysis record | `incident_id: str` | `BobAnalysis` JSON |
| `generate_bluf` | AI | Generates BLUF summary grounded in incident evidence only | `incident_id: str` | BLUF text (stored + returned) |
| `trigger_feed_ingestion` | Control | Trigger a new synthetic feed generation + pipeline run | `scenario: str = "random"` | FeedRun summary |

**Bob Prompt Design (grounding principle: Bob only references data returned by MCP tools):**

`analyse_incident` prompt:
```
You are a senior cyber threat analyst reviewing an automated threat intelligence platform's output.

You have been given the following EVIDENCE retrieved from the platform:
- Incident details: {incident_json}
- Risk score breakdown: {score_explanation_json}
- Fired correlation rule: {fired_rule_id} — {correlation_reason}
- MITRE ATT&CK mappings (tactic → technique → sub-technique, with confidence and evidence strings): {mitre_summary_json}
- Member alert summaries: {alerts_summary_json}
- Automated classification: {auto_classification} — Reason: {auto_classification_reason}

Your task:
1. SCORE EXPLANATION: Explain in plain language why the risk score is {total_score}/100, referencing each component value provided above. Do not invent values.
2. CORRELATION REVIEW: State which correlation rule fired ({fired_rule_id}). Explain whether you agree with the grouping decision and why, based solely on the evidence above.
3. INDEPENDENT CLASSIFICATION: Classify this incident as GENUINE_THREAT or FALSE_POSITIVE. Provide a confidence value (0.0–1.0). Write a reasoning paragraph that cites only the evidence you were given.
4. AGREEMENT: State whether your classification AGREES, DISAGREES, or PARTIALLY AGREES with the automated classification ({auto_classification}). If DISAGREES or PARTIAL, explain the discrepancy.

You must not reference any hostnames, IPs, IOCs, or event details that are not present in the evidence above.
Return your response as a JSON object with keys: score_explanation_text, correlation_review_text, bob_classification, bob_confidence, bob_reasoning, agreement_status, agreement_detail.
```

`generate_bluf` prompt:
```
You are a threat intelligence analyst writing for an operational briefing.

Using ONLY the following incident evidence:
{incident_json_with_bob_analysis}

Write a BLUF (Bottom Line Up Front) summary in this exact format:
BLUF: [Single sentence stating the most critical finding]
SITUATION: [2–3 sentences describing what happened, which assets, which sources]
ASSESSMENT: [2–3 sentences on threat severity, actor behaviour, MITRE techniques observed]
RECOMMENDATIONS: [2–3 actionable bullet points]

Do not introduce any information not present in the evidence provided.
```

**Todo List:**
1. Create `src/mcp_server/__init__.py`
2. Create `src/mcp_server/server.py` — MCP server entry point (stdio or HTTP transport)
3. Create `src/mcp_server/tools/get_incident_details.py` — queries DB, returns incident with `auto_classification`, `auto_classification_reason`, `fired_correlation_rule`
4. Create `src/mcp_server/tools/get_alert_context.py`
5. Create `src/mcp_server/tools/list_open_incidents.py`
6. Create `src/mcp_server/tools/get_risk_score_explanation.py`
7. Create `src/mcp_server/tools/get_mitre_summary.py`
8. Create `src/mcp_server/tools/get_correlation_graph.py`
9. Create `src/mcp_server/tools/analyse_incident.py` — assembles evidence from all data tools, calls Bob with `analyse_incident` prompt, parses structured JSON response, computes `agreement_status`, persists `BobAnalysis` row
10. Create `src/mcp_server/tools/generate_bluf.py` — calls Bob with `generate_bluf` prompt using incident + BobAnalysis data, stores `BlufSummary` row
11. Create `src/mcp_server/tools/trigger_feed_ingestion.py`
12. Create `src/mcp_server/prompts.py` — prompt templates as Python string constants with `{placeholder}` format fields
13. Create `src/mcp_server/evidence_assembler.py` — helper that calls data tools to gather all evidence for a single incident, returns a structured dict used by `analyse_incident` and `generate_bluf`
14. Write `tests/test_mcp_tools.py` — test each data tool returns expected JSON shape (mock DB); test `analyse_incident` parses Bob response correctly and sets `agreement_status` correctly across AGREES/DISAGREES/PARTIAL cases (mock Bob calls)

**Relevant Context:**
- Uses IBM Bob MCP integration pattern
- DB access via shared SQLAlchemy session
- `BOB_API_KEY` and `BOB_MCP_URL` from `.env`
- `evidence_assembler.py` ensures Bob always receives the same structured payload — prevents prompt drift
- `agreement_status` logic: if `bob_classification == auto_classification` → AGREES; if both non-UNCLASSIFIED and opposite → DISAGREES; if `auto_classification == UNCLASSIFIED` and Bob classifies → PARTIAL

---

### ST-09 — FastAPI REST API

**Status:** [ ] pending

**Intent:** Build the REST API that the React frontend consumes. All endpoints return JSON. The API also exposes a Bob-interaction endpoint so the frontend can trigger AI analysis.

**Expected Outcomes:**
- All endpoints return correct HTTP status codes and Pydantic-validated responses
- OpenAPI docs available at `/api/docs`
- CORS configured for React dev server (localhost:5173)
- Background task triggers feed generation without blocking HTTP response

**API Endpoints:**

```
POST   /api/v1/feeds/ingest          # Trigger synthetic feed + pipeline run
GET    /api/v1/feeds/runs            # List feed run history

GET    /api/v1/alerts                # List normalised alerts (paginated, filterable)
GET    /api/v1/alerts/{id}           # Alert detail + MITRE mappings
PATCH  /api/v1/alerts/{id}/fp        # Manually mark alert as false positive

GET    /api/v1/incidents             # List incidents (sorted by risk score, filterable by status/severity)
GET    /api/v1/incidents/{id}        # Incident detail with member alerts + risk score + MITRE
GET    /api/v1/incidents/{id}/graph  # Correlation graph for visualisation
PATCH  /api/v1/incidents/{id}/status # Update incident status

POST   /api/v1/bob/analyse/{incident_id}          # Trigger Bob's full analyse_incident (classification + score explanation + correlation review + agreement)
GET    /api/v1/bob/analysis/{incident_id}         # Retrieve stored BobAnalysis for an incident
POST   /api/v1/bob/bluf/{incident_id}             # Ask Bob to generate_bluf for an incident
GET    /api/v1/bob/bluf/{incident_id}             # Retrieve stored BLUF for an incident
GET    /api/v1/incidents/{id}/classification      # Side-by-side: auto_classification vs bob_classification + agreement_status

GET    /api/v1/dashboard/stats       # Summary: total alerts, open incidents, P1 count, FP rate
GET    /api/v1/mitre/matrix          # All technique mappings aggregated for heatmap

GET    /api/v1/health                # Health check
```

**Todo List:**
1. Create `src/backend/main.py` — FastAPI app, CORS, router registration, lifespan (DB init on startup)
2. Create `src/backend/routers/feeds.py` — ingest + runs endpoints
3. Create `src/backend/routers/alerts.py` — alert list, detail, FP patch
4. Create `src/backend/routers/incidents.py` — incident list, detail, graph, status patch
5. Create `src/backend/routers/bob.py` — Bob analyse + BLUF endpoints (delegates to MCP tools)
6. Create `src/backend/routers/dashboard.py` — stats endpoint
7. Create `src/backend/routers/mitre.py` — matrix endpoint
8. Create `src/backend/dependencies.py` — `get_db()`, `get_current_user()` stub
9. Create `src/backend/config.py` — Pydantic Settings reading from `.env`
10. Write `tests/test_api.py` — integration tests using FastAPI TestClient for every endpoint

**Relevant Context:**
- All routers mount under `/api/v1/`
- Pagination: `?page=1&page_size=20` query params
- Filtering: `?severity=CRITICAL&status=OPEN&source_type=SIEM`
- Auth stub: `X-API-Key` header check (configurable key in `.env`)

---

### ST-10 — React Frontend Application

**Status:** [ ] pending

**Intent:** Build the analyst dashboard as a professional, data-rich React SPA. Seven pages as specified, using React Router, TailwindCSS, and shadcn/ui components.

**Expected Outcomes:**
- All seven pages render with real data from the API
- Dashboard auto-refreshes stats every 30 seconds
- Alert Feed supports filtering by source, severity, status
- Incident detail page shows member alerts, risk score breakdown, MITRE techniques, and Bob analysis
- The **Classification Panel** is prominently displayed on every incident detail page, showing: automated decision, Bob's independent decision, agreement badge, and both reasoning texts
- MITRE page shows a heatmap-style matrix
- BLUF page shows Bob-generated summaries in formatted sections
- Application is fully functional with the backend running

**Pages & Components:**

| Page | Route | Key Components |
|---|---|---|
| Dashboard | `/` | StatsBar (total/P1/FP/GENUINE/UNCLASSIFIED counts), RecentIncidents table, RiskDistributionChart, SourceBreakdownChart, ClassificationBreakdownChart, FeedTriggerButton |
| Alert Feed | `/alerts` | AlertTable with filters, AlertSeverityBadge, SourceTypeBadge, FP toggle |
| Alert Detail | `/alerts/:id` | AlertDetailCard, RawPayloadViewer, MitreMappingList, CorrelationLink |
| Correlated Incidents | `/incidents` | IncidentTable (shows auto_classification + bob_classification columns), IncidentStatusBadge, RiskScoreBadge, AgreementBadge, sort by score |
| Incident Detail | `/incidents/:id` | IncidentHeader, ClassificationPanel, MemberAlertList, RiskScoreBreakdown, CorrelationGraph, MitreSection, BobAnalysisPanel, AnalyseWithBobButton |
| MITRE ATT&CK | `/mitre` | MitreMatrix heatmap (grouped by tactic), TechniqueRow (expands to sub-techniques), SubtechniqueCard (shows sub-technique ID, name, confidence, evidence bullets), TacticFilter, NotDeterminedBadge |
| BLUF Summary | `/incidents/:id/bluf` | BlufCard (formatted BLUF/SITUATION/ASSESSMENT/RECOMMENDATIONS sections), GenerateBobBlufButton, BlufHistory |

**ClassificationPanel component (central UI feature):**
Displayed prominently on the Incident Detail page. Shows two side-by-side cards:
- Left card — **Automated Decision**: `auto_classification` badge (GENUINE_THREAT = green, FALSE_POSITIVE = red, UNCLASSIFIED = grey), `auto_classification_reason` text, fired correlation rule chip, fired rule description
- Right card — **Bob's Assessment**: `bob_classification` badge, `bob_confidence` percentage bar, `bob_reasoning` text paragraph
- Centre — **Agreement Badge**: AGREES (green checkmark), DISAGREES (red X), or PARTIAL (amber tilde); if DISAGREES/PARTIAL, show `agreement_detail` text below
- "Analyse with Bob" button triggers `POST /api/v1/bob/analyse/{incident_id}` and refreshes the panel

**Shared Components:**
- `Layout` — sidebar nav, header with "Powered by Bob" badge
- `LoadingSpinner`, `ErrorBoundary`
- `SeverityBadge`, `StatusBadge`, `SourceBadge`
- `ClassificationBadge` — GENUINE_THREAT | FALSE_POSITIVE | UNCLASSIFIED with colour coding
- `AgreementBadge` — AGREES | DISAGREES | PARTIAL with icon
- `RiskScoreGauge` — circular gauge 0–100 with colour coding
- `BobInsightPanel` — reusable panel showing Bob's reasoning text (score_explanation_text, correlation_review_text, bob_reasoning)
- `FiredRuleChip` — displays fired correlation rule ID + name as a small labelled chip

**State Management:**
- React Query (TanStack Query) for all API calls — caching, loading states, background refetch
- No global state manager needed (React Query + local component state is sufficient)

**Charts:**
- Use Recharts for all visualisations (bar, pie, treemap for MITRE heatmap)

**Todo List:**
1. Scaffold Vite + React 18 + TypeScript project in `src/frontend/`
2. Install dependencies: TailwindCSS, shadcn/ui, React Router v6, TanStack Query, Recharts, Lucide icons
3. Create `src/frontend/src/api/` — typed API client functions (one file per resource: alerts.ts, incidents.ts, bob.ts, dashboard.ts, mitre.ts)
4. Create `src/frontend/src/types/` — TypeScript interfaces mirroring backend Pydantic schemas
5. Build shared Layout component with sidebar navigation
6. Build Dashboard page with StatsBar, RecentIncidents, charts, FeedTriggerButton
7. Build Alert Feed page with table, filters, pagination
8. Build Alert Detail page
9. Build Incidents List page
10. Build Incident Detail page with RiskScoreBreakdown, CorrelationGraph (react-flow or SVG), MitreSection, BobAnalysisPanel
11. Build MITRE ATT&CK page with heatmap matrix
12. Build BLUF Summary page with GenerateBobBlufButton and formatted output
13. Configure Vite proxy to backend (`/api` → `http://localhost:8000`)
14. Write basic Vitest smoke tests for key components

**Relevant Context:**
- API base URL: `/api/v1` (proxied via Vite dev server)
- All fetch calls through TanStack Query hooks in `src/frontend/src/hooks/`
- Colour theme: dark professional (slate/zinc base, amber/red accents for severity)

---

### ST-11 — Docker & Docker Compose Setup

**Status:** [ ] pending

**Intent:** Package the entire application so it can be started with a single `docker compose up` command. Critical for reproducibility and the "Working Demo" judging criterion.

**Expected Outcomes:**
- `docker compose up` starts backend, frontend (served via nginx), and mcp_server
- Frontend is accessible at `http://localhost:3000`
- Backend API accessible at `http://localhost:8000`
- SQLite database persists via a named volume
- `.env.example` documents all required variables
- Cold start (no cache) completes without errors

**Services:**

| Service | Image Base | Port | Notes |
|---|---|---|---|
| `backend` | python:3.11-slim | 8000 | FastAPI + Uvicorn, mounts ./src/backend |
| `frontend` | node:20-alpine (build) + nginx:alpine (serve) | 3000 | Multi-stage Dockerfile, nginx serves built Vite output |
| `mcp_server` | python:3.11-slim | 8001 | MCP server process |

**Todo List:**
1. Create `src/backend/Dockerfile` — python:3.11-slim, install requirements.txt, expose 8000
2. Create `src/frontend/Dockerfile` — multi-stage: node:20-alpine build, then nginx:alpine serve
3. Create `src/mcp_server/Dockerfile` — python:3.11-slim, install requirements.txt, expose 8001
4. Create `docker-compose.yml` at repo root — defines all three services, named volume for SQLite, env_file reference
5. Create `src/.env.example` — document all variables with descriptions
6. Test `docker compose up --build` from scratch
7. Update `docs/setup-guide.md` with Docker Compose run instructions

**Relevant Context:**
- SQLite database file stored in `/data/infinity_threat.db` inside backend container, mounted as Docker volume
- `FRONTEND_API_URL` env var controls API base URL in nginx proxy config

---

### ST-12 — Automated Testing Suite

**Status:** [ ] pending

**Intent:** Ensure the application has meaningful test coverage that judges can run to verify correctness. Tests cover the pipeline logic, API endpoints, and key frontend components.

**Expected Outcomes:**
- `pytest src/backend/tests/` passes with ≥ 80% coverage on processing, correlation, scoring modules
- `npm run test` passes for frontend smoke tests
- Tests run in CI (can be added to GitHub Actions)
- No tests require external services (all Bob calls are mocked)

**Test Files Plan:**

| File | Coverage |
|---|---|
| `tests/test_models.py` | ORM model creation, relationships |
| `tests/test_feeds.py` | Feed generator output validity |
| `tests/test_normaliser.py` | All four source normalisations, fingerprint, FP rules |
| `tests/test_correlation.py` | Each correlation rule, incident builder, scenario matcher |
| `tests/test_scoring.py` | Each score component, explanation JSON, clamping |
| `tests/test_mitre.py` | All alert_type → tactic/technique mappings; sub-technique resolution with and without payload evidence; not_determined fallback; cross-source corroboration upgrade; evidence_strings non-empty for resolved sub-techniques |
| `tests/test_mcp_tools.py` | MCP tool functions (Bob mocked) |
| `tests/test_api.py` | Every REST endpoint via TestClient |

**Todo List:**
1. Create `src/backend/tests/conftest.py` — in-memory SQLite fixture, test client fixture, seeded test data
2. Fill each test file (listed above) with meaningful assertions
3. Create `src/backend/pytest.ini` — testpaths, coverage config
4. Create `src/frontend/src/__tests__/` — Vitest tests for Dashboard and AlertTable components
5. Verify `pytest --cov` reports ≥ 80% on processing/correlation/scoring modules

**Relevant Context:**
- Use `pytest-cov` for coverage
- Use `unittest.mock.patch` to mock Bob API calls
- In-memory SQLite: `engine = create_engine("sqlite:///:memory:")`

---

### ST-13 — Documentation & Demo Artefacts

**Status:** [ ] pending

**Intent:** Finalise all written documentation to competition quality and produce the demo artefacts (screenshots, video link, presentation outline).

**Expected Outcomes:**
- All four docs/ files are complete, accurate, and reflect the implemented system
- `docs/setup-guide.md` has been tested end-to-end on a clean machine
- At least 3 screenshots are in `demo/screenshots/` named 01-, 02-, 03-
- `demo/demo-video-link.txt` contains a real URL
- `presentation/` contains slides.pdf or slides.pptx
- GitHub Actions Validate Submission is green

**Todo List:**
1. Finalise `docs/architecture.md` — update Mermaid diagram to match implemented system, complete component table
2. Finalise `docs/solution-overview.md` — update step-by-step to match actual implementation, document Bob integration specifics
3. Finalise `docs/setup-guide.md` — test on clean machine, fix any broken steps
4. Take screenshots: 01-dashboard.png, 02-incident-detail.png, 03-bluf-summary.png, 04-mitre-matrix.png
5. Add screenshots to `demo/screenshots/`
6. Record 3–5 min demo video and update `demo/demo-video-link.txt`
7. Create presentation slides covering: problem, solution, architecture, Bob integration, live demo moment, team
8. Final submission.yaml review — verify all fields correct
9. Final README.md review — no placeholders remain
10. Trigger GitHub Actions and verify green

---

## Development Phases

### Phase 1 — Foundation (ST-01, ST-02, ST-03)
Get the scaffold right, database models defined, and synthetic data flowing. Everything else depends on data existing.

### Phase 2 — Intelligence Pipeline (ST-04, ST-05, ST-06, ST-07)
Build the processing chain: normalise → correlate → score → map MITRE. This is the technical core that judges evaluate.

### Phase 3 — Bob Integration & API (ST-08, ST-09)
Expose the pipeline through REST API and connect Bob via MCP. This unlocks the AI scoring criterion.

### Phase 4 — Frontend (ST-10)
Build the analyst dashboard once API is stable. Use the API contract (OpenAPI docs at /api/docs) to build against.

### Phase 5 — Packaging & Polish (ST-11, ST-12, ST-13)
Docker packaging, testing, documentation, and demo production.

---

## Key Design Decisions

1. **SQLite over PostgreSQL** — Zero-config, perfect for a hackathon Docker setup. SQLAlchemy makes a future migration trivial.
2. **Rule-based correlation over ML** — Reliable, explainable, and auditable. ML clustering would add complexity without improving demo quality.
3. **Synthetic scenario packs** — Pre-seeded correlated attack stories ensure the demo always has interesting data showing multi-source convergence.
4. **Explainable scoring** — Every score component stored separately so Bob and the UI can narrate the reasoning. This directly addresses the "evidence and reasoning" requirement.
5. **Genuine Threat vs False Positive as first-class pipeline outcome** — `auto_classification` is set deterministically by the pipeline using rule evidence (FP-01–FP-04, GT-01–GT-03). It is never inferred from the risk score alone. This is a primary display element in the UI, not a secondary annotation.
6. **Bob as independent reviewer, not sole authority** — Bob receives all deterministic outputs as structured evidence via MCP tools and produces its own classification independently. The `agreement_status` field (AGREES / DISAGREES / PARTIAL) is stored and displayed. A disagreement is not an error — it is an analytical signal that warrants analyst attention and is highlighted in the UI.
7. **Bob is evidence-grounded by prompt design** — The `analyse_incident` and `generate_bluf` prompts explicitly forbid Bob from inventing details not present in the MCP-tool responses. The `evidence_assembler.py` helper controls exactly what Bob receives, ensuring reproducibility and preventing hallucination.
8. **MCP tools are data-retrieval only (except AI tools)** — Data tools (get_incident_details, get_risk_score_explanation, etc.) are pure DB reads with no side effects. Only `analyse_incident` and `generate_bluf` call Bob and write to the DB. This separation makes the AI layer independently testable.
9. **TanStack Query** — Handles API caching and background refresh cleanly. Dashboard auto-refreshing without manual polling logic.

---

## Environment Variables Reference

| Variable | Default | Required | Description |
|---|---|---|---|
| `DATABASE_URL` | `sqlite:///./infinity_threat.db` | No | SQLAlchemy DB URL |
| `BOB_API_KEY` | — | Yes | IBM Bob API key |
| `BOB_MCP_URL` | `http://localhost:8001` | No | MCP server URL |
| `API_KEY` | `dev-key-infinity` | No | Backend API key for X-API-Key header |
| `CORS_ORIGINS` | `http://localhost:5173` | No | Allowed CORS origins |
| `LOG_LEVEL` | `INFO` | No | Python logging level |
| `FEED_SEED` | — | No | Random seed for deterministic feed generation |
