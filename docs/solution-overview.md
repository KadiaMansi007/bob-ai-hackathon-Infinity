# Solution Overview

## What We Built

The **Infinity Threat Intelligence Fusion & Prioritisation Platform** is a full-stack web application that automates the D2 triage workflow. It ingests simulated multi-source threat feeds, runs them through a deterministic normalisation-correlation-scoring pipeline, maps findings to the MITRE ATT&CK framework, and surfaces results through a professional analyst dashboard. IBM Bob is integrated as a second, independent AI reasoning layer that reviews each incident, provides natural-language explanations of the risk score, and produces its own threat classification — all grounded strictly in evidence assembled by the pipeline.

The key architectural principle is **separation of concerns**: the deterministic pipeline and the AI reasoning layer are fully independent. Both produce a classification (GENUINE_THREAT / FALSE_POSITIVE / UNCLASSIFIED). The dashboard shows both side-by-side, along with an `agreement_status` field (AGREES / DISAGREES / PARTIAL). Disagreements are not errors — they are analytical signals.

---

## How It Works — Step by Step

### Step 1 — Feed Ingestion

The `FeedIngestor` (a FastAPI background task) receives raw alert payloads from four simulated feed generators:

| Feed Type | Simulated Source | Example Signal |
|---|---|---|
| `SIEM` | Corporate network event log | Failed authentication burst from internal host |
| `CYBER_SENSOR` | IDS/IPS network tap | Port scan detected on DMZ subnet |
| `SATELLITE` | Satellite telemetry stream | RF anomaly over monitored geographic zone |
| `INTEL_REPORT` | Intelligence advisory service | Threat actor APT-29 activity report, confidence: high |

Each raw alert is stamped with ingestion timestamp, source feed type, and a raw severity value (1–10).

### Step 2 — Normalisation

The `Normaliser` converts each raw alert into a canonical `NormalisedAlert` record with a uniform schema regardless of source. Fields include: `alert_id`, `source_type`, `severity` (normalised 0.0–1.0), `confidence` (0.0–1.0), `timestamp`, `description`, `raw_iocs` (IPs, domains, hashes), `geo_region`, and `threat_actor_hint`.

### Step 3 — Deduplication

The `Deduplicator` computes a SHA-256 fingerprint over the normalised alert's deterministic fields (source_type + severity_bucket + ioc_set + geo_region + 15-minute time window). If a matching fingerprint already exists in the database, the new alert is marked as a duplicate and linked to the canonical record rather than creating a new entry. This eliminates the false-volume problem where overlapping sensors report the same event multiple times.

### Step 4 — False Positive Pre-filter

Before correlation, a rule-based FP pre-filter evaluates each alert against four FP rules:

| Rule | Condition | Result |
|---|---|---|
| `FP-01` | Severity < 0.2 AND no corroborating source | Marked `FP_CANDIDATE` |
| `FP-02` | Single-source alert with confidence < 0.3 | Marked `FP_CANDIDATE` |
| `FP-03` | Duplicate cluster of 5+ identical alerts in 5 minutes (scanner noise) | Marked `FP_CANDIDATE` |
| `FP-04` | Alert from known internal test/scan IP range | Marked `FP_CANDIDATE` |

Alerts marked `FP_CANDIDATE` are still stored and visible but are excluded from incident correlation unless a later alert escalates the situation. The reason code (`FP-01`, `FP-02`, etc.) is stored with each alert.

### Step 5 — Correlation Engine

The `Correlator` evaluates non-FP-candidate alerts against six correlation rules (C0–C5):

| Rule | Pattern | Example |
|---|---|---|
| `C0` | 3+ alerts from different sources within 30 minutes referencing the same geo_region | Multi-vector regional convergence |
| `C1` | SIEM alert + CYBER_SENSOR alert sharing the same source IP within 10 minutes | Lateral movement signature |
| `C2` | INTEL_REPORT with threat_actor_hint matching any active alert IOC | Known actor IOC match |
| `C3` | SATELLITE anomaly + CYBER_SENSOR alert in the same geo_region within 1 hour | Physical-cyber convergence |
| `C4` | 5+ high-severity alerts from any single source within 15 minutes | Volume-based escalation |
| `C5` | Sequential MITRE tactic progression (Recon → Initial Access → Execution) within 2 hours | Kill-chain pattern |

When a rule fires, the `IncidentBuilder` creates an `Incident` record containing: the matched alert IDs, the fired rule code, an initial `auto_classification`, and an `auto_classification_reason` string.

### Step 6 — Automatic Classification

The pipeline sets `auto_classification` on each incident using three GT rules and the FP pre-filter outcomes:

| Rule | Condition | Classification |
|---|---|---|
| `GT-01` | Rule C2 fired (known actor IOC match) | `GENUINE_THREAT` |
| `GT-02` | Rule C5 fired (kill-chain pattern) | `GENUINE_THREAT` |
| `GT-03` | Rule C0/C1/C3/C4 fired AND 0 member alerts are FP_CANDIDATE | `GENUINE_THREAT` |
| Default | All other correlated incidents | `UNCLASSIFIED` |
| FP path | All member alerts are FP_CANDIDATE | `FALSE_POSITIVE` |

### Step 7 — Risk Scoring

The `RiskScorer` computes a 0.0–100.0 composite score with five named components stored independently:

```
composite_score = (
    severity_score       × 0.30  +
    confidence_score     × 0.25  +
    recency_score        × 0.15  +
    source_reliability   × 0.20  +
    mitre_coverage_score × 0.10
) × 100
```

Every component value is stored in the `RiskScore` table so the UI and Bob can narrate each element individually.

### Step 8 — MITRE ATT&CK Mapping

The `MITREMapper` queries the MITRE ATT&CK knowledge base to map each incident to one or more tactic → technique → sub-technique chains. Mappings are stored in the `MITREMapping` table with a confidence score (0.0–1.0) and the technique ID (e.g., `T1078.003 — Valid Accounts: Local Accounts`).

### Step 9 — IBM Bob AI Review (Layer 2)

After the deterministic pipeline completes, analysts (or an automated trigger) invoke Bob's review via the MCP server. Bob receives a structured evidence package assembled by `evidence_assembler.py` containing:

- Full incident record with auto_classification and reason
- All member alert details (source, severity, confidence, IOCs)
- Complete RiskScore breakdown (all five components)
- Fired correlation rule and its definition
- All MITRE mappings with confidence scores

Bob performs four operations via MCP tools:

1. **`classify_threat`** — produces an independent GENUINE_THREAT / FALSE_POSITIVE verdict with a confidence float (0.0–1.0) and a reasoning paragraph
2. **`score_explanation`** — narrates why each risk score component is at its value, referencing the actual numbers
3. **`correlation_review`** — states whether it agrees the fired rule's conclusion is justified given the member alert evidence
4. **`generate_bluf`** — produces a single structured BLUF summary paragraph suitable for briefing, citing only evidence present in the input

Bob's output is stored as a `BobAnalysis` record. The `agreement_status` field (AGREES / DISAGREES / PARTIAL) is computed by comparing `bob_classification` against `auto_classification`.

### Step 10 — REST API

The FastAPI backend exposes a REST API (port 8000) covering:
- `GET /incidents` — paginated incident list with filters
- `GET /incidents/{id}` — full incident detail including risk score, MITRE mappings, and Bob analysis
- `POST /incidents/{id}/analyse` — trigger Bob AI review
- `GET /alerts` — alert list with source/severity filters
- `GET /health` — service health check

### Step 11 — React Analyst Dashboard

The Vite + React frontend (port 5173) provides:
- Incident queue with risk score, classification badges, and agreement_status indicator
- Incident detail panel: alert list, correlation rule, risk score breakdown chart, MITRE ATT&CK tactic chain, Bob BLUF summary
- Filter and sort controls (by source, severity, classification, date range)
- Auto-refresh via TanStack Query (30-second polling)

---

## Hybrid Architecture: Deterministic + AI

```
Layer 1 (Deterministic — no AI, fully auditable)
  Feed Ingestor → Normaliser → Deduplicator → FP Pre-filter
    → Correlator (C0–C5) → Incident Builder → Auto-Classifier
      → Risk Scorer → MITRE Mapper
        → SQLite DB

Layer 2 (IBM Bob AI — on top of Layer 1 outputs)
  evidence_assembler.py → Bob MCP Server
    → classify_threat → score_explanation → correlation_review → generate_bluf
      → BobAnalysis record (agreement_status, bob_classification, bluf_summary)
```

Bob never modifies Layer 1 outputs. The pipeline risk score, auto_classification, and correlation rule are immutable once written. Bob reads them and produces a parallel record.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| SQLite over PostgreSQL | Zero-config, perfect for a Docker hackathon setup. SQLAlchemy makes future migration trivial. |
| Rule-based correlation over ML clustering | Reliable, explainable, and auditable. Results are reproducible and traceable to a named rule. |
| Fingerprint deduplication (SHA-256) | Eliminates false volume from overlapping sensors without needing ML anomaly detection. |
| Explainable risk score components stored separately | Enables both the UI and Bob to narrate reasoning per-component rather than just showing a number. |
| Bob as independent reviewer, not override authority | Bob's classification is shown alongside the pipeline's — disagreements are surfaced, not hidden, and are treated as analytical signals. |
| Evidence assembler pattern | `evidence_assembler.py` controls exactly what Bob receives via MCP, preventing hallucination of IOCs or alert details not present in the DB. |

---

## IBM Technologies Used

**IBM Bob (via MCP — Model Context Protocol):**
Bob is integrated through a custom MCP server (`src/mcp_server/`) that exposes the following tools to the Bob runtime:

- `get_incident_details` — retrieves the full incident record from SQLite
- `get_risk_score_explanation` — returns all five score components with their weights and raw values
- `get_correlation_rule` — returns the fired rule definition and the member alert evidence
- `get_mitre_mappings` — returns all tactic/technique mappings for the incident
- `analyse_incident` — orchestrates `classify_threat` + `score_explanation` + `correlation_review`, writes `BobAnalysis` to DB
- `generate_bluf` — produces the BLUF summary from structured evidence only

Bob is the sole consumer of these MCP tools. The tools are data-retrieval only (except `analyse_incident` and `generate_bluf` which write to DB). This separation makes the AI layer independently testable without a live Bob connection.
