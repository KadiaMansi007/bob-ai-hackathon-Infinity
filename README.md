# Infinity Threat Intelligence Fusion & Prioritisation Platform

> **Team Infinity — IBM Bob AI Innovation Hackathon 2026 — Track: AI**
>
> Addressing Problem D2: Threat Intelligence Correlation & Alert Prioritisation Assistant

---

## Team

| Field | Value |
|---|---|
| **Team Name** | Infinity |
| **Track** | AI |
| **Team Lead** | Team Lead — team.infinity@ibm.com |
| **Members** | Team Member 1, Team Member 2, Team Member 3 |

---

## Problem Statement

Security Operations Centre (SOC) analysts managing multi-source threat feeds face debilitating alert fatigue. Hundreds of raw signals per hour arrive from SIEMs, cyber sensors, satellite feeds, and intelligence reports — the vast majority of which are false positives. Manual triage for D2 threat correlation takes 30–90 minutes per incident and causes genuine threats to be missed or delayed, directly increasing organisational risk.

See [`docs/problem-statement.md`](docs/problem-statement.md) for the full analysis.

---

## Solution

The **Infinity Threat Intelligence Fusion & Prioritisation Platform** ingests simulated multi-source threat feeds, normalises and deduplicates alerts, correlates them into incidents using deterministic rules, computes explainable risk scores, and maps findings to MITRE ATT&CK. IBM Bob is integrated as an independent AI reasoning layer via a custom MCP server: it classifies each incident as GENUINE_THREAT or FALSE_POSITIVE, explains the risk score in natural language, and generates BLUF summaries — all grounded solely in pipeline-produced evidence.

See [`docs/solution-overview.md`](docs/solution-overview.md) for the detailed walkthrough.

---

## Key Features

| Feature | Description |
|---|---|
| **Multi-source ingestion pipeline** | Normalises and deduplicates alerts from SIEM, cyber sensors, satellite, and intelligence report feeds using SHA-256 fingerprinting |
| **Deterministic correlation engine** | Rules C0–C5 group alerts into incidents; each incident records which rule fired and the `auto_classification` result (GENUINE_THREAT / FALSE_POSITIVE / UNCLASSIFIED) |
| **Explainable risk scoring** | Weighted formula with five per-component scores (severity, confidence, recency, source reliability, MITRE coverage) stored and surfaced individually |
| **IBM Bob AI review layer** | Custom MCP server gives Bob structured access to incident data; Bob independently classifies, explains scores, reviews correlation rules, generates BLUF summaries, and records `agreement_status` vs. the pipeline decision |
| **Dual-layer analyst dashboard** | React dashboard shows deterministic pipeline decisions and Bob AI assessment side-by-side, with MITRE ATT&CK tactic/technique mapping and disagreement highlighting |

---

## Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.11, TypeScript |
| **Backend** | FastAPI, SQLAlchemy, Pydantic v2 |
| **Frontend** | React 18, Vite, TailwindCSS, shadcn/ui, TanStack Query |
| **IBM Technologies** | IBM Bob (via MCP — Model Context Protocol) |
| **Database** | SQLite (file-based, zero-config) |
| **Other** | Docker, Docker Compose, GitHub Actions, Pytest, Vitest |

---

## Repository Structure

```
bob-ai-hackathon-Infinity/
├── src/
│   ├── backend/           # FastAPI application
│   │   ├── models/        # SQLAlchemy ORM models
│   │   ├── feeds/         # Feed ingestors and synthetic generator
│   │   ├── processing/    # Normaliser, deduplicator, FP pre-filter
│   │   ├── correlation/   # Correlation engine (rules C0–C5)
│   │   ├── scoring/       # Risk scoring engine
│   │   ├── mitre/         # MITRE ATT&CK mapper
│   │   ├── routers/       # FastAPI route handlers
│   │   └── schemas/       # Pydantic request/response schemas
│   ├── frontend/          # React + Vite analyst dashboard
│   ├── mcp_server/        # IBM Bob MCP server (custom tool definitions)
│   └── .env.example       # Environment variable template
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/
│   ├── screenshots/       # App screenshots
│   ├── demo-video-link.txt
│   └── live-demo-url.txt
├── presentation/          # Slide deck
└── submission.yaml        # Structured submission metadata
```

---

## How to Run

Full prerequisites and troubleshooting are in [`docs/setup-guide.md`](docs/setup-guide.md).

### Quick start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/ibm-hackathon/bob-ai-hackathon-Infinity.git
cd bob-ai-hackathon-Infinity

# 2. Copy and configure environment
cp src/.env.example src/.env
# Edit src/.env — set BOB_API_KEY to your IBM Bob API key

# 3. Build and run all services
docker compose up --build

# 4. Open the dashboard
open http://localhost:5173
```

### Manual start (without Docker)

```bash
# Backend (Python 3.11+)
cd src
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000

# MCP server (separate terminal)
uvicorn mcp_server.main:app --port 8001

# Frontend (Node 20+, separate terminal)
cd src/frontend
npm install
npm run dev
```

---

## Demo

| Artifact | Link |
|---|---|
| Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| Screenshots | [See demo/screenshots/](demo/screenshots/) |
| Presentation | [See presentation/](presentation/) |

---

## Known Limitations

- All threat feeds are synthetic and simulated — no real external feed APIs are connected
- Authentication is a stub JWT — not production-ready
- Designed for local and Docker deployment only; horizontal scaling not tested
- IBM Bob AI review requires a valid `BOB_API_KEY`; without it the deterministic pipeline runs fully but the AI review layer is disabled
- Frontend has been tested on Chrome and Firefox only

---

## What We Are Most Proud Of

The dual-layer architecture keeps the deterministic pipeline and IBM Bob AI reasoning completely separate and independently auditable. Every risk score component, correlation rule firing, and auto-classification is computed without AI — making decisions fully traceable. Bob then acts as an independent reviewer: it can **agree or disagree** with the pipeline's classification, and the `agreement_status` field surfaces those disagreements as analytical signals in the dashboard rather than hiding them. This design ensures neither layer masks the other and analysts always see both perspectives.

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full Mermaid system diagram and component table.

---

*Made with IBM Bob — IBM Bob AI Innovation Hackathon 2026*
