# Infinity Threat Intelligence Fusion & Prioritisation Platform — Source Code

This directory contains all source code for the platform.

## Directory Structure

```
src/
├── backend/           # FastAPI application (Python 3.11)
│   ├── models/        # SQLAlchemy ORM models (alerts, incidents, risk scores, etc.)
│   ├── feeds/         # Synthetic feed generators (SIEM, cyber sensor, satellite, intel)
│   ├── processing/    # Normaliser, deduplicator, FP pre-filter, auto-classifier
│   ├── correlation/   # Correlation engine (rules C0–C5) and incident builder
│   ├── scoring/       # Risk scoring engine (5-component weighted formula)
│   ├── mitre/         # MITRE ATT&CK mapper (tactic → technique → sub-technique)
│   ├── routers/       # FastAPI route handlers
│   └── schemas/       # Pydantic v2 request/response schemas
├── frontend/          # React 18 + Vite analyst dashboard (TypeScript)
├── mcp_server/        # IBM Bob MCP server — custom tool definitions for Bob AI
├── .env.example       # Environment variable template (copy to .env and fill in)
└── README.md          # This file
```

## Quick Setup

```bash
# Backend
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000

# MCP Server
uvicorn mcp_server.main:app --port 8001

# Frontend
cd frontend && npm install && npm run dev
```

See [`../docs/setup-guide.md`](../docs/setup-guide.md) for full prerequisites and Docker instructions.

## Environment Variables

Copy `.env.example` to `.env` and set `BOB_API_KEY`. All other variables have sensible defaults.
Never commit `.env` — it is in `.gitignore`.
