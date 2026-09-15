# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.11 or higher — [python.org/downloads](https://www.python.org/downloads/)
- Node.js 20 or higher (LTS) — [nodejs.org](https://nodejs.org/)
- Docker Desktop (for the Docker path) — [docker.com/get-started](https://www.docker.com/get-started/)
- Git — [git-scm.com](https://git-scm.com/)
- An IBM Bob API key (required for the AI review layer; the deterministic pipeline runs without it)

Verify your versions:

```bash
python --version    # should print Python 3.11.x or higher
node --version      # should print v20.x.x or higher
docker --version    # should print Docker version 24.x or higher
```

---

## Environment Variables

Copy the example file and set your values:

```bash
cp src/.env.example src/.env
```

Then open `src/.env` in your editor and fill in the values below:

| Variable | Default | Required | Description |
|---|---|---|---|
| `BOB_API_KEY` | — | **Yes** | IBM Bob API key (AI review layer; pipeline runs without it) |
| `DATABASE_URL` | `sqlite:///./infinity_threat.db` | No | SQLAlchemy DB URL; change only if migrating to PostgreSQL |
| `BOB_MCP_URL` | `http://localhost:8001` | No | URL of the Bob MCP server (change if running in Docker) |
| `API_KEY` | `dev-key-infinity` | No | Backend API key sent in `X-API-Key` header by the frontend |
| `CORS_ORIGINS` | `http://localhost:5173` | No | Comma-separated list of allowed CORS origins |
| `LOG_LEVEL` | `INFO` | No | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `FEED_SEED` | — | No | Integer seed for deterministic synthetic feed generation (useful for demos) |

> **Never commit `src/.env`** — it is already in `.gitignore`.

---

## Option A — Docker (recommended)

This starts the backend, MCP server, and frontend in one command.

```bash
# 1. Clone the repository
git clone https://github.com/ibm-hackathon/bob-ai-hackathon-Infinity.git
cd bob-ai-hackathon-Infinity

# 2. Configure environment
cp src/.env.example src/.env
# Edit src/.env and set BOB_API_KEY

# 3. Build and start all services
docker compose up --build

# 4. Verify services are running
#    Backend API:   http://localhost:8000/health
#    MCP server:    http://localhost:8001/health
#    Frontend:      http://localhost:5173
```

To stop all services:

```bash
docker compose down
```

To reset the database (wipe all alerts and incidents):

```bash
docker compose down -v
docker compose up --build
```

---

## Option B — Manual (without Docker)

Run each service in its own terminal window.

### Terminal 1 — Backend API

```bash
# From the repository root
cd src

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows PowerShell

# Install backend dependencies
pip install -r backend/requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env and set BOB_API_KEY

# Run database migrations (creates tables on first run)
python -m backend.db.init_db

# Start the backend API
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

The API is available at `http://localhost:8000`.
Interactive API docs: `http://localhost:8000/docs`

### Terminal 2 — Bob MCP Server

```bash
# From the repository root, with the same virtual environment active
cd src
source .venv/bin/activate        # macOS / Linux

uvicorn mcp_server.main:app --host 0.0.0.0 --port 8001
```

The MCP server is available at `http://localhost:8001`.

### Terminal 3 — Frontend

```bash
# From the repository root
cd src/frontend

# Install Node dependencies
npm install

# Start the development server
npm run dev
```

The dashboard is available at `http://localhost:5173`.

---

## Verifying the Installation

After starting all services, run through this checklist:

1. **Backend health:** Open `http://localhost:8000/health` — expect `{"status": "ok"}`
2. **MCP health:** Open `http://localhost:8001/health` — expect `{"status": "ok"}`
3. **Frontend loads:** Open `http://localhost:5173` — expect the Infinity dashboard
4. **Alerts ingesting:** Wait 30 seconds; the incident queue should start populating
5. **Bob analysis (optional):** Click an incident, press "Analyse with Bob" — requires `BOB_API_KEY`

---

## Running Tests

### Backend tests (Pytest)

```bash
cd src
source .venv/bin/activate
pytest backend/tests/ -v
```

### Frontend tests (Vitest)

```bash
cd src/frontend
npm run test
```

---

## Seeding Demo Data

To populate the database with a pre-built set of correlated attack scenarios for demonstration:

```bash
cd src
source .venv/bin/activate
python -m backend.feeds.seed_demo --scenario all
```

This seeds: a lateral movement scenario (rules C1+C5), a physical-cyber convergence scenario (rule C3), and a known actor scenario (rule C2).

---

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `ModuleNotFoundError: No module named 'backend'` | Virtual environment not active or packages not installed | Run `pip install -r backend/requirements.txt` with the venv active |
| `sqlalchemy.exc.OperationalError: no such table` | Database not initialised | Run `python -m backend.db.init_db` before starting the API |
| `Connection refused` on port 8000 | Backend not running | Start the backend in Terminal 1 first |
| `Connection refused` on port 8001 | MCP server not running | Start the MCP server in Terminal 2 |
| Frontend shows blank page | Node version too old or `npm install` not run | Run `node --version` (need v20+), then `npm install` |
| Bob analysis returns `401 Unauthorized` | `BOB_API_KEY` missing or wrong | Check `src/.env` and confirm the key is correct |
| Bob analysis returns `503` / timeout | MCP server not reachable | Check `BOB_MCP_URL` in `.env` matches where the MCP server is running |
| Docker: `port is already allocated` | Another process is using port 8000/8001/5173 | Stop the conflicting process or change ports in `docker-compose.yml` |
| Docker: database keeps resetting | Volume was wiped | Run `docker compose up --build` without `-v` to retain data |
| Feed generator not producing alerts | `FEED_SEED` set to a non-integer | Remove `FEED_SEED` from `.env` or set it to a valid integer |
