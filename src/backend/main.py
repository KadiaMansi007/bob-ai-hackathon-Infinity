"""
FastAPI application entry point.

Startup sequence:
1. Initialise database (create_all)
2. Mount all routers under /api/v1
3. Configure CORS
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.init_db import init_db
from backend.routers import (
    feeds_router, alerts_router, incidents_router,
    bob_router, dashboard_router, mitre_router,
)

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting Infinity Threat Intelligence Platform...")
    init_db()
    log.info("Database ready.")
    yield
    log.info("Shutting down.")


app = FastAPI(
    title="Infinity Threat Intelligence Fusion & Prioritisation Platform",
    description=(
        "D2: Threat Intelligence Correlation & Alert Prioritisation Assistant. "
        "Dual-layer architecture: deterministic pipeline + IBM Bob AI reasoning."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all routers
PREFIX = "/api/v1"
app.include_router(feeds_router, prefix=PREFIX)
app.include_router(alerts_router, prefix=PREFIX)
app.include_router(incidents_router, prefix=PREFIX)
app.include_router(bob_router, prefix=PREFIX)
app.include_router(dashboard_router, prefix=PREFIX)
app.include_router(mitre_router, prefix=PREFIX)


@app.get("/api/v1/health", tags=["health"])
def health():
    return {"status": "ok", "service": "infinity-threat-platform"}
