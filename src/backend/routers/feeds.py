"""
FastAPI route handlers for feed ingestion.
"""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import FeedRun
from backend.feeds.generator import run_feed_generation
from backend.processing.pipeline import process_feed_run_alerts
from backend.correlation.engine import correlate
from backend.scoring.scorer import score_incident
from backend.mitre.mapper import map_alert
from backend.processing.auto_classifier import classify_incident

router = APIRouter(prefix="/feeds", tags=["feeds"])


def _run_full_pipeline(feed_run_id: str) -> None:
    """Background task: process, correlate, score, and classify all alerts in a FeedRun."""
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        new_alerts, dupes = process_feed_run_alerts(db, feed_run_id)

        # Map MITRE for all new alerts
        for alert in new_alerts:
            if not alert.is_false_positive:
                map_alert(db, alert)

        # Correlate each new alert into incidents
        incidents_touched = set()
        for alert in new_alerts:
            incident = correlate(db, alert)
            incidents_touched.add(incident.id)

        # Score + classify each touched incident
        for inc_id in incidents_touched:
            from backend.models import Incident
            inc = db.get(Incident, inc_id)
            if inc:
                score_incident(db, inc)
                classify_incident(db, inc)

        db.commit()

        # Update FeedRun
        run = db.get(FeedRun, feed_run_id)
        if run:
            run.alerts_deduplicated = dupes
            run.incidents_created = len(incidents_touched)
            db.commit()
    except Exception as exc:
        db.rollback()
        run = db.get(FeedRun, feed_run_id)
        if run:
            run.status = "failed"
            run.error_message = str(exc)
            db.commit()
        raise
    finally:
        db.close()


@router.post("/ingest", summary="Trigger synthetic feed generation + pipeline")
def ingest_feeds(
    scenario: str = "random",
    seed: int | None = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
):
    """Trigger a new synthetic feed run and process all alerts."""
    feed_run = run_feed_generation(db, scenario=scenario, seed=seed)
    db.commit()
    background_tasks.add_task(_run_full_pipeline, feed_run.id)
    return {
        "feed_run_id": feed_run.id,
        "scenario": feed_run.scenario,
        "alerts_generated": feed_run.alerts_generated,
        "status": "processing",
        "message": "Feed ingested. Pipeline running in background.",
    }


@router.get("/runs", summary="List feed run history")
def list_feed_runs(limit: int = 20, db: Session = Depends(get_db)):
    runs = (
        db.query(FeedRun)
        .order_by(FeedRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "scenario": r.scenario,
            "status": r.status,
            "alerts_generated": r.alerts_generated,
            "alerts_deduplicated": r.alerts_deduplicated,
            "incidents_created": r.incidents_created,
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs
    ]
