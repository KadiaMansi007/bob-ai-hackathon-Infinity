"""FastAPI route handlers for dashboard stats."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import (
    NormalisedAlert, Incident, FeedRun, RiskScore, AutoClassification
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", summary="Dashboard summary statistics")
def get_stats(db: Session = Depends(get_db)):
    total_alerts = db.query(func.count(NormalisedAlert.id)).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    open_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(["OPEN", "INVESTIGATING"])
    ).scalar() or 0

    genuine = db.query(func.count(Incident.id)).filter(
        Incident.auto_classification == AutoClassification.GENUINE_THREAT.value
    ).scalar() or 0
    false_pos = db.query(func.count(Incident.id)).filter(
        Incident.auto_classification == AutoClassification.FALSE_POSITIVE.value
    ).scalar() or 0
    unclassified = db.query(func.count(Incident.id)).filter(
        Incident.auto_classification == AutoClassification.UNCLASSIFIED.value
    ).scalar() or 0

    # P1 incidents (risk score ≥ 80)
    p1 = db.query(func.count(RiskScore.id)).filter(RiskScore.total_score >= 80).scalar() or 0

    fp_rate = round(false_pos / total_incidents, 3) if total_incidents > 0 else 0.0

    last_run = db.query(FeedRun).order_by(FeedRun.started_at.desc()).first()

    return {
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "p1_incidents": p1,
        "genuine_threat_count": genuine,
        "false_positive_count": false_pos,
        "unclassified_count": unclassified,
        "false_positive_rate": fp_rate,
        "last_feed_run": {
            "id": last_run.id,
            "scenario": last_run.scenario,
            "status": last_run.status,
            "alerts_generated": last_run.alerts_generated,
            "started_at": last_run.started_at.isoformat(),
        } if last_run else None,
    }
