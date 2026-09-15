"""FastAPI route handlers for incidents."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import (
    Incident, IncidentAlert, NormalisedAlert, RiskScore, BobAnalysis, BlufSummary, MitreMapping
)
from backend.mitre.incident_summary import get_incident_mitre_summary
from mcp_server.tools import tool_get_correlation_graph

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", summary="List incidents sorted by risk score")
def list_incidents(
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    severity: str | None = None,
    auto_classification: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status.upper())
    if severity:
        q = q.filter(Incident.overall_severity == severity.upper())
    if auto_classification:
        q = q.filter(Incident.auto_classification == auto_classification.upper())
    total = q.count()
    incidents = q.order_by(Incident.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()

    result = []
    for inc in incidents:
        rs = db.query(RiskScore).filter(RiskScore.incident_id == inc.id).first()
        ba = db.query(BobAnalysis).filter(BobAnalysis.incident_id == inc.id).first()
        result.append(_incident_summary(inc, rs, ba))

    return {"total": total, "page": page, "page_size": page_size, "items": result}


@router.get("/{incident_id}", summary="Incident detail")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    rs = db.query(RiskScore).filter(RiskScore.incident_id == incident_id).first()
    ba = db.query(BobAnalysis).filter(BobAnalysis.incident_id == incident_id).first()
    bs = db.query(BlufSummary).filter(BlufSummary.incident_id == incident_id).first()

    links = db.query(IncidentAlert).filter(IncidentAlert.incident_id == incident_id).order_by(IncidentAlert.sequence_number).all()
    alert_ids = [l.normalised_alert_id for l in links]
    alerts = db.query(NormalisedAlert).filter(NormalisedAlert.id.in_(alert_ids)).all()
    mitre = get_incident_mitre_summary(db, incident_id)

    return {
        **_incident_summary(inc, rs, ba),
        "correlation_reason": inc.correlation_reason,
        "auto_classification_reason": inc.auto_classification_reason,
        "member_alerts": [_alert_brief(a) for a in alerts],
        "mitre_summary": mitre,
        "bluf_summary": _bluf_dict(bs) if bs else None,
        "bob_analysis": _ba_dict(ba) if ba else None,
    }


@router.get("/{incident_id}/classification", summary="Side-by-side classification comparison")
def get_classification(incident_id: str, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    ba = db.query(BobAnalysis).filter(BobAnalysis.incident_id == incident_id).first()
    return {
        "incident_id": incident_id,
        "automated": {
            "classification": inc.auto_classification,
            "reason": inc.auto_classification_reason,
            "fired_rule": inc.fired_correlation_rule,
        },
        "bob": _ba_dict(ba) if ba else None,
        "agreement_status": ba.agreement_status if ba else "NOT_ANALYSED",
    }


@router.get("/{incident_id}/graph", summary="Correlation graph")
def get_graph(incident_id: str, db: Session = Depends(get_db)):
    return tool_get_correlation_graph(db, incident_id)


@router.patch("/{incident_id}/status", summary="Update incident status")
def update_status(incident_id: str, status: str, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    allowed = ["OPEN", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"]
    if status.upper() not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of {allowed}")
    inc.status = status.upper()
    db.commit()
    return {"id": incident_id, "status": inc.status}


# --- Helpers ----------------------------------------------------------------

def _incident_summary(inc: Incident, rs, ba) -> dict:
    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "overall_severity": inc.overall_severity,
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "affected_assets": list(inc.affected_assets or []),
        "source_types_involved": list(inc.source_types_involved or []),
        "fired_correlation_rule": inc.fired_correlation_rule,
        "auto_classification": inc.auto_classification,
        "risk_score": {
            "total_score": rs.total_score,
            "priority_label": rs.explanation.get("priority_label", ""),
            "explanation": rs.explanation,
        } if rs else None,
        "bob_analysis": {
            "bob_classification": ba.bob_classification,
            "bob_confidence": ba.bob_confidence,
            "agreement_status": ba.agreement_status,
        } if ba else None,
    }


def _alert_brief(a: NormalisedAlert) -> dict:
    return {
        "id": a.id,
        "source_type": a.source_type,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "confidence": a.confidence,
        "timestamp": a.timestamp.isoformat(),
        "target_asset": a.target_asset,
        "is_false_positive": a.is_false_positive,
        "fp_reason": a.fp_reason,
    }


def _ba_dict(ba: BobAnalysis) -> dict:
    return {
        "bob_classification": ba.bob_classification,
        "bob_confidence": ba.bob_confidence,
        "bob_reasoning": ba.bob_reasoning,
        "score_explanation_text": ba.score_explanation_text,
        "correlation_review_text": ba.correlation_review_text,
        "agreement_status": ba.agreement_status,
        "agreement_detail": ba.agreement_detail,
        "analysed_at": ba.analysed_at.isoformat(),
    }


def _bluf_dict(bs: BlufSummary) -> dict:
    return {
        "bluf_line": bs.bluf_line,
        "situation": bs.situation,
        "assessment": bs.assessment,
        "recommendations": bs.recommendations,
        "full_text": bs.full_text,
        "generated_at": bs.generated_at.isoformat(),
    }
