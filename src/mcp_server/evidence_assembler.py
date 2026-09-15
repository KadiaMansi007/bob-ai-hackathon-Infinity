"""
Evidence assembler — gathers all Layer-1 evidence for an incident into a
single structured dict that is passed to IBM Bob via MCP tools.

This is the only place Bob's input is assembled. By centralising it here,
we prevent prompt drift and ensure Bob can only reference evidence that
actually exists in the database.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from backend.models import (
    Incident, IncidentAlert, NormalisedAlert, RiskScore, BobAnalysis
)
from backend.mitre.incident_summary import get_incident_mitre_summary


def assemble_evidence(session: Session, incident_id: str) -> dict[str, Any]:
    """
    Assemble all Layer-1 evidence for one incident.

    Returns a dict with keys:
      incident_json, score_explanation_json, fired_rule_id, correlation_reason,
      mitre_summary_json, alerts_summary_json, auto_classification,
      auto_classification_reason, total_score
    """
    incident = session.get(Incident, incident_id)
    if not incident:
        raise ValueError(f"Incident {incident_id!r} not found")

    # Risk score
    risk_score = (
        session.query(RiskScore)
        .filter(RiskScore.incident_id == incident_id)
        .first()
    )

    # Member alerts
    links = (
        session.query(IncidentAlert)
        .filter(IncidentAlert.incident_id == incident_id)
        .order_by(IncidentAlert.sequence_number)
        .all()
    )
    alert_ids = [l.normalised_alert_id for l in links]
    alerts = (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.id.in_(alert_ids))
        .all()
    )

    # MITRE summary
    mitre = get_incident_mitre_summary(session, incident_id)

    # Incident dict (safe, no raw payload)
    incident_dict = {
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "overall_severity": incident.overall_severity,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "affected_assets": list(incident.affected_assets or []),
        "source_types_involved": list(incident.source_types_involved or []),
        "fired_correlation_rule": incident.fired_correlation_rule,
        "correlation_reason": incident.correlation_reason,
        "auto_classification": incident.auto_classification,
        "auto_classification_reason": incident.auto_classification_reason,
        "alert_count": len(alert_ids),
    }

    # Alert summaries (omit raw_payload to keep prompt focused)
    alerts_summary = [
        {
            "id": a.id,
            "source_type": a.source_type,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "timestamp": a.timestamp.isoformat(),
            "target_asset": a.target_asset,
            "geo_location": a.geo_location,
            "description": a.description,
            "is_false_positive": a.is_false_positive,
            "fp_reason": a.fp_reason,
        }
        for a in alerts
    ]

    score_dict = risk_score.explanation if risk_score else {}
    total_score = risk_score.total_score if risk_score else 0.0

    return {
        "incident_json": json.dumps(incident_dict, default=str),
        "score_explanation_json": json.dumps(score_dict, default=str),
        "fired_rule_id": incident.fired_correlation_rule or "C0",
        "correlation_reason": incident.correlation_reason or "",
        "mitre_summary_json": json.dumps(mitre.get("tactic_summary", {}), default=str),
        "alerts_summary_json": json.dumps(alerts_summary, default=str),
        "auto_classification": incident.auto_classification,
        "auto_classification_reason": incident.auto_classification_reason,
        "total_score": total_score,
    }


def get_bob_analysis_dict(session: Session, incident_id: str) -> dict | None:
    ba = (
        session.query(BobAnalysis)
        .filter(BobAnalysis.incident_id == incident_id)
        .first()
    )
    if not ba:
        return None
    return {
        "bob_classification": ba.bob_classification,
        "bob_confidence": ba.bob_confidence,
        "bob_reasoning": ba.bob_reasoning,
        "score_explanation_text": ba.score_explanation_text,
        "correlation_review_text": ba.correlation_review_text,
        "agreement_status": ba.agreement_status,
        "agreement_detail": ba.agreement_detail,
    }
