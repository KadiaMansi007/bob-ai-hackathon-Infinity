"""
MCP tools — the service layer that routes Bob tool calls to data and AI operations.

These functions are called from the FastAPI routers (bob.py).
They are also what the MCP server exposes to IBM Bob as callable tools.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models import (
    BobAnalysis, BlufSummary, Incident, IncidentAlert,
    NormalisedAlert, RiskScore, AgreementStatus, BobClassification, AutoClassification
)
from backend.mitre.incident_summary import get_incident_mitre_summary
from backend.mitre.mapper import map_alert
from mcp_server.evidence_assembler import assemble_evidence, get_bob_analysis_dict
from mcp_server.bob_client import call_bob_analyse, call_bob_bluf

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data-retrieval tools (pure reads, no Bob calls)
# ---------------------------------------------------------------------------

def tool_get_incident_details(session: Session, incident_id: str) -> dict:
    inc = session.get(Incident, incident_id)
    if not inc:
        return {"error": f"Incident {incident_id!r} not found"}
    rs = session.query(RiskScore).filter(RiskScore.incident_id == incident_id).first()
    ba = session.query(BobAnalysis).filter(BobAnalysis.incident_id == incident_id).first()
    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "overall_severity": inc.overall_severity,
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "affected_assets": list(inc.affected_assets or []),
        "source_types_involved": list(inc.source_types_involved or []),
        "correlation_reason": inc.correlation_reason,
        "fired_correlation_rule": inc.fired_correlation_rule,
        "auto_classification": inc.auto_classification,
        "auto_classification_reason": inc.auto_classification_reason,
        "risk_score": rs.explanation if rs else None,
        "bob_analysis": {
            "bob_classification": ba.bob_classification,
            "bob_confidence": ba.bob_confidence,
            "agreement_status": ba.agreement_status,
        } if ba else None,
    }


def tool_get_risk_score_explanation(session: Session, incident_id: str) -> dict:
    rs = session.query(RiskScore).filter(RiskScore.incident_id == incident_id).first()
    if not rs:
        return {"error": "No risk score found"}
    return rs.explanation


def tool_get_mitre_summary(session: Session, incident_id: str) -> dict:
    return get_incident_mitre_summary(session, incident_id)


def tool_get_correlation_graph(session: Session, incident_id: str) -> dict:
    links = (
        session.query(IncidentAlert)
        .filter(IncidentAlert.incident_id == incident_id)
        .all()
    )
    alert_ids = [l.normalised_alert_id for l in links]
    alerts = (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.id.in_(alert_ids))
        .all()
    )
    nodes = [{"id": "incident", "type": "incident", "label": incident_id[:8]}]
    edges = []
    for a in alerts:
        nodes.append({
            "id": a.id,
            "type": "alert",
            "source_type": a.source_type,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "label": f"{a.source_type}/{a.alert_type}",
        })
        edges.append({"from": "incident", "to": a.id, "label": a.alert_type})
    return {"nodes": nodes, "edges": edges}


def tool_list_open_incidents(session: Session, limit: int = 10) -> list[dict]:
    from backend.models import IncidentStatus
    incidents = (
        session.query(Incident)
        .filter(Incident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]))
        .order_by(Incident.last_seen.desc())
        .limit(limit)
        .all()
    )
    result = []
    for inc in incidents:
        rs = session.query(RiskScore).filter(RiskScore.incident_id == inc.id).first()
        result.append({
            "id": inc.id,
            "title": inc.title,
            "auto_classification": inc.auto_classification,
            "fired_correlation_rule": inc.fired_correlation_rule,
            "overall_severity": inc.overall_severity,
            "total_score": rs.total_score if rs else None,
        })
    return result


# ---------------------------------------------------------------------------
# AI tools (call Bob, write to DB)
# ---------------------------------------------------------------------------

def tool_analyse_incident(session: Session, incident_id: str) -> dict:
    """
    Orchestrate Bob's full analysis of one incident.

    Assembles evidence → calls Bob → parses response → computes agreement_status
    → persists BobAnalysis → returns the record.
    """
    evidence = assemble_evidence(session, incident_id)

    # Call Bob (or mock)
    response = call_bob_analyse(evidence)

    # Parse and validate required fields
    bob_class = response.get("bob_classification", "GENUINE_THREAT")
    if bob_class not in ("GENUINE_THREAT", "FALSE_POSITIVE"):
        bob_class = "GENUINE_THREAT"

    bob_conf = float(response.get("bob_confidence", 0.75))
    bob_conf = max(0.0, min(1.0, bob_conf))

    agree_raw = response.get("agreement_status", "AGREES")
    if agree_raw not in ("AGREES", "DISAGREES", "PARTIAL"):
        # Compute from classification comparison
        auto = evidence["auto_classification"]
        if auto == "UNCLASSIFIED":
            agree_raw = "PARTIAL"
        elif bob_class == auto:
            agree_raw = "AGREES"
        else:
            agree_raw = "DISAGREES"

    # Delete existing analysis if present
    existing = session.query(BobAnalysis).filter(BobAnalysis.incident_id == incident_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    ba = BobAnalysis(
        incident_id=incident_id,
        bob_classification=bob_class,
        bob_confidence=bob_conf,
        bob_reasoning=response.get("bob_reasoning", ""),
        score_explanation_text=response.get("score_explanation_text", ""),
        correlation_review_text=response.get("correlation_review_text", ""),
        agreement_status=agree_raw,
        agreement_detail=response.get("agreement_detail", ""),
        bob_model_version=os.getenv("BOB_MODEL", "ibm/granite-mock"),
    )
    session.add(ba)
    session.flush()

    log.info(
        "Bob analysis for incident %s: %s (confidence=%.2f, agreement=%s)",
        incident_id[:8], bob_class, bob_conf, agree_raw
    )
    return {
        "id": ba.id,
        "incident_id": ba.incident_id,
        "bob_classification": ba.bob_classification,
        "bob_confidence": ba.bob_confidence,
        "bob_reasoning": ba.bob_reasoning,
        "score_explanation_text": ba.score_explanation_text,
        "correlation_review_text": ba.correlation_review_text,
        "agreement_status": ba.agreement_status,
        "agreement_detail": ba.agreement_detail,
        "analysed_at": ba.analysed_at.isoformat(),
        "bob_model_version": ba.bob_model_version,
    }


def tool_generate_bluf(session: Session, incident_id: str) -> dict:
    """Generate and persist a BLUF summary for an incident."""
    evidence = assemble_evidence(session, incident_id)
    bob_analysis = get_bob_analysis_dict(session, incident_id)

    bluf_response = call_bob_bluf(evidence, bob_analysis)

    bluf_line = bluf_response.get("bluf_line", "")
    situation = bluf_response.get("situation", "")
    assessment = bluf_response.get("assessment", "")
    recommendations = bluf_response.get("recommendations", "")
    full_text = (
        f"BLUF: {bluf_line}\n\n"
        f"SITUATION: {situation}\n\n"
        f"ASSESSMENT: {assessment}\n\n"
        f"RECOMMENDATIONS:\n{recommendations}"
    )

    # Delete existing BLUF
    existing = session.query(BlufSummary).filter(BlufSummary.incident_id == incident_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    bs = BlufSummary(
        incident_id=incident_id,
        bluf_line=bluf_line,
        situation=situation,
        assessment=assessment,
        recommendations=recommendations,
        full_text=full_text,
    )
    session.add(bs)
    session.flush()

    return {
        "id": bs.id,
        "incident_id": bs.incident_id,
        "bluf_line": bs.bluf_line,
        "situation": bs.situation,
        "assessment": bs.assessment,
        "recommendations": bs.recommendations,
        "full_text": bs.full_text,
        "generated_at": bs.generated_at.isoformat(),
    }


import os  # noqa: E402 — placed here to avoid circular import in mocks above
