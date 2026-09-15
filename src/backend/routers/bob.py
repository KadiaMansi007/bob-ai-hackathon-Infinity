"""FastAPI route handlers for IBM Bob operations."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import BobAnalysis, BlufSummary
from mcp_server.tools import tool_analyse_incident, tool_generate_bluf

router = APIRouter(prefix="/bob", tags=["bob"])


@router.post("/analyse/{incident_id}", summary="Trigger Bob AI analysis for an incident")
def analyse_incident(incident_id: str, db: Session = Depends(get_db)):
    """Ask Bob to classify the incident, explain the risk score, review the correlation rule,
    and produce an agreement verdict vs the automated classification."""
    try:
        result = tool_analyse_incident(db, incident_id)
        db.commit()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Bob analysis failed: {exc}")


@router.get("/analysis/{incident_id}", summary="Get stored Bob analysis for an incident")
def get_analysis(incident_id: str, db: Session = Depends(get_db)):
    ba = db.query(BobAnalysis).filter(BobAnalysis.incident_id == incident_id).first()
    if not ba:
        raise HTTPException(status_code=404, detail="No Bob analysis found. Run POST /bob/analyse/{id} first.")
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


@router.post("/bluf/{incident_id}", summary="Generate Bob BLUF summary for an incident")
def generate_bluf(incident_id: str, db: Session = Depends(get_db)):
    try:
        result = tool_generate_bluf(db, incident_id)
        db.commit()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"BLUF generation failed: {exc}")


@router.get("/bluf/{incident_id}", summary="Get stored BLUF summary for an incident")
def get_bluf(incident_id: str, db: Session = Depends(get_db)):
    bs = db.query(BlufSummary).filter(BlufSummary.incident_id == incident_id).first()
    if not bs:
        raise HTTPException(status_code=404, detail="No BLUF found. Run POST /bob/bluf/{id} first.")
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
