"""FastAPI route handlers for alerts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import NormalisedAlert, MitreMapping

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", summary="List normalised alerts")
def list_alerts(
    page: int = 1,
    page_size: int = 20,
    severity: str | None = None,
    source_type: str | None = None,
    is_false_positive: bool | None = None,
    fp_masking_suspected: bool | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(NormalisedAlert)
    if severity:
        q = q.filter(NormalisedAlert.severity == severity.upper())
    if source_type:
        q = q.filter(NormalisedAlert.source_type == source_type.upper())
    if is_false_positive is not None:
        q = q.filter(NormalisedAlert.is_false_positive == is_false_positive)
    if fp_masking_suspected is not None:
        q = q.filter(NormalisedAlert.fp_masking_suspected == fp_masking_suspected)
    total = q.count()
    alerts = q.order_by(NormalisedAlert.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_alert_summary(a) for a in alerts],
    }


@router.get("/{alert_id}", summary="Alert detail with MITRE mappings")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.get(NormalisedAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    mappings = db.query(MitreMapping).filter(MitreMapping.normalised_alert_id == alert_id).all()
    return {
        **_alert_summary(alert),
        "description": alert.description,
        "raw_payload": alert.raw_payload,
        "fingerprint": alert.fingerprint,
        "mitre_mappings": [_mitre_dict(m) for m in mappings],
    }


@router.patch("/{alert_id}/fp", summary="Manually mark alert as false positive")
def mark_false_positive(alert_id: str, fp_reason: str = "manual_override", db: Session = Depends(get_db)):
    alert = db.get(NormalisedAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_false_positive = True
    alert.fp_reason = fp_reason
    db.commit()
    return {"id": alert_id, "is_false_positive": True, "fp_reason": fp_reason}


def _alert_summary(a: NormalisedAlert) -> dict:
    return {
        "id": a.id,
        "source_type": a.source_type,
        "source_name": a.source_name,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "confidence": a.confidence,
        "timestamp": a.timestamp.isoformat(),
        "target_asset": a.target_asset,
        "geo_location": a.geo_location,
        "is_false_positive": a.is_false_positive,
        "fp_reason": a.fp_reason,
        "fp_masking_suspected": getattr(a, 'fp_masking_suspected', False),
        "created_at": a.created_at.isoformat(),
    }


def _mitre_dict(m: MitreMapping) -> dict:
    return {
        "id": m.id,
        "tactic_id": m.tactic_id,
        "tactic_name": m.tactic_name,
        "technique_id": m.technique_id,
        "technique_name": m.technique_name,
        "subtechnique_id": m.subtechnique_id,
        "subtechnique_name": m.subtechnique_name,
        "confidence": m.confidence,
        "evidence_strings": m.evidence_strings or [],
        "mapping_method": m.mapping_method,
    }
