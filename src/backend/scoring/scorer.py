"""
Risk scoring engine — computes and persists an explainable RiskScore for an Incident.

Formula (weights from the plan):
  total_score = (
      severity_component      × 0.35
    + confidence_component    × 0.25
    + source_diversity        × 0.20
    + asset_criticality       × 0.10
    + temporal_recency        × 0.10
  ) clamped to [0, 100]

Each component is stored as a separate column so the UI and Bob can
narrate each element individually.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

from backend.models import (
    Incident, IncidentAlert, NormalisedAlert, RiskScore, Severity
)
from backend.scoring.asset_registry import get_asset_criticality

log = logging.getLogger(__name__)

# Component weights
W_SEVERITY   = 0.35
W_CONFIDENCE = 0.25
W_DIVERSITY  = 0.20
W_CRITICALITY = 0.10
W_TEMPORAL   = 0.10

_SEVERITY_SCORES = {
    Severity.CRITICAL.value: 100.0,
    Severity.HIGH.value:      75.0,
    Severity.MEDIUM.value:    50.0,
    Severity.LOW.value:       25.0,
}

_PRIORITY_LABELS = [
    (80, "P1 — Immediate Action"),
    (60, "P2 — Investigate Today"),
    (40, "P3 — Monitor Closely"),
    ( 0, "P4 — Low Priority"),
]


def _priority_label(score: float) -> str:
    for threshold, label in _PRIORITY_LABELS:
        if score >= threshold:
            return label
    return "P4 — Low Priority"


def _calc_severity(alerts: list[NormalisedAlert]) -> tuple[float, str]:
    """Max severity of member alerts → 0–100."""
    if not alerts:
        return 25.0, "No alerts"
    max_sev = max(_SEVERITY_SCORES.get(a.severity, 50.0) for a in alerts)
    sev_name = next(
        (a.severity for a in alerts
         if _SEVERITY_SCORES.get(a.severity, 0) == max_sev), "MEDIUM"
    )
    return max_sev, f"{sev_name} alert present (score={max_sev:.0f})"


def _calc_confidence(alerts: list[NormalisedAlert]) -> tuple[float, str]:
    """Mean confidence of non-FP member alerts → 0–100."""
    non_fp = [a for a in alerts if not a.is_false_positive]
    if not non_fp:
        return 25.0, "All alerts are FP candidates"
    mean_conf = sum(a.confidence for a in non_fp) / len(non_fp)
    raw = mean_conf * 100.0
    return raw, f"Mean confidence {mean_conf:.2f} across {len(non_fp)} alert(s)"


def _calc_diversity(alerts: list[NormalisedAlert]) -> tuple[float, str]:
    """(Unique source types / 4) × 100."""
    sources = {a.source_type for a in alerts if not a.is_false_positive}
    raw = (len(sources) / 4.0) * 100.0
    return raw, f"{len(sources)} of 4 source type(s): {', '.join(sorted(sources))}"


def _calc_criticality(incident: Incident) -> tuple[float, str]:
    """Asset criticality from registry."""
    assets = list(incident.affected_assets or [])
    if not assets:
        return 50.0, "No known assets"
    max_crit = max(get_asset_criticality(a) for a in assets)
    label = "critical asset" if max_crit >= 100 else "standard asset"
    return max_crit, f"Highest criticality asset: {label} ({max_crit:.0f})"


def _calc_temporal(incident: Incident) -> tuple[float, str]:
    """Recency score: last_seen within 1h=100, 24h=50, >24h=10."""
    now = datetime.now(timezone.utc)
    last = incident.last_seen
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age = now - last
    if age <= timedelta(hours=1):
        raw = 100.0
        label = f"last seen {age.seconds//60}min ago"
    elif age <= timedelta(hours=24):
        frac = 1.0 - (age.total_seconds() / 86400.0)
        raw = 10.0 + 40.0 * frac
        label = f"last seen {age.seconds//3600}h ago"
    else:
        raw = 10.0
        label = f"last seen >24h ago"
    return raw, label


def score_incident(session: Session, incident: Incident) -> RiskScore:
    """
    Compute and persist (or replace) the RiskScore for an incident.

    Returns the new RiskScore (flushed, not committed).
    """
    # Load member alerts
    links = (
        session.query(IncidentAlert)
        .filter(IncidentAlert.incident_id == incident.id)
        .all()
    )
    alert_ids = [lnk.normalised_alert_id for lnk in links]
    alerts = (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.id.in_(alert_ids))
        .all()
    )

    # Compute components
    sev_raw,  sev_reason  = _calc_severity(alerts)
    conf_raw, conf_reason = _calc_confidence(alerts)
    div_raw,  div_reason  = _calc_diversity(alerts)
    crit_raw, crit_reason = _calc_criticality(incident)
    temp_raw, temp_reason = _calc_temporal(incident)

    sev_val  = sev_raw  * W_SEVERITY
    conf_val = conf_raw * W_CONFIDENCE
    div_val  = div_raw  * W_DIVERSITY
    crit_val = crit_raw * W_CRITICALITY
    temp_val = temp_raw * W_TEMPORAL

    total = min(100.0, max(0.0, sev_val + conf_val + div_val + crit_val + temp_val))

    explanation: dict[str, Any] = {
        "total_score": round(total, 2),
        "priority_label": _priority_label(total),
        "components": {
            "severity": {
                "value": round(sev_val, 2),
                "weight": W_SEVERITY,
                "raw": round(sev_raw, 2),
                "reason": sev_reason,
            },
            "confidence": {
                "value": round(conf_val, 2),
                "weight": W_CONFIDENCE,
                "raw": round(conf_raw, 2),
                "reason": conf_reason,
            },
            "source_diversity": {
                "value": round(div_val, 2),
                "weight": W_DIVERSITY,
                "raw": round(div_raw, 2),
                "reason": div_reason,
            },
            "asset_criticality": {
                "value": round(crit_val, 2),
                "weight": W_CRITICALITY,
                "raw": round(crit_raw, 2),
                "reason": crit_reason,
            },
            "temporal_recency": {
                "value": round(temp_val, 2),
                "weight": W_TEMPORAL,
                "raw": round(temp_raw, 2),
                "reason": temp_reason,
            },
        },
    }

    # Delete existing score if present
    existing = (
        session.query(RiskScore)
        .filter(RiskScore.incident_id == incident.id)
        .first()
    )
    if existing:
        session.delete(existing)
        session.flush()

    rs = RiskScore(
        incident_id=incident.id,
        total_score=round(total, 2),
        severity_component=round(sev_val, 2),
        confidence_component=round(conf_val, 2),
        source_diversity_component=round(div_val, 2),
        asset_criticality_component=round(crit_val, 2),
        temporal_component=round(temp_val, 2),
        explanation=explanation,
    )
    session.add(rs)
    session.flush()
    log.debug("Scored incident %s: %.1f (%s)", incident.id, total, _priority_label(total))
    return rs
