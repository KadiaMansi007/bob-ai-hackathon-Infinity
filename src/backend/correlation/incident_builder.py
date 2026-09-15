"""
Incident builder — creates and extends Incident records.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models import (
    Incident, IncidentAlert, NormalisedAlert, Severity, IncidentStatus, AutoClassification
)


def _severity_rank(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)


def create_incident(
    session: Session,
    alert: NormalisedAlert,
    fired_rule_id: str,
    correlation_reason: str,
) -> Incident:
    """Create a new Incident from a triggering alert."""
    title = _generate_title(alert, fired_rule_id)
    incident = Incident(
        title=title,
        status=IncidentStatus.OPEN.value,
        overall_severity=alert.severity,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
        affected_assets=[alert.target_asset],
        source_types_involved=[alert.source_type],
        correlation_reason=correlation_reason,
        fired_correlation_rule=fired_rule_id,
        auto_classification=AutoClassification.UNCLASSIFIED.value,
        auto_classification_reason="pending",
    )
    session.add(incident)
    session.flush()

    link = IncidentAlert(
        incident_id=incident.id,
        normalised_alert_id=alert.id,
        sequence_number=1,
    )
    session.add(link)
    session.flush()

    return incident


def extend_incident(
    session: Session,
    incident: Incident,
    alert: NormalisedAlert,
) -> Incident:
    """Add a new alert to an existing incident, updating severity and timestamps."""
    # Update severity (roll up to max)
    if _severity_rank(alert.severity) > _severity_rank(incident.overall_severity):
        incident.overall_severity = alert.severity

    # Update timestamps
    if alert.timestamp < incident.first_seen:
        incident.first_seen = alert.timestamp
    if alert.timestamp > incident.last_seen:
        incident.last_seen = alert.timestamp

    # Update affected assets
    assets: list = list(incident.affected_assets or [])
    if alert.target_asset not in assets:
        assets.append(alert.target_asset)
    incident.affected_assets = assets

    # Update source types
    sources: list = list(incident.source_types_involved or [])
    if alert.source_type not in sources:
        sources.append(alert.source_type)
    incident.source_types_involved = sources

    incident.updated_at = datetime.now(timezone.utc)

    # Determine next sequence number
    from sqlalchemy import func
    max_seq = (
        session.query(func.max(IncidentAlert.sequence_number))
        .filter(IncidentAlert.incident_id == incident.id)
        .scalar()
    ) or 0
    link = IncidentAlert(
        incident_id=incident.id,
        normalised_alert_id=alert.id,
        sequence_number=max_seq + 1,
    )
    session.add(link)
    session.flush()

    return incident


def _generate_title(alert: NormalisedAlert, rule_id: str) -> str:
    rule_names = {
        "C0": "Regional Alert Cluster",
        "C1": "SIEM-Sensor IP Correlation",
        "C2": "Known Actor IOC Match",
        "C3": "Multi-Source Convergence",
        "C4": "Volume-Based Escalation",
        "C5": "Kill-Chain Pattern",
    }
    rule_name = rule_names.get(rule_id, "Correlated Incident")
    return f"{rule_name} — {alert.target_asset} [{alert.alert_type}]"


def find_open_incident_for_asset(
    session: Session, target_asset: str
) -> Incident | None:
    """Find an open incident that already includes the given target asset."""
    all_open = (
        session.query(Incident)
        .filter(Incident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]))
        .all()
    )
    for inc in all_open:
        if target_asset in (inc.affected_assets or []):
            return inc
    return None
