"""
Automated classifier — sets auto_classification on an Incident.

This is a deterministic, rule-based classifier.  It runs AFTER the
correlation engine has created/updated the incident and after MITRE
mapping is complete.  It reads the incident's member alerts and the
fired correlation rule to determine:

  GENUINE_THREAT  — strong evidence of malicious activity
  FALSE_POSITIVE  — all member alerts are FP-flagged
  UNCLASSIFIED    — insufficient evidence for a verdict

Classification rules (from the plan):
  FP-path  All member alerts are false positives → FALSE_POSITIVE
  GT-01    Fired rule is C2 (known actor IOC)    → GENUINE_THREAT
  GT-02    Fired rule is C5 (kill-chain)         → GENUINE_THREAT
  GT-03    Fired rule is C0/C1/C3/C4 AND no member alerts are FP
           AND at least 2 different source types → GENUINE_THREAT
  Default  Everything else                       → UNCLASSIFIED
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.models import AutoClassification, Incident, IncidentAlert, NormalisedAlert


def classify_incident(session: Session, incident: Incident) -> Incident:
    """
    Set auto_classification and auto_classification_reason on an Incident.

    Mutates the incident in place.  Caller is responsible for flush/commit.
    """
    # Load member alerts
    links = (
        session.query(IncidentAlert)
        .filter(IncidentAlert.incident_id == incident.id)
        .all()
    )
    if not links:
        incident.auto_classification = AutoClassification.UNCLASSIFIED.value
        incident.auto_classification_reason = "unclassified_no_member_alerts"
        return incident

    alert_ids = [lnk.normalised_alert_id for lnk in links]
    alerts = (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.id.in_(alert_ids))
        .all()
    )

    # --- FP path: all alerts are false positives -------------------------
    if all(a.is_false_positive for a in alerts):
        incident.auto_classification = AutoClassification.FALSE_POSITIVE.value
        incident.auto_classification_reason = (
            f"All {len(alerts)} member alert(s) flagged as false positive by "
            f"pre-filter rules: "
            + ", ".join({a.fp_reason or "unknown" for a in alerts})
        )
        return incident

    rule = incident.fired_correlation_rule or "C0"

    # --- GT-01: IOC-based correlation ------------------------------------
    if rule == "C2":
        incident.auto_classification = AutoClassification.GENUINE_THREAT.value
        incident.auto_classification_reason = (
            "gt_ioc_cross_source_propagation: Correlation rule C2 (Known actor IOC match) "
            "fired — intelligence report IOC corroborated by active alert evidence."
        )
        return incident

    # --- GT-02: Kill-chain pattern ----------------------------------------
    if rule == "C5":
        incident.auto_classification = AutoClassification.GENUINE_THREAT.value
        incident.auto_classification_reason = (
            "gt_scenario_pattern_match: Correlation rule C5 (Kill-chain tactic progression) "
            "fired — sequential MITRE tactic stages observed."
        )
        return incident

    # --- GT-03: Multi-source convergence ---------------------------------
    non_fp_alerts = [a for a in alerts if not a.is_false_positive]
    unique_sources = {a.source_type for a in non_fp_alerts}
    if rule in ("C0", "C1", "C3", "C4") and len(unique_sources) >= 2:
        incident.auto_classification = AutoClassification.GENUINE_THREAT.value
        incident.auto_classification_reason = (
            f"gt_multi_source_convergence: Correlation rule {rule} fired with "
            f"{len(unique_sources)} distinct source type(s) "
            f"({', '.join(sorted(unique_sources))}) and no FP-flagged members."
        )
        return incident

    # --- Default: unclassified -------------------------------------------
    incident.auto_classification = AutoClassification.UNCLASSIFIED.value
    incident.auto_classification_reason = (
        f"unclassified_insufficient_evidence: Rule {rule} fired but only "
        f"{len(unique_sources)} source type(s) present or some alerts are FP candidates."
    )
    return incident
