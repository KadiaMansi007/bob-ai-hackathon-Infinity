"""
Correlation engine — main entry point.

For each NormalisedAlert:
1. Evaluate rules C6→C5→C0 (priority order)
2. Find or create an Incident
3. Return the Incident
"""
from __future__ import annotations

import logging
from sqlalchemy.orm import Session

from backend.models import NormalisedAlert, Incident
from backend.correlation.rules import evaluate_rules, match_c6
from backend.correlation.incident_builder import (
    create_incident, extend_incident, find_open_incident_for_asset
)

log = logging.getLogger(__name__)


def correlate(session: Session, alert: NormalisedAlert) -> Incident:
    """
    Correlate a NormalisedAlert into an Incident.

    Finds an existing open incident to extend, or creates a new one.
    The fired correlation rule ID is stored on the incident.
    Returns the Incident (flushed, not committed).
    """
    if alert.is_false_positive:
        # FP alerts: run C6 FIRST — attacker may be masking behind FP thresholds
        c6_result = match_c6(session, alert)
        if c6_result.matched:
            log.info(
                "Rule C6 fired on FP alert %s — FP masking detected: %s",
                alert.id, c6_result.reason
            )
            existing = find_open_incident_for_asset(session, alert.target_asset)
            if existing:
                existing.fired_correlation_rule = "C6"
                existing.correlation_reason = c6_result.reason
                existing.fp_masking_warning = True
                return extend_incident(session, existing, alert)
            inc = create_incident(session, alert, "C6", c6_result.reason)
            inc.fp_masking_warning = True
            return inc

        # Normal FP — not masking, just genuine noise
        existing = find_open_incident_for_asset(session, alert.target_asset)
        if existing:
            return extend_incident(session, existing, alert)
        return create_incident(session, alert, "C0", "False positive singleton.")

    # Evaluate rules in priority order
    result = evaluate_rules(session, alert)

    # Try to find an existing open incident for the same asset
    existing = find_open_incident_for_asset(session, alert.target_asset)

    if existing and result.matched:
        log.debug(
            "Rule %s fired — extending existing incident %s",
            result.rule_id, existing.id
        )
        # Update correlation reason and rule if the new rule is higher priority
        rule_priority = {"C5": 5, "C4": 4, "C3": 3, "C2": 2, "C1": 1, "C0": 0}
        existing_priority = rule_priority.get(existing.fired_correlation_rule or "C0", 0)
        new_priority = rule_priority.get(result.rule_id, 0)
        if new_priority > existing_priority:
            existing.fired_correlation_rule = result.rule_id
            existing.correlation_reason = result.reason
        return extend_incident(session, existing, alert)

    if existing and not result.matched:
        return extend_incident(session, existing, alert)

    if result.matched:
        log.debug("Rule %s fired — creating new incident", result.rule_id)
        return create_incident(session, alert, result.rule_id, result.reason)

    # No match and no existing incident — create singleton
    return create_incident(session, alert, "C0", "Singleton: no rule matched.")
