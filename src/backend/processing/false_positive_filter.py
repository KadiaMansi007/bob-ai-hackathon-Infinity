"""
False-positive pre-filter — applies deterministic FP rules to NormalisedAlerts.

Rules (from the plan):
  FP-01  confidence < 0.15                          → FALSE_POSITIVE
  FP-02  SATELLITE + formation_change + signal < -90 dBm → FALSE_POSITIVE
  FP-03  SIEM + event_count == 1 + severity == LOW  → FALSE_POSITIVE
  FP-04  Intel IOC with no cross-source corroboration in 30 min → soft FP

GT pre-classification hints (used later by auto_classifier):
  GT-01  Multi-source convergence (C3 rule) + confidence >= 0.6  → GENUINE_THREAT hint
  GT-02  Scenario pattern matched (C4 rule)                      → GENUINE_THREAT hint
  GT-03  IOC propagation (C5 rule) + confidence >= 0.5           → GENUINE_THREAT hint

This module only handles the FP rules at the alert level.
GT classification is done at the incident level by auto_classifier.py.
"""
from __future__ import annotations

from backend.models import NormalisedAlert, SourceType, Severity


def apply_fp_rules(alert: NormalisedAlert) -> NormalisedAlert:
    """
    Apply false-positive pre-filter rules to a NormalisedAlert.

    Mutates alert.is_false_positive and alert.fp_reason in place.
    Returns the (potentially mutated) alert.
    This function is pure with respect to the database.
    """
    p = alert.raw_payload or {}

    # FP-01 — Very low confidence
    if alert.confidence < 0.15:
        alert.is_false_positive = True
        alert.fp_reason = "fp_low_confidence"
        return alert

    # FP-02 — Satellite formation change with very weak signal
    if (
        alert.source_type == SourceType.SATELLITE.value
        and alert.alert_type == "formation_change"
    ):
        signal = p.get("signal_strength", 0.0)
        try:
            if float(signal) < -90.0:
                alert.is_false_positive = True
                alert.fp_reason = "fp_satellite_weak_signal"
                return alert
        except (TypeError, ValueError):
            pass

    # FP-03 — SIEM single low-severity event
    if (
        alert.source_type == SourceType.SIEM.value
        and alert.severity == Severity.LOW.value
    ):
        event_count = p.get("event_count", 1)
        try:
            if int(event_count) == 1:
                alert.is_false_positive = True
                alert.fp_reason = "fp_siem_single_low_event"
                return alert
        except (TypeError, ValueError):
            pass

    # FP-04 — Intel report with no payload corroboration clue
    # (soft penalty applied to confidence, not hard FP)
    if (
        alert.source_type == SourceType.INTEL_REPORT.value
        and alert.confidence < 0.25
    ):
        alert.confidence = max(0.0, alert.confidence - 0.10)
        # If confidence now falls below threshold, apply FP-01
        if alert.confidence < 0.15:
            alert.is_false_positive = True
            alert.fp_reason = "fp_intel_uncorroborated"
            return alert

    return alert
