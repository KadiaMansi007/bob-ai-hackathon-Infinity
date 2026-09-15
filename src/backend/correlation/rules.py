"""
Correlation rules C0–C5 with match logic.

Each rule is a dataclass with a match() class method.
match() returns (matched: bool, reason: str).

Rules are evaluated in priority order: C5 → C4 → C3 → C2 → C1 → C0.
The first matching rule's ID is stored on the incident.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from backend.models import NormalisedAlert


@dataclass
class RuleResult:
    matched: bool
    rule_id: str
    reason: str


def _open_incidents_with_asset(session: Session, target_asset: str) -> list:
    """Return open incidents that contain the given target asset."""
    from backend.models import Incident, AutoClassification
    return (
        session.query(Incident)
        .filter(
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.affected_assets.contains(f'"{target_asset}"'),
        )
        .all()
    )


def _recent_alerts_window(
    session: Session,
    minutes: int,
    source_type: str | None = None,
    alert_type: str | None = None,
) -> list[NormalisedAlert]:
    """Return non-FP alerts from the last N minutes, optionally filtered."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    q = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
    )
    if source_type:
        q = q.filter(NormalisedAlert.source_type == source_type)
    if alert_type:
        q = q.filter(NormalisedAlert.alert_type == alert_type)
    return q.all()


# ---------------------------------------------------------------------------
# Rule C5 — Kill-chain tactic progression  (Recon → Cred/Initial → Exec/C2)
# ---------------------------------------------------------------------------
_KILLCHAIN_STAGES = [
    {"recon": ["ioc_match", "threat_actor_sighting", "port_scan"]},
    {"access": ["failed_login_burst", "vulnerability_exploitation", "lateral_movement"]},
    {"exec": ["c2_beacon", "dns_tunnelling", "malware_hash_match", "data_exfil"]},
]

def match_c5(session: Session, alert: NormalisedAlert) -> RuleResult:
    """Kill-chain: Recon → Access → Execution within 2 hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
    recent = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.target_asset == alert.target_asset,
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )
    seen_types = {a.alert_type for a in recent} | {alert.alert_type}
    stages_covered = 0
    for stage in _KILLCHAIN_STAGES:
        for types in stage.values():
            if seen_types & set(types):
                stages_covered += 1
                break
    if stages_covered >= 3:
        return RuleResult(
            True, "C5",
            f"Kill-chain pattern: {stages_covered}/3 stages observed on {alert.target_asset} "
            f"within 2h (types: {', '.join(sorted(seen_types))})"
        )
    return RuleResult(False, "C5", "")


# ---------------------------------------------------------------------------
# Rule C4 — Volume-based escalation (5+ high-severity from one source in 15 min)
# ---------------------------------------------------------------------------
def match_c4(session: Session, alert: NormalisedAlert) -> RuleResult:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
    count = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.source_type == alert.source_type,
            NormalisedAlert.severity.in_(["HIGH", "CRITICAL"]),
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .count()
    )
    if count >= 4:  # 4 existing + current = 5
        return RuleResult(
            True, "C4",
            f"Volume escalation: {count + 1} HIGH/CRITICAL alerts from {alert.source_type} "
            f"within 15 minutes."
        )
    return RuleResult(False, "C4", "")


# ---------------------------------------------------------------------------
# Rule C3 — Multi-source convergence (same asset, ≥2 source types, 30 min)
# ---------------------------------------------------------------------------
def match_c3(session: Session, alert: NormalisedAlert) -> RuleResult:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
    recent = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.target_asset == alert.target_asset,
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )
    sources = {a.source_type for a in recent} | {alert.source_type}
    if len(sources) >= 2:
        return RuleResult(
            True, "C3",
            f"Multi-source convergence: {len(sources)} source type(s) "
            f"({', '.join(sorted(sources))}) targeting {alert.target_asset} within 30 min."
        )
    return RuleResult(False, "C3", "")


# ---------------------------------------------------------------------------
# Rule C2 — Known actor IOC match
# ---------------------------------------------------------------------------
def match_c2(session: Session, alert: NormalisedAlert) -> RuleResult:
    if alert.source_type != "INTEL_REPORT":
        return RuleResult(False, "C2", "")
    ioc_value = alert.raw_payload.get("ioc_value") or alert.raw_payload.get("target_asset", "")
    if not ioc_value:
        return RuleResult(False, "C2", "")
    # Check if the IOC appears in any other recent alert's raw payload
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    recent = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.source_type != "INTEL_REPORT",
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )
    for a in recent:
        payload_str = str(a.raw_payload)
        if ioc_value in payload_str:
            actor = alert.raw_payload.get("actor_name", "unknown")
            return RuleResult(
                True, "C2",
                f"Known actor IOC match: IOC '{ioc_value}' (actor: {actor}) "
                f"found in {a.source_type} alert on {a.target_asset}."
            )
    return RuleResult(False, "C2", "")


# ---------------------------------------------------------------------------
# Rule C1 — SIEM + Sensor sharing same source IP within 10 minutes
# ---------------------------------------------------------------------------
def match_c1(session: Session, alert: NormalisedAlert) -> RuleResult:
    src_ip = alert.raw_payload.get("src_ip") or alert.raw_payload.get("dst_ip")
    if not src_ip:
        return RuleResult(False, "C1", "")
    partner_source = (
        "CYBER_SENSOR" if alert.source_type == "SIEM" else
        "SIEM" if alert.source_type == "CYBER_SENSOR" else None
    )
    if not partner_source:
        return RuleResult(False, "C1", "")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    partners = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.source_type == partner_source,
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )
    for p in partners:
        p_payload = p.raw_payload or {}
        if src_ip in (p_payload.get("src_ip", ""), p_payload.get("dst_ip", "")):
            return RuleResult(
                True, "C1",
                f"SIEM+Sensor IP correlation: IP {src_ip} seen in both "
                f"{alert.source_type} and {partner_source} within 10 min."
            )
    return RuleResult(False, "C1", "")


# ---------------------------------------------------------------------------
# Rule C0 — Default (same geo-region, 3+ alerts within 30 min)
# ---------------------------------------------------------------------------
def match_c0(session: Session, alert: NormalisedAlert) -> RuleResult:
    if not alert.geo_location:
        return RuleResult(False, "C0", "")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
    region_prefix = alert.geo_location.split(",")[0][:6]  # rough geo match
    recent = (
        session.query(NormalisedAlert)
        .filter(
            NormalisedAlert.timestamp >= cutoff,
            NormalisedAlert.geo_location.like(f"{region_prefix}%"),
            NormalisedAlert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )
    if len(recent) >= 2:
        sources = {a.source_type for a in recent} | {alert.source_type}
        return RuleResult(
            True, "C0",
            f"Regional convergence: {len(recent)+1} alerts in region "
            f"{region_prefix}... from {len(sources)} source(s) within 30 min."
        )
    return RuleResult(False, "C0", "")


# ---------------------------------------------------------------------------
# Rule evaluation — priority order: C5 > C4 > C3 > C2 > C1 > C0
# ---------------------------------------------------------------------------
RULES_ORDERED = [match_c5, match_c4, match_c3, match_c2, match_c1, match_c0]


def evaluate_rules(session: Session, alert: NormalisedAlert) -> RuleResult:
    """Evaluate all rules in priority order. Return first match."""
    for rule_fn in RULES_ORDERED:
        result = rule_fn(session, alert)
        if result.matched:
            return result
    return RuleResult(False, "C0", "Singleton: no correlation rule matched.")
