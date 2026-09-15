"""
Tests for ST-05 correlation engine and ST-06 risk scoring.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from backend.models import (
    NormalisedAlert, RawAlert, Incident, IncidentAlert, RiskScore, AutoClassification
)
from backend.correlation.engine import correlate
from backend.correlation.rules import (
    match_c0, match_c1, match_c2, match_c3, match_c5, evaluate_rules
)
from backend.correlation.incident_builder import create_incident, extend_incident
from backend.scoring.scorer import score_incident
from backend.scoring.asset_registry import get_asset_criticality


def _make_alert(session, source_type, alert_type, target_asset,
                confidence=0.85, severity="HIGH",
                geo_location=None, payload_extra=None) -> NormalisedAlert:
    ra = RawAlert(source_type=source_type, source_name="test",
                  raw_payload={"alert_type": alert_type})
    session.add(ra)
    session.flush()
    na = NormalisedAlert(
        raw_alert_id=ra.id,
        source_type=source_type, source_name="test",
        alert_type=alert_type, severity=severity,
        confidence=confidence, timestamp=datetime.now(timezone.utc),
        target_asset=target_asset, description="test",
        geo_location=geo_location,
        raw_payload={"alert_type": alert_type, **(payload_extra or {})},
        fingerprint=uuid.uuid4().hex[:64],
        is_false_positive=False,
    )
    session.add(na)
    session.flush()
    return na


class TestCorrelationRules:
    def test_c3_multi_source_convergence(self, session):
        # Pre-seed DB with SIEM alert on same asset
        _make_alert(session, "SIEM", "privilege_escalation", "target-asset-c3")
        # New CYBER_SENSOR alert on same asset
        new_alert = _make_alert(session, "CYBER_SENSOR", "lateral_movement", "target-asset-c3")
        result = match_c3(session, new_alert)
        assert result.matched is True
        assert result.rule_id == "C3"

    def test_c3_single_source_no_match(self, session):
        new_alert = _make_alert(session, "SIEM", "port_scan", f"only-siem-{uuid.uuid4().hex[:6]}")
        result = match_c3(session, new_alert)
        assert result.matched is False

    def test_c2_ioc_match(self, session):
        # Pre-seed SIEM alert that mentions the IOC value in its payload
        ioc = "185.220.101.47"
        _make_alert(session, "SIEM", "c2_beacon", "victim-host",
                    payload_extra={"src_ip": ioc, "dst_ip": ioc})
        intel = _make_alert(session, "INTEL_REPORT", "ioc_match", ioc,
                            payload_extra={"ioc_value": ioc, "ioc_type": "ip"})
        result = match_c2(session, intel)
        assert result.matched is True
        assert result.rule_id == "C2"

    def test_c1_siem_sensor_ip_match(self, session):
        shared_ip = "10.0.0.99"
        _make_alert(session, "CYBER_SENSOR", "port_scan", shared_ip,
                    payload_extra={"src_ip": shared_ip})
        siem = _make_alert(session, "SIEM", "failed_login_burst", shared_ip,
                           payload_extra={"src_ip": shared_ip})
        result = match_c1(session, siem)
        assert result.matched is True

    def test_c0_geo_regional(self, session):
        geo = "US-EAST"
        _make_alert(session, "SIEM", "port_scan", "host-a", geo_location=geo)
        _make_alert(session, "SIEM", "port_scan", "host-b", geo_location=geo)
        new_alert = _make_alert(session, "SATELLITE", "rf_signal_anomaly", "ZONE-A", geo_location=geo)
        result = match_c0(session, new_alert)
        assert result.matched is True


class TestCorrelationEngine:
    def test_creates_incident(self, session):
        alert = _make_alert(session, "SIEM", "privilege_escalation", f"host-{uuid.uuid4().hex[:6]}")
        inc = correlate(session, alert)
        assert inc is not None
        assert inc.id is not None
        links = session.query(IncidentAlert).filter(IncidentAlert.incident_id == inc.id).all()
        assert len(links) >= 1

    def test_extends_existing_incident(self, session):
        asset = f"shared-asset-{uuid.uuid4().hex[:6]}"
        a1 = _make_alert(session, "SIEM", "privilege_escalation", asset)
        inc1 = correlate(session, a1)
        a2 = _make_alert(session, "CYBER_SENSOR", "lateral_movement", asset)
        inc2 = correlate(session, a2)
        assert inc1.id == inc2.id  # Same incident extended
        links = session.query(IncidentAlert).filter(IncidentAlert.incident_id == inc1.id).all()
        assert len(links) == 2

    def test_fired_rule_stored(self, session):
        asset = f"rule-test-{uuid.uuid4().hex[:6]}"
        # Seed SIEM alert
        _make_alert(session, "SIEM", "privilege_escalation", asset)
        # New sensor alert on same asset → should trigger C3
        new_alert = _make_alert(session, "CYBER_SENSOR", "lateral_movement", asset)
        inc = correlate(session, new_alert)
        assert inc.fired_correlation_rule is not None


class TestRiskScoring:
    def test_score_range(self, session):
        asset = f"score-test-{uuid.uuid4().hex[:6]}"
        a = _make_alert(session, "SIEM", "privilege_escalation", asset, confidence=0.90)
        inc = create_incident(session, a, "C3", "test")
        rs = score_incident(session, inc)
        assert 0.0 <= rs.total_score <= 100.0

    def test_critical_asset_higher_score(self, session):
        # Critical asset
        a_crit = _make_alert(session, "SIEM", "privilege_escalation", "srv-dc01", confidence=0.85)
        inc_crit = create_incident(session, a_crit, "C3", "critical test")
        rs_crit = score_incident(session, inc_crit)

        # Unknown asset
        a_norm = _make_alert(session, "SIEM", "privilege_escalation", "random-host-xyz", confidence=0.85)
        inc_norm = create_incident(session, a_norm, "C3", "normal test")
        rs_norm = score_incident(session, inc_norm)

        assert rs_crit.total_score > rs_norm.total_score

    def test_explanation_structure(self, session):
        a = _make_alert(session, "SIEM", "c2_beacon", f"host-{uuid.uuid4().hex[:6]}")
        inc = create_incident(session, a, "C1", "test")
        rs = score_incident(session, inc)
        exp = rs.explanation
        assert "total_score" in exp
        assert "priority_label" in exp
        assert "components" in exp
        comps = exp["components"]
        for key in ["severity", "confidence", "source_diversity", "asset_criticality", "temporal_recency"]:
            assert key in comps
            assert "value" in comps[key]
            assert "reason" in comps[key]

    def test_priority_labels(self, session):
        from backend.scoring.scorer import _priority_label
        assert "P1" in _priority_label(85.0)
        assert "P2" in _priority_label(65.0)
        assert "P3" in _priority_label(45.0)
        assert "P4" in _priority_label(20.0)

    def test_asset_criticality_registry(self):
        assert get_asset_criticality("srv-dc01") == 100.0
        assert get_asset_criticality("unknown-random-host-xyz") == 50.0
        assert get_asset_criticality("") == 50.0
