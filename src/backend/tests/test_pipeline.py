"""
Tests for ST-03 feed generator + ST-04 normaliser/deduplicator/FP-filter/auto-classifier.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from backend.models import (
    RawAlert, NormalisedAlert, Incident, IncidentAlert,
    AutoClassification, Severity, SourceType
)
from backend.feeds.generator import run_feed_generation
from backend.feeds.scenario_packs import SCENARIO_PACKS
from backend.processing.normaliser import normalise, _map_severity, _map_confidence
from backend.processing.fingerprint import compute_fingerprint
from backend.processing.deduplicator import find_duplicate
from backend.processing.false_positive_filter import apply_fp_rules
from backend.processing.pipeline import process_raw_alert
from backend.processing.auto_classifier import classify_incident


def _make_raw(session, source_type, payload) -> RawAlert:
    ra = RawAlert(source_type=source_type, source_name="test", raw_payload=payload)
    session.add(ra)
    session.flush()
    return ra


# -----------------------------------------------------------------------
# Feed generator
# -----------------------------------------------------------------------

class TestFeedGenerator:
    def test_generates_all_source_types(self, session):
        fr = run_feed_generation(session, scenario="random", seed=42)
        sources = set(fr.source_counts.keys())
        assert "SIEM" in sources
        assert "CYBER_SENSOR" in sources
        assert "SATELLITE" in sources
        assert "INTEL_REPORT" in sources

    def test_deterministic_with_seed(self, session):
        fr1 = run_feed_generation(session, scenario="apt_lateral_movement", seed=99)
        count1 = fr1.alerts_generated
        fr2 = run_feed_generation(session, scenario="apt_lateral_movement", seed=99)
        count2 = fr2.alerts_generated
        assert count1 == count2

    def test_all_scenario_packs(self, session):
        for pack in SCENARIO_PACKS:
            fr = run_feed_generation(session, scenario=pack["name"], seed=1)
            assert fr.alerts_generated > 0

    def test_feed_run_status(self, session):
        fr = run_feed_generation(session, scenario="random", seed=7)
        assert fr.status == "completed"
        assert fr.completed_at is not None


# -----------------------------------------------------------------------
# Normaliser
# -----------------------------------------------------------------------

class TestNormaliser:
    def test_siem_normalisation(self, session):
        ra = _make_raw(session, "SIEM", {
            "alert_type": "failed_login_burst", "severity": "HIGH",
            "confidence": 0.85, "hostname": "srv-dc01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "Test", "geo_location": "US-EAST"
        })
        na = normalise(ra)
        assert na.source_type == "SIEM"
        assert na.alert_type == "failed_login_burst"
        assert na.severity == "HIGH"
        assert na.target_asset == "srv-dc01"
        assert 0.0 <= na.confidence <= 1.0

    def test_cyber_sensor_normalisation(self, session):
        ra = _make_raw(session, "CYBER_SENSOR", {
            "alert_type": "c2_beacon", "severity": "CRITICAL",
            "confidence": 0.92, "dst_ip": "10.0.0.5",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "C2 beacon"
        })
        na = normalise(ra)
        assert na.target_asset == "10.0.0.5"
        assert na.severity == "CRITICAL"

    def test_satellite_normalisation(self, session):
        ra = _make_raw(session, "SATELLITE", {
            "alert_type": "rf_signal_anomaly", "severity": "MEDIUM",
            "confidence": 0.70, "object_id": "ZONE-ALPHA-7",
            "lat": 34.5, "lon": 38.2,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "RF anomaly"
        })
        na = normalise(ra)
        assert na.target_asset == "ZONE-ALPHA-7"
        assert "34.5" in (na.geo_location or "")

    def test_intel_report_normalisation(self, session):
        ra = _make_raw(session, "INTEL_REPORT", {
            "alert_type": "ioc_match", "severity": "HIGH",
            "confidence": 0.88, "ioc_value": "185.220.101.47",
            "ioc_type": "ip", "actor_name": "APT-29",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "IOC match"
        })
        na = normalise(ra)
        assert na.target_asset == "185.220.101.47"

    def test_severity_mapping(self):
        assert _map_severity("critical") == "CRITICAL"
        assert _map_severity("HIGH") == "HIGH"
        assert _map_severity("low") == "LOW"
        assert _map_severity(9.5) == "CRITICAL"
        assert _map_severity("unknown_value") == "MEDIUM"


# -----------------------------------------------------------------------
# Fingerprint
# -----------------------------------------------------------------------

class TestFingerprint:
    def test_deterministic(self):
        ts = datetime(2024, 1, 15, 14, 7, 33, tzinfo=timezone.utc)
        fp1 = compute_fingerprint("SIEM", "failed_login_burst", "srv-dc01", ts)
        fp2 = compute_fingerprint("SIEM", "failed_login_burst", "srv-dc01", ts)
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_same_5min_bucket(self):
        ts1 = datetime(2024, 1, 15, 14, 7, 10, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 14, 7, 55, tzinfo=timezone.utc)
        assert compute_fingerprint("SIEM", "port_scan", "host", ts1) == \
               compute_fingerprint("SIEM", "port_scan", "host", ts2)

    def test_different_bucket(self):
        ts1 = datetime(2024, 1, 15, 14, 4, 59, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 15, 14, 5, 1, tzinfo=timezone.utc)
        assert compute_fingerprint("SIEM", "port_scan", "host", ts1) != \
               compute_fingerprint("SIEM", "port_scan", "host", ts2)


# -----------------------------------------------------------------------
# Deduplicator
# -----------------------------------------------------------------------

class TestDeduplicator:
    def test_no_duplicate(self, session):
        assert find_duplicate(session, "nonexistent-fingerprint") is None

    def test_finds_existing(self, session):
        ra = _make_raw(session, "SIEM", {
            "alert_type": "port_scan", "severity": "LOW", "confidence": 0.5,
            "hostname": "ws-1", "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "d"
        })
        na = normalise(ra)
        na.fingerprint = "unique-fp-for-dedup-test-" + uuid.uuid4().hex[:32]
        session.add(na)
        session.flush()
        found = find_duplicate(session, na.fingerprint)
        assert found is not None
        assert found.id == na.id


# -----------------------------------------------------------------------
# FP Filter
# -----------------------------------------------------------------------

class TestFPFilter:
    def _make_na(self, **kwargs) -> NormalisedAlert:
        defaults = dict(
            raw_alert_id="test-raw-id",
            source_type="SIEM", source_name="test",
            alert_type="port_scan", severity="LOW",
            confidence=0.5, timestamp=datetime.now(timezone.utc),
            target_asset="host", description="d",
            raw_payload={}, fingerprint=uuid.uuid4().hex[:64],
            is_false_positive=False,
        )
        defaults.update(kwargs)
        return NormalisedAlert(**defaults)

    def test_fp01_low_confidence(self):
        na = self._make_na(confidence=0.10)
        result = apply_fp_rules(na)
        assert result.is_false_positive is True
        assert result.fp_reason == "fp_low_confidence"

    def test_fp02_satellite_weak_signal(self):
        na = self._make_na(
            source_type="SATELLITE", alert_type="formation_change",
            raw_payload={"signal_strength": -93.0}
        )
        result = apply_fp_rules(na)
        assert result.is_false_positive is True
        assert result.fp_reason == "fp_satellite_weak_signal"

    def test_fp03_siem_single_low_event(self):
        na = self._make_na(
            source_type="SIEM", severity="LOW",
            raw_payload={"event_count": 1}
        )
        result = apply_fp_rules(na)
        assert result.is_false_positive is True
        assert result.fp_reason == "fp_siem_single_low_event"

    def test_no_fp_for_high_confidence(self):
        na = self._make_na(confidence=0.90, severity="HIGH")
        result = apply_fp_rules(na)
        assert result.is_false_positive is False


# -----------------------------------------------------------------------
# Pipeline (integration: raw → normalised)
# -----------------------------------------------------------------------

class TestPipeline:
    def test_process_raw_alert(self, session):
        ra = _make_raw(session, "SIEM", {
            "alert_type": "privilege_escalation", "severity": "HIGH",
            "confidence": 0.88, "hostname": "srv-dc01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "description": "Priv esc", "event_count": 3
        })
        na = process_raw_alert(session, ra)
        assert na is not None
        assert na.alert_type == "privilege_escalation"

    def test_duplicate_returns_none(self, session):
        payload = {
            "alert_type": "port_scan", "severity": "MEDIUM", "confidence": 0.6,
            "hostname": "dedup-host", "timestamp": "2024-01-15T14:07:00+00:00",
            "description": "scan"
        }
        ra1 = _make_raw(session, "SIEM", payload)
        na1 = process_raw_alert(session, ra1)
        assert na1 is not None

        ra2 = _make_raw(session, "SIEM", payload)
        na2 = process_raw_alert(session, ra2)
        assert na2 is None  # duplicate fingerprint


# -----------------------------------------------------------------------
# Auto-classifier
# -----------------------------------------------------------------------

class TestAutoClassifier:
    def test_all_fp_members(self, session):
        ra = _make_raw(session, "SIEM", {
            "alert_type": "failed_login_burst", "severity": "LOW",
            "confidence": 0.10, "hostname": "ws-1",
            "timestamp": datetime.now(timezone.utc).isoformat(), "description": "d"
        })
        na = normalise(ra)
        na.fingerprint = uuid.uuid4().hex[:64]
        na.is_false_positive = True
        na.fp_reason = "fp_low_confidence"
        session.add(na)
        session.flush()

        from backend.correlation.incident_builder import create_incident
        inc = create_incident(session, na, "C0", "Test")
        classify_incident(session, inc)
        assert inc.auto_classification == "FALSE_POSITIVE"

    def test_gt03_multi_source(self, session):
        # Create two alerts from different sources for same asset
        for src, atype in [("SIEM", "privilege_escalation"), ("CYBER_SENSOR", "lateral_movement")]:
            ra = _make_raw(session, src, {
                "alert_type": atype, "severity": "HIGH",
                "confidence": 0.85, "hostname": "srv-dc01", "dst_ip": "srv-dc01",
                "timestamp": datetime.now(timezone.utc).isoformat(), "description": "d",
                "event_count": 5,
            })
            na = normalise(ra)
            na.fingerprint = uuid.uuid4().hex[:64]
            session.add(na)
        session.flush()

        alerts = session.query(NormalisedAlert).filter(
            NormalisedAlert.target_asset == "srv-dc01"
        ).all()
        assert len(alerts) >= 2
