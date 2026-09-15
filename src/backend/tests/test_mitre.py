"""
Tests for ST-07 MITRE ATT&CK mapping — tactic/technique/sub-technique with evidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from backend.models import NormalisedAlert, MitreMapping
from backend.mitre.mapper import map_alert
from backend.mitre.evidence_rules import SUBTECHNIQUE_EVIDENCE_RULES
from backend.models.mitre_mapping import SUBTECHNIQUE_NOT_DETERMINED


def _make_na(session, alert_type, source_type, payload) -> NormalisedAlert:
    from backend.models import RawAlert
    ra = RawAlert(source_type=source_type, source_name="test",
                  raw_payload={"alert_type": alert_type, **payload})
    session.add(ra)
    session.flush()

    na = NormalisedAlert(
        raw_alert_id=ra.id,
        source_type=source_type, source_name="test",
        alert_type=alert_type, severity="HIGH",
        confidence=0.85, timestamp=datetime.now(timezone.utc),
        target_asset="test-asset", description="test",
        raw_payload={"alert_type": alert_type, **payload},
        fingerprint=uuid.uuid4().hex[:64],
        is_false_positive=False,
    )
    session.add(na)
    session.flush()
    return na


class TestMitreMapper:
    def test_every_alert_type_maps(self, session):
        """Every known alert_type should produce at least one MitreMapping."""
        alert_types = [
            ("failed_login_burst", "SIEM", {}),
            ("privilege_escalation", "SIEM", {}),
            ("lateral_movement", "CYBER_SENSOR", {}),
            ("data_exfil", "SIEM", {}),
            ("port_scan", "CYBER_SENSOR", {}),
            ("c2_beacon", "CYBER_SENSOR", {}),
            ("malware_hash_match", "CYBER_SENSOR", {}),
            ("dns_tunnelling", "CYBER_SENSOR", {"protocol": "DNS"}),
            ("ioc_match", "INTEL_REPORT", {}),
            ("threat_actor_sighting", "INTEL_REPORT", {}),
            ("vulnerability_exploitation", "INTEL_REPORT", {}),
            ("anomalous_vessel_movement", "SATELLITE", {}),
            ("rf_signal_anomaly", "SATELLITE", {}),
            ("formation_change", "SATELLITE", {}),
        ]
        for alert_type, src, payload in alert_types:
            na = _make_na(session, alert_type, src, payload)
            mappings = map_alert(session, na)
            assert len(mappings) >= 1, f"No mapping for alert_type={alert_type}"

    def test_password_spray_resolved(self, session):
        """failed_login_burst with spray=True → T1110.003 Password Spraying."""
        na = _make_na(session, "failed_login_burst", "SIEM",
                      {"spray": True, "distinct_usernames": 15})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1110.003" for m in mappings)
        # Evidence strings must be non-empty for resolved sub-technique
        resolved = next(m for m in mappings if m.subtechnique_id == "T1110.003")
        assert len(resolved.evidence_strings) > 0

    def test_password_guess_resolved(self, session):
        """failed_login_burst with single username, high count → T1110.001."""
        na = _make_na(session, "failed_login_burst", "SIEM",
                      {"spray": False, "distinct_usernames": 1, "event_count": 50})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1110.001" for m in mappings)

    def test_no_evidence_gives_not_determined(self, session):
        """failed_login_burst with no spray evidence → not_determined."""
        na = _make_na(session, "failed_login_burst", "SIEM",
                      {"spray": False, "distinct_usernames": 1, "event_count": 2})
        mappings = map_alert(session, na)
        # Neither spray nor single-user-high-count → not_determined
        assert any(m.subtechnique_id == SUBTECHNIQUE_NOT_DETERMINED for m in mappings)

    def test_smb_lateral_movement(self, session):
        """lateral_movement with protocol=SMB → T1021.002."""
        na = _make_na(session, "lateral_movement", "CYBER_SENSOR",
                      {"protocol": "SMB", "port": 445})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1021.002" for m in mappings)

    def test_ssh_lateral_movement(self, session):
        """lateral_movement with protocol=SSH → T1021.004."""
        na = _make_na(session, "lateral_movement", "CYBER_SENSOR",
                      {"protocol": "SSH", "port": 22})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1021.004" for m in mappings)

    def test_lateral_movement_no_protocol(self, session):
        """lateral_movement without protocol → not_determined."""
        na = _make_na(session, "lateral_movement", "CYBER_SENSOR", {})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == SUBTECHNIQUE_NOT_DETERMINED for m in mappings)

    def test_dns_tunnelling_always_resolved(self, session):
        """dns_tunnelling always resolves to T1071.004 DNS."""
        na = _make_na(session, "dns_tunnelling", "CYBER_SENSOR", {"protocol": "DNS"})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1071.004" for m in mappings)

    def test_c2_http_resolved(self, session):
        """c2_beacon with protocol=HTTP → T1071.001."""
        na = _make_na(session, "c2_beacon", "CYBER_SENSOR", {"protocol": "HTTP"})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1071.001" for m in mappings)

    def test_c2_dns_resolved(self, session):
        """c2_beacon with protocol=DNS → T1071.004."""
        na = _make_na(session, "c2_beacon", "CYBER_SENSOR", {"protocol": "DNS"})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1071.004" for m in mappings)

    def test_ioc_match_cve(self, session):
        """ioc_match with ioc_type=cve → T1595.002."""
        na = _make_na(session, "ioc_match", "INTEL_REPORT",
                      {"ioc_type": "cve", "cve_id": "CVE-2024-3400"})
        mappings = map_alert(session, na)
        assert any(m.subtechnique_id == "T1595.002" for m in mappings)

    def test_evidence_strings_non_empty_for_resolved(self, session):
        """Every resolved sub-technique MUST have non-empty evidence_strings."""
        na = _make_na(session, "malware_hash_match", "CYBER_SENSOR",
                      {"file_type": "exe"})
        mappings = map_alert(session, na)
        resolved = [m for m in mappings if m.subtechnique_id != SUBTECHNIQUE_NOT_DETERMINED]
        for m in resolved:
            assert len(m.evidence_strings) > 0, \
                f"Resolved sub-technique {m.subtechnique_id} has no evidence_strings"

    def test_never_invents_subtechnique(self, session):
        """No sub-technique assigned without a matching evidence rule."""
        # threat_actor_sighting has no sub-techniques → must be not_determined
        na = _make_na(session, "threat_actor_sighting", "INTEL_REPORT", {})
        mappings = map_alert(session, na)
        for m in mappings:
            assert m.subtechnique_id == SUBTECHNIQUE_NOT_DETERMINED

    def test_confidence_reduced_for_not_determined(self, session):
        """not_determined mapping should have lower confidence than alert base."""
        na = _make_na(session, "port_scan", "CYBER_SENSOR", {})
        na.confidence = 0.80
        session.flush()
        mappings = map_alert(session, na)
        nd = next(m for m in mappings if m.subtechnique_id == SUBTECHNIQUE_NOT_DETERMINED)
        # alert_type_lookup confidence = base * 0.7 = 0.56
        assert nd.confidence < na.confidence

    def test_correct_tactic_ids(self, session):
        """Spot-check tactic IDs are real ATT&CK IDs."""
        expected = {
            ("failed_login_burst", "TA0006"),
            ("c2_beacon", "TA0011"),
            ("vulnerability_exploitation", "TA0001"),
        }
        for alert_type, expected_tactic in expected:
            src = "SIEM" if alert_type in ("failed_login_burst",) else "INTEL_REPORT" if alert_type == "vulnerability_exploitation" else "CYBER_SENSOR"
            na = _make_na(session, alert_type, src, {})
            mappings = map_alert(session, na)
            assert any(m.tactic_id == expected_tactic for m in mappings), \
                f"{alert_type} should map to tactic {expected_tactic}"
