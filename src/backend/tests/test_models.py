"""
ST-02 Model smoke tests.

Tests that:
1. All ORM tables are created without error (create_all)
2. One row can be inserted and queried for every model
3. Relationships are navigable (FK constraints work)
4. Enum values round-trip correctly through the DB
5. Fingerprint uniqueness constraint is enforced
6. BobAnalysis unique constraint per incident is enforced
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker, Session

from backend.models import (
    Base,
    RawAlert,
    NormalisedAlert,
    Incident,
    IncidentAlert,
    RiskScore,
    MitreMapping,
    BobAnalysis,
    BlufSummary,
    FeedRun,
    AutoClassification,
    BobClassification,
    AgreementStatus,
    IncidentStatus,
    Severity,
    SourceType,
    SUBTECHNIQUE_NOT_DETERMINED,
    SUBTECHNIQUE_NAME_NOT_DETERMINED,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """In-memory SQLite engine — isolated per test module."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    # Enable foreign keys for SQLite
    from sqlalchemy import event
    @event.listens_for(eng, "connect")
    def set_fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)


@pytest.fixture(scope="module")
def session(engine) -> Session:
    """Single session used by all tests in this module."""
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = SessionLocal()
    yield db
    db.rollback()
    db.close()


def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ST-02-01  All tables created
# ---------------------------------------------------------------------------

def test_all_tables_created(engine):
    """Every expected table must exist after create_all."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    expected = {
        "raw_alerts",
        "normalised_alerts",
        "incidents",
        "incident_alerts",
        "risk_scores",
        "mitre_mappings",
        "bob_analyses",
        "bluf_summaries",
        "feed_runs",
    }
    assert expected.issubset(tables), f"Missing tables: {expected - tables}"


# ---------------------------------------------------------------------------
# ST-02-02  FeedRun insert
# ---------------------------------------------------------------------------

def test_feed_run_insert(session):
    run = FeedRun(
        id=_uid(),
        scenario="apt_lateral_movement",
        seed=42,
        alerts_generated=0,
        source_counts={},
        status="running",
    )
    session.add(run)
    session.flush()
    fetched = session.get(FeedRun, run.id)
    assert fetched is not None
    assert fetched.scenario == "apt_lateral_movement"
    assert fetched.seed == 42
    assert fetched.status == "running"


# ---------------------------------------------------------------------------
# ST-02-03  RawAlert insert
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def raw_alert(session) -> RawAlert:
    ra = RawAlert(
        id=_uid(),
        source_type=SourceType.SIEM.value,
        source_name="splunk-prod",
        raw_payload={"event": "failed_login", "count": 50},
    )
    session.add(ra)
    session.flush()
    return ra


def test_raw_alert_insert(raw_alert):
    assert raw_alert.source_type == "SIEM"
    assert raw_alert.raw_payload["count"] == 50


# ---------------------------------------------------------------------------
# ST-02-04  NormalisedAlert insert + FK + fingerprint
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def normalised_alert(session, raw_alert) -> NormalisedAlert:
    na = NormalisedAlert(
        id=_uid(),
        raw_alert_id=raw_alert.id,
        source_type=SourceType.SIEM.value,
        source_name="splunk-prod",
        alert_type="failed_login_burst",
        severity=Severity.HIGH.value,
        confidence=0.85,
        timestamp=_now(),
        target_asset="srv-dc01",
        geo_location="US-EAST",
        description="50 failed login attempts from 10.0.0.5 in 2 minutes.",
        raw_payload={"event": "failed_login", "count": 50, "distinct_usernames": 12},
        fingerprint="aabbccdd" * 8,  # 64-char hex string
        is_false_positive=False,
    )
    session.add(na)
    session.flush()
    return na


def test_normalised_alert_insert(normalised_alert, raw_alert):
    assert normalised_alert.severity == "HIGH"
    assert normalised_alert.is_false_positive is False
    assert normalised_alert.raw_alert_id == raw_alert.id


def test_normalised_alert_raw_relationship(session, normalised_alert, raw_alert):
    """Relationship from NormalisedAlert → RawAlert must be navigable."""
    session.refresh(normalised_alert)
    assert normalised_alert.raw_alert.id == raw_alert.id


def test_fingerprint_unique_constraint(session, normalised_alert):
    """Inserting a duplicate fingerprint must raise IntegrityError."""
    dup = NormalisedAlert(
        id=_uid(),
        raw_alert_id=normalised_alert.raw_alert_id,  # same raw (will also fail unique)
        source_type=SourceType.SIEM.value,
        source_name="splunk-prod",
        alert_type="failed_login_burst",
        severity=Severity.HIGH.value,
        confidence=0.85,
        timestamp=_now(),
        target_asset="srv-dc01",
        description="Duplicate.",
        raw_payload={},
        fingerprint=normalised_alert.fingerprint,  # duplicate fingerprint
        is_false_positive=False,
    )
    session.add(dup)
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


# ---------------------------------------------------------------------------
# ST-02-05  Incident + IncidentAlert
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def incident(session) -> Incident:
    inc = Incident(
        id=_uid(),
        title="APT Lateral Movement — srv-dc01",
        status=IncidentStatus.OPEN.value,
        overall_severity=Severity.HIGH.value,
        first_seen=_now(),
        last_seen=_now(),
        affected_assets=["srv-dc01"],
        source_types_involved=["SIEM", "CYBER_SENSOR"],
        correlation_reason="Rule C1 fired: SIEM + Cyber Sensor sharing same source IP.",
        fired_correlation_rule="C1",
        auto_classification=AutoClassification.GENUINE_THREAT.value,
        auto_classification_reason="gt_multi_source_convergence",
    )
    session.add(inc)
    session.flush()
    return inc


def test_incident_insert(incident):
    assert incident.auto_classification == "GENUINE_THREAT"
    assert incident.fired_correlation_rule == "C1"
    assert incident.status == "OPEN"


@pytest.fixture(scope="module")
def normalised_alert_2(session) -> NormalisedAlert:
    """Second alert so we can re-attach a fresh raw_alert."""
    ra2 = RawAlert(
        id=_uid(),
        source_type=SourceType.CYBER_SENSOR.value,
        source_name="suricata-dmz",
        raw_payload={"port": 445, "protocol": "SMB"},
    )
    session.add(ra2)
    session.flush()
    na2 = NormalisedAlert(
        id=_uid(),
        raw_alert_id=ra2.id,
        source_type=SourceType.CYBER_SENSOR.value,
        source_name="suricata-dmz",
        alert_type="lateral_movement",
        severity=Severity.HIGH.value,
        confidence=0.90,
        timestamp=_now(),
        target_asset="srv-dc01",
        description="SMB lateral movement detected.",
        raw_payload={"port": 445, "protocol": "SMB"},
        fingerprint="deadbeef" * 8,
        is_false_positive=False,
    )
    session.add(na2)
    session.flush()
    return na2


def test_incident_alert_join(session, incident, normalised_alert, normalised_alert_2):
    """Two alerts linked to one incident via IncidentAlert join table."""
    link1 = IncidentAlert(
        id=_uid(),
        incident_id=incident.id,
        normalised_alert_id=normalised_alert.id,
        sequence_number=1,
    )
    link2 = IncidentAlert(
        id=_uid(),
        incident_id=incident.id,
        normalised_alert_id=normalised_alert_2.id,
        sequence_number=2,
    )
    session.add_all([link1, link2])
    session.flush()
    session.refresh(incident)
    assert len(incident.alert_links) == 2


# ---------------------------------------------------------------------------
# ST-02-06  RiskScore
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def risk_score(session, incident) -> RiskScore:
    rs = RiskScore(
        id=_uid(),
        incident_id=incident.id,
        total_score=78.5,
        severity_component=26.25,
        confidence_component=21.25,
        source_diversity_component=15.0,
        asset_criticality_component=10.0,
        temporal_component=6.0,
        explanation={
            "total_score": 78.5,
            "priority_label": "P2 — Investigate Today",
            "components": {
                "severity": {"value": 26.25, "weight": 0.35, "raw": 75, "reason": "HIGH alert present"},
            },
        },
    )
    session.add(rs)
    session.flush()
    return rs


def test_risk_score_insert(risk_score, incident):
    assert risk_score.total_score == pytest.approx(78.5)
    assert risk_score.incident_id == incident.id
    assert risk_score.explanation["priority_label"] == "P2 — Investigate Today"


def test_risk_score_incident_relationship(session, risk_score, incident):
    session.refresh(incident)
    assert incident.risk_score is not None
    assert incident.risk_score.total_score == pytest.approx(78.5)


# ---------------------------------------------------------------------------
# ST-02-07  MitreMapping (tactic / technique / sub-technique)
# ---------------------------------------------------------------------------

def test_mitre_mapping_resolved_subtechnique(session, normalised_alert, incident):
    """Sub-technique resolved from payload evidence."""
    mm = MitreMapping(
        id=_uid(),
        normalised_alert_id=normalised_alert.id,
        incident_id=incident.id,
        tactic_id="TA0006",
        tactic_name="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        subtechnique_id="T1110.003",
        subtechnique_name="Password Spraying",
        confidence=0.90,
        evidence_strings=["distinct_usernames=12", "spray_pattern_detected"],
        mapping_method="payload_keyword",
    )
    session.add(mm)
    session.flush()
    fetched = session.get(MitreMapping, mm.id)
    assert fetched.subtechnique_id == "T1110.003"
    assert fetched.subtechnique_name == "Password Spraying"
    assert len(fetched.evidence_strings) == 2
    assert fetched.mapping_method == "payload_keyword"


def test_mitre_mapping_not_determined(session, normalised_alert_2, incident):
    """Sub-technique not determined — sentinel values stored, no evidence strings."""
    mm = MitreMapping(
        id=_uid(),
        normalised_alert_id=normalised_alert_2.id,
        incident_id=incident.id,
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id=SUBTECHNIQUE_NOT_DETERMINED,
        subtechnique_name=SUBTECHNIQUE_NAME_NOT_DETERMINED,
        confidence=0.65,
        evidence_strings=[],  # no payload evidence → not_determined
        mapping_method="alert_type_lookup",
    )
    session.add(mm)
    session.flush()
    fetched = session.get(MitreMapping, mm.id)
    assert fetched.subtechnique_id == "not_determined"
    assert fetched.subtechnique_name == "Not determined"
    assert fetched.evidence_strings == []


# ---------------------------------------------------------------------------
# ST-02-08  BobAnalysis
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bob_analysis(session, incident) -> BobAnalysis:
    ba = BobAnalysis(
        id=_uid(),
        incident_id=incident.id,
        bob_classification=BobClassification.GENUINE_THREAT.value,
        bob_confidence=0.92,
        bob_reasoning=(
            "The incident shows credential access via password spraying "
            "on a domain controller followed by SMB lateral movement, "
            "consistent with APT pre-staging behaviour."
        ),
        score_explanation_text="The score of 78.5 reflects HIGH severity (35% weight)...",
        correlation_review_text="Rule C1 correctly grouped these alerts — shared IP confirmed.",
        agreement_status=AgreementStatus.AGREES.value,
        agreement_detail="",
        bob_model_version="bob-1.0",
    )
    session.add(ba)
    session.flush()
    return ba


def test_bob_analysis_insert(bob_analysis, incident):
    assert bob_analysis.bob_classification == "GENUINE_THREAT"
    assert bob_analysis.agreement_status == "AGREES"
    assert bob_analysis.bob_confidence == pytest.approx(0.92)
    assert bob_analysis.incident_id == incident.id


def test_bob_analysis_unique_per_incident(session, incident):
    """A second BobAnalysis for the same incident must raise IntegrityError."""
    dup = BobAnalysis(
        id=_uid(),
        incident_id=incident.id,
        bob_classification=BobClassification.FALSE_POSITIVE.value,
        bob_confidence=0.5,
        bob_reasoning="Duplicate.",
        score_explanation_text="",
        correlation_review_text="",
        agreement_status=AgreementStatus.DISAGREES.value,
        agreement_detail="Duplicate entry test.",
        bob_model_version="bob-1.0",
    )
    session.add(dup)
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_bob_analysis_incident_relationship(session, bob_analysis, incident):
    session.refresh(incident)
    assert incident.bob_analysis is not None
    assert incident.bob_analysis.agreement_status == "AGREES"


# ---------------------------------------------------------------------------
# ST-02-09  BlufSummary
# ---------------------------------------------------------------------------

def test_bluf_summary_insert(session, incident):
    bs = BlufSummary(
        id=_uid(),
        incident_id=incident.id,
        bluf_line="Suspected APT credential spray targeting srv-dc01 requires immediate investigation.",
        situation="At 14:32 UTC, 50 failed login attempts from 10.0.0.5 were detected by SIEM...",
        assessment="Multi-source convergence of SIEM and cyber sensor evidence indicates...",
        recommendations="1. Isolate 10.0.0.5\n2. Reset srv-dc01 credentials\n3. Review SMB access logs",
        full_text="BLUF: Suspected APT...\nSITUATION: ...\nASSESSMENT: ...\nRECOMMENDATIONS: ...",
    )
    session.add(bs)
    session.flush()
    session.refresh(incident)
    assert incident.bluf_summary is not None
    assert "srv-dc01" in incident.bluf_summary.bluf_line


# ---------------------------------------------------------------------------
# ST-02-10  Enum round-trip
# ---------------------------------------------------------------------------

def test_enum_values_round_trip(session, incident):
    """Enum values stored as strings must round-trip through the DB."""
    session.refresh(incident)
    assert incident.status in [e.value for e in IncidentStatus]
    assert incident.overall_severity in [e.value for e in Severity]
    assert incident.auto_classification in [e.value for e in AutoClassification]


# ---------------------------------------------------------------------------
# ST-02-11  Pydantic schema round-trip
# ---------------------------------------------------------------------------

def test_pydantic_schemas_importable():
    """All schemas must be importable and constructable without errors."""
    from backend.schemas import (
        RawAlertRead,
        NormalisedAlertRead,
        NormalisedAlertSummary,
        MitreMappingRead,
        RiskScoreRead,
        BobAnalysisRead,
        BobAnalysisSummary,
        BlufSummaryRead,
        IncidentRead,
        IncidentSummary,
        FeedRunRead,
        DashboardStats,
    )
    # Spot-check: DashboardStats with required fields
    stats = DashboardStats(
        total_alerts=100,
        total_incidents=10,
        open_incidents=5,
        p1_incidents=2,
        genuine_threat_count=3,
        false_positive_count=4,
        unclassified_count=3,
        false_positive_rate=0.4,
        last_feed_run=None,
    )
    assert stats.total_alerts == 100
    assert stats.false_positive_rate == pytest.approx(0.4)
