"""
Pydantic v2 schemas for all ORM models.

These schemas are used for:
- FastAPI request/response serialisation
- Input validation at API boundaries
- Type-safe data transfer between pipeline stages

Naming convention:
  <Model>Base     — fields shared by create and read
  <Model>Create   — fields required when creating a new record
  <Model>Read     — full record returned by API (includes id, timestamps)
  <Model>Summary  — lightweight version for list endpoints
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Shared config
# ---------------------------------------------------------------------------
class _OrmBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Enums (re-exported as string literals for OpenAPI schema clarity)
# ---------------------------------------------------------------------------
class SourceTypeEnum(str):
    SIEM = "SIEM"
    CYBER_SENSOR = "CYBER_SENSOR"
    SATELLITE = "SATELLITE"
    INTEL_REPORT = "INTEL_REPORT"


# ---------------------------------------------------------------------------
# RawAlert
# ---------------------------------------------------------------------------
class RawAlertRead(_OrmBase):
    id: str
    source_type: str
    source_name: str
    feed_run_id: str | None
    raw_payload: dict[str, Any]
    received_at: datetime


# ---------------------------------------------------------------------------
# NormalisedAlert
# ---------------------------------------------------------------------------
class NormalisedAlertSummary(_OrmBase):
    id: str
    source_type: str
    alert_type: str
    severity: str
    confidence: float
    timestamp: datetime
    target_asset: str
    is_false_positive: bool
    fp_reason: str | None


class NormalisedAlertRead(_OrmBase):
    id: str
    raw_alert_id: str
    source_type: str
    source_name: str
    alert_type: str
    severity: str
    confidence: float
    timestamp: datetime
    target_asset: str
    geo_location: str | None
    description: str
    raw_payload: dict[str, Any]
    fingerprint: str
    is_false_positive: bool
    fp_reason: str | None
    created_at: datetime


# ---------------------------------------------------------------------------
# MitreMapping
# ---------------------------------------------------------------------------
class MitreMappingRead(_OrmBase):
    id: str
    normalised_alert_id: str
    incident_id: str | None
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str
    subtechnique_name: str
    confidence: float
    evidence_strings: list[str]
    mapping_method: str
    created_at: datetime


# ---------------------------------------------------------------------------
# RiskScore
# ---------------------------------------------------------------------------
class RiskScoreRead(_OrmBase):
    id: str
    incident_id: str
    total_score: float
    severity_component: float
    confidence_component: float
    source_diversity_component: float
    asset_criticality_component: float
    temporal_component: float
    explanation: dict[str, Any]
    scored_at: datetime


# ---------------------------------------------------------------------------
# BobAnalysis
# ---------------------------------------------------------------------------
class BobAnalysisRead(_OrmBase):
    id: str
    incident_id: str
    bob_classification: str
    bob_confidence: float
    bob_reasoning: str
    score_explanation_text: str
    correlation_review_text: str
    agreement_status: str
    agreement_detail: str
    analysed_at: datetime
    bob_model_version: str


class BobAnalysisSummary(_OrmBase):
    """Lightweight version for incident list views."""
    bob_classification: str
    bob_confidence: float
    agreement_status: str
    analysed_at: datetime


# ---------------------------------------------------------------------------
# BlufSummary
# ---------------------------------------------------------------------------
class BlufSummaryRead(_OrmBase):
    id: str
    incident_id: str
    bluf_line: str
    situation: str
    assessment: str
    recommendations: str
    full_text: str
    generated_at: datetime


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class IncidentSummary(_OrmBase):
    """Lightweight incident record for list views."""
    id: str
    title: str
    status: str
    overall_severity: str
    first_seen: datetime
    last_seen: datetime
    auto_classification: str
    fired_correlation_rule: str | None
    risk_score: RiskScoreRead | None
    bob_analysis: BobAnalysisSummary | None


class IncidentRead(_OrmBase):
    """Full incident record including all related data."""
    id: str
    title: str
    status: str
    overall_severity: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    affected_assets: list[str]
    source_types_involved: list[str]
    correlation_reason: str
    fired_correlation_rule: str | None
    auto_classification: str
    auto_classification_reason: str
    risk_score: RiskScoreRead | None
    bob_analysis: BobAnalysisRead | None
    bluf_summary: BlufSummaryRead | None
    mitre_mappings: list[MitreMappingRead] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# FeedRun
# ---------------------------------------------------------------------------
class FeedRunRead(_OrmBase):
    id: str
    scenario: str
    seed: int | None
    started_at: datetime
    completed_at: datetime | None
    alerts_generated: int
    alerts_deduplicated: int
    incidents_created: int
    source_counts: dict[str, int]
    status: str
    error_message: str | None


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------
class DashboardStats(BaseModel):
    total_alerts: int
    total_incidents: int
    open_incidents: int
    p1_incidents: int
    genuine_threat_count: int
    false_positive_count: int
    unclassified_count: int
    false_positive_rate: float  # 0.0–1.0
    last_feed_run: FeedRunRead | None
