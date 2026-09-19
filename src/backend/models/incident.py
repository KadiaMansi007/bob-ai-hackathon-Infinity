"""
Incident and IncidentAlert ORM models.

An Incident is a correlated group of NormalisedAlerts that the correlation
engine has judged to be related. The IncidentAlert table is the many-to-many
join between incidents and their member alerts.

Key design points:
- fired_correlation_rule stores which rule (C0–C5) created this incident.
- auto_classification is set deterministically by the pipeline auto-classifier.
- bob_analysis is populated later by IBM Bob via the MCP server.
"""
from datetime import datetime

from sqlalchemy import (
    DateTime, ForeignKey, Index, Integer,
    String, Text, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now
from .enums import AutoClassification, IncidentStatus, Severity


class IncidentAlert(Base):
    """
    Many-to-many join table between Incident and NormalisedAlert.

    Stores the order in which alerts were added to the incident so the
    frontend and Bob can reconstruct the timeline.
    """
    __tablename__ = "incident_alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    normalised_alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("normalised_alerts.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # Position of this alert in the incident timeline (1-based)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationships
    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="alert_links"
    )
    normalised_alert: Mapped["NormalisedAlert"] = relationship(
        "NormalisedAlert", back_populates="incident_links"
    )

    __table_args__ = (
        Index("ix_incident_alert_pair", "incident_id", "normalised_alert_id", unique=True),
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentAlert incident={self.incident_id!r} "
            f"alert={self.normalised_alert_id!r} seq={self.sequence_number}>"
        )


class Incident(Base):
    """
    A correlated incident — one or more related NormalisedAlerts grouped
    by the correlation engine.

    Layer 1 (deterministic pipeline) sets:
      - fired_correlation_rule  (which rule fired)
      - auto_classification     (GENUINE_THREAT / FALSE_POSITIVE / UNCLASSIFIED)
      - auto_classification_reason

    Layer 2 (IBM Bob) writes to the related BobAnalysis record, not here.
    """
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )

    # --- Identity --------------------------------------------------------
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False,
        default=IncidentStatus.OPEN.value, index=True
    )
    overall_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )

    # --- Temporal --------------------------------------------------------
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    # --- Scope -----------------------------------------------------------
    # JSON array of target asset strings e.g. ["10.0.0.5", "srv-dc01"]
    affected_assets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # JSON array of SourceType strings e.g. ["SIEM", "CYBER_SENSOR"]
    source_types_involved: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )

    # --- Correlation provenance ------------------------------------------
    # Human-readable explanation of why these alerts were grouped
    correlation_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Which rule ID fired: "C0", "C1", ... "C5"
    fired_correlation_rule: Mapped[str | None] = mapped_column(
        String(8), nullable=True, index=True
    )

    # --- Deterministic classification (Layer 1) --------------------------
    auto_classification: Mapped[str] = mapped_column(
        String(32), nullable=False,
        default=AutoClassification.UNCLASSIFIED.value, index=True
    )
    auto_classification_reason: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )

    # --- FP Masking flag -------------------------------------------------
    # Set to True when C6 fires — attacker deliberately kept alerts below FP
    # thresholds but cumulative pattern reveals genuine threat
    fp_masking_warning: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )

    # --- Relationships ---------------------------------------------------
    alert_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="incident",
        cascade="all, delete-orphan", order_by="IncidentAlert.sequence_number"
    )
    risk_score: Mapped["RiskScore | None"] = relationship(
        "RiskScore", back_populates="incident",
        uselist=False, cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[list["MitreMapping"]] = relationship(
        "MitreMapping", back_populates="incident"
    )
    bob_analysis: Mapped["BobAnalysis | None"] = relationship(
        "BobAnalysis", back_populates="incident",
        uselist=False, cascade="all, delete-orphan"
    )
    bluf_summary: Mapped["BlufSummary | None"] = relationship(
        "BlufSummary", back_populates="incident",
        uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id!r} title={self.title!r} "
            f"status={self.status!r} auto_class={self.auto_classification!r}>"
        )
