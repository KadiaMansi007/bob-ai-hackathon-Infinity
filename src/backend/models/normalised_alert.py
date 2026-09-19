"""
NormalisedAlert ORM model.

Represents a raw alert that has been:
  1. Converted to the canonical schema (normalisation)
  2. Checked for duplicates (fingerprint deduplication)
  3. Pre-filtered for obvious false positives (FP-01 through FP-04)

This is the primary working record for all downstream pipeline stages
(correlation, scoring, MITRE mapping, Bob analysis).
"""
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey,
    Index, String, Text, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now
from .enums import SourceType, Severity


class NormalisedAlert(Base):
    """
    Canonical, deduplicated alert record.

    One NormalisedAlert corresponds to at most one RawAlert (1-to-1).
    Many NormalisedAlerts can belong to one Incident (many-to-many via
    the IncidentAlert join table).
    """
    __tablename__ = "normalised_alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )

    # --- Origin ----------------------------------------------------------
    raw_alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("raw_alerts.id", ondelete="RESTRICT"),
        nullable=False, unique=True, index=True
    )
    source_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    alert_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # --- Severity & confidence -------------------------------------------
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # --- Temporal --------------------------------------------------------
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # --- Asset & location ------------------------------------------------
    target_asset: Mapped[str] = mapped_column(
        String(256), nullable=False, index=True
    )
    geo_location: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # --- Content ---------------------------------------------------------
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    # --- Deduplication ---------------------------------------------------
    # SHA-256 hash of (source_type + alert_type + target_asset + 5-min bucket)
    fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # --- False-positive pre-filter ---------------------------------------
    is_false_positive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )
    # Reason code e.g. "fp_low_confidence", "fp_satellite_weak_signal"
    fp_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- FP Masking detection --------------------------------------------
    # Set to True if this alert was marked FP but its IP/asset appears in a
    # cluster of FP-marked alerts — indicating deliberate FP masking by attacker
    fp_masking_suspected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )

    # --- Relationships ---------------------------------------------------
    raw_alert: Mapped["RawAlert"] = relationship(
        "RawAlert", back_populates="normalised_alert"
    )
    incident_links: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="normalised_alert",
        cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[list["MitreMapping"]] = relationship(
        "MitreMapping", back_populates="normalised_alert",
        cascade="all, delete-orphan"
    )

    # --- Composite index for correlation window queries ------------------
    __table_args__ = (
        Index(
            "ix_nalert_source_type_timestamp",
            "source_type", "timestamp"
        ),
        Index(
            "ix_nalert_target_asset_timestamp",
            "target_asset", "timestamp"
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<NormalisedAlert id={self.id!r} type={self.alert_type!r} "
            f"severity={self.severity!r} fp={self.is_false_positive}>"
        )
