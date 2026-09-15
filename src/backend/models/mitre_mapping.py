"""
MitreMapping ORM model.

Stores the full three-level MITRE ATT&CK hierarchy for a normalised alert:
  Tactic → Technique → Sub-technique

Key design rules (from the plan):
- subtechnique_id is ALWAYS set — either to a real sub-technique ID (e.g.
  "T1071.004") or to the sentinel value "not_determined".
- subtechnique_name mirrors this: real name or "Not determined".
- evidence_strings contains the payload fragments that justified the
  sub-technique resolution. This list MUST be non-empty when a real
  sub-technique was resolved.
- mapping_method records how the mapping was produced:
    "alert_type_lookup"        — parent technique only, no payload evidence
    "payload_keyword"          — sub-technique resolved from payload fields
    "cross_source_corroboration" — confidence upgraded by multi-source agreement
"""
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now


# Sentinel used when evidence does not support a specific sub-technique.
SUBTECHNIQUE_NOT_DETERMINED = "not_determined"
SUBTECHNIQUE_NAME_NOT_DETERMINED = "Not determined"


class MitreMapping(Base):
    """
    MITRE ATT&CK tactic/technique/sub-technique mapping for one alert.

    A single alert may produce multiple MitreMapping rows (e.g. if an
    alert matches both Reconnaissance and Initial Access tactics).
    """
    __tablename__ = "mitre_mappings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )

    # --- Foreign keys ----------------------------------------------------
    normalised_alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("normalised_alerts.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # Set when the incident is built (nullable until then)
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True, index=True
    )

    # --- Tactic (level 1) ------------------------------------------------
    tactic_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    tactic_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # --- Technique (level 2) ---------------------------------------------
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(256), nullable=False)

    # --- Sub-technique (level 3) -----------------------------------------
    # Either a real ID like "T1071.004" or the sentinel "not_determined"
    subtechnique_id: Mapped[str] = mapped_column(
        String(16), nullable=False,
        default=SUBTECHNIQUE_NOT_DETERMINED, index=True
    )
    subtechnique_name: Mapped[str] = mapped_column(
        String(256), nullable=False,
        default=SUBTECHNIQUE_NAME_NOT_DETERMINED
    )

    # --- Evidence & confidence -------------------------------------------
    # Float 0.0–1.0; higher when payload evidence corroborates the mapping
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    # JSON array of strings — evidence fragments from the alert payload
    # e.g. ["protocol=DNS", "packet_size=4096", "query_entropy=high"]
    # MUST be non-empty when subtechnique_id != "not_determined"
    evidence_strings: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    # How this mapping was produced
    mapping_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="alert_type_lookup"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # --- Relationships ---------------------------------------------------
    normalised_alert: Mapped["NormalisedAlert"] = relationship(
        "NormalisedAlert", back_populates="mitre_mappings"
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident", back_populates="mitre_mappings"
    )

    __table_args__ = (
        Index("ix_mitre_technique_alert", "technique_id", "normalised_alert_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<MitreMapping {self.tactic_name!r} → {self.technique_id!r} "
            f"→ {self.subtechnique_id!r} conf={self.confidence:.2f}>"
        )
