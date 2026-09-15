"""
RiskScore ORM model.

Stores the explainable 5-component risk score for each incident.
Every component is stored as a separate float column so the frontend
and IBM Bob can narrate each element individually rather than just
displaying a single opaque number.

Scoring formula (from the plan):
  total_score = (
      severity_component      * 0.35
    + confidence_component    * 0.25
    + source_diversity        * 0.20
    + asset_criticality       * 0.10
    + temporal_recency        * 0.10
  ) clamped to [0, 100]
"""
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now


class RiskScore(Base):
    """
    Explainable risk score for one incident.

    One-to-one with Incident (each incident has at most one RiskScore row;
    it is replaced when the incident is updated with new member alerts).
    """
    __tablename__ = "risk_scores"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )

    # --- Composite score -------------------------------------------------
    total_score: Mapped[float] = mapped_column(Float, nullable=False)

    # --- Individual components (0–100 scale before weighting) -----------
    severity_component: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_component: Mapped[float] = mapped_column(Float, nullable=False)
    source_diversity_component: Mapped[float] = mapped_column(Float, nullable=False)
    asset_criticality_component: Mapped[float] = mapped_column(Float, nullable=False)
    temporal_component: Mapped[float] = mapped_column(Float, nullable=False)

    # --- Full explanation JSON -------------------------------------------
    # Structure:
    # {
    #   "total_score": 82.5,
    #   "priority_label": "P1 — Immediate Action",
    #   "components": {
    #     "severity":          {"value": 35.0, "weight": 0.35, "raw": 100, "reason": "..."},
    #     "confidence":        {"value": 18.75, "weight": 0.25, "raw": 75,  "reason": "..."},
    #     "source_diversity":  {"value": 15.0, "weight": 0.20, "raw": 75,  "reason": "..."},
    #     "asset_criticality": {"value": 10.0, "weight": 0.10, "raw": 100, "reason": "..."},
    #     "temporal_recency":  {"value": 8.75, "weight": 0.10, "raw": 87.5,"reason": "..."}
    #   }
    # }
    explanation: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    scored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # --- Relationship ----------------------------------------------------
    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="risk_score"
    )

    def __repr__(self) -> str:
        return (
            f"<RiskScore incident={self.incident_id!r} "
            f"total={self.total_score:.1f}>"
        )
