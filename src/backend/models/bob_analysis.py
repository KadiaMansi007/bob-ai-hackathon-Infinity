"""
BobAnalysis ORM model.

Stores IBM Bob's independent review of one incident.

This record is Layer 2 — it is written AFTER the deterministic pipeline
(Layer 1) has completed. It never modifies Layer 1 fields.

Key fields:
- bob_classification: Bob's independent verdict (GENUINE_THREAT | FALSE_POSITIVE)
- bob_confidence: Bob's self-reported confidence (0.0–1.0)
- bob_reasoning: Bob's full evidence-grounded reasoning paragraph
- score_explanation_text: Bob's plain-language walkthrough of the risk score
- correlation_review_text: Bob's commentary on the fired correlation rule
- agreement_status: Comparison of bob_classification vs auto_classification
- agreement_detail: Explanation when DISAGREES or PARTIAL
"""
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now
from .enums import AgreementStatus, BobClassification


class BobAnalysis(Base):
    """
    IBM Bob's independent analysis of a single incident.

    One-to-one with Incident (unique constraint on incident_id ensures
    only one active BobAnalysis per incident; re-running analysis
    replaces the existing record).
    """
    __tablename__ = "bob_analyses"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )

    # --- Bob's classification -------------------------------------------
    bob_classification: Mapped[str] = mapped_column(
        String(32), nullable=False, unique=True, index=True
    )
    bob_confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # --- Bob's reasoning (all grounded in MCP-delivered evidence only) ---
    bob_reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    score_explanation_text: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_review_text: Mapped[str] = mapped_column(Text, nullable=False)

    # --- Agreement with deterministic pipeline ---------------------------
    # AGREES | DISAGREES | PARTIAL
    agreement_status: Mapped[str] = mapped_column(
        String(16), nullable=False, unique=True, index=True
    )
    # Non-empty when agreement_status is DISAGREES or PARTIAL
    agreement_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # --- Auditability ----------------------------------------------------
    analysed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    # Model version string for reproducibility audit trail
    bob_model_version: Mapped[str] = mapped_column(
        String(64), nullable=False, default=""
    )

    # --- Relationship ----------------------------------------------------
    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="bob_analysis"
    )

    def __repr__(self) -> str:
        return (
            f"<BobAnalysis incident={self.incident_id!r} "
            f"classification={self.bob_classification!r} "
            f"agreement={self.agreement_status!r} "
            f"confidence={self.bob_confidence:.2f}>"
        )
