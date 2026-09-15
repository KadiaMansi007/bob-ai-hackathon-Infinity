"""
BlufSummary ORM model.

Stores the IBM Bob-generated BLUF (Bottom Line Up Front) investigation
summary for an incident. Bob generates this text only from structured
evidence assembled by evidence_assembler.py — it never invents details.

BLUF format:
  BLUF:            [One sentence — the most critical finding]
  SITUATION:       [2–3 sentences — what happened, which assets, which sources]
  ASSESSMENT:      [2–3 sentences — severity, actor behaviour, MITRE techniques]
  RECOMMENDATIONS: [2–3 actionable bullet points]
"""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now


class BlufSummary(Base):
    """
    Bob-generated BLUF summary for one incident.

    One-to-one with Incident (unique constraint on incident_id).
    Re-generating the BLUF replaces the existing record.
    """
    __tablename__ = "bluf_summaries"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True
    )

    # --- BLUF sections (stored separately for UI rendering) --------------
    bluf_line: Mapped[str] = mapped_column(Text, nullable=False)
    situation: Mapped[str] = mapped_column(Text, nullable=False)
    assessment: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations: Mapped[str] = mapped_column(Text, nullable=False)

    # Full formatted text (all sections joined) — for quick display
    full_text: Mapped[str] = mapped_column(Text, nullable=False)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # --- Relationship ----------------------------------------------------
    incident: Mapped["Incident"] = relationship(
        "Incident", back_populates="bluf_summary"
    )

    def __repr__(self) -> str:
        preview = self.bluf_line[:60] + "..." if len(self.bluf_line) > 60 else self.bluf_line
        return f"<BlufSummary incident={self.incident_id!r} bluf={preview!r}>"
