"""
RawAlert ORM model.

One row per alert as received from any feed source, before normalisation.
The raw payload is stored verbatim so it is never lost during processing.
"""
from datetime import datetime

from sqlalchemy import DateTime, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, new_uuid, utc_now
from .enums import SourceType


class RawAlert(Base):
    """
    Raw alert exactly as delivered by a feed generator.

    This table is append-only. Nothing is ever deleted from it.
    The normalised_alerts table holds the processed version.
    """
    __tablename__ = "raw_alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    source_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    feed_run_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    # Relationship to the normalised version (may be None if still pending)
    normalised_alert: Mapped["NormalisedAlert | None"] = relationship(
        "NormalisedAlert", back_populates="raw_alert", uselist=False
    )

    def __repr__(self) -> str:
        return (
            f"<RawAlert id={self.id!r} source={self.source_type!r} "
            f"received_at={self.received_at!r}>"
        )
