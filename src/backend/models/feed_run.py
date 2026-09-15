"""
FeedRun ORM model.

Records each synthetic feed generation run. Used for:
- Audit trail of when data was ingested
- The /api/v1/feeds/runs endpoint
- Reproducibility (seed is stored so a run can be replayed)
"""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, new_uuid, utc_now


class FeedRun(Base):
    """
    Log of one synthetic feed generation run.

    Created when POST /api/v1/feeds/ingest is called.
    Updated when the run completes (alert counts populated).
    """
    __tablename__ = "feed_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )

    # Scenario requested: "random", "apt_lateral_movement", etc.
    scenario: Mapped[str] = mapped_column(
        String(64), nullable=False, default="random"
    )

    # Optional seed used for deterministic generation
    seed: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Timestamps
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Alert counts per source type (populated on completion)
    alerts_generated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_deduplicated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incidents_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Per-source breakdown JSON e.g. {"SIEM": 10, "CYBER_SENSOR": 8, ...}
    source_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Status: "running" | "completed" | "failed"
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="running"
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<FeedRun id={self.id!r} scenario={self.scenario!r} "
            f"status={self.status!r} alerts={self.alerts_generated}>"
        )
