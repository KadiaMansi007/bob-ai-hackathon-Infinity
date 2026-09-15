"""
Database initialisation script.

Creates all tables defined by the ORM models if they do not already exist.
Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS semantics.

Usage:
    python -m backend.init_db
    # or from application startup (called by main.py lifespan)
"""
import logging

from backend.database import engine
from backend.models import Base  # noqa: F401 — imports all models via __init__

log = logging.getLogger(__name__)


def init_db() -> None:
    """Create all database tables."""
    log.info("Initialising database at: %s", engine.url)
    Base.metadata.create_all(bind=engine)
    log.info("Database initialisation complete — all tables created.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
