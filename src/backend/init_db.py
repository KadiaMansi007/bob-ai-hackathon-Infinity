"""
Database initialisation script.

Creates all tables defined by the ORM models if they do not already exist.
Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS semantics.

Also applies lightweight column migrations for new fields added after initial
table creation (SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS
in older versions, so we catch the OperationalError).

Usage:
    python -m backend.init_db
    # or from application startup (called by main.py lifespan)
"""
import logging

from sqlalchemy import text

from backend.database import engine
from backend.models import Base  # noqa: F401 — imports all models via __init__

log = logging.getLogger(__name__)

# New columns added after initial schema — (table, column, sql_type, default)
_MIGRATIONS = [
    ("normalised_alerts", "fp_masking_suspected", "BOOLEAN", "0"),
    ("incidents", "fp_masking_warning", "BOOLEAN", "0"),
]


def _apply_migrations() -> None:
    """Add new columns to existing tables if they don't already exist."""
    with engine.connect() as conn:
        for table, column, col_type, default in _MIGRATIONS:
            try:
                conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type} NOT NULL DEFAULT {default}")
                )
                conn.commit()
                log.info("Migration applied: %s.%s", table, column)
            except Exception:
                # Column already exists — safe to ignore
                pass


def init_db() -> None:
    """Create all database tables and apply column migrations."""
    log.info("Initialising database at: %s", engine.url)
    Base.metadata.create_all(bind=engine)
    _apply_migrations()
    log.info("Database initialisation complete — all tables created.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
