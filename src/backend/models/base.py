"""
Base declarative class and shared helpers for all SQLAlchemy ORM models.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, mapped_column, MappedColumn


def utc_now() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Generate a new UUID4 string. Used as the default for all PKs."""
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """
    Shared declarative base for all ORM models.

    All models inherit from this class, which gives them access to
    SQLAlchemy's type annotation mapping and the shared metadata object
    used by create_all() and Alembic.
    """
    pass
