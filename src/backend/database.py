"""
Database engine, session factory, and FastAPI dependency.

Usage in FastAPI route handlers:
    from backend.database import get_db
    from sqlalchemy.orm import Session

    def my_route(db: Session = Depends(get_db)):
        ...

Usage in scripts / tests:
    from backend.database import engine, SessionLocal
    with SessionLocal() as session:
        ...
"""
import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./infinity_threat.db")

# connect_args is SQLite-specific: allows the same connection to be used
# across threads (needed by FastAPI's background tasks).
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    echo=os.getenv("LOG_LEVEL", "INFO").upper() == "DEBUG",
)

# Enable WAL mode and foreign-key enforcement for SQLite
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
def get_db() -> Session:
    """
    Yield a database session and guarantee it is closed after the request.

    Use as a FastAPI dependency:
        db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
