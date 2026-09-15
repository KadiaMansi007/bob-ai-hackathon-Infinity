"""FastAPI route handlers — package init."""
from .feeds import router as feeds_router
from .alerts import router as alerts_router
from .incidents import router as incidents_router
from .bob import router as bob_router
from .dashboard import router as dashboard_router
from .mitre import router as mitre_router

__all__ = [
    "feeds_router", "alerts_router", "incidents_router",
    "bob_router", "dashboard_router", "mitre_router",
]
