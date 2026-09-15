"""
Deduplicator — checks whether a NormalisedAlert already exists by fingerprint.

Returns:
  - The existing NormalisedAlert if a duplicate is found (None is not returned
    so callers know to skip persisting the new one).
  - None if no duplicate exists (caller should persist the new alert).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.models import NormalisedAlert


def find_duplicate(session: Session, fingerprint: str) -> NormalisedAlert | None:
    """
    Look up a NormalisedAlert by fingerprint.

    Returns the existing record if found, or None if this is a new alert.
    """
    return (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.fingerprint == fingerprint)
        .first()
    )
