"""
Processing pipeline — orchestrates the full Layer-1 deterministic pipeline.

For each RawAlert:
  1. Normalise
  2. Fingerprint + deduplicate
  3. Apply FP pre-filter
  4. Persist NormalisedAlert
  5. (Correlation and scoring happen separately — called from the ingestor
     after all alerts in a batch are normalised)

process_raw_alert() returns the NormalisedAlert or None (if duplicate).
run_batch_pipeline() handles the full flow for a FeedRun.
"""
from __future__ import annotations

import logging
from sqlalchemy.orm import Session

from backend.models import RawAlert, NormalisedAlert
from backend.processing.normaliser import normalise
from backend.processing.deduplicator import find_duplicate
from backend.processing.false_positive_filter import apply_fp_rules

log = logging.getLogger(__name__)


def process_raw_alert(
    session: Session, raw_alert: RawAlert
) -> NormalisedAlert | None:
    """
    Run one RawAlert through normalise → dedup → FP-filter.

    Returns the new NormalisedAlert (flushed, not committed) or None if
    the alert was a duplicate.
    """
    # Step 1 — Normalise
    normalised = normalise(raw_alert)

    # Step 2 — Dedup check
    existing = find_duplicate(session, normalised.fingerprint)
    if existing is not None:
        log.debug(
            "Duplicate alert fingerprint=%s (existing id=%s), skipping.",
            normalised.fingerprint[:12], existing.id
        )
        return None

    # Step 3 — FP pre-filter
    normalised = apply_fp_rules(normalised)

    # Step 4 — Persist
    session.add(normalised)
    session.flush()

    log.debug(
        "Normalised alert id=%s type=%s fp=%s",
        normalised.id, normalised.alert_type, normalised.is_false_positive
    )
    return normalised


def process_feed_run_alerts(
    session: Session, feed_run_id: str
) -> tuple[list[NormalisedAlert], int]:
    """
    Process all RawAlerts belonging to a FeedRun.

    Returns:
        (list of new NormalisedAlerts, count of duplicates skipped)
    """
    from backend.models import RawAlert as RA
    raw_alerts = (
        session.query(RA)
        .filter(RA.feed_run_id == feed_run_id)
        .all()
    )

    new_alerts: list[NormalisedAlert] = []
    duplicates = 0

    for raw in raw_alerts:
        result = process_raw_alert(session, raw)
        if result is not None:
            new_alerts.append(result)
        else:
            duplicates += 1

    return new_alerts, duplicates
