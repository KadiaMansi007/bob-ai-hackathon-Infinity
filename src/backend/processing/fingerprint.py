"""
Fingerprint computation for deduplication.

The fingerprint is a SHA-256 hash of:
  source_type + alert_type + target_asset + 5-minute time bucket

Two alerts that are identical in these four dimensions within the same
5-minute window are considered duplicates.
"""
from __future__ import annotations

import hashlib
from datetime import datetime


def _five_minute_bucket(ts: datetime) -> str:
    """Return a string representing the 5-minute bucket for a timestamp."""
    bucket_minute = (ts.minute // 5) * 5
    return f"{ts.year}{ts.month:02d}{ts.day:02d}{ts.hour:02d}{bucket_minute:02d}"


def compute_fingerprint(
    source_type: str,
    alert_type: str,
    target_asset: str,
    timestamp: datetime,
) -> str:
    """
    Compute a 64-character hex SHA-256 fingerprint for deduplication.

    Two alerts with the same (source_type, alert_type, target_asset)
    occurring within the same 5-minute window produce the same fingerprint.
    """
    bucket = _five_minute_bucket(timestamp)
    raw = f"{source_type}|{alert_type}|{target_asset.lower().strip()}|{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
