"""
Alert normaliser — converts a RawAlert payload into a NormalisedAlert.

This is a pure function: no database access, no side effects.
Input:  RawAlert ORM object
Output: NormalisedAlert ORM object (not yet persisted)

Normalisation covers:
- Severity mapping (source strings → canonical LOW/MEDIUM/HIGH/CRITICAL)
- Confidence extraction (float 0.0–1.0)
- Target asset extraction (source-type-specific logic)
- Geo-location extraction
- Timestamp parsing (to UTC datetime)
- Description concatenation
- Raw payload preservation
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.models import NormalisedAlert, RawAlert, Severity, SourceType
from backend.processing.fingerprint import compute_fingerprint


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
_SEVERITY_MAP: dict[str, str] = {
    "critical": Severity.CRITICAL.value,
    "high":     Severity.HIGH.value,
    "medium":   Severity.MEDIUM.value,
    "med":      Severity.MEDIUM.value,
    "low":      Severity.LOW.value,
    "info":     Severity.LOW.value,
    "informational": Severity.LOW.value,
    "warning":  Severity.MEDIUM.value,
    "severe":   Severity.HIGH.value,
}

def _map_severity(raw: Any) -> str:
    if isinstance(raw, str):
        return _SEVERITY_MAP.get(raw.lower().strip(), Severity.MEDIUM.value)
    if isinstance(raw, (int, float)):
        if raw >= 9:   return Severity.CRITICAL.value
        if raw >= 7:   return Severity.HIGH.value
        if raw >= 4:   return Severity.MEDIUM.value
        return Severity.LOW.value
    return Severity.MEDIUM.value


def _map_confidence(payload: dict) -> float:
    raw = payload.get("confidence", 0.5)
    try:
        v = float(raw)
        return max(0.0, min(1.0, v))
    except (TypeError, ValueError):
        return 0.5


def _parse_timestamp(payload: dict) -> datetime:
    raw = payload.get("timestamp")
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw
    if isinstance(raw, str):
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _extract_target_asset(source_type: str, payload: dict) -> str:
    """Source-type-specific target asset extraction."""
    if source_type == SourceType.SIEM.value:
        return (payload.get("hostname") or payload.get("target_asset") or "unknown-host")
    if source_type == SourceType.CYBER_SENSOR.value:
        return (payload.get("dst_ip") or payload.get("target_asset") or "unknown-ip")
    if source_type == SourceType.SATELLITE.value:
        return (payload.get("object_id") or payload.get("target_asset") or "unknown-object")
    if source_type == SourceType.INTEL_REPORT.value:
        return (payload.get("ioc_value") or payload.get("target_asset") or "unknown-ioc")
    return payload.get("target_asset", "unknown")


def _extract_geo(source_type: str, payload: dict) -> str | None:
    if source_type == SourceType.SATELLITE.value:
        lat = payload.get("lat")
        lon = payload.get("lon")
        if lat is not None and lon is not None:
            return f"{lat}N,{lon}E"
    return payload.get("geo_location") or payload.get("region")


def normalise(raw_alert: RawAlert) -> NormalisedAlert:
    """
    Convert a RawAlert into a NormalisedAlert (not yet persisted).

    This function is pure: it does not read or write the database.
    """
    p = raw_alert.raw_payload  # convenience alias
    source_type = raw_alert.source_type
    alert_type = p.get("alert_type", "unknown")
    severity = _map_severity(p.get("severity", "medium"))
    confidence = _map_confidence(p)
    timestamp = _parse_timestamp(p)
    target_asset = _extract_target_asset(source_type, p)
    geo_location = _extract_geo(source_type, p)
    description = p.get("description") or f"{alert_type} from {source_type}"

    fingerprint = compute_fingerprint(source_type, alert_type, target_asset, timestamp)

    return NormalisedAlert(
        raw_alert_id=raw_alert.id,
        source_type=source_type,
        source_name=raw_alert.source_name,
        alert_type=alert_type,
        severity=severity,
        confidence=confidence,
        timestamp=timestamp,
        target_asset=target_asset,
        geo_location=geo_location,
        description=description,
        raw_payload=p,
        fingerprint=fingerprint,
        is_false_positive=False,
        fp_reason=None,
    )
