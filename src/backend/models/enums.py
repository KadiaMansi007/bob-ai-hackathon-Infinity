"""
Shared enumerations used across multiple ORM models.

These are Python enums stored as VARCHAR columns in SQLite.
Using string values (not integers) keeps the database human-readable
and safe against enum reordering.
"""
import enum


class SourceType(str, enum.Enum):
    """The four simulated feed source types."""
    SIEM = "SIEM"
    CYBER_SENSOR = "CYBER_SENSOR"
    SATELLITE = "SATELLITE"
    INTEL_REPORT = "INTEL_REPORT"


class Severity(str, enum.Enum):
    """Normalised alert/incident severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    """Lifecycle status of a correlated incident."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AutoClassification(str, enum.Enum):
    """
    Deterministic pipeline classification — set by the auto-classifier,
    never by IBM Bob. Both pipeline and Bob decisions are stored separately.
    """
    GENUINE_THREAT = "GENUINE_THREAT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCLASSIFIED = "UNCLASSIFIED"


class BobClassification(str, enum.Enum):
    """IBM Bob's independent classification of an incident."""
    GENUINE_THREAT = "GENUINE_THREAT"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AgreementStatus(str, enum.Enum):
    """
    Agreement between the deterministic auto_classification and Bob's
    independent bob_classification. DISAGREES is an analytical signal,
    not an error.
    """
    AGREES = "AGREES"
    DISAGREES = "DISAGREES"
    PARTIAL = "PARTIAL"
