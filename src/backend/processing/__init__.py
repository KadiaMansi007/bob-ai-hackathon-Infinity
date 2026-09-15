"""Processing pipeline package."""
from .pipeline import process_raw_alert, process_feed_run_alerts
from .normaliser import normalise
from .deduplicator import find_duplicate
from .false_positive_filter import apply_fp_rules
from .auto_classifier import classify_incident
from .fingerprint import compute_fingerprint

__all__ = [
    "process_raw_alert",
    "process_feed_run_alerts",
    "normalise",
    "find_duplicate",
    "apply_fp_rules",
    "classify_incident",
    "compute_fingerprint",
]
