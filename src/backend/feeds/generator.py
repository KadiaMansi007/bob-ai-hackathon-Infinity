"""
Synthetic feed generator — orchestrates all four source types.

Creates RawAlert rows in the database for one feed run.
Returns a FeedRun record with counts.

Usage:
    from backend.feeds.generator import run_feed_generation
    feed_run = run_feed_generation(session, scenario="apt_lateral_movement", seed=42)
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.models import FeedRun, RawAlert, SourceType
from backend.feeds.scenario_packs import SCENARIO_PACKS


# -----------------------------------------------------------------------
# Noise alert templates (random background traffic in addition to scenarios)
# -----------------------------------------------------------------------
_SIEM_NOISE = [
    {"alert_type": "failed_login_burst", "severity": "LOW", "confidence_range": (0.10, 0.35),
     "target_assets": ["workstation-{n}", "laptop-{n}"],
     "extra_fn": lambda rng: {"user_id": f"user{rng.randint(1,50)}", "hostname": f"ws-{rng.randint(1,20)}", "event_count": rng.randint(1,3), "distinct_usernames": 1, "spray": False}},
    {"alert_type": "port_scan", "severity": "MEDIUM", "confidence_range": (0.40, 0.65),
     "target_assets": ["dmz-host-{n}"],
     "extra_fn": lambda rng: {"src_ip": f"192.168.{rng.randint(1,10)}.{rng.randint(1,254)}", "dst_ip": f"10.0.0.{rng.randint(1,50)}", "protocol": "TCP", "packet_count": rng.randint(100,5000)}},
]
_SENSOR_NOISE = [
    {"alert_type": "port_scan", "severity": "LOW", "confidence_range": (0.20, 0.45),
     "target_assets": ["10.0.0.{n}"],
     "extra_fn": lambda rng: {"src_ip": f"172.16.{rng.randint(1,5)}.{rng.randint(1,254)}", "dst_ip": f"10.0.0.{rng.randint(1,50)}", "protocol": "TCP", "packet_count": rng.randint(50,500)}},
    {"alert_type": "malware_hash_match", "severity": "MEDIUM", "confidence_range": (0.30, 0.55),
     "target_assets": ["endpoint-{n}"],
     "extra_fn": lambda rng: {"src_ip": f"10.1.{rng.randint(1,5)}.{rng.randint(1,100)}", "dst_ip": "0.0.0.0", "protocol": "N/A", "packet_count": 1, "file_type": rng.choice(["exe", "dll", "ps1"]), "hash": uuid.uuid4().hex}},
]
_SAT_NOISE = [
    {"alert_type": "formation_change", "severity": "LOW", "confidence_range": (0.10, 0.25),
     "target_assets": ["ZONE-NOISE-{n}"],
     "extra_fn": lambda rng: {"lat": round(rng.uniform(-60, 60), 2), "lon": round(rng.uniform(-180, 180), 2), "object_id": f"VESSEL-NOISE-{rng.randint(1000,9999)}", "signal_strength": rng.uniform(-95, -88), "deviation_nm": rng.randint(0,2)}},
]
_INTEL_NOISE = [
    {"alert_type": "ioc_match", "severity": "LOW", "confidence_range": (0.10, 0.28),
     "target_assets": ["unknown-host-{n}"],
     "extra_fn": lambda rng: {"ioc_type": "domain", "ioc_value": f"noise-{rng.randint(1000,9999)}.example.com", "actor_name": None, "cve_id": None}},
]


def _make_noise_alert(
    template: dict, rng: random.Random, window_start: datetime, window_seconds: int
) -> dict:
    n = rng.randint(1, 99)
    target = rng.choice(template["target_assets"]).format(n=n)
    conf_lo, conf_hi = template["confidence_range"]
    ts = window_start + timedelta(seconds=rng.randint(0, window_seconds))
    return {
        "source_type": None,  # set by caller
        "alert_type": template["alert_type"],
        "severity": template["severity"],
        "confidence": round(rng.uniform(conf_lo, conf_hi), 3),
        "target_asset": target,
        "geo_location": f"REGION-{rng.randint(1,5)}",
        "description": f"Background noise: {template['alert_type']} on {target}.",
        "extra": template["extra_fn"](rng),
        "timestamp": ts,
    }


def _scenario_alerts(
    scenario: dict, rng: random.Random, window_start: datetime
) -> list[dict]:
    """Expand a scenario pack into concrete alert dicts with jittered timestamps."""
    results = []
    spread = scenario["time_spread"]
    base_ts = window_start + timedelta(seconds=rng.randint(0, max(0, 3600 - spread)))
    for i, tmpl in enumerate(scenario["alerts"]):
        ts = base_ts + timedelta(seconds=rng.randint(0, spread))
        a = {
            "source_type": tmpl["source_type"],
            "alert_type": tmpl["alert_type"],
            "severity": tmpl["severity"],
            "confidence": tmpl["confidence"],
            "target_asset": tmpl["target_asset"],
            "geo_location": tmpl["geo_location"],
            "description": tmpl["description"],
            "extra": tmpl["extra"],
            "timestamp": ts,
        }
        results.append(a)
    return results


def run_feed_generation(
    session: Session,
    scenario: str = "random",
    seed: int | None = None,
    noise_count: int = 12,
) -> FeedRun:
    """
    Generate synthetic alerts for one feed run.

    Args:
        session:     SQLAlchemy session (caller manages commit).
        scenario:    "random" runs all 5 scenarios; otherwise runs by name.
        seed:        Integer seed for reproducible output.
        noise_count: Number of background noise alerts to add per run.

    Returns:
        FeedRun record (flushed but not committed).
    """
    rng = random.Random(seed)
    window_start = datetime.now(timezone.utc) - timedelta(hours=6)
    window_seconds = 6 * 3600

    # --- Create FeedRun record -------------------------------------------
    feed_run = FeedRun(
        scenario=scenario,
        seed=seed,
        status="running",
        source_counts={},
    )
    session.add(feed_run)
    session.flush()

    # --- Select scenarios to run -----------------------------------------
    if scenario == "random":
        packs = SCENARIO_PACKS
    else:
        packs = [p for p in SCENARIO_PACKS if p["name"] == scenario]
        if not packs:
            packs = SCENARIO_PACKS

    # --- Generate scenario alerts ----------------------------------------
    all_alert_dicts: list[tuple[str, dict]] = []  # (source_type, dict)
    for pack in packs:
        for alert in _scenario_alerts(pack, rng, window_start):
            all_alert_dicts.append((alert["source_type"], alert))

    # --- Generate noise alerts -------------------------------------------
    noise_templates = [
        (SourceType.SIEM.value, _SIEM_NOISE),
        (SourceType.CYBER_SENSOR.value, _SENSOR_NOISE),
        (SourceType.SATELLITE.value, _SAT_NOISE),
        (SourceType.INTEL_REPORT.value, _INTEL_NOISE),
    ]
    for _ in range(noise_count):
        src_type, templates = rng.choice(noise_templates)
        tmpl = rng.choice(templates)
        alert = _make_noise_alert(tmpl, rng, window_start, window_seconds)
        alert["source_type"] = src_type
        all_alert_dicts.append((src_type, alert))

    # --- Persist RawAlert rows -------------------------------------------
    source_counts: dict[str, int] = {}
    raw_alerts: list[RawAlert] = []

    for source_type, alert_dict in all_alert_dicts:
        ts = alert_dict.get("timestamp", window_start)
        payload: dict[str, Any] = {
            "alert_type": alert_dict["alert_type"],
            "severity": alert_dict["severity"],
            "confidence": alert_dict["confidence"],
            "target_asset": alert_dict["target_asset"],
            "geo_location": alert_dict["geo_location"],
            "description": alert_dict["description"],
            "timestamp": ts.isoformat(),
            **alert_dict.get("extra", {}),
        }
        raw = RawAlert(
            source_type=source_type,
            source_name=_source_name(source_type, rng),
            feed_run_id=feed_run.id,
            raw_payload=payload,
            received_at=datetime.now(timezone.utc),
        )
        session.add(raw)
        raw_alerts.append(raw)
        source_counts[source_type] = source_counts.get(source_type, 0) + 1

    session.flush()

    # --- Update FeedRun with counts --------------------------------------
    feed_run.alerts_generated = len(raw_alerts)
    feed_run.source_counts = source_counts
    feed_run.status = "completed"
    feed_run.completed_at = datetime.now(timezone.utc)
    session.flush()

    return feed_run


def _source_name(source_type: str, rng: random.Random) -> str:
    names = {
        SourceType.SIEM.value: ["splunk-prod", "qradar-primary", "sentinel-corp"],
        SourceType.CYBER_SENSOR.value: ["suricata-dmz", "snort-perimeter", "darktrace-east"],
        SourceType.SATELLITE.value: ["sat-feed-primary", "geoint-stream-01", "leo-watch"],
        SourceType.INTEL_REPORT.value: ["ti-feed-mandiant", "misp-community", "crowdstrike-intel"],
    }
    return rng.choice(names.get(source_type, ["unknown-source"]))
