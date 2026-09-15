"""
Scenario pack definitions for the synthetic feed generator.

Each scenario pack describes a correlated attack storyline that spans
multiple source types. The generator uses these to produce realistic
multi-source alert clusters that will trigger correlation rules C1–C5.

Scenario structure:
  name        — human-readable label
  alerts      — list of alert templates; each is a dict with keys:
                   source_type, alert_type, severity, confidence,
                   target_asset, geo_location, description, extra_fields
  time_spread — max seconds of jitter between alerts in the scenario
"""
from __future__ import annotations

SCENARIO_PACKS: list[dict] = [

    # ------------------------------------------------------------------
    # SCENARIO 1 — APT Lateral Movement
    # Triggers: C1 (SIEM+Sensor same IP), C3 (multi-source convergence)
    # auto_classification: GENUINE_THREAT (GT-01/GT-03)
    # ------------------------------------------------------------------
    {
        "name": "apt_lateral_movement",
        "description": "APT actor performs privilege escalation then lateral movement via SMB",
        "expected_rule": "C3",
        "expected_classification": "GENUINE_THREAT",
        "time_spread": 900,
        "alerts": [
            {
                "source_type": "SIEM",
                "alert_type": "privilege_escalation",
                "severity": "HIGH",
                "confidence": 0.88,
                "target_asset": "srv-dc01",
                "geo_location": "US-EAST",
                "description": "Privilege escalation detected: svcAccount gained SYSTEM token on srv-dc01.",
                "extra": {
                    "user_id": "svcAccount",
                    "hostname": "srv-dc01",
                    "event_count": 3,
                    "process": "lsass.exe",
                },
            },
            {
                "source_type": "CYBER_SENSOR",
                "alert_type": "lateral_movement",
                "severity": "HIGH",
                "confidence": 0.91,
                "target_asset": "srv-dc01",
                "geo_location": "US-EAST",
                "description": "SMB lateral movement from 10.0.0.15 to srv-dc01 on port 445.",
                "extra": {
                    "src_ip": "10.0.0.15",
                    "dst_ip": "10.0.0.5",
                    "protocol": "SMB",
                    "port": 445,
                    "packet_count": 214,
                },
            },
            {
                "source_type": "INTEL_REPORT",
                "alert_type": "ioc_match",
                "severity": "HIGH",
                "confidence": 0.83,
                "target_asset": "srv-dc01",
                "geo_location": "US-EAST",
                "description": "IOC match: 10.0.0.15 linked to APT-29 infrastructure in TI feed.",
                "extra": {
                    "ioc_type": "ip",
                    "ioc_value": "10.0.0.15",
                    "actor_name": "APT-29",
                    "cve_id": None,
                },
            },
        ],
    },

    # ------------------------------------------------------------------
    # SCENARIO 2 — Ransomware Pre-Stage
    # Triggers: C2 (IOC match), C5 (kill-chain Recon→Cred→Exec)
    # auto_classification: GENUINE_THREAT (GT-02)
    # ------------------------------------------------------------------
    {
        "name": "ransomware_prestage",
        "description": "Credential brute force followed by C2 beacon and vulnerability exploitation",
        "expected_rule": "C5",
        "expected_classification": "GENUINE_THREAT",
        "time_spread": 1800,
        "alerts": [
            {
                "source_type": "SIEM",
                "alert_type": "failed_login_burst",
                "severity": "MEDIUM",
                "confidence": 0.79,
                "target_asset": "vpn-gw01",
                "geo_location": "EU-WEST",
                "description": "57 failed login attempts against vpn-gw01 from 185.220.101.47.",
                "extra": {
                    "user_id": "multiple",
                    "hostname": "vpn-gw01",
                    "event_count": 57,
                    "distinct_usernames": 14,
                    "spray": True,
                    "src_ip": "185.220.101.47",
                },
            },
            {
                "source_type": "CYBER_SENSOR",
                "alert_type": "c2_beacon",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "target_asset": "ws-finance-03",
                "geo_location": "EU-WEST",
                "description": "Periodic C2 beacon to 185.220.101.47 via HTTPS from ws-finance-03.",
                "extra": {
                    "src_ip": "10.10.5.3",
                    "dst_ip": "185.220.101.47",
                    "protocol": "HTTPS",
                    "port": 443,
                    "packet_count": 48,
                    "beacon_interval_sec": 60,
                },
            },
            {
                "source_type": "INTEL_REPORT",
                "alert_type": "vulnerability_exploitation",
                "severity": "CRITICAL",
                "confidence": 0.87,
                "target_asset": "vpn-gw01",
                "geo_location": "EU-WEST",
                "description": "CVE-2024-3400 exploitation attempt against PAN-OS VPN gateway.",
                "extra": {
                    "ioc_type": "cve",
                    "ioc_value": "CVE-2024-3400",
                    "actor_name": "UNC4899",
                    "cve_id": "CVE-2024-3400",
                },
            },
        ],
    },

    # ------------------------------------------------------------------
    # SCENARIO 3 — Satellite + Signals Anomaly
    # Triggers: C3 (satellite + sensor in same region)
    # auto_classification: GENUINE_THREAT (GT-03)
    # ------------------------------------------------------------------
    {
        "name": "satellite_anomaly",
        "description": "RF signal anomaly and vessel movement in monitored zone correlated with intel report",
        "expected_rule": "C3",
        "expected_classification": "GENUINE_THREAT",
        "time_spread": 3600,
        "alerts": [
            {
                "source_type": "SATELLITE",
                "alert_type": "rf_signal_anomaly",
                "severity": "HIGH",
                "confidence": 0.76,
                "target_asset": "ZONE-ALPHA-7",
                "geo_location": "34.5N,38.2E",
                "description": "Anomalous RF emission detected at 34.5N 38.2E; signal strength -62dBm.",
                "extra": {
                    "lat": 34.5,
                    "lon": 38.2,
                    "object_id": "ZONE-ALPHA-7",
                    "signal_strength": -62.0,
                    "frequency_mhz": 432.5,
                },
            },
            {
                "source_type": "SATELLITE",
                "alert_type": "anomalous_vessel_movement",
                "severity": "MEDIUM",
                "confidence": 0.71,
                "target_asset": "VESSEL-IMO-9876543",
                "geo_location": "34.6N,38.4E",
                "description": "Vessel IMO-9876543 deviated from filed route by 12nm near ZONE-ALPHA-7.",
                "extra": {
                    "lat": 34.6,
                    "lon": 38.4,
                    "object_id": "VESSEL-IMO-9876543",
                    "signal_strength": -75.0,
                    "deviation_nm": 12,
                },
            },
            {
                "source_type": "INTEL_REPORT",
                "alert_type": "threat_actor_sighting",
                "severity": "HIGH",
                "confidence": 0.80,
                "target_asset": "ZONE-ALPHA-7",
                "geo_location": "34.5N,38.2E",
                "description": "Threat actor group SANDSTORM reported active in ZONE-ALPHA-7 region.",
                "extra": {
                    "ioc_type": "region",
                    "ioc_value": "ZONE-ALPHA-7",
                    "actor_name": "SANDSTORM",
                    "cve_id": None,
                },
            },
        ],
    },

    # ------------------------------------------------------------------
    # SCENARIO 4 — Data Exfiltration
    # Triggers: C1 (SIEM + Sensor), C4 (volume-based)
    # auto_classification: GENUINE_THREAT
    # ------------------------------------------------------------------
    {
        "name": "data_exfiltration",
        "description": "Large data exfiltration via DNS tunnelling and direct C2 channel",
        "expected_rule": "C1",
        "expected_classification": "GENUINE_THREAT",
        "time_spread": 600,
        "alerts": [
            {
                "source_type": "SIEM",
                "alert_type": "data_exfil",
                "severity": "CRITICAL",
                "confidence": 0.93,
                "target_asset": "db-server-01",
                "geo_location": "US-WEST",
                "description": "Unusually large outbound transfer from db-server-01: 2.3GB in 8 minutes.",
                "extra": {
                    "user_id": "db_service",
                    "hostname": "db-server-01",
                    "event_count": 1,
                    "bytes_out": 2469606195,
                    "dst_ip": "45.155.205.233",
                },
            },
            {
                "source_type": "CYBER_SENSOR",
                "alert_type": "dns_tunnelling",
                "severity": "HIGH",
                "confidence": 0.89,
                "target_asset": "db-server-01",
                "geo_location": "US-WEST",
                "description": "DNS tunnelling detected from db-server-01; query entropy 4.9 bits.",
                "extra": {
                    "src_ip": "10.20.1.50",
                    "dst_ip": "45.155.205.233",
                    "protocol": "DNS",
                    "port": 53,
                    "packet_count": 8432,
                    "query_entropy": 4.9,
                },
            },
            {
                "source_type": "CYBER_SENSOR",
                "alert_type": "c2_beacon",
                "severity": "HIGH",
                "confidence": 0.85,
                "target_asset": "db-server-01",
                "geo_location": "US-WEST",
                "description": "Persistent C2 beacon from db-server-01 to 45.155.205.233 via HTTP.",
                "extra": {
                    "src_ip": "10.20.1.50",
                    "dst_ip": "45.155.205.233",
                    "protocol": "HTTP",
                    "port": 80,
                    "packet_count": 156,
                    "beacon_interval_sec": 30,
                },
            },
        ],
    },

    # ------------------------------------------------------------------
    # SCENARIO 5 — False Positive Noise Cluster
    # These are designed to hit FP rules and produce FALSE_POSITIVE incidents
    # ------------------------------------------------------------------
    {
        "name": "false_positive_noise",
        "description": "Low-confidence isolated alerts designed to be filtered as false positives",
        "expected_rule": "C0",
        "expected_classification": "FALSE_POSITIVE",
        "time_spread": 300,
        "alerts": [
            {
                "source_type": "SIEM",
                "alert_type": "failed_login_burst",
                "severity": "LOW",
                "confidence": 0.12,
                "target_asset": "workstation-47",
                "geo_location": "US-CENTRAL",
                "description": "Single failed login on workstation-47 — likely user error.",
                "extra": {
                    "user_id": "jdoe",
                    "hostname": "workstation-47",
                    "event_count": 1,
                    "distinct_usernames": 1,
                    "spray": False,
                },
            },
            {
                "source_type": "SATELLITE",
                "alert_type": "formation_change",
                "severity": "LOW",
                "confidence": 0.18,
                "target_asset": "ZONE-BRAVO-2",
                "geo_location": "52.3N,4.9E",
                "description": "Minor vessel formation change in low-traffic zone BRAVO-2.",
                "extra": {
                    "lat": 52.3,
                    "lon": 4.9,
                    "object_id": "ZONE-BRAVO-2",
                    "signal_strength": -94.0,
                    "deviation_nm": 1,
                },
            },
        ],
    },
]
