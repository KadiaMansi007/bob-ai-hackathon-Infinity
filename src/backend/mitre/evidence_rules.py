"""
Sub-technique evidence rules.

Maps (alert_type, subtechnique_id) → evidence condition function.
Each function accepts a raw_payload dict and returns (matched, evidence_strings).

RULE: A sub-technique is ONLY assigned when the condition function returns
      matched=True AND evidence_strings is non-empty.
      Never invent a sub-technique.
"""
from __future__ import annotations

from typing import Callable


EvidenceFn = Callable[[dict], tuple[bool, list[str]]]

# ---------------------------------------------------------------------------
# Individual evidence functions
# ---------------------------------------------------------------------------

def _spray(p: dict) -> tuple[bool, list[str]]:
    spray = p.get("spray", False)
    distinct = p.get("distinct_usernames", 0)
    try:
        distinct = int(distinct)
    except (TypeError, ValueError):
        distinct = 0
    if spray or distinct > 10:
        evidence = []
        if spray:
            evidence.append("spray=True (password spray pattern detected)")
        if distinct > 10:
            evidence.append(f"distinct_usernames={distinct} (>10)")
        return True, evidence
    return False, []


def _password_guess(p: dict) -> tuple[bool, list[str]]:
    distinct = p.get("distinct_usernames", 0)
    count = p.get("event_count", 0)
    try:
        distinct = int(distinct)
        count = int(count)
    except (TypeError, ValueError):
        return False, []
    if distinct <= 1 and count > 5:
        return True, [f"single_username ({distinct}), high_attempt_count={count}"]
    return False, []


def _smb(p: dict) -> tuple[bool, list[str]]:
    proto = str(p.get("protocol", "")).upper()
    port = p.get("port", 0)
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if proto == "SMB" or port == 445:
        return True, [f"protocol={proto}", f"port={port}"]
    return False, []


def _ssh(p: dict) -> tuple[bool, list[str]]:
    proto = str(p.get("protocol", "")).upper()
    port = p.get("port", 0)
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if proto == "SSH" or port == 22:
        return True, [f"protocol={proto}", f"port={port}"]
    return False, []


def _http_https(p: dict) -> tuple[bool, list[str]]:
    proto = str(p.get("protocol", "")).upper()
    if proto in ("HTTP", "HTTPS"):
        return True, [f"protocol={proto}"]
    return False, []


def _dns(p: dict) -> tuple[bool, list[str]]:
    proto = str(p.get("protocol", "")).upper()
    if proto == "DNS":
        return True, [f"protocol=DNS"]
    return False, []


def _malicious_file(p: dict) -> tuple[bool, list[str]]:
    file_type = str(p.get("file_type", "")).lower()
    if file_type in ("exe", "dll", "ps1", "bat", "vbs", "msi", "scr"):
        return True, [f"file_type={file_type} (executable)"]
    return False, []


def _url_indicator(p: dict) -> tuple[bool, list[str]]:
    if p.get("url_indicator"):
        return True, [f"url_indicator present: {p['url_indicator']}"]
    return False, []


def _ip_range(p: dict) -> tuple[bool, list[str]]:
    ioc_type = str(p.get("ioc_type", "")).lower()
    if ioc_type == "ip_range":
        return True, [f"ioc_type=ip_range"]
    return False, []


def _cve_vuln(p: dict) -> tuple[bool, list[str]]:
    ioc_type = str(p.get("ioc_type", "")).lower()
    cve_id = p.get("cve_id")
    if ioc_type in ("cve", "vuln") or cve_id:
        ev = [f"ioc_type={ioc_type}"]
        if cve_id:
            ev.append(f"cve_id={cve_id}")
        return True, ev
    return False, []


# Always matches for dns_tunnelling alert_type (intrinsically DNS)
def _always_dns(_: dict) -> tuple[bool, list[str]]:
    return True, ["alert_type=dns_tunnelling (intrinsically DNS protocol)"]


# ---------------------------------------------------------------------------
# Rules registry keyed by (alert_type, subtechnique_id)
# ---------------------------------------------------------------------------
SUBTECHNIQUE_EVIDENCE_RULES: dict[tuple[str, str], EvidenceFn] = {
    ("failed_login_burst",   "T1110.003"): _spray,
    ("failed_login_burst",   "T1110.001"): _password_guess,
    ("lateral_movement",     "T1021.002"): _smb,
    ("lateral_movement",     "T1021.004"): _ssh,
    ("c2_beacon",            "T1071.001"): _http_https,
    ("c2_beacon",            "T1071.004"): _dns,
    ("malware_hash_match",   "T1204.002"): _malicious_file,
    ("malware_hash_match",   "T1204.001"): _url_indicator,
    ("dns_tunnelling",       "T1071.004"): _always_dns,
    ("ioc_match",            "T1595.001"): _ip_range,
    ("ioc_match",            "T1595.002"): _cve_vuln,
}
