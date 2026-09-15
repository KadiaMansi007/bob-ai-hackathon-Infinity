"""
MITRE ATT&CK mapper — maps a NormalisedAlert to the full hierarchy.

Resolution logic (from the plan):
1. Look up alert_type in mitre_data.json → get tactic + parent technique
2. Iterate sub-technique evidence rules for this (alert_type, subtechnique_id)
3. If evidence condition matches → assign sub-technique, store evidence_strings
4. If no evidence condition matches → set subtechnique_id = "not_determined"
5. NEVER assign a sub-technique without a matching evidence string

Base confidence calculation:
  - payload_keyword  mapping:  alert.confidence × 0.9
  - alert_type_lookup mapping: alert.confidence × 0.7
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from backend.models import MitreMapping, NormalisedAlert
from backend.models.mitre_mapping import SUBTECHNIQUE_NOT_DETERMINED, SUBTECHNIQUE_NAME_NOT_DETERMINED
from backend.mitre.evidence_rules import SUBTECHNIQUE_EVIDENCE_RULES

log = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent / "mitre_data.json"
_MITRE_DATA: dict | None = None


def _load_data() -> dict:
    global _MITRE_DATA
    if _MITRE_DATA is None:
        with open(_DATA_PATH, "r", encoding="utf-8") as fh:
            _MITRE_DATA = json.load(fh)
    return _MITRE_DATA


def map_alert(
    session: Session, alert: NormalisedAlert
) -> list[MitreMapping]:
    """
    Map one NormalisedAlert to one or more MitreMapping records.

    Returns a list of persisted (flushed) MitreMapping rows.
    Returns empty list if alert_type is not in the mapping table.
    """
    data = _load_data()
    mapping_entry = data["alert_type_mappings"].get(alert.alert_type)
    if not mapping_entry:
        log.debug("No MITRE mapping for alert_type=%s", alert.alert_type)
        return []

    technique_id = mapping_entry["technique_id"]
    technique = data["techniques"].get(technique_id)
    if not technique:
        return []

    tactic_id = technique["tactic_id"]
    tactic = data["tactics"].get(tactic_id, {})
    tactic_name = tactic.get("name", tactic_id)
    technique_name = technique["name"]
    subtechniques = technique.get("subtechniques", {})

    results: list[MitreMapping] = []

    if not subtechniques:
        # No sub-techniques defined in ATT&CK for this technique
        mm = _make_mapping(
            alert=alert,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            technique_id=technique_id,
            technique_name=technique_name,
            subtechnique_id=SUBTECHNIQUE_NOT_DETERMINED,
            subtechnique_name=SUBTECHNIQUE_NAME_NOT_DETERMINED,
            confidence=round(alert.confidence * 0.7, 3),
            evidence_strings=[],
            mapping_method="alert_type_lookup",
        )
        session.add(mm)
        session.flush()
        results.append(mm)
        return results

    # Try each sub-technique in order
    resolved = False
    for sub_id, sub_info in subtechniques.items():
        rule_fn = SUBTECHNIQUE_EVIDENCE_RULES.get((alert.alert_type, sub_id))
        if rule_fn is None:
            continue
        matched, evidence_strings = rule_fn(alert.raw_payload or {})
        if matched and evidence_strings:
            mm = _make_mapping(
                alert=alert,
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                technique_id=technique_id,
                technique_name=technique_name,
                subtechnique_id=sub_id,
                subtechnique_name=sub_info["name"],
                confidence=round(alert.confidence * 0.9, 3),
                evidence_strings=evidence_strings,
                mapping_method="payload_keyword",
            )
            session.add(mm)
            session.flush()
            results.append(mm)
            resolved = True
            break  # first matching sub-technique wins

    if not resolved:
        # Fallback to not_determined
        mm = _make_mapping(
            alert=alert,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            technique_id=technique_id,
            technique_name=technique_name,
            subtechnique_id=SUBTECHNIQUE_NOT_DETERMINED,
            subtechnique_name=SUBTECHNIQUE_NAME_NOT_DETERMINED,
            confidence=round(alert.confidence * 0.7, 3),
            evidence_strings=[],
            mapping_method="alert_type_lookup",
        )
        session.add(mm)
        session.flush()
        results.append(mm)

    return results


def _make_mapping(
    alert: NormalisedAlert,
    tactic_id: str,
    tactic_name: str,
    technique_id: str,
    technique_name: str,
    subtechnique_id: str,
    subtechnique_name: str,
    confidence: float,
    evidence_strings: list[str],
    mapping_method: str,
) -> MitreMapping:
    return MitreMapping(
        normalised_alert_id=alert.id,
        incident_id=None,  # set later when incident is built
        tactic_id=tactic_id,
        tactic_name=tactic_name,
        technique_id=technique_id,
        technique_name=technique_name,
        subtechnique_id=subtechnique_id,
        subtechnique_name=subtechnique_name,
        confidence=confidence,
        evidence_strings=evidence_strings,
        mapping_method=mapping_method,
    )
