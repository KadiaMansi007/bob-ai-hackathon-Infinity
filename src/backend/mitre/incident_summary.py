"""
Incident MITRE summary — aggregates all mappings for an incident.

Used by the MCP get_mitre_summary tool and the /mitre/matrix endpoint.
Also applies cross-source corroboration confidence upgrades.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.models import IncidentAlert, MitreMapping, NormalisedAlert


def get_incident_mitre_summary(session: Session, incident_id: str) -> dict:
    """
    Return a structured MITRE hierarchy for all member alerts of an incident.

    Applies cross-source corroboration: if two different source_types produce
    mappings to the same sub-technique, confidence is upgraded and
    mapping_method becomes 'cross_source_corroboration'.

    Returns dict with keys:
      incident_id, mappings (list), tactic_summary (dict tactic→techniques)
    """
    links = (
        session.query(IncidentAlert)
        .filter(IncidentAlert.incident_id == incident_id)
        .all()
    )
    if not links:
        return {"incident_id": incident_id, "mappings": [], "tactic_summary": {}}

    alert_ids = [l.normalised_alert_id for l in links]

    # Load all MitreMapping rows for these alerts
    mappings = (
        session.query(MitreMapping)
        .filter(MitreMapping.normalised_alert_id.in_(alert_ids))
        .all()
    )

    # Update incident_id on mappings that don't have it set
    for mm in mappings:
        if mm.incident_id is None:
            mm.incident_id = incident_id
    if mappings:
        session.flush()

    # Build source-type index for corroboration check
    alert_source_map: dict[str, str] = {}
    alerts = (
        session.query(NormalisedAlert)
        .filter(NormalisedAlert.id.in_(alert_ids))
        .all()
    )
    for a in alerts:
        alert_source_map[a.id] = a.source_type

    # Group by (technique_id, subtechnique_id) to find corroborated mappings
    subtechnique_sources: dict[tuple, set] = {}
    for mm in mappings:
        key = (mm.technique_id, mm.subtechnique_id)
        src = alert_source_map.get(mm.normalised_alert_id, "UNKNOWN")
        subtechnique_sources.setdefault(key, set()).add(src)

    # Apply corroboration upgrade
    for mm in mappings:
        key = (mm.technique_id, mm.subtechnique_id)
        if (
            len(subtechnique_sources.get(key, set())) >= 2
            and mm.subtechnique_id != "not_determined"
            and mm.mapping_method != "cross_source_corroboration"
        ):
            mm.mapping_method = "cross_source_corroboration"
            mm.confidence = min(1.0, mm.confidence * 1.15)

    if mappings:
        session.flush()

    # Build structured output
    mapping_list = []
    for mm in mappings:
        mapping_list.append({
            "id": mm.id,
            "alert_id": mm.normalised_alert_id,
            "tactic_id": mm.tactic_id,
            "tactic_name": mm.tactic_name,
            "technique_id": mm.technique_id,
            "technique_name": mm.technique_name,
            "subtechnique_id": mm.subtechnique_id,
            "subtechnique_name": mm.subtechnique_name,
            "confidence": round(mm.confidence, 3),
            "evidence_strings": mm.evidence_strings or [],
            "mapping_method": mm.mapping_method,
        })

    # Build tactic summary for heatmap
    tactic_summary: dict = {}
    for item in mapping_list:
        tname = item["tactic_name"]
        tactic_summary.setdefault(tname, {})
        tid = item["technique_id"]
        tactic_summary[tname].setdefault(tid, {
            "technique_name": item["technique_name"],
            "subtechniques": {}
        })
        sub_id = item["subtechnique_id"]
        tactic_summary[tname][tid]["subtechniques"][sub_id] = {
            "name": item["subtechnique_name"],
            "confidence": item["confidence"],
            "evidence_strings": item["evidence_strings"],
            "mapping_method": item["mapping_method"],
        }

    return {
        "incident_id": incident_id,
        "mappings": mapping_list,
        "tactic_summary": tactic_summary,
    }
