"""FastAPI route handlers for MITRE ATT&CK matrix."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import MitreMapping

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/matrix", summary="All MITRE technique mappings aggregated for heatmap")
def get_matrix(db: Session = Depends(get_db)):
    mappings = db.query(MitreMapping).all()

    # Aggregate by tactic/technique/subtechnique
    matrix: dict = {}
    for mm in mappings:
        tactic = mm.tactic_name
        tech = mm.technique_id
        sub = mm.subtechnique_id

        matrix.setdefault(tactic, {})
        matrix[tactic].setdefault(tech, {
            "technique_name": mm.technique_name,
            "count": 0,
            "max_confidence": 0.0,
            "subtechniques": {}
        })
        matrix[tactic][tech]["count"] += 1
        matrix[tactic][tech]["max_confidence"] = max(
            matrix[tactic][tech]["max_confidence"], mm.confidence
        )
        matrix[tactic][tech]["subtechniques"].setdefault(sub, {
            "name": mm.subtechnique_name,
            "count": 0,
            "confidence": 0.0,
            "evidence_strings": [],
        })
        matrix[tactic][tech]["subtechniques"][sub]["count"] += 1
        matrix[tactic][tech]["subtechniques"][sub]["confidence"] = max(
            matrix[tactic][tech]["subtechniques"][sub]["confidence"], mm.confidence
        )
        for ev in (mm.evidence_strings or []):
            if ev not in matrix[tactic][tech]["subtechniques"][sub]["evidence_strings"]:
                matrix[tactic][tech]["subtechniques"][sub]["evidence_strings"].append(ev)

    return {"matrix": matrix, "total_mappings": len(mappings)}
