from fastapi import APIRouter, Depends, HTTPException
from core.dependencies import get_current_user
from core.elastic import elastic_client

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/coverage")
async def get_mitre_coverage(current_user: dict = Depends(get_current_user)):
    from services.mitre_mapper.main import MITRE_TECHNIQUES

    total_techniques = 0
    covered_techniques = 0
    coverage_by_tactic = {}

    for tactic_name, tactic_data in MITRE_TECHNIQUES.items():
        tactic_total = len(tactic_data["techniques"])
        tactic_covered = sum(1 for t in tactic_data["techniques"] if t["detections"] > 0)
        total_techniques += tactic_total
        covered_techniques += tactic_covered
        coverage_by_tactic[tactic_name] = {
            "tactic_id": tactic_data["id"],
            "total": tactic_total,
            "covered": tactic_covered,
            "coverage_pct": round((tactic_covered / max(tactic_total, 1)) * 100, 1),
            "techniques": tactic_data["techniques"],
        }

    return {
        "overall_coverage_pct": round((covered_techniques / max(total_techniques, 1)) * 100, 1),
        "total_techniques": total_techniques,
        "covered_techniques": covered_techniques,
        "by_tactic": coverage_by_tactic,
    }


@router.get("/heatmap")
async def get_mitre_heatmap(current_user: dict = Depends(get_current_user)):
    from services.mitre_mapper.main import MITRE_TECHNIQUES

    heatmap = []
    for tactic_name, tactic_data in MITRE_TECHNIQUES.items():
        for tech in tactic_data["techniques"]:
            heatmap.append({
                "tactic": tactic_name.replace("_", " ").title(),
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "detections": tech["detections"],
                "coverage": tech["coverage"],
                "severity": "critical" if tech["coverage"] >= 0.8 else "high" if tech["coverage"] >= 0.5 else "medium" if tech["coverage"] >= 0.3 else "low",
            })

    return heatmap


@router.get("/techniques/{tactic}")
async def get_tactic_techniques(tactic: str, current_user: dict = Depends(get_current_user)):
    from services.mitre_mapper.main import MITRE_TECHNIQUES

    data = MITRE_TECHNIQUES.get(tactic)
    if not data:
        raise HTTPException(status_code=404, detail=f"Tactic '{tactic}' not found")
    return data
