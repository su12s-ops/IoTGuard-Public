from collections import Counter, defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models
from app.database import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    vulnerabilities = db.query(models.VulnerabilityInfo).all()
    kev_count = db.query(models.ThreatIntelSource).filter_by(is_kev=True).count()
    assets = db.query(models.LinuxAsset).all()
    affected_asset_ids = {m.asset_id for m in db.query(models.VulnerabilityMatch).filter_by(affected=True).all()}
    risks = db.query(models.RiskAssessment).all()
    # 候选阶段 final=0：统一按"有效分数"（final 或 preliminary）排序与展示
    for risk in risks:
        risk._display_score = risk.final_score if risk.final_score and risk.final_score > 0 else (risk.preliminary_score or 0)
        risk._display_level = risk.risk_level if risk.final_score and risk.final_score > 0 else (risk.preliminary_level or "Low")
    risks.sort(key=lambda r: r._display_score, reverse=True)
    risk_dist = Counter(r._display_level for r in risks)
    source_dist = Counter(v.source for v in vulnerabilities)
    top_assets_map = defaultdict(float)
    for risk in risks:
        top_assets_map[risk.asset_id] = max(top_assets_map[risk.asset_id], risk._display_score)
    top_assets = []
    for asset_id, score in sorted(top_assets_map.items(), key=lambda item: item[1], reverse=True)[:5]:
        asset = db.get(models.LinuxAsset, asset_id)
        top_assets.append({"asset_id": asset_id, "hostname": asset.hostname if asset else str(asset_id), "score": score})
    top_vulnerabilities = []
    for risk in risks[:5]:
        asset = db.get(models.LinuxAsset, risk.asset_id)
        top_vulnerabilities.append(
            {
                "rank": risk.priority_rank,
                "hostname": asset.hostname if asset else "",
                "cve_id": risk.cve_id,
                "score": risk._display_score,
                "risk_level": risk._display_level,
            }
        )
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "high_risk_vulnerabilities": sum(1 for r in risks if r._display_level in {"Critical", "High"}),
        "kev_vulnerabilities": kev_count,
        "asset_count": len(assets),
        "affected_asset_count": len(affected_asset_ids),
        "pending_remediation_tasks": db.query(models.RemediationTask).filter_by(status="pending").count(),
        "blocked_remediation_tasks": db.query(models.RemediationTask).filter_by(status="blocked").count(),
        "risk_level_distribution": dict(risk_dist),
        "source_distribution": dict(source_dist),
        "top_assets": top_assets,
        "top_vulnerabilities": top_vulnerabilities,
    }
