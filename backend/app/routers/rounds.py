"""分析轮次 API：当前轮工作台状态与一键发起新一轮。

归档/重置由实验生命周期（/api/experiment，见 ExperimentModal 与
result_archive / experiment_lifecycle）统一负责：先写结果存档，再删除
派生数据、保留设备与采集配置。本路由只补齐「开始执行」链路——
匹配 → 风险计算 → 四智能体研判（复用 /api/analysis 唯一正式入口），
不引入第二套归档机制。
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import config, models
from app.database import get_db
from app.services.device_access import require_control
from app.services.result_archive import list_result_archives

router = APIRouter(prefix="/rounds", tags=["Analysis rounds"])


@router.get("/current")
def current_round(db: Session = Depends(get_db)):
    """轮次工作台状态：接入设备、本轮数据量、流水线配置与历史存档概况。"""
    assets = db.query(models.LinuxAsset).order_by(models.LinuxAsset.id).all()
    match_counts = {
        asset_id: int(count)
        for asset_id, count in (
            db.query(models.VulnerabilityMatch.asset_id, func.count(models.VulnerabilityMatch.id))
            .filter(models.VulnerabilityMatch.active.is_(True))
            .group_by(models.VulnerabilityMatch.asset_id).all()
        )
    }
    risk_counts = {
        asset_id: int(count)
        for asset_id, count in (
            db.query(models.RiskAssessment.asset_id, func.count(models.RiskAssessment.id))
            .filter(models.RiskAssessment.active.is_(True))
            .group_by(models.RiskAssessment.asset_id).all()
        )
    }
    devices = [
        {
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "ip": asset.ip_address or "",
            "distribution": asset.distribution or "",
            "os_version": asset.os_version or "",
            "device_type": asset.device_type or "",
            "package_count": len(asset.packages),
            "active_matches": match_counts.get(asset.id, 0),
            "active_risks": risk_counts.get(asset.id, 0),
            "inventory_complete": bool(asset.inventory_complete),
            "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else "",
        }
        for asset in assets
    ]
    running = db.query(models.UnifiedAnalysisRun).filter(
        models.UnifiedAnalysisRun.status.in_(("running", "queued", "queued_remote", "pending"))
    ).count()
    archives = list_result_archives(8)
    return {
        "devices": devices,
        "device_count": len(devices),
        "active": {
            "unified_runs": db.query(models.UnifiedAnalysisRun).count(),
            "risks": db.query(models.RiskAssessment).filter(
                models.RiskAssessment.active.is_(True)).count(),
            "candidates": db.query(models.RiskAssessment).filter(
                models.RiskAssessment.active.is_(True),
                models.RiskAssessment.review_status.in_(("candidate", "reanalysis_required")),
            ).count(),
            "running": bool(running),
        },
        "intel": {
            "vulnerability_count": db.query(models.VulnerabilityInfo).count(),
        },
        "pipeline": {
            "mode": config.UNIFIED_PIPELINE_MODE,
            "model_configured": bool(getattr(config, "DEEPSEEK_API_KEY", "")),
        },
        "archives": {
            "count": len(archives),
            "latest": archives[0] if archives else None,
        },
    }


class RoundStartInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int = Field(default=0, ge=0)
    batch_size: int = Field(default=1, ge=1, le=4)
    investigation_goal: str = Field(default="", max_length=2000)


@router.post("/start", dependencies=[Depends(require_control)])
def start_round(payload: RoundStartInput, db: Session = Depends(get_db)):
    """发起下一轮：匹配 → 风险计算 → 四智能体研判（后台）。

    匹配与风险计算总是执行（确定性、无模型依赖）；研判环节复用
    POST /api/analysis/runs 的唯一正式入口，未启用统一编排器时以
    review_unavailable_reason 如实返回，不静默跳过。
    """
    from app.routers import analysis as analysis_router
    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk

    if payload.asset_id and not db.get(models.LinuxAsset, payload.asset_id):
        raise HTTPException(status_code=404, detail="资产不存在")

    openwrt_stats: dict = {}
    match_count = run_matching(db, asset_id=payload.asset_id or None, openwrt_stats=openwrt_stats)
    risk_count = calculate_risk(db)

    review = None
    review_unavailable_reason = ""
    try:
        review = analysis_router.create_run(
            retry_failed=False, risk_id=0, batch_size=payload.batch_size,
            post_repair=False, investigation_goal=payload.investigation_goal, db=db,
        )
    except HTTPException as exc:
        review_unavailable_reason = str(exc.detail)
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "match_count": match_count,
        "risk_count": risk_count,
        "vulnerability_count": db.query(models.VulnerabilityInfo).count(),
        "review": review,
        "review_unavailable_reason": review_unavailable_reason or None,
        "pipeline_mode": config.UNIFIED_PIPELINE_MODE,
        "openwrt": openwrt_stats.get("assets", []),
    }
