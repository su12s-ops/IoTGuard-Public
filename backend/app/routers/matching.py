from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.matching_engine import run_matching
from app.services.device_access import require_control

router = APIRouter(prefix="/matching", tags=["Matching"])


class OpenWrtIntelSyncInput(BaseModel):
    """离线/气隙场景可显式提交官方快照；载荷仍需通过官方 URL 与格式校验。"""
    rows: list[dict] | None = Field(default=None, max_length=1000)


@router.post("/run", dependencies=[Depends(require_control)])
def run(asset_id: int | None = Query(default=None, gt=0), db: Session = Depends(get_db)):
    if asset_id is not None and not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    openwrt_stats: dict = {}
    count = run_matching(db, asset_id=asset_id, openwrt_stats=openwrt_stats)
    payload = {"message": "Matching finished", "count": count}
    if openwrt_stats.get("assets"):
        payload["openwrt"] = openwrt_stats["assets"]
    return payload


@router.post("/openwrt-intel/sync", dependencies=[Depends(require_control)])
def sync_openwrt_intel(payload: OpenWrtIntelSyncInput | None = None,
                       db: Session = Depends(get_db)):
    """拉取并规范化 OpenWrt 官方 GHSA 快照（可持续更新入口）。

    默认在线抓取 api.github.com（钉扎 + 解析后 IP 边界校验）；也可提交
    已保存的官方快照 rows。只写入公告与情报行，不触发匹配或风险判定。
    """
    from app.services import openwrt_intel

    try:
        rows = payload.rows if payload and payload.rows else openwrt_intel.fetch_advisory_rows()
        summary = openwrt_intel.sync_openwrt_advisories(db, rows)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(502, f"OpenWrt 官方公告同步失败：{exc}") from exc
    db.commit()
    return summary


@router.get("/results")
def results(affected: bool | None = None, db: Session = Depends(get_db)):
    query = db.query(models.VulnerabilityMatch).filter(models.VulnerabilityMatch.active.is_(True))
    if affected is not None:
        query = query.filter_by(affected=affected)
    rows = []
    for item in query.order_by(models.VulnerabilityMatch.affected.desc(), models.VulnerabilityMatch.cve_id).all():
        asset = db.get(models.LinuxAsset, item.asset_id)
        rows.append(
            {
                "id": item.id,
                "asset_id": item.asset_id,
                "hostname": asset.hostname if asset else "",
                "cve_id": item.cve_id,
                "package_name": item.package_name,
                "installed_version": item.installed_version,
                "fixed_version": item.fixed_version,
                "affected": item.affected,
                "match_status": item.match_status,
                "reason_code": item.reason_code,
                "match_reason": item.match_reason,
                "confidence": item.confidence,
                "active": item.active,
            }
        )
    return rows
