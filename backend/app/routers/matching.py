from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.matching_engine import run_matching
from app.services.device_access import require_control

router = APIRouter(prefix="/matching", tags=["Matching"])


@router.post("/run", dependencies=[Depends(require_control)])
def run(asset_id: int | None = Query(default=None, gt=0), db: Session = Depends(get_db)):
    if asset_id is not None and not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    count = run_matching(db, asset_id=asset_id)
    return {"message": "Matching finished", "count": count}


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
