import json
import hashlib
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import update
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from app import models
from app.database import get_db
from app.services.asset_parser import save_parsed_asset
from app.services.asset_import import parse_asset_document
from app.services.device_access import require_control, collection_only_mode

router = APIRouter(prefix="/assets", tags=["Assets"])


def serialize_asset(asset: models.LinuxAsset, include_detail: bool = False):
    payload = {
        "id": asset.id,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "os_name": asset.os_name,
        "os_version": asset.os_version,
        "distribution": asset.distribution,
        "kernel_version": asset.kernel_version,
        "architecture": asset.architecture,
        "exposure_level": asset.exposure_level,
        "business_level": asset.business_level,
        "repair_domain": asset.repair_domain,
        "owner": asset.owner,
        "description": asset.description,
        "device_type": asset.device_type,
        "device_model": asset.device_model,
        "mac_address": asset.mac_address,
        "firmware_version": asset.firmware_version,
        "identity_source": asset.identity_source,
        "identity_confidence": asset.identity_confidence,
        "capabilities": json.loads(asset.capabilities_json or "{}"),
        "inventory_complete": asset.inventory_complete,
        "inventory_collected_at": asset.inventory_collected_at,
        "inventory_sha256": asset.inventory_sha256,
        "inventory_metadata": json.loads(asset.inventory_metadata_json or "{}"),
        "inventory_external_id": asset.inventory_external_id,
        "last_seen_at": asset.last_seen_at,
    }
    if include_detail:
        payload["packages"] = [
            {
                "package_name": pkg.package_name,
                "package_version": pkg.package_version,
                "package_manager": pkg.package_manager,
                "architecture": pkg.architecture,
            }
            for pkg in asset.packages
        ]
        payload["services"] = [
            {
                "service_name": svc.service_name,
                "port": svc.port,
                "protocol": svc.protocol,
                "listen_address": svc.listen_address,
                "process_name": svc.process_name,
                "is_public_exposed": svc.is_public_exposed,
            }
            for svc in asset.services
        ]
    return payload


class RepairDomainEnrollment(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    domain: Literal["production", "openwrt_lab"]
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2000)


@router.post("/{asset_id}/repair-domain", dependencies=[Depends(require_control)])
def enroll_repair_domain(asset_id: int, payload: RepairDomainEnrollment,
                         db: Session = Depends(get_db)):
    asset = db.get(models.LinuxAsset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if asset.distribution != "openwrt":
        raise HTTPException(409, "此授权域仅适用于 OpenWrt")
    # One-time compare-and-set: no inventory/API update can relabel an existing
    # production device as a lab clone (or vice versa), including concurrent calls.
    changed = db.execute(update(models.LinuxAsset).where(
        models.LinuxAsset.id == asset_id,
        models.LinuxAsset.repair_domain == "unassigned",
    ).values(repair_domain=payload.domain, repair_domain_actor=payload.actor,
             repair_domain_reason=payload.reason)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, "授权域已登记，不能通过此入口改写；请登记独立资产")
    db.commit()
    db.refresh(asset)
    return serialize_asset(asset)


@router.get("")
def list_assets(db: Session = Depends(get_db)):
    assets = db.query(models.LinuxAsset).order_by(models.LinuxAsset.hostname).all()
    rows = []
    for asset in assets:
        row = serialize_asset(asset)
        top_risk = db.query(models.RiskAssessment).filter(
            models.RiskAssessment.asset_id == asset.id,
            models.RiskAssessment.active.is_(True),
            models.RiskAssessment.review_status.notin_(("resolved", "inactive")),
        ).order_by(models.RiskAssessment.final_score.desc()).first()
        row["risk_level"] = top_risk.risk_level if top_risk else None
        row["risk_score"] = top_risk.final_score if top_risk else None
        row["risk_assessment_status"] = "current" if top_risk else "unassessed"
        rows.append(row)
    return rows


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.LinuxAsset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return serialize_asset(asset, include_detail=True)


@router.post("/upload", dependencies=[Depends(require_control)])
async def upload_asset(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read(5_000_001)
    if len(raw) > 5_000_000:
        raise HTTPException(413, "采集文件不能超过 5 MB")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "采集文件须使用 UTF-8 编码；未保存资产") from exc
    try:
        parsed = parse_asset_document(content)
        if collection_only_mode() and (parsed.distribution != "openwrt" or not parsed.inventory_external_id):
            raise ValueError("联调模式仅接受带外部资产编号的完整 OpenWrt 1.0 JSON；在线更新请使用已绑定连接的采集任务")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (TypeError, AttributeError) as exc:
        raise HTTPException(400, "采集文件格式无效；未保存资产") from exc
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Unable to parse hostname from asset file")
    try:
        parsed.inventory_sha256 = hashlib.sha256(raw).hexdigest()
        asset = save_parsed_asset(db, parsed)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if parsed.observations:
        from app.services.iot_devices import save_gateway_observations
        save_gateway_observations(db, asset, parsed.observations)
    return {"message": "Asset uploaded and parsed", "asset": serialize_asset(asset, include_detail=True),
            "package_parse_stats": parsed.package_parse_stats}
