"""智能设备清单 API：在线发现 → 服务识别 → 设备详情。

阶段一范围：设备的发现、画像（Device → Service → Component）与详情查询。
设备级 CVE 匹配与修复在后续阶段接入现有 matching/risk/remediation 流水线。
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.device_access import allowed_host, require_control
from app.services.device_inventory import upsert_device
from app.services import trace_service as tracing
from app.services.discovery_pipeline import _capability_marks
from app.services.device_vulnerability import (
    device_matches, register_advisory, run_device_matching,
)

router = APIRouter(prefix="/devices", tags=["IoT device inventory"])


@router.get("/official-coverage/{ecosystem}")
def official_coverage(ecosystem: str, version: str, db: Session = Depends(get_db)):
    """Official snapshot coverage, separate from operational risk decisions."""
    from app.services.iot_official import assess_snapshot
    try:
        return assess_snapshot(db, ecosystem, version)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


class DiscoverInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(max_length=64)
    ports: list[int] = Field(default_factory=list, max_length=16)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values):
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("端口必须在 1–65535 之间")
        return sorted(set(values))


def serialize_service(service: models.IotDeviceService) -> dict:
    return {
        "port": service.port, "transport": service.transport, "service_type": service.service_type,
        "product": service.product, "version": service.version, "banner": service.banner,
        "auth_state": service.auth_state, "status": service.status,
        "first_seen_at": service.first_seen_at, "last_seen_at": service.last_seen_at,
    }


def serialize_component(component: models.IotDeviceComponent) -> dict:
    return {
        "component_name": component.component_name, "component_type": component.component_type,
        "version": component.version, "cpe": component.cpe, "source": component.source,
        "service_row_id": component.service_row_id, "updated_at": component.updated_at,
    }


def serialize_device(device: models.IotDevice, include_detail: bool = False, db: Session | None = None) -> dict:
    open_services = [service for service in device.services if service.status == "open"]
    affected_count = 0
    if db is not None:
        affected_count = db.query(models.DeviceVulnerabilityMatch).filter(
            models.DeviceVulnerabilityMatch.device_row_id == device.id,
            models.DeviceVulnerabilityMatch.active.is_(True),
            models.DeviceVulnerabilityMatch.affected.is_(True),
        ).count()
    data = {
        "device_id": device.device_id, "device_name": device.device_name,
        "device_type": device.device_type, "vendor": device.vendor, "model": device.model,
        "firmware_version": device.firmware_version, "os": device.os, "ip": device.ip,
        "status": device.status, "risk_score": device.risk_score,
        "risk_score_basis": device.risk_score_basis, "security_status": device.security_status,
        "identity_source": device.identity_source, "identity_confidence": device.identity_confidence,
        "open_ports": sorted(service.port for service in open_services),
        "service_count": len(open_services),
        "component_count": len(device.components),
        # 设备级 CVE 匹配结果的真实计数（未匹配时为真实的 0）。
        "vulnerability_count": affected_count,
        "vulnerability_assessment": "cve_match" if db is not None else "not_available",
        "first_seen_at": device.first_seen_at, "last_seen_at": device.last_seen_at,
    }
    if include_detail:
        data["services"] = [serialize_service(service) for service in
                            sorted(device.services, key=lambda item: item.port)]
        data["components"] = [serialize_component(component) for component in device.components]
        data["metadata"] = device.metadata_json
    return data


@router.post("/discover", dependencies=[Depends(require_control)])
def discover_device(payload: DiscoverInput, db: Session = Depends(get_db)):
    """对授权网段内的单个目标执行端口探测与服务识别，写入设备清单。"""
    try:
        host = allowed_host(payload.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        device, report = upsert_device(db, host, payload.ports or None)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except OSError as exc:
        raise HTTPException(502, f"探测失败：{exc}") from exc
    data = serialize_device(device, include_detail=True, db=db)
    data["discovery_report"] = report
    return data


@router.get("")
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(models.IotDevice).order_by(models.IotDevice.last_seen_at.desc()).all()
    return [serialize_device(device, db=db) for device in devices]


@router.get("/{device_id}")
def device_detail(device_id: str, db: Session = Depends(get_db)):
    device = db.query(models.IotDevice).filter_by(device_id=device_id).one_or_none()
    if not device:
        raise HTTPException(404, "设备不存在")
    return serialize_device(device, include_detail=True, db=db)


@router.post("/{device_id}/refresh", dependencies=[Depends(require_control)])
def refresh_device(device_id: str, db: Session = Depends(get_db)):
    """按设备记录的 IP 重新探测识别；关闭的端口会如实标记为 closed。

    第八阶段：刷新即一次只读设备管线任务，生成统一 Trace（探测→服务识别→
    能力边界标注→组件/身份刷新），事件与证据引用全程可回放。
    """
    device = db.query(models.IotDevice).filter_by(device_id=device_id).one_or_none()
    if not device:
        raise HTTPException(404, "设备不存在")
    try:
        host = allowed_host(device.ip)
    except ValueError as exc:
        raise HTTPException(400, f"设备地址已不在允许网段内：{exc}") from exc
    trace = tracing.start_trace(db, task_type="device_refresh", target_type="device",
                                target_ref=device_id, run_ref_type="device_task",
                                run_ref_id=device_id, metadata={"host": host})
    marks = _capability_marks(device)
    if marks:
        tracing.emit(db, trace.trace_id, "capability_marks", actor="pipeline",
                     status="unsupported",
                     payload={"target": device_id, "capabilities": marks})
    try:
        device, report = upsert_device(db, host, [service.port for service in device.services] or None)
    except ValueError as exc:
        device.status = "offline"
        device.last_seen_at = models.utcnow()
        db.commit()
        tracing.finish_trace(db, trace.trace_id, "completed",
                             summary={"status": "offline", "detail": str(exc)})
        return {"device_id": device_id, "status": "offline", "detail": str(exc)}
    tracing.emit(db, trace.trace_id, "device_refreshed", actor="pipeline", status="succeeded",
                 payload={"probed_ports": report.get("probed_ports", []),
                          "identified": report.get("identified", {}),
                          "identity_source": report.get("identity_source", ""),
                          "identity_confidence": report.get("identity_confidence", 0)})
    data = serialize_device(device, include_detail=True, db=db)
    data["discovery_report"] = report
    data["trace_id"] = trace.trace_id
    tracing.finish_trace(db, trace.trace_id, "completed",
                         summary={"status": device.status,
                                  "services": len(device.services),
                                  "components": len(device.components)})
    return data


# ── 阶段六：设备厂商公告登记与 CVE 匹配 ────────────────────────────────────────


class AdvisoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    component_name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9+_. -]{0,127}$")
    affected_versions: list[str] = Field(min_length=1, max_length=50)
    fixed_versions: list[str] = Field(min_length=1, max_length=50)
    source_url: str = Field(min_length=8, max_length=2048)
    cvss_score: float = Field(default=0, ge=0, le=10)
    cvss_severity: str = Field(default="", max_length=32)
    notes: str = Field(default="", max_length=2000)

    @field_validator("affected_versions", "fixed_versions")
    @classmethod
    def valid_versions(cls, values):
        if any(not re.fullmatch(r"[a-zA-Z0-9+_.:~\-]{1,128}", value) for value in values):
            raise ValueError("版本必须是明确、完整的版本字符串")
        return list(dict.fromkeys(values))

    @field_validator("source_url")
    @classmethod
    def https_source(cls, value):
        if not value.startswith("https://"):
            raise ValueError("公告地址必须是官方 HTTPS 链接；内容仍需操作人员核对")
        return value


def _get_device(db: Session, device_id: str) -> models.IotDevice:
    device = db.query(models.IotDevice).filter_by(device_id=device_id).one_or_none()
    if not device:
        raise HTTPException(404, "设备不存在")
    return device


@router.post("/{device_id}/advisories", dependencies=[Depends(require_control)])
def add_device_advisory(device_id: str, payload: AdvisoryInput, db: Session = Depends(get_db)):
    """登记设备厂商公告（人工核对官方公告后录入；匹配引擎只采信精确版本）。"""
    device = _get_device(db, device_id)
    row = register_advisory(db, {
        "cve_id": payload.cve_id, "vendor": device.vendor, "model": device.model,
        "component_name": payload.component_name,
        "affected_versions": payload.affected_versions,
        "fixed_versions": payload.fixed_versions,
        "source_url": payload.source_url, "notes": payload.notes,
        "cvss_score": payload.cvss_score, "cvss_severity": payload.cvss_severity,
    })
    return {"id": row.id, "cve_id": row.cve_id, "model": row.model,
            "component_name": row.component_name,
            "message": "公告已登记；请调用 POST /devices/{id}/match 执行匹配。"}


@router.post("/{device_id}/match", dependencies=[Depends(require_control)])
def match_device(device_id: str, db: Session = Depends(get_db)):
    """对设备执行组件 × CVE 匹配（厂商公告精确版本优先，NVD 通用路线降级）。"""
    device = _get_device(db, device_id)
    trace = tracing.start_trace(db, task_type="device_cve_match", target_type="device",
                                target_ref=device_id, run_ref_type="device_task",
                                run_ref_id=device_id)
    result = run_device_matching(db, device)
    matches = device_matches(db, device)
    tracing.emit(db, trace.trace_id, "cve_match", actor="pipeline", status="succeeded",
                 payload={"matched": result.get("matched", 0),
                          "tiers": {m["cve_id"]: m["match_status"] for m in matches[:20]}},
                 evidence_refs=[m["cve_id"] for m in matches])
    tracing.finish_trace(db, trace.trace_id, "completed",
                         summary={"matched": result.get("matched", 0),
                                  "affected": sum(1 for m in matches if m["affected"])})
    return {"device_id": device_id, **result, "trace_id": trace.trace_id,
            "matches": matches}


@router.get("/{device_id}/vulnerabilities")
def device_vulnerabilities(device_id: str, db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    matches = device_matches(db, device)
    return {"device_id": device_id, "count": len(matches),
            "affected_count": sum(1 for m in matches if m["affected"]),
            "matches": matches}
