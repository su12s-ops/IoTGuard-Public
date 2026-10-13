"""互联网授权目标扫描 API（阶段六）：目标登记 → 发起扫描 → 运行/结果查询。

双重授权：变更类端点需 X-Control-Token；登记与每次扫描都重新校验
LINUXGUARD_DISCOVERY_CIDRS 网段白名单 + 目标表显式登记的授权依据。
只做指纹识别，不做漏洞利用验证。
"""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.device_access import allowed_networks, allowed_host, require_control
from app.services.scan_service import (
    new_scan_run_id, normalize_ports, scan_limits, start_scan_run, target_ports,
)

router = APIRouter(prefix="/scans", tags=["Internet target scanning"])


def _valid_ports(values: list[int]) -> list[int]:
    if any(port < 1 or port > 65535 for port in values):
        raise ValueError("端口必须在 1–65535 之间")
    return sorted(set(values))


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    ip: str = Field(max_length=64)
    authorization_basis: str = Field(min_length=8, max_length=2000)
    ports: list[int] = Field(default_factory=list, max_length=1024)
    notes: str = Field(default="", max_length=2000)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values):
        return _valid_ports(values)


class TargetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=128)
    authorization_basis: str | None = Field(default=None, min_length=8, max_length=2000)
    ports: list[int] | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values):
        return None if values is None else _valid_ports(values)


class ScanStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: int
    ports: list[int] = Field(default_factory=list, max_length=1024)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values):
        return _valid_ports(values)


def serialize_target(target: models.ScanTarget, db: Session) -> dict:
    ports = json.loads(target.ports_profile_json or "[]")
    last_run = db.get(models.ScanRun, target.last_run_id) if target.last_run_id else None
    return {
        "id": target.id, "name": target.name, "ip": target.ip_address,
        "authorization_basis": target.authorization_basis,
        "ports": ports, "ports_count": len(ports), "enabled": target.enabled,
        "notes": target.notes, "created_at": target.created_at,
        "updated_at": target.updated_at,
        "last_run": {
            "run_id": last_run.run_id, "status": last_run.status,
            "open_ports_count": last_run.open_ports_count,
            "identified_count": last_run.identified_count,
            "vulnerability_hits": last_run.vulnerability_hits,
            "completed_at": last_run.completed_at,
        } if last_run else None,
    }


def serialize_run(run: models.ScanRun) -> dict:
    return {
        "run_id": run.run_id, "target_id": run.target_id, "target_ip": run.target_ip,
        "status": run.status,
        "ports_scanned": json.loads(run.ports_scanned or "[]"),
        "ports_scanned_count": run.ports_scanned_count,
        "open_ports": json.loads(run.open_ports_json or "[]"),
        "open_ports_count": run.open_ports_count,
        "identified_services": json.loads(run.identified_services_json or "[]"),
        "identified_count": run.identified_count,
        "unmatched_ports": json.loads(run.unmatched_ports_json or "[]"),
        "vulnerability_hits": run.vulnerability_hits,
        "device_id": run.device_id,
        "findings": json.loads(run.findings or "{}"),
        "error": run.error,
        "created_at": run.created_at, "completed_at": run.completed_at,
    }


@router.get("/capabilities")
def scan_capabilities():
    try:
        networks = [str(network) for network in allowed_networks()]
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    limits = scan_limits()
    return {
        "control_configured": bool(os.getenv("LINUXGUARD_CONTROL_TOKEN", "")),
        "allowed_networks": networks,
        "limits": limits,
        "note": "仅支持 IP 字面量目标；登记目标必须位于允许网段内并填写授权依据。只做指纹识别，不做漏洞利用验证。",
    }


@router.get("/targets")
def list_targets(db: Session = Depends(get_db)):
    targets = db.query(models.ScanTarget).order_by(models.ScanTarget.updated_at.desc()).all()
    return [serialize_target(target, db) for target in targets]


@router.post("/targets", dependencies=[Depends(require_control)])
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    try:
        host = allowed_host(payload.ip)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if db.query(models.ScanTarget).filter_by(ip_address=host).first():
        raise HTTPException(409, "该 IP 已登记为扫描目标；请编辑现有目标")
    try:
        ports = normalize_ports(payload.ports or None)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    target = models.ScanTarget(
        name=payload.name.strip(), ip_address=host,
        authorization_basis=payload.authorization_basis.strip(),
        ports_profile_json=json.dumps([] if not payload.ports else ports),
        notes=payload.notes.strip(),
    )
    db.add(target)
    db.commit()
    return serialize_target(target, db)


def _get_target(db: Session, target_id: int) -> models.ScanTarget:
    target = db.get(models.ScanTarget, target_id)
    if not target:
        raise HTTPException(404, "扫描目标不存在")
    return target


@router.patch("/targets/{target_id}", dependencies=[Depends(require_control)])
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db)):
    """编辑目标（IP 与授权语义绑定，不可改 IP；改 IP 请删除后重新登记）。"""
    target = _get_target(db, target_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "没有需要更新的字段")
    if "ports" in changes:
        try:
            ports = normalize_ports(changes.pop("ports") or None)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        target.ports_profile_json = json.dumps(ports)
    for field in ("name", "authorization_basis", "notes"):
        if field in changes:
            setattr(target, field, str(changes.pop(field)).strip())
    if "enabled" in changes:
        target.enabled = bool(changes.pop("enabled"))
    db.commit()
    return serialize_target(target, db)


@router.delete("/targets/{target_id}", dependencies=[Depends(require_control)])
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = _get_target(db, target_id)
    db.delete(target)
    db.commit()
    return {"deleted": target_id}


@router.post("/runs", response_class=JSONResponse, dependencies=[Depends(require_control)])
def start_scan(payload: ScanStart, db: Session = Depends(get_db)):
    """对已登记目标发起一次后台扫描（202 + run_id，轮询 GET /scans/runs/{id}）。"""
    target = _get_target(db, payload.target_id)
    if not target.enabled:
        raise HTTPException(422, "目标已停用；先启用才能扫描")
    # 登记时的白名单可能在登记后收紧，发起时再校验一次。
    try:
        allowed_host(target.ip_address)
    except ValueError as exc:
        raise HTTPException(400, f"目标地址已不在允许网段内：{exc}") from exc
    try:
        ports = target_ports(target, payload.ports or None)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    run = models.ScanRun(
        run_id=new_scan_run_id(), target_id=target.id, target_ip=target.ip_address,
        status="running", ports_scanned=json.dumps(ports),
        ports_scanned_count=len(ports),
    )
    db.add(run)
    db.commit()
    start_scan_run(run.run_id, db.get_bind())
    return JSONResponse(status_code=202, content={
        "run_id": run.run_id, "status": "running", "target_id": target.id,
        "target_ip": target.ip_address, "ports": ports,
    })


@router.get("/runs")
def list_runs(target_id: int | None = None, limit: int = 20, db: Session = Depends(get_db)):
    query = db.query(models.ScanRun)
    if target_id:
        query = query.filter(models.ScanRun.target_id == target_id)
    runs = query.order_by(models.ScanRun.created_at.desc()).limit(max(1, min(limit, 100))).all()
    return [serialize_run(run) for run in runs]


@router.get("/runs/{run_id}")
def run_detail(run_id: str, db: Session = Depends(get_db)):
    run = db.query(models.ScanRun).filter_by(run_id=run_id).one_or_none()
    if not run:
        raise HTTPException(404, "扫描运行不存在")
    return serialize_run(run)
