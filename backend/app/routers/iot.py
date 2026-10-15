from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services import trace_service as tracing
from app.routers.assets import serialize_asset
from app.services.device_access import allowed_host, allowed_networks, require_control, connection_signature, collector_node, collection_only_mode
from app.services.iot_devices import collect_openwrt, discover
from app.services import collection_tasks

router = APIRouter(prefix="/iot", tags=["IoT devices"])


class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int | None = Field(default=None, gt=0)
    label: str = Field(default="", max_length=128)
    host: str = Field(max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    auth_type: Literal["password", "ssh_key"] = "password"
    credential_env: str = Field(default="", pattern=r"^(?:LINUXGUARD_DEVICE_[A-Z0-9_]{1,80})?$")
    key_path_env: str = Field(default="", pattern=r"^(?:LINUXGUARD_DEVICE_[A-Z0-9_]{1,80})?$")
    key_passphrase_env: str = Field(default="", pattern=r"^(?:LINUXGUARD_DEVICE_[A-Z0-9_]{1,80})?$")
    host_key_sha256: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")
    enabled: bool = True

    @model_validator(mode="after")
    def authentication_references(self):
        if self.auth_type == "password":
            if not self.credential_env or self.key_path_env or self.key_passphrase_env:
                raise ValueError("密码认证须提供凭据变量，不接受密钥变量")
        elif not self.key_path_env or self.credential_env:
            raise ValueError("密钥认证须提供私钥路径变量，不接受密码凭据变量")
        return self


class DiscoveryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str = Field(max_length=32)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 1883, 8883], min_length=1, max_length=8)
    enroll: bool = False  # 阶段五：True 时对发现结果执行识别→建档→CVE 闭环（默认保持旧行为）

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values):
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("端口必须在 1–65535 之间")
        return sorted(set(values))


class AdvisoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    package_name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}$")
    release: str = Field(min_length=1, max_length=64)
    affected_versions: list[str] = Field(min_length=1, max_length=100)
    fixed_versions: list[str] = Field(min_length=1, max_length=100)
    source_url: str = Field(max_length=2048)
    notes: str = Field(default="", max_length=2000)

    @field_validator("affected_versions", "fixed_versions")
    @classmethod
    def valid_versions(cls, values):
        if any(not re.fullmatch(r"[a-zA-Z0-9+_.:~\-]{1,128}", value) for value in values):
            raise ValueError("版本必须是明确、完整的版本字符串")
        return list(dict.fromkeys(values))

    @field_validator("source_url")
    @classmethod
    def official_source(cls, value):
        url = urlparse(value)
        if url.scheme != "https" or not (url.hostname == "openwrt.org" or (url.hostname or "").endswith(".openwrt.org")):
            raise ValueError("请提供 OpenWrt 官方 HTTPS 公告地址；导入内容仍需由操作人员核对")
        return value


def connection_dict(row, db=None):
    value = {name: getattr(row, name) for name in ("id", "asset_id", "label", "adapter", "host", "port", "username", "auth_type", "credential_env", "key_path_env", "key_passphrase_env", "host_key_sha256", "enabled")}
    asset = db.get(models.LinuxAsset, row.asset_id) if db is not None and row.asset_id else None
    metadata = json.loads(asset.inventory_metadata_json or "{}") if asset else {}
    value["identity_verified"] = bool(row.enabled and asset and asset.identity_source == "pinned_ssh_inventory"
        and metadata.get("connection_signature") == connection_signature(row))
    return value


def validate_asset_binding(db, asset_id, connection_id=None):
    if asset_id is None:
        return
    asset = db.get(models.LinuxAsset, asset_id)
    if not asset or asset.distribution != "openwrt":
        raise HTTPException(400, "须选择已登记的 OpenWrt 资产")
    bound = db.query(models.DeviceConnection).filter_by(asset_id=asset_id).first()
    if bound and bound.id != connection_id:
        raise HTTPException(409, "所选资产已绑定其他连接")
    if db.get(models.HarnessAssetLock, asset_id):
        raise HTTPException(409, "所选资产有设备任务正在执行")


@router.get("/capabilities")
def capabilities():
    import os
    return {"supported_adapters": ["openwrt_ssh"], "supported_auth_types": ["password", "ssh_key"], "discovery_cidrs": [str(n) for n in allowed_networks()],
            "control_configured": bool(os.getenv("LINUXGUARD_CONTROL_TOKEN")), "max_discovery_addresses": 128,
            "repair_execution_enabled": not collection_only_mode() and os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") == "1",
            "collection_only": collection_only_mode(), "discovery_enabled": not collection_only_mode(), "collector_node": collector_node(),
            # OS 能力画像（增量）：异构 OS 的能力边界如实声明，供前端与联调判断
            "os_capability_profiles": {
                "linux/openwrt": {"discovery": "supported", "protocol_fingerprint": "supported",
                                  "ssh_inventory": "supported", "cve_exact_versions": "supported"},
                "zephyr": {"discovery": "supported", "protocol_fingerprint": "supported",
                           "device_identity_endpoint": "supported",
                           "ssh_inventory": "unsupported", "package_inventory": "unsupported",
                           "ebpf_runtime": "unsupported",
                           "cve_exact_versions": "supported(via_vendor_advisory)",
                           "note": "设备线走 IotDevice/IotDeviceAdvisory；主机线采集不适用"}}}


@router.get("/connections")
def connections(db: Session = Depends(get_db)):
    return [connection_dict(row, db) for row in db.query(models.DeviceConnection).order_by(models.DeviceConnection.id).all()]


@router.post("/connections", dependencies=[Depends(require_control)])
def create_connection(payload: ConnectionInput, db: Session = Depends(get_db)):
    if collection_only_mode() and (payload.asset_id is None or payload.auth_type != "ssh_key"):
        raise HTTPException(400, "联调模式须选择已有资产并使用 Ubuntu 本地密钥引用")
    validate_asset_binding(db, payload.asset_id)
    try:
        allowed_host(payload.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if db.query(models.DeviceConnection).filter_by(host=payload.host, port=payload.port).first():
        raise HTTPException(409, "该设备地址和管理端口已登记")
    row = models.DeviceConnection(**payload.model_dump())
    db.add(row)
    db.commit()
    return connection_dict(row, db)


@router.put("/connections/{connection_id}", dependencies=[Depends(require_control)])
def update_connection(connection_id: int, payload: ConnectionInput, db: Session = Depends(get_db)):
    if collection_only_mode() and payload.auth_type != "ssh_key":
        raise HTTPException(400, "联调模式只允许 Ubuntu 本地密钥引用")
    row = db.get(models.DeviceConnection, connection_id)
    if not row:
        raise HTTPException(404, "设备连接不存在")
    if row.asset_id and db.get(models.HarnessAssetLock, row.asset_id):
        raise HTTPException(409, "设备任务正在执行，暂不能修改连接")
    if "asset_id" in payload.model_fields_set:
        if row.asset_id is not None and payload.asset_id != row.asset_id:
            raise HTTPException(409, "已绑定连接不能直接改绑其他资产")
        validate_asset_binding(db, payload.asset_id, row.id)
    duplicate = db.query(models.DeviceConnection).filter_by(host=payload.host, port=payload.port).first()
    if duplicate and duplicate.id != row.id:
        raise HTTPException(409, "该设备地址和管理端口已登记")
    try:
        allowed_host(payload.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    for name, value in payload.model_dump().items():
        if name == "asset_id" and name not in payload.model_fields_set:
            continue
        setattr(row, name, value)
    db.commit()
    return connection_dict(row, db)


@router.post("/connections/{connection_id}/collect", dependencies=[Depends(require_control)])
def collect(connection_id: int, db: Session = Depends(get_db)):
    row = db.get(models.DeviceConnection, connection_id)
    if not row:
        raise HTTPException(404, "设备连接不存在")
    if row.asset_id and db.get(models.HarnessAssetLock, row.asset_id):
        raise HTTPException(409, "设备任务正在执行，请从任务中查看采集结果")
    try:
        run = collection_tasks.create_run(db, connection_id)
        collection_tasks.execute(db, run)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if run.status != "completed":
        raise HTTPException(400, {"message": run.error, "run_id": run.id, "status": run.status,
                                  "error_code": json.loads(run.result_json).get("error_code")})
    return {"asset": serialize_asset(db.get(models.LinuxAsset, run.asset_id), include_detail=True),
            "connection_id": connection_id, "collection_run": collection_tasks.serialize(db, run)}


class CollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,128}$")


@router.get("/connections/{connection_id}/preflight", dependencies=[Depends(require_control)])
def connection_preflight(connection_id: int, db: Session = Depends(get_db)):
    row = db.get(models.DeviceConnection, connection_id)
    if not row:
        raise HTTPException(404, "设备连接不存在")
    return collection_tasks.preflight(db, row)


@router.post("/connections/{connection_id}/collection-runs", dependencies=[Depends(require_control)])
def create_collection(connection_id: int, payload: CollectionRequest, db: Session = Depends(get_db)):
    try:
        return collection_tasks.serialize(db, collection_tasks.create_run(db, connection_id, payload.request_id))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/connections/{connection_id}/collect-logs", dependencies=[Depends(require_control)])
def collect_runtime_logs(connection_id: int, db: Session = Depends(get_db)):
    """eBPF 2.0 P2-2：OpenWrt logread 只读拉取 → P0 统一事件管线。

    统一 Trace 记录本次运行（task_type=runtime_log_collection）；事件
    source=openwrt_logread（观察模式 syslog，绝不伪装 eBPF）；重复采集由
    服务端指纹幂等收敛（duplicates 如实返回）。
    """
    from app.services.openwrt_runtime_log import collect_runtime_logs as run_collect

    row = db.get(models.DeviceConnection, connection_id)
    if not row:
        raise HTTPException(404, "设备连接不存在")
    if row.asset_id and db.get(models.HarnessAssetLock, row.asset_id):
        raise HTTPException(409, "设备任务正在执行，请稍后再拉取日志")
    asset = db.get(models.LinuxAsset, row.asset_id) if row.asset_id else None
    trace = tracing.start_trace(db, task_type="runtime_log_collection",
                                target_type="linux_asset",
                                target_ref=str(row.asset_id or ""),
                                run_ref_type="device_connection", run_ref_id=str(row.id),
                                metadata={"collector_type": "openwrt_logread", "host": row.host})
    try:
        result = run_collect(db, row)
    except ValueError as exc:
        db.rollback()
        tracing.finish_trace(db, trace.trace_id, "failed", error=str(exc)[:400])
        code = getattr(exc, "code", "collection_failed")
        raise HTTPException(400, {"message": str(exc), "error_code": code}) from exc
    summary = {key: result[key] for key in ("stored_new", "duplicates", "sensor_id", "asset_id")}
    summary["log_window"] = result["meta"]
    summary["audit"] = {key: result["audit"][key] for key in
                        ("collector_type", "collector_sha256", "node", "ssh_host_identity",
                         "ssh_authentication", "events_stored_new", "events_duplicates")}
    tracing.emit(db, trace.trace_id, "logread_collected", actor="collector", status="completed",
                 payload=summary, duration_ms=0, commit=False)
    tracing.finish_trace(db, trace.trace_id, "completed", summary=summary)
    summary["trace_id"] = trace.trace_id
    return summary


@router.get("/collection-runs", dependencies=[Depends(require_control)])
def collection_runs(connection_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(models.HarnessRun)
    if connection_id is not None:
        query = query.filter_by(connection_id=connection_id)
    # These rows share the Harness table, but investigation/repair runs are excluded.
    result = []
    for row in query.order_by(models.HarnessRun.created_at.desc()).yield_per(100):
        if json.loads(row.plan_json).get("goal") == "collect":
            result.append(collection_tasks.serialize(db, row))
            if len(result) == 100:
                break
    return result


@router.get("/collection-runs/{run_id}", dependencies=[Depends(require_control)])
def collection_detail(run_id: str, db: Session = Depends(get_db)):
    try:
        return collection_tasks.serialize(db, collection_tasks.get_run(db, run_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/collection-runs/{run_id}/execute", dependencies=[Depends(require_control)])
def execute_collection(run_id: str, db: Session = Depends(get_db)):
    try:
        run = collection_tasks.get_run(db, run_id)
        return collection_tasks.serialize(db, collection_tasks.execute(db, run))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/discovery", dependencies=[Depends(require_control)])
def run_discovery(payload: DiscoveryInput, db: Session = Depends(get_db)):
    if payload.enroll:
        from app.services.discovery_pipeline import discover_and_enroll
        # 第八阶段：入档式发现 = 一次 IoT 设备管线任务，生成统一 Trace
        trace = tracing.start_trace(db, task_type="discovery_enrollment",
                                    target_type="cidr", target_ref=payload.cidr,
                                    run_ref_type="device_task", run_ref_id=payload.cidr,
                                    metadata={"ports": payload.ports})
        try:
            result = discover_and_enroll(db, payload.cidr, payload.ports)
        except ValueError as exc:
            tracing.finish_trace(db, trace.trace_id, "failed", error=str(exc),
                                 summary={"rejected": True})
            raise HTTPException(400, str(exc)) from exc
        tracing.emit(db, trace.trace_id, "discovery_completed", actor="pipeline",
                     status="succeeded", payload=result)
        tracing.finish_trace(db, trace.trace_id, "completed", summary=result)
        return result
    try:
        return discover(db, payload.cidr, payload.ports)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/observations")
def observations(db: Session = Depends(get_db)):
    rows = db.query(models.DeviceObservation).order_by(models.DeviceObservation.last_seen_at.desc()).limit(500).all()
    return [{"id": r.id, "scope": r.scope, "ip_address": r.ip_address, "mac_address": r.mac_address,
             "hostname": r.hostname, "source": r.source, "presence": r.presence,
             "review_status": r.review_status or "pending", "review_note": r.review_note,
             "review_attempts": r.review_attempts or 0, "reviewed_at": r.reviewed_at,
             "promoted_device_id": r.promoted_device_id or "",
             "first_seen_at": r.first_seen_at, "last_seen_at": r.last_seen_at,
             "evidence": json.loads(r.evidence_json)} for r in rows]


@router.get("/advisories")
def advisories(db: Session = Depends(get_db)):
    return [{"id": r.id, "cve_id": r.cve_id, "package_name": r.package_name, "release": r.release,
             "affected_versions": json.loads(r.affected_versions_json), "fixed_versions": json.loads(r.fixed_versions_json),
             "source_url": r.source_url, "notes": r.notes} for r in db.query(models.OpenWrtAdvisory).all()]


@router.post("/advisories", dependencies=[Depends(require_control)])
def import_advisory(payload: AdvisoryInput, db: Session = Depends(get_db)):
    if set(payload.affected_versions) & set(payload.fixed_versions):
        raise HTTPException(400, "同一版本不能同时标记为受影响和已修复")
    row = db.query(models.OpenWrtAdvisory).filter_by(cve_id=payload.cve_id, package_name=payload.package_name, release=payload.release).one_or_none()
    if row is None:
        row = models.OpenWrtAdvisory(cve_id=payload.cve_id, package_name=payload.package_name, release=payload.release)
        db.add(row)
    row.affected_versions_json = json.dumps(payload.affected_versions)
    row.fixed_versions_json = json.dumps(payload.fixed_versions)
    row.source_url, row.notes = payload.source_url, payload.notes
    if not db.query(models.VulnerabilityInfo).filter_by(cve_id=payload.cve_id).first():
        db.add(models.VulnerabilityInfo(cve_id=payload.cve_id, title=f"{payload.cve_id} / OpenWrt {payload.package_name}",
                    affected_package=payload.package_name, source="openwrt_operator_advisory", references=payload.source_url,
                    description="操作人员根据官方公告整理的精确版本记录；未自动抓取或验证公告正文。"))
    db.commit()
    return {"id": row.id, "source_status": "operator_supplied", "message": "已保存；请运行漏洞匹配。"}
