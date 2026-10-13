"""Persistent collection-only runs using the existing Harness models and locks.

Ubuntu runs this same backend; no remote worker protocol or credentials are sent
through the API. One explicit execute request performs one fixed collector run.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app import models
from app.services import device_access, iot_devices


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def preflight(db, connection):
    """Metadata checks only: never load a private key or open a socket."""
    asset = db.get(models.LinuxAsset, connection.asset_id) if connection.asset_id else None
    checks = {"asset_bound": bool(asset and asset.distribution == "openwrt"), "connection_enabled": bool(connection.enabled),
              "host_fingerprint_configured": bool(re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", connection.host_key_sha256 or ""))}
    try:
        device_access.allowed_host(connection.host)
        checks["authorized_target"] = True
    except ValueError:
        checks["authorized_target"] = False
    checks["collector_available"] = iot_devices.COLLECTOR.is_file()
    node = device_access.collector_node()
    checks["node_platform"] = node["platform"] == "Linux"
    checks["node_identity_configured"] = bool(node["id"] and (not device_access.collection_only_mode() or node["id"] != "backend-local"))
    auth = connection.auth_type or "password"
    reference = connection.key_path_env if auth == "ssh_key" else connection.credential_env
    valid_reference = bool(re.fullmatch(r"LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}", reference or ""))
    checks["authentication_reference_configured"] = valid_reference and bool(os.getenv(reference, ""))
    if auth == "ssh_key":
        # Path metadata is inspected, but the path and contents are never returned.
        path = Path(os.getenv(reference, "")).expanduser() if valid_reference else Path("")
        try:
            checks["key_path_metadata"] = path.is_absolute() and path.is_file() and path.stat().st_size <= 65536
        except OSError:
            checks["key_path_metadata"] = False
        passphrase_ref = connection.key_passphrase_env
        checks["passphrase_reference_configured"] = not passphrase_ref or bool(
            re.fullmatch(r"LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}", passphrase_ref) and os.getenv(passphrase_ref, ""))
    return {"ready": all(checks.values()), "checks": checks, "node": node, "connection_id": connection.id,
            "asset_id": connection.asset_id, "network_attempted": False, "key_loaded": False,
            "ssh_host_identity": "not_attempted", "ssh_authentication": "not_attempted",
            "cve_applicability": "not_evaluated"}


def create_run(db, connection_id, request_id=None):
    connection = db.get(models.DeviceConnection, connection_id)
    asset = db.get(models.LinuxAsset, connection.asset_id) if connection and connection.asset_id else None
    if not asset or asset.distribution != "openwrt":
        raise ValueError("创建采集任务前须绑定已有 OpenWrt 资产")
    request_id = request_id or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,128}", request_id):
        raise ValueError("采集请求编号格式无效")
    run_id = hashlib.sha256(f"openwrt-collect:{connection_id}:{request_id}".encode()).hexdigest()[:32]
    signature = device_access.connection_signature(connection)
    existing = db.get(models.HarnessRun, run_id)
    if existing:
        if json.loads(existing.plan_json).get("connection_hash") != signature:
            raise ValueError("该采集请求编号已用于其他连接配置；请创建新任务")
        return existing
    try:
        script = iot_devices.COLLECTOR.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("固定 OpenWrt Collector 不可用，任务未创建") from exc
    plan = {"goal": "collect", "policy_version": "iotguard-collection-v1", "request_id": request_id,
            "connection_id": connection.id, "asset_id": asset.id, "connection_hash": signature,
            "node": device_access.collector_node(), "collector_type": "openwrt_ssh",
            "collector_sha256": hashlib.sha256(script.encode()).hexdigest(), "steps": ["collect_inventory"],
            "model_review": False, "cve_matching": False, "repair": False}
    snapshot = {"asset_id": asset.id, "inventory_sha256": asset.inventory_sha256,
                "metadata": json.loads(asset.inventory_metadata_json or "{}"),
                "packages": [{"name": p.package_name, "version": p.package_version, "architecture": p.architecture,
                              "manager": p.package_manager} for p in asset.packages]}
    result = {"node": plan["node"], "collector_type": "openwrt_ssh", "collector_sha256": plan["collector_sha256"],
              "ssh_host_identity": "not_attempted", "ssh_authentication": "not_attempted",
              "asset_collection": "pending", "cve_applicability": "not_evaluated"}
    run = models.HarnessRun(id=run_id, asset_id=asset.id, connection_id=connection.id, status="pending",
                            plan_json=encode(plan), plan_hash=digest(plan), snapshot_json=encode(snapshot), result_json=encode(result))
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        run = db.get(models.HarnessRun, run_id)
        if not run:
            raise
        if json.loads(run.plan_json).get("connection_hash") != signature:
            raise ValueError("并发请求的连接配置不一致")
    return run


def get_run(db, run_id):
    run = db.get(models.HarnessRun, run_id)
    if not run or json.loads(run.plan_json).get("goal") != "collect":
        raise ValueError("采集任务不存在")
    return run


def serialize(db, run):
    plan = json.loads(run.plan_json)
    calls = db.query(models.HarnessToolCall).filter_by(run_id=run.id).order_by(models.HarnessToolCall.id).all()
    return {"id": run.id, "asset_id": run.asset_id, "connection_id": run.connection_id, "status": run.status,
            "attempts": run.attempts, "created_at": run.created_at, "completed_at": run.completed_at,
            "started_at": calls[0].created_at if calls else None, "node": plan.get("node"),
            "collector_type": plan.get("collector_type"), "error": run.error,
            "result": json.loads(run.result_json), "tool_calls": [{"id": c.id, "status": c.status,
                "started_at": c.created_at, "completed_at": c.completed_at, "duration_ms": c.duration_ms,
                "error": c.error, "output": json.loads(c.output_json)} for c in calls]}


def failure(exc):
    if isinstance(exc, device_access.DeviceOperationError):
        return exc.code, str(exc)
    if isinstance(exc, TimeoutError):
        return "collector_timeout", "采集超时，远端结束状态未知；保留已有资产，不自动重试"
    if isinstance(exc, ValueError):
        return "inventory_validation_failed", "采集或认证配置校验失败；未覆盖已有资产"
    return "collection_failed", "采集执行或数据库提交失败；未覆盖已有资产，请查看脱敏审计状态"


def execute(db, run):
    plan = json.loads(run.plan_json)
    if plan.get("goal") != "collect" or digest(plan) != run.plan_hash:
        raise ValueError("采集计划类型或摘要无效")
    if run.status in {"completed", "failed", "interrupted", "cancelled"}:
        return run  # Terminal jobs never repeat SSH; retry requires a new request ID.
    if run.status != "pending":
        raise ValueError("采集任务正在执行，请查询当前任务")
    # Claim and lock are committed before any device access, and shared with Harness.
    changed = db.execute(update(models.HarnessRun).where(models.HarnessRun.id == run.id,
                        models.HarnessRun.status == "pending").values(status="running", attempts=1, current_step="collect_inventory"))
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("采集任务已被其他请求领取")
    try:
        db.add(models.HarnessAssetLock(asset_id=run.asset_id, run_id=run.id))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("此资产已有任务执行中，未开始 SSH") from exc
    db.refresh(run)
    audit = json.loads(run.result_json)
    audit.update(run_id=run.id, asset_id=run.asset_id, started_at=models.utcnow().isoformat(), asset_collection="running")
    call = models.HarnessToolCall(run_id=run.id, tool="collect_inventory", status="running", side_effect=False,
                                arguments_json=encode({"node": plan["node"], "collector_type": plan["collector_type"]}), output_json=encode(audit))
    db.add(call)
    run.result_json = encode(audit)
    db.commit()
    run_id, call_id = run.id, call.id
    started = time.monotonic()

    def authenticated(current):
        # Persist SSH success before collection, without committing any asset writes.
        run.result_json = call.output_json = encode(current)
        db.commit()

    try:
        if device_access.collector_node()["platform"] != "Linux":
            raise device_access.DeviceOperationError("node_platform_invalid", "真实纯采集任务须由 Ubuntu/Linux 节点执行，Windows 仅用于开发与离线测试")
        connection = db.get(models.DeviceConnection, run.connection_id)
        if not connection or device_access.connection_signature(connection) != plan["connection_hash"]:
            raise device_access.DeviceOperationError("connection_changed", "连接配置已变化，请创建新的采集任务")
        if device_access.collector_node() != plan["node"]:
            raise device_access.DeviceOperationError("node_changed", "执行节点已变化，请创建新的采集任务")
        script_hash = hashlib.sha256(iot_devices.COLLECTOR.read_text(encoding="utf-8").encode()).hexdigest()
        if script_hash != plan["collector_sha256"]:
            raise device_access.DeviceOperationError("collector_changed", "Collector 已变化，请创建新的采集任务")
        iot_devices.collect_openwrt(db, connection, commit=False, audit=audit, on_authenticated=authenticated)
        run.status, call.status = "completed", "completed"
        audit["asset_collection"] = "succeeded"
        finish(db, run, call, audit, started)
        db.commit()  # Inventory, observations, success record and lock release are atomic.
    except Exception as exc:
        db.rollback()  # Includes any already-flushed replacement package rows.
        run, call = db.get(models.HarnessRun, run_id), db.get(models.HarnessToolCall, call_id)
        code, message = failure(exc)
        audit.update(asset_collection="failed", error_code=code)
        if isinstance(exc, TimeoutError):
            audit["remote_execution_status"] = "unknown"
        if isinstance(exc, device_access.DeviceOperationError):
            if audit["ssh_authentication"] != "succeeded":
                audit.update(ssh_host_identity=exc.host_identity, ssh_authentication=exc.authentication)
            if exc.exit_status is not None:
                audit["collector_exit_status"] = exc.exit_status
                audit["remote_execution_status"] = "exited"
        run.status, call.status, run.error, call.error = "failed", "failed", message, message
        finish(db, run, call, audit, started)
        db.commit()
    return run


def finish(db, run, call, audit, started):
    now = models.utcnow()
    audit["finished_at"] = now.isoformat()
    run.completed_at = call.completed_at = now
    run.result_json = call.output_json = encode(audit)
    call.duration_ms = round((time.monotonic() - started) * 1000)
    db.query(models.HarnessAssetLock).filter_by(asset_id=run.asset_id, run_id=run.id).delete()


def recover(db):
    """Called only after confirming the previous collection executor has stopped."""
    rows = db.query(models.HarnessRun).filter_by(status="running").all()
    count = 0
    for run in rows:
        if json.loads(run.plan_json).get("goal") != "collect":
            continue
        count += 1
        run.status, run.error, run.completed_at = "interrupted", "采集进程已中断；保留已有资产，未重放 SSH", models.utcnow()
        result = json.loads(run.result_json)
        result.update(asset_collection="interrupted", finished_at=run.completed_at.isoformat(), error_code="executor_interrupted")
        run.result_json = encode(result)
        for call in db.query(models.HarnessToolCall).filter_by(run_id=run.id, status="running"):
            call.status, call.error, call.completed_at, call.output_json = "interrupted", run.error, run.completed_at, encode(result)
        db.query(models.HarnessAssetLock).filter_by(run_id=run.id).delete()
    db.commit()
    return count
