"""Persistent collection-only runs using the existing Harness models and locks.

One explicit execute request performs one fixed collector run, locally on Linux
or on a registered Linux node. Credential values never pass through the API.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
import uuid
from datetime import timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app import models
from app.services import device_access, iot_devices
from app.services import trace_service as tracing


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def runtime_schedule_tick(db, now=None):
    """Bounded, persistent time buckets reuse the existing collection queue.

    Disabled unless connection IDs are explicitly configured. At most two
    attempts per window; shared asset locks prevent overlapping device access.
    A disconnected runner cannot build an unbounded backlog.
    """
    now = time.time() if now is None else now
    raw = os.getenv("LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS", "")
    ids = sorted({int(x) for x in raw.split(",") if x.strip().isdigit()})
    interval = max(60, min(3600, int(os.getenv("LINUXGUARD_OPENWRT_LOG_INTERVAL_S", "60"))))
    for connection_id in ids:
        connection = db.get(models.DeviceConnection, connection_id)
        asset = db.get(models.LinuxAsset, connection.asset_id) if connection else None
        if not connection or not connection.enabled or not asset or asset.distribution != "openwrt":
            continue
        lock = db.get(models.HarnessAssetLock, asset.id)
        if lock:
            active = db.get(models.HarnessRun, lock.run_id)
            if active and json.loads(active.plan_json).get("purpose") == "runtime_logs":
                stamp = active.created_at.replace(tzinfo=timezone.utc).timestamp()
                if now - stamp > 900:
                    active.status, active.error, active.completed_at = "interrupted", "periodic_collection_timeout_no_blind_replay", models.utcnow()
                    db.delete(lock)
                    for call in db.query(models.HarnessToolCall).filter_by(run_id=active.id, status="running"):
                        call.status, call.error, call.completed_at = "interrupted", active.error, active.completed_at
                    sensor = db.query(models.RuntimeSensor).filter_by(asset_id=asset.id, sensor_id=f"openwrt-logread-{connection_id}").first()
                    if sensor:
                        sensor.status, sensor.detail = "failed", active.error
                    db.commit()
            continue
        for attempt in range(2):
            run = create_run(db, connection_id, f"periodic-{int(now // interval)}-{attempt}", "runtime_logs")
            if run.status == "pending":
                execute(db, run)
                break
            if run.status not in {"failed", "interrupted"}:
                break
        if run.status in {"failed", "interrupted"}:
            sensor = db.query(models.RuntimeSensor).filter_by(asset_id=asset.id, sensor_id=f"openwrt-logread-{connection_id}").first()
            if sensor:
                sensor.status, sensor.detail = "failed", run.error or "periodic_collection_failed"
                db.commit()


async def periodic_runtime_collection():
    import asyncio
    import logging
    from app.database import SessionLocal
    def tick():
        with SessionLocal() as db:
            runtime_schedule_tick(db)
    while True:
        try:
            await asyncio.to_thread(tick)
        except Exception:
            logging.getLogger(__name__).exception("Periodic read-only collection tick failed")
        await asyncio.sleep(15)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def remote_node_id():
    """Registered Linux collection node that executes SSH collection for this backend.

    The Windows development backend never performs device SSH itself; when a
    Linux collection node is registered, collection runs are delegated to it
    (pull model: the node claims and executes, results go through the official
    ingestion path). Unset keeps the historical behaviour unchanged.
    """
    value = (os.getenv("LINUXGUARD_COLLECTION_NODE_ID", "") or "").strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", value) else ""


def collection_execution_mode():
    """Select an executor without pretending the API host has another platform."""
    mode = os.getenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", "auto").strip().lower()
    if mode not in {"auto", "pull", "local"}:
        raise ValueError("invalid_collection_execution_mode")
    return mode


def uses_pull_execution(node):
    mode = collection_execution_mode()
    return mode == "pull" or (mode == "auto" and node["platform"] != "Linux")


def registered_nodes():
    """Registered pull nodes: the M5 primary plus optional independently
    credentialed extras used by the isolated Stage-10 clone experiment.

    Extras come from LINUXGUARD_COLLECTION_NODES_JSON, a JSON array of
    ``{"id": ..., "local_asset_ids": "a,b"}`` objects; every extra node
    authenticates with its own ``LINUXGUARD_COLLECTION_NODE_TOKEN_<SUFFIX>``
    variable, never by reusing the primary token. Absent or invalid JSON keeps
    the historical single-node behaviour byte-for-byte.
    """
    nodes = {}
    primary = remote_node_id()
    if primary:
        nodes[primary] = {os.getenv("LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID", "").strip()}
    raw = (os.getenv("LINUXGUARD_COLLECTION_NODES_JSON", "") or "").strip()
    if raw:
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            entries = []
        for entry in entries if isinstance(entries, list) else []:
            node_id = str((entry or {}).get("id", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", node_id) or node_id in nodes:
                continue
            asset_ids = str((entry or {}).get("local_asset_ids", "") or "")
            nodes[node_id] = {part.strip() for part in asset_ids.split(",") if part.strip()}
    return nodes


def token_env_for(node_id):
    if node_id == remote_node_id():
        return "LINUXGUARD_COLLECTION_NODE_TOKEN"
    return "LINUXGUARD_COLLECTION_NODE_TOKEN_" + re.sub(r"[^A-Z0-9]", "_", node_id.upper())


def registered_node_tokens():
    return {node_id: os.getenv(token_env_for(node_id), "") for node_id in registered_nodes()}


def node_ids_for_token(token):
    supplied = (token or "").encode()
    return sorted(node_id for node_id, expected in registered_node_tokens().items()
                  if expected and hmac.compare_digest(expected.encode(), supplied))


def node_for_asset(asset):
    """Node registered for this asset's isolated execution; primary if unbound."""
    for node_id, asset_ids in registered_nodes().items():
        if asset is not None and str(asset.id) in asset_ids:
            return node_id
    return remote_node_id()


def collector_for(asset, purpose="inventory"):
    if purpose == "runtime_logs":
        if not asset or asset.distribution != "openwrt":
            raise ValueError("runtime_logs_requires_openwrt")
        return iot_devices.COLLECTOR.with_name("openwrt_logread_capture.sh"), "openwrt_logread"
    if asset and asset.distribution == "ubuntu":
        return iot_devices.COLLECTOR.with_name("collect_linux_asset.sh"), "linux_ssh"
    return iot_devices.COLLECTOR, "openwrt_ssh"


def is_node_local(asset):
    return bool(asset and asset.distribution == "ubuntu" and
                str(asset.id) in registered_nodes().get(node_for_asset(asset), set()))


def validate_plan(db, run):
    plan = json.loads(run.plan_json)
    connection = db.get(models.DeviceConnection, run.connection_id)
    asset = db.get(models.LinuxAsset, run.asset_id)
    if plan.get("goal") != "collect" or digest(plan) != run.plan_hash:
        raise device_access.DeviceOperationError("plan_changed", "采集计划摘要无效")
    if not connection or not connection.enabled or connection.asset_id != run.asset_id or device_access.connection_signature(connection) != plan["connection_hash"]:
        raise device_access.DeviceOperationError("connection_changed", "连接配置已变化，请创建新的采集任务")
    device_access.allowed_host(connection.host)
    path, kind = collector_for(asset, plan.get("purpose", "inventory"))
    script = path.read_text(encoding="utf-8")
    if kind != plan["collector_type"] or hashlib.sha256(script.encode()).hexdigest() != plan["collector_sha256"]:
        raise device_access.DeviceOperationError("collector_changed", "固定 Collector 与计划不一致")
    return connection, asset, script


def preflight(db, connection):
    """Metadata checks only: never load a private key or open a socket."""
    asset = db.get(models.LinuxAsset, connection.asset_id) if connection.asset_id else None
    checks = {"asset_bound": bool(asset and asset.distribution in {"openwrt", "ubuntu"}), "connection_enabled": bool(connection.enabled),
              "host_fingerprint_configured": bool(re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", connection.host_key_sha256 or ""))}
    try:
        device_access.allowed_host(connection.host)
        checks["authorized_target"] = True
    except ValueError:
        checks["authorized_target"] = False
    checks["collector_available"] = collector_for(asset)[0].is_file()
    node = device_access.collector_node()
    checks["node_platform"] = node["platform"] == "Linux"
    checks["remote_node_configured"] = bool(registered_nodes())
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
    pull = uses_pull_execution(node)
    remote = pull and bool(node_for_asset(asset))
    if remote:
        # Credentials belong to the execution node, including for Docker APIs.
        checks["authentication_reference_configured"] = valid_reference and auth == "ssh_key"
        checks.pop("key_path_metadata", None)
        checks["passphrase_reference_configured"] = not connection.key_passphrase_env
        if is_node_local(asset):
            checks["authentication_reference_configured"] = True
    # Pull requires a mapped node even on Linux; local requires a real Linux host.
    collection_capable = remote if pull else checks["node_platform"]
    ready = collection_capable and all(
        value for name, value in checks.items() if name not in {"node_platform", "remote_node_configured"})
    return {"ready": ready, "checks": checks, "node": node, "connection_id": connection.id,
            "asset_id": connection.asset_id, "network_attempted": False, "key_loaded": False,
            "ssh_host_identity": "not_attempted", "ssh_authentication": "not_attempted",
            "cve_applicability": "not_evaluated"}


def create_run(db, connection_id, request_id=None, purpose="inventory"):
    connection = db.get(models.DeviceConnection, connection_id)
    asset = db.get(models.LinuxAsset, connection.asset_id) if connection and connection.asset_id else None
    if not asset or asset.distribution not in {"openwrt", "ubuntu"}:
        raise ValueError("创建采集任务前须绑定已有 OpenWrt/Ubuntu 资产")
    request_id = request_id or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,128}", request_id):
        raise ValueError("采集请求编号格式无效")
    if purpose not in {"inventory", "runtime_logs"}:
        raise ValueError("invalid_collection_purpose")
    namespace = "openwrt-collect" if purpose == "inventory" else "openwrt-logs"
    run_id = hashlib.sha256(f"{namespace}:{connection_id}:{request_id}".encode()).hexdigest()[:32]
    signature = device_access.connection_signature(connection)
    existing = db.get(models.HarnessRun, run_id)
    if existing:
        if json.loads(existing.plan_json).get("connection_hash") != signature:
            raise ValueError("该采集请求编号已用于其他连接配置；请创建新任务")
        return existing
    try:
        collector, collector_type = collector_for(asset, purpose)
        script = collector.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("固定 OpenWrt Collector 不可用，任务未创建") from exc
    plan = {"goal": "collect", "purpose": purpose, "policy_version": "iotguard-collection-v1", "request_id": request_id,
            "connection_id": connection.id, "asset_id": asset.id, "connection_hash": signature,
            "node": device_access.collector_node(), "collector_type": collector_type,
            "collector_sha256": hashlib.sha256(script.encode()).hexdigest(), "steps": ["collect_inventory"],
            "model_review": False, "cve_matching": False, "repair": False}
    snapshot = {"asset_id": asset.id, "inventory_sha256": asset.inventory_sha256,
                "metadata": json.loads(asset.inventory_metadata_json or "{}"),
                "packages": [{"name": p.package_name, "version": p.package_version, "architecture": p.architecture,
                              "manager": p.package_manager} for p in asset.packages]}
    result = {"node": plan["node"], "collector_type": collector_type, "collector_sha256": plan["collector_sha256"],
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
    if not run.trace_id:
        trace = tracing.start_trace(db, task_type="harness_collect", target_type="asset",
            target_ref=str(asset.id), run_ref_type="harness", run_ref_id=run.id, harness_run_id=run.id,
            metadata={"collector_type": collector_type, "read_only": True})
        run.trace_id = trace.trace_id
        db.commit()
    return run


def get_run(db, run_id):
    run = db.get(models.HarnessRun, run_id)
    if not run or json.loads(run.plan_json).get("goal") != "collect":
        raise ValueError("采集任务不存在")
    return run


def serialize(db, run):
    plan = json.loads(run.plan_json)
    calls = db.query(models.HarnessToolCall).filter_by(run_id=run.id).order_by(models.HarnessToolCall.id).all()
    return {"id": run.id, "asset_id": run.asset_id, "connection_id": run.connection_id, "status": run.status, "trace_id": run.trace_id,
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
    if run.status == "queued_remote":
        return run  # Already delegated to the collection node; claim via the node API.
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
        execution_node = device_access.collector_node()
        if uses_pull_execution(execution_node):
            remote = node_for_asset(db.get(models.LinuxAsset, run.asset_id))
            if not remote:
                raise device_access.DeviceOperationError("node_platform_invalid", "真实纯采集任务须由 Ubuntu/Linux 节点执行，Windows 仅用于开发与离线测试；未登记远程采集节点，任务转交不可用")
            # Windows 开发节点不执行设备 SSH：任务原样转交已登记的 Linux 采集节点，
            # 由节点拉取执行并回传结果；采集与身份核验语义保持不变。
            db.rollback()   # 释放执行中的占位，改为排队转交状态
            run = db.get(models.HarnessRun, run_id)
            audit = json.loads(run.result_json)
            audit.update(asset_collection="queued_remote", queued_for_node=remote,
                         queued_at=models.utcnow().isoformat(),
                         execution="delegated_to_linux_collection_node",
                         error_code="")
            changed = db.execute(update(models.HarnessRun).where(
                models.HarnessRun.id == run.id,
                models.HarnessRun.status == "running").values(status="queued_remote"))
            if changed.rowcount != 1:
                db.rollback()
                raise ValueError("采集任务状态已变化，转交未执行；请查询当前任务")
            call = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="collect_inventory").order_by(models.HarnessToolCall.id.desc()).first()
            if call is not None:
                call.output_json = encode(audit)
            run.result_json = encode(audit)
            tracing.emit(db, run.trace_id, "collection_delegated", actor="collector", status="queued_remote",
                payload={"node_id": remote, "connection_id": run.connection_id}, commit=False)
            db.commit()
            return db.get(models.HarnessRun, run_id)
        if execution_node["platform"] != "Linux":
            raise device_access.DeviceOperationError("node_platform_invalid", "本地采集必须在 Linux 上执行；不会回退到远程执行")
        connection, asset, script = validate_plan(db, run)
        if not connection or device_access.connection_signature(connection) != plan["connection_hash"]:
            raise device_access.DeviceOperationError("connection_changed", "连接配置已变化，请创建新的采集任务")
        if device_access.collector_node() != plan["node"]:
            raise device_access.DeviceOperationError("node_changed", "执行节点已变化，请创建新的采集任务")
        script_hash = hashlib.sha256(script.encode()).hexdigest()
        if script_hash != plan["collector_sha256"]:
            raise device_access.DeviceOperationError("collector_changed", "Collector 已变化，请创建新的采集任务")
        if plan.get("purpose") == "runtime_logs":
            client = device_access.open_connection(connection)
            try:
                audit.update(ssh_host_identity="verified", ssh_authentication="succeeded")
                authenticated(audit)
                text = device_access.run_fixed_script(client, script, timeout=60, max_bytes=4_000_000)
            finally:
                client.close()
            ingest_runtime_logs(db, connection, text, audit)
        elif asset.distribution == "ubuntu":
            client = device_access.open_connection(connection)
            try:
                audit.update(ssh_host_identity="verified", ssh_authentication="succeeded")
                authenticated(audit)
                # Linux collector is bash and stdout-only (/dev/stdout argument).
                text = device_access.run_fixed_script(client, "exec bash -s -- /dev/stdout <<'IOTGUARD_LINUX'\n" + script + "\nIOTGUARD_LINUX\n", timeout=180)
            finally:
                client.close()
            ingest_linux_inventory(db, connection, text, audit)
        else:
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
    tracing.emit(db, run.trace_id, "collection_finished", actor="collector", status=run.status,
        payload={k: audit.get(k) for k in ("asset_collection", "execution_node", "ssh_host_identity", "ssh_authentication", "output_sha256", "package_count", "error_code")},
        evidence_refs=[audit["inventory_evidence_id"]] if audit.get("inventory_evidence_id") else [], commit=False)
    trace = db.query(models.TraceRun).filter_by(trace_id=run.trace_id).first() if run.trace_id else None
    if trace:
        trace.status, trace.finished_at = run.status, now
        trace.error = run.error or ""


def claim_for_node(db, node_id: str, node_platform: str):
    """Atomically hand one queued_remote run to the registered Linux collection node.

    The node identity must match the backend-registered id and the node must
    run on Linux; the run is claimed exclusively (status queued_remote →
    running) before any assignment payload is built. Only env-variable NAMES
    and the pinned host fingerprint leave the backend — never key material.
    """
    expected = registered_nodes()
    if not expected:
        raise ValueError("后端未登记 Linux 采集节点（LINUXGUARD_COLLECTION_NODE_ID 未配置）")
    if node_id not in expected:
        raise ValueError("采集节点身份与登记不一致；拒绝领取")
    if node_platform != "Linux":
        raise ValueError("采集节点必须在 Ubuntu/Linux 上执行")
    run = connection = asset = script = None
    for candidate in (db.query(models.HarnessRun)
                      .filter(models.HarnessRun.status == "queued_remote").order_by(models.HarnessRun.created_at)
                      .yield_per(20)):
        queued_for = str(json.loads(candidate.result_json).get("queued_for_node", "") or "")
        if queued_for and queued_for != node_id and queued_for in expected:
            continue   # Another registered node's task stays claimable by that node.
        if json.loads(candidate.plan_json).get("adapter") == "ubuntu-apt-v1":
            from app.services import ubuntu_repair
            return ubuntu_repair.claim(db, candidate, node_id)
        if json.loads(candidate.plan_json).get("goal") != "collect":
            return None
        connection, asset, script = validate_plan(db, candidate)
        if queued_for != node_id:
            raise ValueError("任务不属于此采集节点")
        run = candidate
        break
    if run is None:
        return None
    changed = db.execute(update(models.HarnessRun).where(
        models.HarnessRun.id == run.id,
        models.HarnessRun.status == "queued_remote").values(status="running", current_step="collect_inventory_remote"))
    if changed.rowcount != 1:
        db.rollback()
        return None
    audit = json.loads(run.result_json)
    audit.update(execution_node=node_id, claimed_at=models.utcnow().isoformat(),
                 asset_collection="running_remote")
    run.result_json = encode(audit)
    tracing.emit(db, run.trace_id, "collection_claimed", actor="collector", status="running",
        payload={"execution_node": node_id}, commit=False)
    db.commit()
    assignment = {
        "run_id": run.id,
        "node": {"id": node_id},
        "collector_type": plan_collector_type(run),
        "collector_sha256": json.loads(run.plan_json).get("collector_sha256"),
        "collector_script": script,
        "connection": {name: getattr(connection, name) for name in
                       ("host", "port", "username", "auth_type", "key_path_env",
                        "key_passphrase_env", "host_key_sha256")},
        "authorized_cidrs": [str(n) for n in device_access.allowed_networks()],
        "asset": {"id": asset.id, "hostname": asset.hostname, "distribution": asset.distribution},
        "execution": "node_local" if is_node_local(asset) else "ssh",
    }
    return assignment


def plan_collector_type(run) -> str:
    return json.loads(run.plan_json).get("collector_type", "openwrt_ssh")


def submit_result(db, run_id: str, payload: dict):
    """Ingest one collection-node execution result through the official path.

    Success requires the executed collector hash to match the pinned plan hash
    and an attested pinned-host verification; ingestion runs the exact same
    server-side validation/identity checks as a backend-local collection.
    Failures are recorded verbatim with their error code and never masked by
    stale inventory.
    """
    run = db.get(models.HarnessRun, run_id)
    if run is not None and json.loads(run.plan_json).get("adapter") == "ubuntu-apt-v1":
        from app.services import ubuntu_repair
        return ubuntu_repair.submit(db, run, payload)
    if not run or json.loads(run.plan_json).get("goal") != "collect":
        raise ValueError("采集任务不存在")
    audit = json.loads(run.result_json)
    node_id = str(payload.get("node_id") or "")
    if not node_id or node_id not in registered_nodes() or payload.get("node_platform") != "Linux" or audit.get("execution_node") != node_id:
        raise ValueError("采集节点身份与登记不一致；结果被拒绝")
    if run.status == "completed":
        if payload.get("output_sha256") != audit.get("output_sha256"):
            raise ValueError("重复结果摘要不一致")
        return run
    if run.status != "running":
        raise ValueError("采集任务不在执行中；结果被拒绝")
    call = (db.query(models.HarnessToolCall)
            .filter_by(run_id=run.id, tool="collect_inventory")
            .order_by(models.HarnessToolCall.id.desc()).first())
    call_id = call.id if call else None
    started = time.monotonic()
    succeeded = payload.get("status") == "succeeded"
    try:
        connection, asset, script = validate_plan(db, run)
        if succeeded:
            if payload.get("collector_sha256") != audit.get("collector_sha256"):
                raise device_access.DeviceOperationError(
                    "collector_changed", "采集节点执行的 Collector 与计划钉扎摘要不一致")
            local = is_node_local(asset)
            if local and payload.get("local_hostname") != asset.hostname:
                raise device_access.DeviceOperationError("node_identity_mismatch", "采集节点本机身份与明确登记的资产不一致")
            if not local and not payload.get("host_fingerprint_verified"):
                raise device_access.DeviceOperationError(
                    "host_identity_not_attested", "采集节点未核验 SSH 主机指纹；结果不作为新采集入库")
            text = payload.get("inventory_text") or ""
            if not local and payload.get("ssh_authentication") != "succeeded":
                raise device_access.DeviceOperationError("authentication_not_attested", "节点未确认 SSH 认证成功")
            marker = "===== LOGREAD =====" if plan_collector_type(run) == "openwrt_logread" else "===== OS_RELEASE ====="
            if not text or marker not in text:
                raise device_access.DeviceOperationError(
                    "inventory_validation_failed", "采集结果不是固定 Collector 输出格式；不入库")
            raw = text.encode("utf-8")
            output_hash = hashlib.sha256(raw).hexdigest()
            if payload.get("output_sha256") != output_hash or payload.get("output_bytes") != len(raw):
                raise device_access.DeviceOperationError("output_integrity_failed", "原始采集输出摘要或字节数不一致")
            audit.update(output_sha256=output_hash, output_bytes=len(raw),
                         ssh_host_identity="not_applicable" if local else "verified",
                         ssh_authentication="not_applicable" if local else "succeeded",
                         node_identity="authenticated", execution="node_local" if local else "ssh")
            if plan_collector_type(run) == "openwrt_logread":
                ingest_runtime_logs(db, connection, text, audit)
            elif asset.distribution == "ubuntu":
                ingest_linux_inventory(db, connection, text, audit)
            else:
                iot_devices.ingest_openwrt_inventory(
                db, connection, text, audit=audit,
                execution_node=node_id or audit.get("execution_node") or "",
                ssh_attestation={
                    "host_fingerprint_verified": bool(payload.get("host_fingerprint_verified")),
                    "ssh_authentication": payload.get("ssh_authentication") or "succeeded",
                }, commit=False)
            run.status, run.error = "completed", ""
            if call is not None:
                call.status = "completed"
            audit["asset_collection"] = "succeeded"
        else:
            code = str(payload.get("error_code") or "collection_failed")
            detail = str(payload.get("detail") or "采集节点报告执行失败")[:400]
            audit.update(asset_collection="failed", error_code=code,
                         ssh_host_identity="verified" if payload.get("host_fingerprint_verified") else (payload.get("ssh_host_identity") or "unknown"),
                         ssh_authentication=payload.get("ssh_authentication") or "unknown")
            run.status, run.error = "failed", detail
            if call is not None:
                call.status, call.error = "failed", detail
    except Exception as exc:
        db.rollback()
        run = db.get(models.HarnessRun, run_id)
        audit = json.loads(run.result_json)
        code, message = failure(exc)
        audit.update(asset_collection="failed", error_code=code)
        run.status, run.error = "failed", message
        call = db.get(models.HarnessToolCall, call_id) if call_id else None
        if call is not None:
            call.status, call.error = "failed", message
    if call is not None:
        finish(db, run, call, audit, started)
    else:
        now = models.utcnow()
        audit["finished_at"] = now.isoformat()
        run.completed_at = now
        db.query(models.HarnessAssetLock).filter_by(asset_id=run.asset_id, run_id=run.id).delete()
    run.result_json = encode(audit)
    if call is not None:
        call.output_json = encode(audit)
        call.duration_ms = round((time.monotonic() - started) * 1000)
        call.completed_at = run.completed_at
    db.commit()
    return db.get(models.HarnessRun, run_id)


def ingest_runtime_logs(db, connection, text, audit):
    from app.services.openwrt_runtime_log import parse_capture_output, build_events, _record_sensor
    from app.services.ebpf_event_collector import append_events
    asset = db.get(models.LinuxAsset, connection.asset_id)
    capture = parse_capture_output(text)
    hostname = capture["identity"].get("hostname", "")
    # Inventory uses a MAC (or pinned-key) suffix to disambiguate default
    # OpenWrt hostnames. Reproduce that exact rule, never strip arbitrary suffixes.
    suffix = (asset.mac_address.replace(":", "") if asset.mac_address else
              hashlib.sha256(connection.host_key_sha256.encode()).hexdigest()[:12])
    inventory_hostname = hostname if hostname.endswith("-" + suffix) else hostname + "-" + suffix
    if (not hostname or asset.hostname not in (hostname, inventory_hostname)
            or not capture["identity"].get("boot_id")):
        raise ValueError("runtime_log_device_identity_mismatch")
    sha = hashlib.sha256(text.encode()).hexdigest()
    evidence_id = "LOG-" + audit["run_id"]
    prior = db.query(models.CollectionEvidence).filter_by(evidence_id=evidence_id).first()
    if prior and prior.content_sha256 != sha:
        raise ValueError("runtime_log_evidence_changed")
    if not prior:
        db.add(models.CollectionEvidence(evidence_id=evidence_id, run_id=audit["run_id"],
            asset_id=asset.id, content_sha256=sha, raw_text=text))
    sensor_id = f"openwrt-logread-{connection.id}"
    events, meta = build_events(capture, asset_hostname=asset.hostname, asset_id=asset.id, sensor_id=sensor_id)
    if not asset.mac_address:
        # The authenticated connection establishes the suffixed inventory name;
        # keep the device's original name in raw for stable event fingerprints.
        for event in events:
            event["hostname"] = asset.hostname
    # Existing ingestion commits idempotent event batches. A crash before the
    # final receipt can leave preserved raw evidence/events; replay deduplicates.
    stored = append_events(events, db=db) if events else []
    fresh = sum(not e.get("duplicate") for e in stored)
    duplicates = sum(bool(e.get("duplicate")) for e in stored)
    _record_sensor(db, asset_id=asset.id, sensor_id=sensor_id, meta=meta,
        stored_new=fresh, duplicates=duplicates)
    audit.update(runtime_evidence_id=evidence_id, output_sha256=sha, log_window=meta,
        events_stored_new=fresh, events_duplicates=duplicates, runtime_collection="succeeded")


def ingest_linux_inventory(db, connection, text, audit):
    from app.services.asset_parser import parse_asset_text, save_parsed_asset, record_collection_evidence
    existing = db.get(models.LinuxAsset, connection.asset_id)
    parsed = parse_asset_text(text)
    if parsed.distribution != "ubuntu" or not parsed.inventory_complete or parsed.hostname != existing.hostname or parsed.os_version != existing.os_version:
        raise device_access.DeviceOperationError("device_identity_mismatch", "Ubuntu 身份或清单完整性与绑定资产不一致")
    for field in ("owner", "business_level", "exposure_level", "description"):
        setattr(parsed, field, getattr(existing, field))
    raw = text.encode("utf-8")
    parsed.inventory_sha256 = hashlib.sha256(raw).hexdigest()
    parsed.inventory_collected_at = models.utcnow()
    parsed.identity_source = "authenticated_collection_node" if audit.get("execution") == "node_local" else "pinned_ssh_inventory"
    parsed.identity_confidence = 0.95
    metadata = json.loads(parsed.inventory_metadata_json)
    metadata.update(connection_signature=device_access.connection_signature(connection),
        collection_run_id=audit["run_id"], execution_node=audit.get("execution_node") or device_access.collector_node()["id"],
        collector_sha256=audit["collector_sha256"], ssh_host_identity=audit.get("ssh_host_identity"), timestamp_basis="backend_received_at")
    metadata["inventory_evidence_id"] = record_collection_evidence(db, existing.id, text, audit)
    parsed.inventory_metadata_json = encode(metadata)
    save_parsed_asset(db, parsed, asset_id=existing.id, commit=False)
    audit.update(asset_collection="succeeded", package_count=len(parsed.packages), output_sha256=parsed.inventory_sha256, output_bytes=len(raw))


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
