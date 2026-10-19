"""Persistent, bounded execution around the existing evidence-review agents.

The model recommends actions; this deterministic harness owns the tool policy.
Device writes require a reviewed risk, a pinned connection, a checksum-bound
artifact and approval of the exact plan. An uncertain write is never retried.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import object_session

from app import models
from app.services import device_access, iot_devices
from app.services import trace_service as tracing
from app.services.matching_engine import run_matching
from app.services.remediation_engine import _authorized
from app.services.runtime_telemetry import coverage, compare_windows

POLICY_VERSION = "iot-evidence-harness-v1"
BLOCKED_PACKAGES = {"kernel", "base-files", "busybox", "libc", "musl", "procd", "opkg", "apk-tools", "dropbear", "uhttpd", "firewall", "firewall4"}


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def inventory(asset):
    return {"asset_id": asset.id, "distribution": asset.distribution, "release": asset.os_version,
            "model": asset.device_model, "mac": asset.mac_address, "complete": asset.inventory_complete,
            "architecture": asset.architecture,
            "package_managers": {p.package_name: p.package_manager for p in asset.packages},
            "packages": {p.package_name: p.package_version for p in asset.packages}}


def connection_signature(row):
    return device_access.connection_signature(row)


def review_signature(risk):
    return digest({key: getattr(risk, key) for key in ("review_status", "human_review_required", "review_evidence_ids",
        "review_completed_at", "recommended_action", "candidate_fingerprint", "risk_level", "active")})


def artifact_registry():
    raw = os.getenv("LINUXGUARD_REPAIR_MANIFEST", "")
    if not raw:
        return {}, None
    manifest = Path(raw).resolve()
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    rows = payload.get("artifacts", [])
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError("修复清单格式无效")
    registry = {}
    for row in rows:
        if not isinstance(row, dict) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", str(row.get("id", ""))):
            raise ValueError("修复产物 ID 无效")
        if row["id"] in registry:
            raise ValueError("修复产物 ID 重复")
        registry[row["id"]] = row
    return registry, manifest.parent


def checked_file(root, relative, expected_hash, max_bytes=64 * 1024 * 1024):
    path = (root / str(relative)).resolve()
    if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("产物或检查脚本不在允许目录内，或超过大小限制")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", str(expected_hash)):
        raise ValueError("产物缺少有效 SHA256")
    if hashlib.sha256(path.read_bytes()).hexdigest().lower() != expected_hash.lower():
        raise ValueError("产物或检查脚本的 SHA256 不匹配")
    return path


def load_artifact(artifact_id):
    registry, root = artifact_registry()
    if artifact_id not in registry or root is None:
        raise ValueError("尚未登记该修复产物")
    item = dict(registry[artifact_id])
    package = str(item.get("package_name", ""))
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,127}", package) or package in BLOCKED_PACKAGES or package.startswith("kmod-"):
        raise ValueError("此版本仅允许应用软件包修复；核心系统、管理服务和固件升级须走独立流程")
    if item.get("package_manager") not in {"opkg", "apk"}:
        raise ValueError("修复产物的包管理器必须是 opkg 或 apk")
    for field in ("version", "release", "board_name"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            raise ValueError(f"修复产物缺少 {field}")
    path = checked_file(root, item.get("path", ""), item.get("sha256", ""))
    if path.suffix != (".ipk" if item["package_manager"] == "opkg" else ".apk"):
        raise ValueError("软件包扩展名与包管理器不一致")
    checks = item.get("checks") or {}
    for kind in ("regression", "business"):
        check = checks.get(kind)
        if not isinstance(check, dict):
            raise ValueError("修复产物须登记漏洞回归和业务检查脚本")
        script = checked_file(root, check.get("path", ""), check.get("sha256", ""), max_bytes=1_000_000)
        if script.suffix != ".py":
            raise ValueError("检查工具仅支持已登记的 Python 脚本")
    return item, path, root


def _risk_and_match(db, run, require_active=True):
    risk = db.get(models.RiskAssessment, run.risk_id) if run.risk_id else None
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk and risk.match_id else None
    if (not risk or risk.asset_id != run.asset_id or not match or match.asset_id != run.asset_id
            or match.cve_id != risk.cve_id or (require_active and (not risk.active or not match.active))):
        raise ValueError("任务没有有效且属于当前资产的风险事件")
    from app.services.review_common.governance import correction
    if correction(db, risk):
        raise ValueError("officially_corrected_risk_execution_blocked")
    if require_active:
        from app.services.review_common.governance import assert_execution_allowed
        assert_execution_allowed(db, risk)
    return risk, match


def create_run(db, asset_id, risk_id=None, goal="investigate", artifact_id="", model_review=False,
               trace_id="", shadow_run_id=""):
    if model_review:
        raise ValueError("harness_embedded_llm_retired_use_formal_analysis")
    if device_access.collection_only_mode() and goal != "collect":
        raise ValueError("联调采集模式只允许纯采集任务，不允许调查、复核或修复")
    if goal == "collect":
        if risk_id or artifact_id or model_review:
            raise ValueError("纯采集任务不能指定风险、修复产物或模型复核")
        connection = db.query(models.DeviceConnection).filter_by(asset_id=asset_id).one_or_none()
        if not connection:
            raise ValueError("纯采集任务需要已绑定的设备连接")
        from app.services import collection_tasks
        return collection_tasks.create_run(db, connection.id)
    asset = db.get(models.LinuxAsset, asset_id)
    if not asset:
        raise ValueError("资产不存在")
    risk = db.get(models.RiskAssessment, risk_id) if risk_id else None
    if risk_id and (not risk or risk.asset_id != asset_id):
        raise ValueError("风险事件不属于所选资产")
    connection = db.query(models.DeviceConnection).filter_by(asset_id=asset_id, enabled=True).one_or_none()
    snapshot = inventory(asset)
    plan = {"policy_version": POLICY_VERSION, "goal": goal, "asset_id": asset_id, "risk_id": risk_id,
            "repair_domain": asset.repair_domain,
            "model_review": bool(model_review), "inventory_hash": digest(snapshot),
            "connection_hash": connection_signature(connection) if connection else "",
            "agent_recommended_action": risk.recommended_action if risk else "",
            "agent_evidence_ids": json.loads(risk.review_evidence_ids or "[]") if risk else [],
            "review_hash": review_signature(risk) if risk else "",
            "steps": ["collect_inventory" if connection and asset.distribution == "openwrt" else "inspect_inventory", "inspect_runtime", "inspect_evidence"],
            "blocked_reasons": [], "limits": {"max_tool_calls": 16, "max_read_attempts": 3, "reserved_rollback_calls": 6},
            "artifact_id": artifact_id}
    if shadow_run_id:
        candidate = db.query(models.UnifiedAnalysisRun).filter_by(run_id=shadow_run_id).first()
        if not candidate or candidate.mode != "shadow" or candidate.status != "completed" or candidate.risk_id != risk_id or not risk_id:
            raise ValueError("影子候选计划须已完成且属于同一风险；不能作为修复授权")
        candidate_plan = json.loads(candidate.plan_json or "{}")
        plan["shadow_candidate"] = {"run_id": shadow_run_id, "trace_id": candidate.trace_id,
            "plan_sha256": digest(candidate_plan), "original_evidence_ids": candidate_plan.get("original_evidence_ids", []),
            "authorization": "none"}
    run = models.HarnessRun(id=uuid.uuid4().hex, asset_id=asset_id, risk_id=risk_id,
                            connection_id=connection.id if connection else None, snapshot_json=encode(snapshot))
    if goal == "repair":
        if asset.distribution == "ubuntu":
            from app.services import ubuntu_repair
            ubuntu_repair.enrich_plan(db, run, asset, risk, connection, plan)
        else:
            _openwrt_repair_plan(db, run, asset, risk, connection, snapshot, plan, artifact_id)
    else:
        run.status = "pending"
    run.plan_json, run.plan_hash = encode(plan), digest(plan)
    run.trace_id = trace_id or ""
    db.add(run)
    db.commit()
    if run.trace_id:
        payload = {"goal": goal, "plan_hash": run.plan_hash, "status": run.status,
                   "steps": plan["steps"], "blocked_reasons": plan.get("blocked_reasons", [])}
        tracing.emit(db, run.trace_id, "harness_plan", actor="harness",
                     status=run.status, payload=payload,
                     evidence_refs=plan.get("agent_evidence_ids", []))
        if run.status == "blocked":
            tracing.emit(db, run.trace_id, "harness_policy_blocked", actor="harness",
                         status="blocked", payload={"reasons": plan.get("blocked_reasons", [])})
    return run


def _openwrt_repair_plan(db, run, asset, risk, connection, snapshot, plan, artifact_id):
    reasons = plan["blocked_reasons"]
    if not connection:
        reasons.append("缺少已绑定的 OpenWrt SSH 连接")
    if asset.distribution != "openwrt" or not asset.inventory_complete:
        reasons.append("需要完整的 OpenWrt 资产清单")
    if not risk or not _authorized(risk):
        reasons.append("风险尚未通过现有审核策略")
    try:
        _, match = _risk_and_match(db, run)
        item, _, _ = load_artifact(artifact_id)
        if item["package_name"] != match.package_name or item["version"] != match.fixed_version:
            raise ValueError("产物的组件或修复版本与风险事件不一致")
        if match.reason_code != "openwrt_exact_affected_version" or not match.affected:
            raise ValueError("缺少精确的 OpenWrt 受影响版本证据")
        if item["release"] != asset.os_version or item["board_name"] != asset.device_model:
            raise ValueError("产物不适用于当前固件版本或设备型号")
        if item["package_manager"] != snapshot["package_managers"].get(item["package_name"]):
            raise ValueError("产物与当前设备的软件包管理器不一致")
        old_id = item.get("rollback_artifact_id", "")
        old, _, _ = load_artifact(old_id)
        if (old["package_name"] != item["package_name"] or old["version"] != snapshot["packages"].get(item["package_name"])
                or old["release"] != asset.os_version or old["board_name"] != asset.device_model
                or old["package_manager"] != item["package_manager"]):
            raise ValueError("回退产物与当前设备的软件版本不一致")
        plan.update(artifact_hash=digest(item), artifact={k: item[k] for k in ("id", "package_name", "version", "release", "board_name", "sha256")},
                    rollback_artifact_id=old_id, rollback_artifact_hash=digest(old), match_fingerprint=match.evidence_fingerprint)
    except (ValueError, OSError) as exc:
        reasons.append(str(exc))
    plan["model_review"] = False
    plan["steps"] = ["collect_inventory", "validate_plan", "install_registered_package", "collect_inventory", "verify_vendor_version", "regression_check", "business_check"]
    run.status = "blocked" if reasons else "awaiting_approval"

def approve(db, run, plan_hash, actor, reason):
    if run.risk_id:
        from app.services.review_common.governance import assert_execution_allowed
        assert_execution_allowed(db, db.get(models.RiskAssessment, run.risk_id))
    if digest(json.loads(run.plan_json)) != plan_hash:
        tracing.emit(db, run.trace_id, "harness_policy_blocked", actor="harness",
                     status="blocked", payload={"check": "plan_hash_mismatch", "submitted": plan_hash})
        raise ValueError("计划完整性校验失败")
    changed = db.execute(update(models.HarnessRun).where(models.HarnessRun.id == run.id,
        models.HarnessRun.status == "awaiting_approval", models.HarnessRun.plan_hash == plan_hash).values(
        approval_hash=plan_hash, approved_by=actor, approval_reason=reason, status="approved"))
    if changed.rowcount != 1:
        db.rollback()
        tracing.emit(db, run.trace_id, "harness_policy_blocked", actor="harness",
                     status="blocked", payload={"check": "approve_precondition", "status_was": run.status})
        raise ValueError("计划已变化或当前任务不处于待审批状态")
    db.commit()
    db.refresh(run)
    tracing.emit(db, run.trace_id, "harness_approved", actor="harness", status="approved",
                 payload={"plan_hash": plan_hash, "approved_by": actor, "reason": reason[:200]})


def cancel(db, run):
    changed = db.execute(update(models.HarnessRun).where(models.HarnessRun.id == run.id,
        models.HarnessRun.status.in_({"pending", "awaiting_preflight", "preflight_failed", "awaiting_approval", "approved", "blocked", "needs_evidence", "failed"})
    ).values(status="cancelled"))
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("运行中或结果待复查的任务不能直接取消")
    db.commit()
    db.refresh(run)
    tracing.finish_trace(db, run.trace_id, "completed",
                         summary={"harness_status": "cancelled", "cancelled": True})


def tool(db, run, name, function, arguments=None, side_effect=False, phase="main"):
    calls = db.query(models.HarnessToolCall).filter_by(run_id=run.id).all()
    phase_count = sum(json.loads(c.arguments_json).get("_phase", "main") == phase for c in calls)
    if phase_count >= (6 if phase == "rollback" else 16):
        tracing.emit(db, run.trace_id, "harness_policy_blocked", actor="harness", status="blocked",
                     payload={"check": "tool_budget", "phase": phase, "budget": 6 if phase == "rollback" else 16})
        raise ValueError("任务工具调用预算已用尽；请新建任务继续调查")
    call = models.HarnessToolCall(run_id=run.id, tool=name, side_effect=side_effect, arguments_json=encode({**(arguments or {}), "_phase": phase}))
    run.current_step = name
    db.add(call)
    db.commit()
    tracing.emit(db, run.trace_id, "harness_tool_started", actor="harness", status="running",
                 payload={"tool": name, "phase": phase, "side_effect": bool(side_effect),
                          "call_id": call.id}, commit=False)
    started = time.monotonic()
    try:
        result = function()
        call.status, call.output_json = "completed", encode(result)
        return result
    except Exception as exc:
        call.status, call.error = "failed", str(exc)[:1200]
        tracing.emit(db, run.trace_id, "harness_tool_failed", actor="harness", status="failed",
                     payload={"tool": name, "phase": phase, "call_id": call.id,
                              "error": str(exc)[:500]},
                     duration_ms=round((time.monotonic() - started) * 1000), commit=False)
        raise
    finally:
        call.duration_ms = round((time.monotonic() - started) * 1000)
        call.completed_at = models.utcnow()
        db.commit()
        if call.status == "completed":
            tracing.emit(db, run.trace_id, "harness_tool_finished", actor="harness",
                         status="succeeded",
                         payload={"tool": name, "phase": phase, "call_id": call.id,
                                  "side_effect": bool(side_effect),
                                  "summary": _tool_result_brief(result) if call.status == "completed" else ""},
                         duration_ms=call.duration_ms)


def _tool_result_brief(result, limit=400):
    text = encode(result)
    return text[:limit] + ("…" if len(text) > limit else "")


def _collect(db, connection):
    return inventory(iot_devices.collect_openwrt(db, connection))


def verification_proposal(db, run):
    """Read-only addendum: server registry selects checks, never a caller path."""
    plan = json.loads(run.plan_json)
    if (plan.get("goal") != "repair" or plan.get("adapter") or
            digest(plan) != run.plan_hash or run.approval_hash != run.plan_hash):
        raise ValueError("original_approved_openwrt_plan_required")
    connection = db.get(models.DeviceConnection, run.connection_id)
    if (not connection or connection.asset_id != run.asset_id or not connection.enabled or
            connection_signature(connection) != plan["connection_hash"]):
        raise ValueError("original_device_identity_required")
    original, _, _ = load_artifact(plan["artifact_id"])
    if digest(original) != plan["artifact_hash"]:
        raise ValueError("original_artifact_registration_changed")
    calls = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="install_registered_package").all()
    if len(calls) != 1:
        raise ValueError("one_successful_original_installation_required")
    receipt = calls[0]
    output, args = json.loads(receipt.output_json), json.loads(receipt.arguments_json)
    if (receipt.status != "completed" or not receipt.completed_at or not receipt.side_effect or
            output.get("command_exit_success") is not True or
            any(args.get(k) != original[v] or output.get(k) != original[v]
                for k, v in (("artifact_id", "id"), ("sha256", "sha256")))):
        raise ValueError("intact_successful_installation_receipt_required")
    item, _, _ = load_artifact(os.getenv("LINUXGUARD_VERIFICATION_ARTIFACT_ID", ""))
    if {k: v for k, v in item.items() if k not in {"id", "checks", "notes"}} != {
            k: v for k, v in original.items() if k not in {"id", "checks", "notes"}}:
        raise ValueError("verification_addendum_may_only_change_checks")
    proposal = {"run_id": run.id, "asset_id": run.asset_id, "risk_id": run.risk_id,
                "original_plan_sha256": run.plan_hash, "connection_hash": plan["connection_hash"],
                "installation_call_id": receipt.id,
                "installation_receipt_sha256": digest({"args": args, "output": output,
                    "completed_at": receipt.completed_at.isoformat()}),
                "artifact_id": item["id"], "artifact_hash": digest(item), "checks": item["checks"],
                "allowed_operations": ["collect_inventory", "version_and_scope", "regression_check", "business_check", "read_logread_and_device_clock"],
                "device_writes": False, "business_accepted": False}
    return {"proposal": proposal, "sha256": digest(proposal)}


def approve_verification(db, run, plan_hash, actor, reason):
    proposal = verification_proposal(db, run)
    if proposal["sha256"] != plan_hash:
        raise ValueError("verification_addendum_hash_mismatch")
    prior = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="verification_addendum_approved", status="completed").all()
    if any(json.loads(c.output_json).get("sha256") == plan_hash for c in prior):
        return proposal
    if run.status not in {"verification_required", "interrupted"}:
        raise ValueError("verification_resume_state_required")
    return tool(db, run, "verification_addendum_approved", lambda: proposal,
                {"actor": actor, "reason": reason, "previous_result": json.loads(run.result_json),
                 "previous_error": run.error}, phase="verification_approval")


def _verification_item(db, run):
    proposal = verification_proposal(db, run)
    approvals = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="verification_addendum_approved", status="completed").all()
    if not any(json.loads(c.output_json) == proposal for c in approvals):
        raise ValueError("verification_addendum_requires_operator_approval")
    return load_artifact(proposal["proposal"]["artifact_id"])


def _read_verification_logs(connection):
    client = device_access.open_connection(connection)
    try:
        output = device_access.run_fixed_script(client, "date -u '+%Y-%m-%dT%H:%M:%SZ'\nlogread | tail -n 120\n", timeout=20)
        # Coverage is bounded to this tail; absence of a hit is not proof of no compromise.
        text = output if isinstance(output, str) else encode(output)
        hits = re.findall(r"(?im)^.*(?:kernel panic|segmentation fault|out of memory|oom-kill|uhttpd.*crash|dnsmasq.*failed).*$", text)
        return {"passed": len(text.splitlines()) > 1 and not hits, "evidence": {"output": output, "severe_hits": hits,
                "coverage": "latest_120_logread_lines_only", "received_at": models.utcnow().isoformat()}}
    finally:
        client.close()


def _run_check(item, root, kind, target):
    config = item["checks"][kind]
    path = checked_file(root, config["path"], config["sha256"], max_bytes=1_000_000)
    # The script is an administrator-registered tool, never model-generated code.
    # Do not pass model keys or device passwords to the check process.
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP") if key in os.environ}
    env["PYTHONUTF8"] = "1"
    output = subprocess.run([sys.executable, str(path)], input=encode(target), text=True, encoding="utf-8",
                            capture_output=True, timeout=45, cwd=str(root), env=env, check=False)
    if output.returncode or len(output.stdout) > 20000:
        raise ValueError(f"{kind} 检查失败或输出超限")
    try:
        result = json.loads(output.stdout)
    except ValueError as exc:
        raise ValueError(f"{kind} 检查未返回结构化结果") from exc
    if not isinstance(result, dict) or not isinstance(result.get("passed"), bool) or not result.get("evidence"):
        raise ValueError(f"{kind} 检查必须返回 passed 布尔值及 evidence")
    return result


def openwrt_lab_write_state(asset_id):
    """Isolated OpenWrt lab-clone write contract (fail-closed).

    The production master switch LINUXGUARD_ENABLE_DEVICE_REPAIR is deliberately
    NOT consulted here and this scope never substitutes for it: a lab approval
    cannot be granted by turning on the production device switch, and vice
    versa. Empty or unset scope rejects every write.
    """
    if os.getenv("LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", "0") != "1":
        return False, "openwrt_lab_repair_disabled"
    scope = {part.strip() for part in (os.getenv("LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE", "") or "").split(",") if part.strip()}
    if str(asset_id) not in scope:
        return False, "openwrt_lab_asset_scope_not_declared"
    return True, ""


def _device_write_enabled(asset_id, db=None):
    # Only an operator-enrolled persistent domain grants eligibility. Inventory,
    # hostnames and environment allowlists cannot assign or change that domain.
    asset = db.get(models.LinuxAsset, asset_id) if db is not None else None
    if asset is None or asset.distribution != "openwrt":
        return False
    db.refresh(asset, attribute_names=["repair_domain"])
    if asset.repair_domain == "openwrt_lab":
        return openwrt_lab_write_state(asset_id)[0]
    if asset.repair_domain == "production":
        return os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") == "1"
    return False


def install_registered_package(connection, item, path, rollback=False):
    db = object_session(connection) if isinstance(connection, models.DeviceConnection) else None
    if not _device_write_enabled(connection.asset_id, db):
        raise ValueError("设备写操作未启用；请先完成产物、回退和检查配置")
    client = device_access.open_connection(connection)
    remote = "/tmp/linuxguard-" + uuid.uuid4().hex + path.suffix
    try:
        # Standard OpenWrt/Dropbear often has no SFTP server. Stream a bounded
        # artifact over SSH stdin; never require installing an extra service.
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest().lower() != item["sha256"].lower():
            raise ValueError("修复产物在审批后发生变化")
        stdin, stdout, stderr = client.exec_command("umask 077; cat > " + shlex.quote(remote), timeout=30)
        stdin.channel.sendall(data)
        stdin.channel.shutdown_write()
        deadline = time.monotonic() + 45
        while not stdout.channel.exit_status_ready():
            if stdout.channel.recv_stderr_ready():
                stdout.channel.recv_stderr(4096)
            if time.monotonic() > deadline:
                stdout.channel.close()
                raise TimeoutError("传输软件包超时")
            time.sleep(0.02)
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError("传输软件包失败")
        manager = item["package_manager"]
        command = (("opkg --force-downgrade install " if rollback else "opkg install ") if manager == "opkg" else "apk add --no-network ") + shlex.quote(remote)
        script = "set -eu\n" + "test \"$(sha256sum " + shlex.quote(remote) + " | cut -d ' ' -f 1)\" = " + shlex.quote(item["sha256"].lower()) + "\n" + command + "\n"
        device_access.run_fixed_script(client, script, timeout=90)
        return {"artifact_id": item["id"], "sha256": item["sha256"], "command_exit_success": True,
                "verification_pending": True}
    finally:
        try:
            device_access.run_fixed_script(client, "rm -f " + shlex.quote(remote), timeout=5)
        except Exception:
            pass
        client.close()



def _verify(db, run, connection, item, root):
    verification_started = models.utcnow()
    fresh = tool(db, run, "collect_inventory", lambda: _collect(db, connection))
    risk, match = _risk_and_match(db, run, require_active=False)
    run_matching(db, cve_ids=[risk.cve_id])
    db.refresh(match)
    original = json.loads(run.snapshot_json)
    expected_packages = {**original["packages"], item["package_name"]: item["version"]}
    scope_ok = (fresh["packages"] == expected_packages and fresh["package_managers"] == original["package_managers"]
                and all(fresh[key] == original[key] for key in ("mac", "model", "release", "architecture")))
    version_ok = (fresh["complete"] and fresh["packages"].get(item["package_name"]) == item["version"]
                  and match.match_status == "fixed" and match.reason_code == "openwrt_exact_fixed_version")
    target = {"host": connection.host, "asset_id": run.asset_id, "cve_id": risk.cve_id,
              "package_name": item["package_name"], "expected_version": item["version"]}
    installation = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="install_registered_package", status="completed").first()
    asset = db.get(models.LinuxAsset, run.asset_id)
    from app.services.evidence_freshness import freshness
    timing = freshness(asset.inventory_collected_at, installation.completed_at if installation else None, verification_started)
    target.update(installation_completed_at=installation.completed_at.isoformat() if installation and installation.completed_at else None,
                  verification_started_at=verification_started.isoformat())
    results = {"version_verified": bool(version_ok), "inventory_scope_verified": bool(scope_ok), "regression": None, "business": None}
    if version_ok and scope_ok:
        for kind in ("regression", "business"):
            results[kind] = tool(db, run, kind + "_check", lambda kind=kind: _run_check(item, root, kind, target), {"check_sha256": item["checks"][kind]["sha256"]})
    # Historical adapters retain their original contract; addenda require receipt-based timing.
    if os.getenv("LINUXGUARD_VERIFICATION_ARTIFACT_ID") == item["id"]:
        results["evidence_freshness"] = timing
        version_ok = version_ok and timing["passed"]
        if version_ok and scope_ok:
            results["logread"] = tool(db, run, "verification_logread", lambda: _read_verification_logs(connection))
            version_ok = version_ok and results["logread"]["passed"]
    passed = version_ok and scope_ok and all(results[kind] and results[kind]["passed"] for kind in ("regression", "business"))
    results["verified"] = bool(passed)
    installation = db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="install_registered_package").first()
    checkpoint = installation.created_at if installation else run.created_at
    results["runtime_comparison"] = compare_windows(db, run.asset_id, checkpoint.isoformat())
    run.status = "verified" if passed else "verification_required"
    if passed:
        risk.review_status = "resolved"
        risk.active = False
        risk.human_review_required = False
        for task in db.query(models.RemediationTask).filter_by(risk_id=risk.id):
            task.status = "verified"
    return results


def _claim(db, run, allowed_states):
    changed = db.execute(update(models.HarnessRun).where(models.HarnessRun.id == run.id,
                         models.HarnessRun.status.in_(allowed_states)).values(status="running", updated_at=models.utcnow()))
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("任务状态已变化或正在运行，请刷新")
    try:
        db.add(models.HarnessAssetLock(asset_id=run.asset_id, run_id=run.id))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("此资产已有任务执行中，暂不能并发操作") from exc
    db.refresh(run)


def execute(db, run, verify_only=False):
    plan = json.loads(run.plan_json)
    if not isinstance(plan, dict) or digest(plan) != run.plan_hash:
        raise ValueError("计划完整性校验失败")
    if plan.get("model_review"):
        raise ValueError("harness_embedded_llm_retired_use_formal_analysis")
    if plan.get("adapter") == "ubuntu-apt-v1":
        from app.services import ubuntu_repair
        return ubuntu_repair.queue(db, run, "verify" if verify_only else "execute")
    if plan.get("goal") == "collect":
        if verify_only:
            raise ValueError("纯采集任务不执行修复复查")
        from app.services import collection_tasks
        return collection_tasks.execute(db, run)
    if device_access.collection_only_mode():
        raise ValueError("联调采集模式不执行调查或修复任务")
    repair = plan["goal"] == "repair"
    if run.attempts >= 3:
        raise ValueError("任务尝试次数已达上限")
    if digest(plan) != run.plan_hash:
        raise ValueError("计划完整性校验失败")
    if repair and run.approval_hash != run.plan_hash:
        raise ValueError("尚未批准当前计划")
    verification_item = None
    if verify_only and repair and os.getenv("LINUXGUARD_VERIFICATION_ARTIFACT_ID"):
        verification_item = _verification_item(db, run)
        if run.status == "verified":
            return run
    states = {"verification_required", "interrupted"} if verify_only else {"approved"} if repair else {"pending", "needs_evidence", "failed"}
    if verify_only and not repair:
        raise ValueError("调查任务无需修复复查")
    _claim(db, run, states)
    run.attempts += 1
    run.error = ""
    db.commit()
    if run.trace_id:
        tracing.emit(db, run.trace_id, "harness_execute_started", actor="harness", status="running",
                     payload={"attempt": run.attempts, "goal": plan.get("goal"),
                              "verify_only": bool(verify_only),
                              "approved": run.approval_hash == run.plan_hash,
                              "asset_lock": run.asset_id})
    write_started = False
    try:
        connection = db.get(models.DeviceConnection, run.connection_id) if run.connection_id else None
        asset = db.get(models.LinuxAsset, run.asset_id)
        if not asset:
            raise ValueError("资产已不存在")
        if connection and connection_signature(connection) != plan["connection_hash"]:
            raise ValueError("设备连接已变化，必须重新创建并审批计划")
        if not repair:
            # The existing device Harness collector is OpenWrt-specific. Ubuntu
            # investigation consumes the separately authenticated node snapshot;
            # it must never run the OpenWrt script on a Linux host.
            snapshot = tool(db, run, "collect_inventory", lambda: _collect(db, connection)) if connection and asset.distribution == "openwrt" else tool(db, run, "inspect_inventory", lambda: inventory(asset))
            evidence = tool(db, run, "inspect_runtime", lambda: coverage(db, asset.id))
            result = {"inventory": snapshot, "runtime_coverage": evidence, "missing_evidence": []}
            if not snapshot["complete"]:
                result["missing_evidence"].append("完整软件包清单")
            if evidence["status"] != "running":
                result["missing_evidence"].append("有效采集心跳及覆盖范围")
            if run.risk_id:
                risk, _ = _risk_and_match(db, run)
                run_matching(db, cve_ids=[risk.cve_id])
                from app.services.review_common import build_evidence_packet
                result["evidence_packet"] = tool(db, run, "inspect_evidence", lambda: build_evidence_packet(db, risk).model_dump())
            run.status = "needs_evidence" if result["missing_evidence"] else "completed"
        else:
            if connection is None:
                raise ValueError("设备连接不存在")
            item, path, root = verification_item or load_artifact(plan["artifact_id"])
            if not verification_item and digest(item) != plan["artifact_hash"]:
                raise ValueError("修复产物清单已变化，审批已失效")
            if not verify_only:
                if plan.get("repair_domain") != db.get(models.LinuxAsset, run.asset_id).repair_domain:
                    raise ValueError("资产授权域与审批计划不一致，必须重新制定计划")
                risk, match = _risk_and_match(db, run)
                if not _authorized(risk) or review_signature(risk) != plan["review_hash"]:
                    raise ValueError("风险审核或漏洞证据已变化，必须重新审批")
                snapshot = tool(db, run, "collect_inventory", lambda: _collect(db, connection))
                if digest(snapshot) != plan["inventory_hash"]:
                    raise ValueError("设备软件清单在计划生成后发生变化，必须重新制定计划")
                run_matching(db, cve_ids=[risk.cve_id])
                db.refresh(match)
                if match.evidence_fingerprint != plan["match_fingerprint"]:
                    raise ValueError("漏洞适用性记录已变化，必须重新制定计划")
                old, _, _ = load_artifact(plan["rollback_artifact_id"])
                if digest(old) != plan["rollback_artifact_hash"]:
                    raise ValueError("回退产物变化，审批已失效")
                if not _device_write_enabled(run.asset_id, db):
                    raise ValueError("设备写操作未启用")
                write_started = True
                tool(db, run, "install_registered_package", lambda: install_registered_package(connection, item, path),
                     {"artifact_id": item["id"], "sha256": item["sha256"]}, side_effect=True)
            result = _verify(db, run, connection, item, root)
        run.result_json = encode(result)
    except Exception as exc:
        run.status = "verification_required" if write_started or verify_only else "failed"
        run.error = str(exc)[:1200]
    finally:
        run.completed_at = models.utcnow()
        db.query(models.HarnessAssetLock).filter_by(asset_id=run.asset_id, run_id=run.id).delete()
        db.commit()
        if run.trace_id:
            tracing.emit(db, run.trace_id, "harness_finished", actor="harness",
                         status=run.status,
                         payload={"harness_status": run.status, "error": (run.error or "")[:500],
                                  "verify_only": bool(verify_only)})
            trace_status = ("completed" if run.status in {"completed", "verified", "needs_evidence"}
                            else "failed")
            tracing.finish_trace(db, run.trace_id, trace_status, error=run.error,
                                 summary={"harness_status": run.status,
                                          "asset_id": run.asset_id,
                                          "verify_only": bool(verify_only)})
    return run


def recover_interrupted(db):
    """Expired leases become inspect-only; never replay an uncertain device write."""
    cutoff = models.utcnow() - timedelta(minutes=15)
    rows = db.query(models.HarnessRun).filter(models.HarnessRun.status == "running", models.HarnessRun.updated_at < cutoff).all()
    rows += [r for r in db.query(models.HarnessRun).filter(models.HarnessRun.status == "queued_remote",
        models.HarnessRun.updated_at < cutoff).all() if json.loads(r.plan_json).get("adapter") == "ubuntu-apt-v1"]
    for row in rows:
        row.status, row.error = "interrupted", "执行租约已超时；先复查设备状态，禁止自动重放写操作。"
        db.query(models.HarnessAssetLock).filter_by(run_id=row.id).delete()
        for call in db.query(models.HarnessToolCall).filter_by(run_id=row.id, status="running"):
            call.status, call.error = "interrupted", "运行进程中断或租约超时"
        if row.trace_id:
            tracing.emit(db, row.trace_id, "harness_finished", actor="harness",
                         status="interrupted",
                         payload={"harness_status": "interrupted",
                                  "note": "执行租约超时；未重放任何写操作"})
    db.commit()
    return len(rows)


def rollback(db, run, plan_hash, actor, reason):
    plan = json.loads(run.plan_json)
    if plan["goal"] != "repair" or plan_hash != run.plan_hash or digest(plan) != plan_hash or run.approval_hash != plan_hash:
        raise ValueError("回退审批与原始计划不一致")
    if plan.get("adapter") == "ubuntu-apt-v1":
        raise ValueError("Ubuntu 回滚依据为隔离 VM 快照；恢复操作须另行批准，禁止套用 OpenWrt 降级命令")
    if (not _device_write_enabled(run.asset_id, db) or
            plan.get("repair_domain") != db.get(models.LinuxAsset, run.asset_id).repair_domain):
        raise ValueError("设备写操作未启用或回退审批授权域已变化")
    if not db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="install_registered_package").first():
        raise ValueError("任务尚未尝试修复，无需回退")
    connection = db.get(models.DeviceConnection, run.connection_id)
    if not connection or connection_signature(connection) != plan["connection_hash"]:
        raise ValueError("设备连接已变化，回退被阻止")
    item, path, root = load_artifact(plan["rollback_artifact_id"])
    if digest(item) != plan["rollback_artifact_hash"]:
        raise ValueError("回退产物清单已变化")
    _claim(db, run, {"verification_required", "interrupted", "verified"})
    try:
        snapshot = tool(db, run, "collect_inventory", lambda: _collect(db, connection), phase="rollback")
        original = json.loads(run.snapshot_json)
        if any(snapshot[key] != original[key] for key in ("mac", "model", "release")):
            raise ValueError("设备身份或固件变化，不能回退")
        if not snapshot["complete"] or snapshot["packages"].get(item["package_name"]) not in {
                item["version"], plan["artifact"]["version"]}:
            raise ValueError("当前软件版本不属于原计划的修复或回退版本")
        # Invalidate a previous success before the first rollback write. A lost
        # connection after downgrade must never leave the risk marked resolved.
        if run.risk_id:
            risk, _ = _risk_and_match(db, run, require_active=False)
            risk.review_status = "verification"
            risk.active = True
            for task in db.query(models.RemediationTask).filter_by(risk_id=risk.id):
                task.status = "in_progress"
        db.commit()
        tool(db, run, "install_rollback_package", lambda: install_registered_package(connection, item, path, rollback=True),
             {"artifact_id": item["id"], "sha256": item["sha256"], "approved_by": actor, "reason": reason}, side_effect=True, phase="rollback")
        fresh = tool(db, run, "collect_inventory", lambda: _collect(db, connection), phase="rollback")
        restored = fresh["complete"] and fresh["packages"].get(item["package_name"]) == item["version"]
        business = tool(db, run, "business_check", lambda: _run_check(item, root, "business", {"host": connection.host, "asset_id": run.asset_id}), phase="rollback")
        run.status = "rolled_back" if restored and business["passed"] else "verification_required"
        run.result_json = encode({"rollback_version_restored": restored, "business": business, "vulnerability_resolved": False})
        if run.risk_id:
            risk, _ = _risk_and_match(db, run, require_active=False)
            run_matching(db, cve_ids=[risk.cve_id])
            risk.active = True
            risk.review_status = "remediation_ready"
            for task in db.query(models.RemediationTask).filter_by(risk_id=risk.id):
                task.status = "pending"
    except Exception as exc:
        run.status, run.error = "verification_required", str(exc)[:1200]
    finally:
        db.query(models.HarnessAssetLock).filter_by(asset_id=run.asset_id, run_id=run.id).delete()
        db.commit()
        if run.trace_id:
            tracing.emit(db, run.trace_id, "harness_rollback", actor="harness", status=run.status,
                         payload={"harness_status": run.status, "error": (run.error or "")[:500],
                                  "rollback_artifact_id": plan.get("rollback_artifact_id", "")})
            tracing.finish_trace(db, run.trace_id,
                                 "completed" if run.status == "rolled_back" else "failed",
                                 error=run.error,
                                 summary={"harness_status": run.status, "rollback": True})
    return run
