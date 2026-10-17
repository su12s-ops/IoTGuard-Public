"""Ubuntu adapter for agent_harness, not a second execution framework.

Uses HarnessRun, exact approval, tool budget, asset lock, Trace, and the existing
authenticated Linux collection-node transport. Original risks/reviews are read-only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
from types import SimpleNamespace
import uuid
from datetime import timezone

from sqlalchemy import update

from app import models
from app.services import device_access, collection_tasks, canonical_official
from app.services import trace_service as tracing
from app.services.matching_engine import _evaluate_match
from app.services.remediation_engine import _authorized

ROOT = Path(__file__).resolve().parents[3]
MAINTENANCE = ROOT / "collector" / "ubuntu_package_maintenance.py"
COLLECTOR = ROOT / "collector" / "collect_linux_asset.sh"
ADAPTER = "ubuntu-apt-v1"
SEPARATOR = "\nIOTGUARD_POST_INVENTORY\n"
ALLOW = frozenset({"curl", "libcurl4t64", "libcurl3t64-gnutls", "libcurl3t64-nss",
                   "libcurl4-openssl-dev", "libcurl4-gnutls-dev", "libcurl4-nss-dev", "libcurl4-doc"})


def h():
    from app.services import agent_harness
    return agent_harness


def official(db, cve, refresh=False):
    cve = cve.split(":")[0]
    if refresh:
        canonical_official.import_official_records(db, [cve])
        db.commit()
    row = db.query(models.OfficialCveRecord).filter_by(cve_id=cve).order_by(models.OfficialCveRecord.id.desc()).first()
    if not row or row.evidence_status != "available" or row.source_url != canonical_official.official_record_url(cve):
        raise ValueError("official_evidence_unavailable")
    fetched_at = row.fetched_at.replace(tzinfo=timezone.utc) if row.fetched_at.tzinfo is None else row.fetched_at
    if not 0 <= (models.utcnow() - fetched_at).total_seconds() <= 86400:
        raise ValueError("official_evidence_stale")
    data = json.loads(row.raw_json)
    if hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest() != row.content_sha256:
        raise ValueError("official_evidence_integrity_failed")
    entries = [e for e in canonical_official.record_statuses(cve, data) if e["release"] == "noble" and e["package"] == "curl"]
    if len(entries) != 1 or not entries[0]["fixed_version"] or entries[0]["effective_status"] != "released":
        raise ValueError("official_release_fix_unavailable")
    entry = entries[0]
    notices = [n for n in data.get("notices", []) if cve in n.get("cves_ids", []) and
               any(p.get("is_source") and p.get("name") == "curl" and p.get("version") == entry["fixed_version"]
                   for p in n.get("release_packages", {}).get("noble", []))]
    if not notices:
        raise ValueError("official_usn_fix_unavailable")
    binaries = sorted({p["name"] for n in notices for p in n["release_packages"]["noble"]
                       if not p.get("is_source") and p.get("version") == entry["fixed_version"]})
    return {"evidence_id": row.evidence_id, "sha256": row.content_sha256, "url": row.source_url,
            "fetched_at": row.fetched_at.isoformat(), "fixed_version": entry["fixed_version"],
            "canonical_table_status": entry["raw_status"], "notices": [n["id"] for n in notices],
            "binaries": binaries, "release": "noble", "source": "curl"}


def enrich_plan(db, run, asset, risk, connection, plan):
    reasons = plan["blocked_reasons"]
    plan.update(adapter=ADAPTER, steps=["ubuntu_dry_run", "approve_exact_plan", "ubuntu_preflight",
        "ubuntu_install_pinned_packages", "collect_inventory", "official_rematch", "risk_update_recommendation"],
        model_review=False, action_categories={"vulnerability_fix": "upgrade_installed_curl_source_binaries",
            "collector_health": "out_of_scope", "log_backup": "separate_operator_action",
            "rollback": "isolated_snapshot_restore_requires_separate_approval"})
    try:
        if not connection or not connection.enabled or connection.asset_id != asset.id:
            raise ValueError("缺少启用且绑定当前资产的连接")
        device_access.allowed_host(connection.host)
        if connection.auth_type != "ssh_key" or not re.fullmatch(r"LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}", connection.key_path_env or "") or connection.key_passphrase_env:
            raise ValueError("执行节点连接认证引用无效")
        node = collection_tasks.node_for_asset(asset)
        if not node or not os.getenv(collection_tasks.token_env_for(node)) or not collection_tasks.is_node_local(asset):
            raise ValueError("Ubuntu 修复须绑定已认证 Linux 本机节点；当前不开放远程 SSH 修复")
        if not asset.inventory_complete or not asset.os_version.startswith("24.04"):
            raise ValueError("本适配器仅支持完整 Ubuntu 24.04 noble 清单")
        checked_risk, match = h()._risk_and_match(db, run)
        if checked_risk != risk or match.package_name != "curl" or not match.affected:
            raise ValueError("需要当前资产的有效 curl 风险")
        proof = official(db, risk.cve_id)
        metadata = json.loads(asset.inventory_metadata_json or "{}")
        packages = {p.package_name: p for p in asset.packages}
        targets = []
        for line in metadata.get("package_sources", []):
            parts = line.split("|")
            if len(parts) != 3 or parts[1] != "curl":
                continue
            binary, source, source_version = parts
            name = binary.split(":")[0]
            pkg = packages.get(binary) or packages.get(name)
            if pkg:
                if name not in ALLOW or name not in proof["binaries"] or pkg.package_manager != "dpkg":
                    raise ValueError("同源二进制包未进入固定白名单或官方 USN")
                targets.append({"name": name, "binary": binary, "version": pkg.package_version,
                    "source": source, "source_version": source_version, "architecture": pkg.architecture})
        if not {"curl", "libcurl4t64"}.issubset({p["name"] for p in targets}):
            raise ValueError("缺少 curl/libcurl4t64 的真实已安装同源映射")
        plan.update(official=proof, targets=sorted(targets, key=lambda p: p["binary"]),
            identity={"hostname": asset.hostname, "distribution": "ubuntu", "release": "24.04", "codename": "noble"},
            node_id=node, maintenance_sha256=hashlib.sha256(MAINTENANCE.read_bytes()).hexdigest(),
            collector_sha256=hashlib.sha256(COLLECTOR.read_bytes()).hexdigest(),
            match_fingerprint=match.evidence_fingerprint, preflight=None,
            rollback={"strategy": "isolated_vm_snapshot_restore", "status": "awaiting_clone_and_restore_test",
                      "automatic_downgrade": False}, execution_authorization="requires_risk_review_and_separate_clone_permit")
    except (ValueError, OSError) as exc:
        reasons.append(str(exc))
    run.status = "blocked" if reasons else "awaiting_preflight"


def validate(db, run):
    from app.services.review_common.governance import assert_execution_allowed
    assert_execution_allowed(db, db.get(models.RiskAssessment, run.risk_id))
    plan = json.loads(run.plan_json)
    if plan.get("adapter") != ADAPTER or h().digest(plan) != run.plan_hash:
        raise ValueError("计划摘要无效")
    asset = db.get(models.LinuxAsset, run.asset_id)
    connection = db.get(models.DeviceConnection, run.connection_id) if run.connection_id else None
    if not asset or asset.distribution != "ubuntu" or not connection or not connection.enabled or connection.asset_id != run.asset_id or h().connection_signature(connection) != plan["connection_hash"]:
        raise ValueError("资产或连接绑定已变化")
    device_access.allowed_host(connection.host)
    if plan["node_id"] != collection_tasks.node_for_asset(asset) or not collection_tasks.is_node_local(asset) or asset.hostname != plan["identity"]["hostname"] or asset.os_version != plan["identity"]["release"]:
        raise ValueError("执行节点或目标身份已变化")
    if hashlib.sha256(MAINTENANCE.read_bytes()).hexdigest() != plan["maintenance_sha256"] or hashlib.sha256(COLLECTOR.read_bytes()).hexdigest() != plan["collector_sha256"]:
        raise ValueError("固定维护工具已变化")
    return plan, asset, connection


def queue(db, run, operation):
    if device_access.collection_only_mode():
        raise ValueError("采集模式不允许修复适配器")
    plan, asset, _ = validate(db, run)
    if run.attempts >= 3:
        raise ValueError("任务尝试次数已达上限")
    if operation == "dry_run":
        states = {"awaiting_preflight", "preflight_failed"}
    elif operation == "execute":
        states = {"approved"}
        risk, match = h()._risk_and_match(db, run)
        if run.approval_hash != run.plan_hash or not _authorized(risk) or h().review_signature(risk) != plan["review_hash"] or match.evidence_fingerprint != plan["match_fingerprint"]:
            raise ValueError("风险授权或精确计划审批未满足")
        if official(db, risk.cve_id)["sha256"] != plan["official"]["sha256"]:
            raise ValueError("官方修复依据已变化，须创建新计划")
        age = time.time() - plan.get("preflight_received_at", 0)
        if not plan.get("preflight") or not plan["preflight"]["ready"] or not 0 <= age <= 900:
            raise ValueError("预演缺失或已过期，须创建新计划")
        if os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") != "1" or os.getenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0") != "1":
            raise ValueError("设备写操作未启用；隔离副本执行须单独批准")
        # Backend and execution node independently require the clone-specific permit.
        from importlib.util import spec_from_file_location, module_from_spec
        spec = spec_from_file_location("ubuntu_maintenance", MAINTENANCE)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        module.permit({"asset_id": run.asset_id, "plan_hash": run.plan_hash}, plan["preflight"]["identity"])
    elif operation == "verify":
        states = {"verification_required", "interrupted"}
        if not db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="ubuntu_execute_dispatch", side_effect=True).first():
            raise ValueError("尚未尝试修复，不接受修复后复检")
    else:
        raise ValueError("不支持的 Ubuntu 操作")
    if operation != "verify" and h().digest(h().inventory(asset)) != plan["inventory_hash"]:
        raise ValueError("计划生成后资产清单变化，须创建新计划")
    h()._claim(db, run, states)
    try:
        request = {"operation": operation, "asset_id": run.asset_id, "plan_hash": run.plan_hash,
                   "identity": plan["identity"], "targets": plan["targets"],
                   "fixed_version": plan["official"]["fixed_version"], "preflight": plan.get("preflight")}
        script = "set -eu\npython3 -c " + shlex.quote(MAINTENANCE.read_text(encoding="utf-8")) + " <<'IOTGUARD_REQUEST'\n" + h().encode(request) + "\nIOTGUARD_REQUEST\n"
        if operation in {"execute", "verify"}:
            script += "printf '\\nIOTGUARD_POST_INVENTORY\\n'\nbash -s -- /dev/stdout <<'IOTGUARD_COLLECTOR'\n" + COLLECTOR.read_text(encoding="utf-8") + "\nIOTGUARD_COLLECTOR\n"
        audit = h().tool(db, run, "ubuntu_" + operation + "_dispatch", lambda: {
            "operation": operation, "queued_for_node": plan["node_id"], "script": script,
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(), "plan_hash": run.plan_hash,
            "request_id": uuid.uuid4().hex, "execution_status": "not_started"}, side_effect=operation == "execute")
        result = json.loads(run.result_json or "{}")
        result.update(dispatch=audit, execution_status="queued" if operation == "execute" else result.get("execution_status", "not_executed"))
        run.result_json, run.status = h().encode(result), "queued_remote"
        run.attempts += 1
        trace = db.query(models.TraceRun).filter_by(trace_id=run.trace_id).first() if run.trace_id else None
        if trace:
            trace.status, trace.finished_at, trace.error = "running", None, ""
        db.commit()
    except Exception:
        run.status = "failed"
        db.query(models.HarnessAssetLock).filter_by(run_id=run.id).delete()
        db.commit()
        raise
    return run


def claim(db, run, node_id):
    plan, asset, conn = validate(db, run)
    audit = json.loads(run.result_json)["dispatch"]
    if node_id != plan["node_id"] or audit["queued_for_node"] != node_id or audit["plan_hash"] != run.plan_hash:
        raise ValueError("节点或任务摘要不匹配")
    if audit["operation"] == "execute" and (run.approval_hash != run.plan_hash or os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") != "1"):
        raise ValueError("执行审批或写开关已变化")
    if audit["operation"] == "execute":
        risk, match = h()._risk_and_match(db, run)
        if not _authorized(risk) or h().review_signature(risk) != plan["review_hash"] or match.evidence_fingerprint != plan["match_fingerprint"]:
            raise ValueError("领取前风险授权已变化")
        if os.getenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0") != "1":
            raise ValueError("隔离副本写开关已关闭")
        if not 0 <= time.time() - plan.get("preflight_received_at", 0) <= 900:
            raise ValueError("执行预演已过期")
    changed = db.execute(update(models.HarnessRun).where(models.HarnessRun.id == run.id,
        models.HarnessRun.status == "queued_remote").values(status="running"))
    if changed.rowcount != 1:
        db.rollback()
        return None
    audit.update(execution_node=node_id, claimed_at=time.time(), execution_status="claimed")
    result = json.loads(run.result_json)
    result["dispatch"] = audit
    run.result_json = h().encode(result)
    tracing.emit(db, run.trace_id, "ubuntu_operation_claimed", actor="harness", status="running",
        payload={"operation": audit["operation"], "node_id": node_id}, commit=False)
    db.commit()
    return {"run_id": run.id, "node": {"id": node_id}, "collector_type": "linux_ssh",
        "harness_adapter": ADAPTER, "operation": audit["operation"], "collector_script": audit["script"],
        "collector_sha256": audit["script_sha256"], "execution": "node_local",
        "connection": {k: getattr(conn, k) for k in ("host", "port", "username", "auth_type", "key_path_env", "key_passphrase_env", "host_key_sha256")},
        "authorized_cidrs": [str(n) for n in device_access.allowed_networks()],
        "asset": {"id": asset.id, "hostname": asset.hostname, "distribution": "ubuntu"}}


def rematch(db, run, plan, post, inventory_text):
    """Fresh collector + fresh official response → deterministic recommendation.

    Reuses the matcher's pure evaluator; never updates the old match/risk/review.
    """
    from app.services.asset_parser import parse_asset_text
    fresh = parse_asset_text(inventory_text)
    if not fresh.inventory_complete or any(getattr(fresh, k) != plan["identity"][j] for k, j in
            (("hostname", "hostname"), ("distribution", "distribution"), ("os_version", "release"))):
        raise ValueError("post_inventory_identity_or_completeness_failed")
    if post.get("identity") != plan["preflight"]["identity"]:
        raise ValueError("post_machine_identity_changed")
    source_rows = post.get("packages", [])
    if sorted(p["binary"] for p in source_rows) != sorted(p["binary"] for p in plan["targets"]):
        raise ValueError("post_source_mapping_changed")
    source_lines = json.loads(fresh.inventory_metadata_json).get("package_sources", [])
    raw_sources = [line.split("|")[0] for line in source_lines if len(line.split("|")) == 3 and line.split("|")[1] == "curl"]
    if sorted(raw_sources) != sorted(p["binary"] for p in source_rows):
        raise ValueError("post_source_metadata_scope_changed")
    evidence_id = "INV-" + uuid.uuid4().hex
    raw_hash = hashlib.sha256(inventory_text.encode()).hexdigest()
    db.add(models.CollectionEvidence(evidence_id=evidence_id, run_id=run.id, asset_id=run.asset_id,
                                    content_sha256=raw_hash, raw_text=inventory_text))
    # Publish fresh inventory through the established ingestion path; keep old
    # evidence immutable. Raw result evidence is also retained if ingestion fails.
    connection = db.get(models.DeviceConnection, run.connection_id)
    collection_tasks.ingest_linux_inventory(db, connection, inventory_text, {
        "run_id": run.id + "-post", "execution": "node_local", "execution_node": plan["node_id"],
        "collector_sha256": plan["collector_sha256"], "ssh_host_identity": "not_applicable"})
    proof = official(db, plan["cve_id"], refresh=True)
    matches = []
    packages = {p["package_name"]: SimpleNamespace(**p) for p in fresh.packages}
    original = {p["binary"]: p for p in plan["targets"]}
    statuses = []
    for row in source_rows:
        pkg = packages.get(row["binary"]) or packages.get(row["name"])
        if not pkg or pkg.package_version != row["version"] or row["source"] != "curl":
            raise ValueError("post_inventory_source_inconsistent")
        if f"{row['binary']}|curl|{row['source_version']}" not in source_lines:
            raise ValueError("post_source_metadata_inconsistent")
        value = _evaluate_match(fresh, SimpleNamespace(affected_package=row["name"], fixed_version=proof["fixed_version"]), pkg,
            {"source": "canonical", "release": "noble", "fixed_version": proof["fixed_version"], "status": "fixed"})
        source_value = _evaluate_match(fresh, SimpleNamespace(affected_package="curl", fixed_version=proof["fixed_version"]),
            SimpleNamespace(package_version=row["source_version"]),
            {"source": "canonical", "release": "noble", "fixed_version": proof["fixed_version"], "status": "fixed"})
        if source_value["match_status"] != "fixed":
            value.update(match_status="potentially_affected", affected=True, reason_code="source_version_below_official_fix")
        matches.append({"binary": row["binary"], **value})
        statuses.append("version_unchanged" if row["version"] == original[row["binary"]]["version"] else
                        "fixed" if value["match_status"] == "fixed" else "partial_update")
    verified = bool(statuses) and all(s == "fixed" for s in statuses)
    return {"verified": verified, "status": "fixed_version_verified" if verified else
            "version_unchanged" if all(s == "version_unchanged" for s in statuses) else "partial_update",
            "risk_update_recommendation": "fixed_pending_human_acceptance" if verified else "keep_open",
            "original_risk_unchanged": True, "inventory_evidence_id": evidence_id, "inventory_sha256": raw_hash,
            "official": proof, "matches": matches, "before": plan["targets"], "after": source_rows,
            "business_validation": "requires_isolated_experiment_acceptance"}


def submit(db, run, payload):
    plan, _, _ = validate(db, run)
    result = json.loads(run.result_json)
    audit = result["dispatch"]
    if run.status != "running" or payload.get("node_id") != plan["node_id"] or payload.get("node_platform") != "Linux" or audit.get("execution_node") != plan["node_id"]:
        raise ValueError("未领取任务或错误节点，拒绝结果")
    operation = audit["operation"]
    try:
        if payload.get("status") != "succeeded":
            raise ValueError(str(payload.get("error_code") or "node_operation_failed"))
        text = payload.get("inventory_text", "")
        if payload.get("local_hostname") != plan["identity"]["hostname"] or payload.get("collector_sha256") != audit["script_sha256"] or payload.get("output_sha256") != hashlib.sha256(text.encode()).hexdigest() or payload.get("output_bytes") != len(text.encode()):
            raise ValueError("node_result_integrity_or_identity_failed")
        evidence_id = "PRE-" + uuid.uuid4().hex
        db.add(models.CollectionEvidence(evidence_id=evidence_id, run_id=run.id, asset_id=run.asset_id,
            content_sha256=hashlib.sha256(text.encode()).hexdigest(), raw_text=text))
        output, _, inventory_text = text.partition(SEPARATOR)
        data = h().tool(db, run, "ubuntu_" + operation + "_result", lambda: json.loads(output), {"evidence_id": evidence_id})
        if data.get("error"):
            raise ValueError(data["error"])
        if operation == "dry_run":
            pre = data["preflight"]
            if any(pre["identity"].get(k) != v for k, v in plan["identity"].items()) or pre["packages"] != plan["targets"]:
                raise ValueError("preflight_identity_or_installed_version_changed")
            if set(pre["candidate_versions"]) != {p["binary"] for p in plan["targets"]}:
                raise ValueError("preflight_candidate_scope_changed")
            plan.update(preflight=pre, preflight_evidence_id=evidence_id, preflight_received_at=time.time())
            plan["identity"] = pre["identity"]
            plan["cve_id"] = h()._risk_and_match(db, run)[0].cve_id.split(":")[0]
            # Approve only the plan containing the observed versions and dry-run.
            run.plan_json, run.plan_hash = h().encode(plan), h().digest(plan)
            run.approval_hash = ""
            result.update(dry_run=pre, preflight_evidence_id=evidence_id, rollback=plan["rollback"], execution_status="not_executed")
            run.status = "awaiting_approval" if pre["ready"] else "preflight_failed"
        else:
            if operation == "execute":
                result["execution"] = data
                result["execution_status"] = "command_succeeded" if data.get("exit_code") == 0 else "package_operation_failed"
                result["rollback"] = {"strategy": "isolated_vm_snapshot_restore", "status": "restore_verified_by_operator_attestation",
                                      "snapshot_permit": data.get("snapshot_permit"), "restored": False}
            post = data if operation == "verify" else data["after"]
            verification = h().tool(db, run, "ubuntu_official_rematch", lambda: rematch(db, run, plan, post, inventory_text))
            result["verification"] = verification
            if operation == "execute" and data.get("exit_code") != 0:
                verification.update(verified=False, status="package_operation_failed", risk_update_recommendation="keep_open")
            run.status = "verified" if verification["verified"] else "verification_required"
        result["latest_evidence_id"] = evidence_id
        run.error = ""
    except Exception as exc:
        result.update(failure={"code": str(exc)[:160], "operation": operation},
            execution_status="unknown_or_interrupted" if operation == "execute" else result.get("execution_status", "not_executed"))
        run.error = str(exc)[:500]
        run.status = "preflight_failed" if operation == "dry_run" else "verification_required"
    finally:
        result["dispatch"] = {k: v for k, v in audit.items() if k != "script"}
        run.result_json = h().encode(result)
        run.completed_at = models.utcnow()
        db.query(models.HarnessAssetLock).filter_by(run_id=run.id).delete()
        tracing.emit(db, run.trace_id, "ubuntu_operation_finished", actor="harness", status=run.status,
            payload={"operation": operation, "error": run.error, "result": {k: result.get(k) for k in ("execution_status", "verification", "preflight_evidence_id")}},
            evidence_refs=[result.get("latest_evidence_id", ""), result.get("preflight_evidence_id", ""),
                (result.get("verification") or {}).get("inventory_evidence_id", ""),
                ((result.get("verification") or {}).get("official") or plan.get("official", {})).get("evidence_id", "")], commit=False)
        db.commit()
        tracing.finish_trace(db, run.trace_id, "blocked" if run.status == "preflight_failed" else
            "failed" if run.status == "verification_required" else "completed", error=run.error,
            summary={"harness_status": run.status, "operation": operation})
    return run
