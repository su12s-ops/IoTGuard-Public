"""Read-only planning bridge to the existing deterministic Harness.

No run creation, task dispatch, approval, database write or device I/O occurs
here. A successful precheck is technical advice, never execution authority.
The caller stores this bounded result in the existing LangGraph state/Trace.
"""
from __future__ import annotations

import json
import os
import re
import time
from types import SimpleNamespace

from app import models
from app.services import agent_harness as harness, device_access
from app.services.remediation_engine import _authorized
from app.services.review_common.governance import correction

CONTRACT = "unified-harness-readonly-v1"
READ_ACTIONS = frozenset({"collect_evidence", "verify_version", "check_service"})
TECHNICAL_ORDER = ("incompatible_version", "missing_artifact",
                   "missing_recovery_point", "insufficient_evidence")


def _mapping(value):
    return value.model_dump() if hasattr(value, "model_dump") else dict(value or {})


def _json(value):
    try:
        data = json.loads(value or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def _id(value, prefix=""):
    text = str(value or "")
    if prefix and text.startswith(prefix + "-"):
        text = text[len(prefix) + 1:]
    return int(text) if text.isdigit() and int(text) > 0 else None


def _refs(state):
    snapshot = state.get("evidence_snapshot") or {}
    registry = snapshot.get("evidence_registry")
    if isinstance(registry, dict):
        from app.services.unified.collaboration import evidence_registry_ids
        return evidence_registry_ids(snapshot)
    return {str(value) for value in
            ((state.get("baseline") or {}).get("packet_evidence_ids") or []) if value}


def _issue(issues, status, reason):
    row = {"status": status, "reason": reason}
    if row not in issues:
        issues.append(row)


def _objects(db, state):
    snapshot = state.get("evidence_snapshot") or {}
    risk_id = _id((state.get("baseline") or {}).get("object_id"), "risk")
    risk_id = risk_id or _id(state.get("object_id"), "risk") or _id(snapshot.get("risk_id"))
    risk = db.get(models.RiskAssessment, risk_id) if risk_id else None
    asset_id = risk.asset_id if risk else _id(snapshot.get("asset_id") or state.get("asset_id"))
    asset = db.get(models.LinuxAsset, asset_id) if asset_id else None
    if not asset and state.get("target_ref"):
        target = state["target_ref"]
        asset = db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == target) | (models.LinuxAsset.ip_address == target)).first()
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk and risk.match_id else None
    return asset, risk, match


def _write_policy(asset):
    if device_access.collection_only_mode():
        return False, "collection_only_mode"
    if asset.distribution == "openwrt":
        if asset.repair_domain == "production":
            enabled = os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") == "1"
            return enabled, "" if enabled else "production_device_write_disabled"
        if asset.repair_domain == "openwrt_lab":
            return harness.openwrt_lab_write_state(asset.id)
        return False, "asset_repair_domain_unassigned"
    if asset.distribution == "ubuntu":
        from app.services import ubuntu_repair
        return ubuntu_repair.lab_write_state(asset.id)
    return False, "repair_adapter_unavailable"


def _openwrt_capabilities(asset, match, issues):
    """Reuse the registered artifact loader; never execute registered scripts."""
    artifacts = []
    try:
        registry, _ = harness.artifact_registry()
    except (ValueError, OSError):
        _issue(issues, "missing_artifact", "artifact_registry_unavailable")
        registry = {}
    relevant = [item for item in registry.values()
                if match and item.get("package_name") == match.package_name
                and item.get("version") == match.fixed_version]
    installed = {p.package_name: p for p in asset.packages}
    for registered in relevant:
        artifact_issues = []
        try:
            item, _, _ = harness.load_artifact(registered["id"])
        except (ValueError, OSError):
            _issue(issues, "missing_artifact", "registered_artifact_integrity_or_policy_failed")
            continue
        package = installed.get(item["package_name"])
        if (item["release"] != asset.os_version or item["board_name"] != asset.device_model
                or not package or item["package_manager"] != package.package_manager):
            _issue(artifact_issues, "incompatible_version", "artifact_device_or_package_manager_mismatch")
        architecture = str(item.get("architecture") or "")
        expected_arch = package.architecture if package and package.architecture else asset.architecture
        if not architecture or not expected_arch:
            _issue(artifact_issues, "insufficient_evidence", "artifact_architecture_unverified")
        elif architecture not in {expected_arch, "all", "noarch"}:
            _issue(artifact_issues, "incompatible_version", "artifact_architecture_mismatch")
        recovery = {"ready": False, "artifact_id": item.get("rollback_artifact_id", "")}
        try:
            old, _, _ = harness.load_artifact(recovery["artifact_id"])
            if (not package or old["package_name"] != item["package_name"]
                    or old["version"] != package.package_version or old["release"] != asset.os_version
                    or old["board_name"] != asset.device_model
                    or old["package_manager"] != item["package_manager"]
                    or old.get("architecture") not in {expected_arch, "all", "noarch"}):
                raise ValueError("recovery_artifact_incompatible")
            recovery["ready"] = True
        except (ValueError, OSError):
            _issue(artifact_issues, "missing_recovery_point", "compatible_registered_rollback_artifact_required")
        artifacts.append({**{key: item.get(key, "") for key in
            ("id", "package_name", "version", "release", "board_name", "sha256", "package_manager")},
            "architecture": architecture, "integrity_verified": True,
            "trust_basis": "operator_registered_checksum_bound_artifact_and_checks",
            "compatible": not artifact_issues, "issues": artifact_issues, "recovery": recovery})
    compatible = [item for item in artifacts if item["compatible"]]
    if not artifacts:
        _issue(issues, "missing_artifact", "trusted_matching_artifact_required")
    elif not compatible:
        for item in artifacts:
            for issue in item["issues"]:
                _issue(issues, **issue)
    return artifacts


def _ubuntu_capabilities(db, asset, risk, connection, latest, issues):
    """Reuse the adapter's plan checks on an unpersisted request only."""
    from app.services import ubuntu_repair
    transient = SimpleNamespace(asset_id=asset.id, risk_id=risk.id if risk else None, status="")
    plan = {"blocked_reasons": []}
    ubuntu_repair.enrich_plan(db, transient, asset, risk, connection, plan)
    if plan["blocked_reasons"]:
        _issue(issues, "insufficient_evidence", "ubuntu_adapter_preconditions_unsatisfied")
    previous = _json(latest.plan_json) if latest else {}
    preflight = previous.get("preflight") or {}
    same_context = bool(latest and latest.risk_id == (risk.id if risk else None)
        and previous.get("inventory_hash") == harness.digest(harness.inventory(asset))
        and previous.get("official", {}).get("sha256") == plan.get("official", {}).get("sha256"))
    age = time.time() - previous.get("preflight_received_at", 0)
    valid_preflight = bool(same_context and 0 <= age <= 900 and preflight.get("ready")
                           and ubuntu_repair.root_preflight(preflight))
    if not valid_preflight:
        _issue(issues, "insufficient_evidence", "fresh_authenticated_ubuntu_dependency_dry_run_required")
    # Snapshot permission must still be independently verified at execution.
    _issue(issues, "missing_recovery_point", "ubuntu_clone_restore_permit_requires_execution_time_validation")
    proof = plan.get("official") or {}
    return {"official_fixed_version": proof.get("fixed_version", ""),
            "official_evidence_id": proof.get("evidence_id", ""),
            "targets": plan.get("targets", []), "dependency_dry_run_valid": valid_preflight,
            "dry_run_performed_here": False}


def query_capabilities(db, state) -> dict:
    """Fresh metadata query, safe for both Pydantic and dict graph states."""
    state = _mapping(state)
    issues = []
    # Even callers with autoflush=True cannot persist pending changes here.
    with db.no_autoflush:
        asset, risk, match = _objects(db, state)
        result = {"contract": CONTRACT, "queried_at": models.utcnow().isoformat(),
            "snapshot_id": state.get("evidence_snapshot_id") or
                (state.get("evidence_snapshot") or {}).get("snapshot_id", ""),
            "read_only": True, "device_writes": False, "execution_authorized": False,
            "adapter": None, "supported_actions": sorted(READ_ACTIONS),
            "identity": {}, "trusted_artifacts": [], "issues": issues,
            "approvals": {"risk_review_required": True, "exact_plan_approval_required": True,
                "capability_query_grants_authorization": False},
            "policy": {"writes_enabled": False, "denied_reasons": []},
            "current_harness": None, "business_accepted": False}
        if not asset:
            _issue(issues, "insufficient_evidence", "asset_identity_not_resolved")
            return result
        result["identity"] = {"asset_id": asset.id, "risk_id": risk.id if risk else None,
            "cve_id": risk.cve_id if risk else "", "distribution": asset.distribution,
            "release": asset.os_version, "architecture": asset.architecture,
            "package_name": match.package_name if match else "",
            "installed_version": match.installed_version if match else "",
            "fixed_version": match.fixed_version if match else "",
            "inventory_sha256": asset.inventory_sha256 or "",
            "inventory_hash": harness.digest(harness.inventory(asset))}
        snapshot = state.get("evidence_snapshot") or {}
        if snapshot.get("asset_id") and _id(snapshot["asset_id"]) != asset.id:
            _issue(issues, "policy_denied", "snapshot_asset_scope_mismatch")
        if snapshot.get("risk_id") and _id(snapshot["risk_id"]) != (risk.id if risk else None):
            _issue(issues, "policy_denied", "snapshot_risk_scope_mismatch")
        valid_match = bool(risk and match and risk.asset_id == asset.id and match.asset_id == asset.id
                           and match.cve_id == risk.cve_id)
        if not valid_match:
            _issue(issues, "insufficient_evidence", "asset_bound_risk_and_match_required")
            if risk and match:
                _issue(issues, "policy_denied", "risk_match_scope_mismatch")
        elif not risk.active or not match.active or correction(db, risk):
            _issue(issues, "policy_denied", "risk_inactive_or_officially_corrected")
        elif not match.affected or match.match_status == "fixed":
            _issue(issues, "incompatible_version", "repair_not_applicable_to_current_match")
        if risk:
            result["approvals"]["risk_review_required"] = not _authorized(risk)
        if not asset.inventory_complete:
            _issue(issues, "insufficient_evidence", "complete_inventory_required")
        connection = db.query(models.DeviceConnection).filter_by(asset_id=asset.id, enabled=True).first()
        if not connection:
            _issue(issues, "insufficient_evidence", "bound_enabled_connection_required")
        else:
            try:
                device_access.allowed_host(connection.host)
            except ValueError:
                _issue(issues, "policy_denied", "device_outside_authorized_network_scope")
            if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", connection.host_key_sha256 or ""):
                _issue(issues, "insufficient_evidence", "pinned_device_identity_required")
        runs = db.query(models.HarnessRun).filter_by(asset_id=asset.id)
        if risk:
            runs = runs.filter_by(risk_id=risk.id)
        latest = runs.order_by(models.HarnessRun.created_at.desc()).first()
        if latest:
            result["current_harness"] = {"run_id": latest.id, "status": latest.status,
                "risk_id": latest.risk_id, "completed_at":
                    latest.completed_at.isoformat() if latest.completed_at else None,
                "execution_verified": latest.status == "verified",
                "business_acceptance_inferred": False, "approval_reused": False}
        if asset.distribution == "openwrt":
            result["adapter"] = "openwrt_registered_package"
            result["supported_actions"].append("update_package")
            if not match or match.reason_code != "openwrt_exact_affected_version":
                _issue(issues, "insufficient_evidence", "exact_openwrt_affected_version_required")
            result["trusted_artifacts"] = _openwrt_capabilities(asset, match, issues)
        elif asset.distribution == "ubuntu":
            result["adapter"] = "ubuntu-apt-v1"
            result["supported_actions"].append("update_package")
            result["ubuntu"] = _ubuntu_capabilities(db, asset, risk, connection, latest, issues)
        else:
            _issue(issues, "insufficient_evidence", "repair_adapter_unavailable")
        enabled, reason = _write_policy(asset)
        result["policy"]["writes_enabled"] = enabled
        if reason:
            _issue(issues, "policy_denied", reason)
        result["policy"]["denied_reasons"] = [i["reason"] for i in issues if i["status"] == "policy_denied"]
        result["compatibility"] = {"verified": bool(result["trusted_artifacts"] and
            any(a["compatible"] for a in result["trusted_artifacts"])),
            "unknown_is_not_compatible": True}
        result["recovery"] = {"ready": bool(result["trusted_artifacts"] and
            any(a["compatible"] and a["recovery"]["ready"] for a in result["trusted_artifacts"])),
            "requires_separate_execution_validation": True}
        return result


def build_candidate_intents(state, plan) -> list[dict]:
    """Bind model action names to deterministic identity, refs and fixed versions."""
    state, plan = _mapping(state), _mapping(plan)
    capabilities = state.get("harness_capabilities") or {}
    identity = capabilities.get("identity") or {}
    known = _refs(state)
    cited = set(plan.get("original_evidence_ids") or [])
    for verdict in (state.get("decision") or {}).get("verdicts") or []:
        cited.update(verdict.get("supporting_evidence_ids") or [])
    snapshot = state.get("evidence_snapshot") or {}
    if snapshot:
        from app.services.unified.collaboration import classify_evidence_id
        unexplained = {ref for ref in cited - known
                       if classify_evidence_id(ref, snapshot) != "known_but_summarized"}
    else:
        unexplained = cited - known
    intents = []
    for index, action in enumerate(plan.get("actions") or []):
        action = _mapping(action)
        kind = action.get("action", "")
        target = action.get("target", "")
        params = action.get("params") or {}
        missing = []
        if not identity.get("asset_id"):
            missing.append("deterministic_asset_identity_required")
        if not cited.intersection(known):
            missing.append("validated_evidence_references_required")
        if unexplained:
            missing.append("unknown_evidence_references_rejected")
        if kind == "update_package" and any(params.get(k) and params[k] != identity.get("fixed_version")
                for k in ("version", "target_version", "fixed_version")):
            missing.append("model_version_conflicts_with_deterministic_fix")
        intents.append({"intent_id": f"intent-{index + 1}",
            "asset_id": identity.get("asset_id"), "risk_id": identity.get("risk_id"),
            "cve_id": identity.get("cve_id", ""),
            "snapshot_id": state.get("evidence_snapshot_id") or capabilities.get("snapshot_id", ""),
            "inventory_hash": identity.get("inventory_hash", ""),
            "evidence_ids": sorted(cited.intersection(known)), "action_type": kind,
            "target_component": target,
            "expected_result": {"fixed_version": identity.get("fixed_version", "")
                if kind == "update_package" else "", "risk_closure_automatic": False},
            "artifact_requirements": {"operator_registered": True, "checksum_verified": True,
                "matching_release_architecture_component": True} if kind == "update_package" else {},
            "preconditions": ["current_snapshot", "asset_bound_evidence"] +
                (["eligible_risk_review", "exact_plan_approval", "device_write_policy"]
                 if kind not in READ_ACTIONS else []),
            "verification_requirements": ["fresh_inventory", "vendor_version_rematch",
                "registered_regression_and_business_checks", "full_four_role_reassessment"]
                if kind == "update_package" else ["authorized_read_only_collection"],
            "rollback_requirements": ["compatible_registered_recovery_artifact_or_approved_restore_point"]
                if kind == "update_package" else [],
            "unsatisfied_conditions": missing, "requires_approval": True,
            "execution_authorized": False})
    return intents


def precheck_intents(db, state, intents) -> dict:
    """Pure metadata dry-run; authorization and live dependencies are never cached."""
    state = _mapping(state)
    capabilities = query_capabilities(db, state)
    identity = capabilities["identity"]
    known = _refs(state)
    checked, feedback = [], []
    for raw in intents:
        intent = _mapping(raw)
        issues = []
        write = intent.get("action_type") not in READ_ACTIONS
        if write:
            issues.extend(dict(item) for item in capabilities["issues"])
        else:
            # Read-only advice also cannot escape the incident's identity scope.
            issues.extend(dict(item) for item in capabilities["issues"]
                if item["reason"] in {"snapshot_asset_scope_mismatch", "snapshot_risk_scope_mismatch",
                    "risk_match_scope_mismatch"})
        if (not identity or intent.get("asset_id") != identity.get("asset_id")
                or intent.get("risk_id") != identity.get("risk_id")):
            _issue(issues, "policy_denied", "intent_identity_scope_mismatch")
        if intent.get("cve_id", "") != identity.get("cve_id", ""):
            _issue(issues, "policy_denied", "intent_cve_scope_mismatch")
        if not intent.get("snapshot_id") or intent["snapshot_id"] != capabilities["snapshot_id"]:
            _issue(issues, "insufficient_evidence", "current_snapshot_required")
        if not intent.get("inventory_hash") or intent["inventory_hash"] != identity.get("inventory_hash"):
            _issue(issues, "insufficient_evidence", "inventory_changed_since_candidate_intent")
        references = set(intent.get("evidence_ids") or [])
        if not references or references - known:
            _issue(issues, "insufficient_evidence", "validated_evidence_references_required")
        for reason in intent.get("unsatisfied_conditions") or []:
            _issue(issues, "insufficient_evidence", reason)
        if intent.get("action_type") not in capabilities["supported_actions"]:
            _issue(issues, "policy_denied", "unsupported_harness_action")
        if intent.get("action_type") == "update_package":
            allowed_targets = {identity.get("package_name")}
            allowed_targets.update(t["name"] for t in capabilities.get("ubuntu", {}).get("targets", []))
            if intent.get("target_component") not in allowed_targets:
                _issue(issues, "incompatible_version", "fix_target_not_affected_component")
            if not identity.get("fixed_version") or (intent.get("expected_result") or {}).get("fixed_version") != identity.get("fixed_version"):
                _issue(issues, "incompatible_version", "fix_version_not_deterministically_verified")
        technical = next((status for status in TECHNICAL_ORDER if any(i["status"] == status for i in issues)), "executable")
        terminal = any(i["status"] == "policy_denied" for i in issues)
        if write:
            _issue(issues, "authorization_required", "exact_plan_hash_and_operator_approval_required")
            if capabilities["approvals"]["risk_review_required"]:
                _issue(issues, "authorization_required", "eligible_risk_review_required")
        status = "policy_denied" if terminal else technical if technical != "executable" else "authorization_required" if write else "executable"
        row = {"intent_id": intent.get("intent_id"), "status": status, "technical_status": technical,
            "terminal": terminal, "reasons": [i["reason"] for i in issues], "issues": issues,
            "execution_authorized": False, "device_writes": False,
            "next_action": "stop_repair_planning_and_request_operator_review" if terminal else
                "investigate_artifact_or_manual_remediation" if technical == "missing_artifact" else
                "satisfy_preconditions_then_create_deterministic_harness_plan" if write else
                "use_existing_authorized_read_only_collection"}
        feedback.append(row)
        checked.append({**intent, "precheck": row})
    terminal = any(row["terminal"] for row in feedback)
    status = "policy_denied" if terminal else next((row["status"] for row in feedback
        if row["status"] != "executable"), "executable" if feedback else "no_action")
    return {"contract": CONTRACT, "status": status, "terminal": terminal,
        "feedback": feedback, "reasons": sorted({r for row in feedback for r in row["reasons"]}),
        "intents": checked, "capabilities": capabilities, "read_only": True,
        "dry_run_scope": "metadata_and_registered_local_artifacts_only",
        "live_dependency_probe_performed": False, "execution_authorized": False,
        "device_writes": False, "business_accepted": False}
