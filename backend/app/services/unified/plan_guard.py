"""Technical basis for candidate plans. No execution or authorization mutation."""
from __future__ import annotations

import json
import re


def capability_blockers(state: dict, plan: dict) -> list[str]:
    """Reject promises of measurable loss without an established sensor capability.

    This is a conservative plan review, never an assertion that loss is zero.
    """
    facts = json.dumps({"runtime": (state.get("evidence_prep") or {}).get("runtime_facts"),
                        "capabilities": state.get("capability_marks"),
                        "report": state.get("runtime")}, ensure_ascii=False).lower()
    checks = [a.get("expected_verification", "") for a in plan.get("actions") or []]
    checks += [json.dumps(v, ensure_ascii=False) for v in plan.get("verification_plan") or []]
    unknown_loss = "logread" in facts or "unavailable" in facts or "unsupported" in facts
    def promises_measurement(check: str) -> bool:
        if not re.search(r"dropped_events|丢失计数|丢失量", check, re.I):
            return False
        # Remove only explicitly negated clauses, not the whole check: a later
        # affirmative promise must still be rejected even when a disclaimer exists.
        affirmative = re.sub(r"(?:不要求|不能保证|不保证|不承诺|不得要求|无需)[^，。；;]*", "", check)
        return bool(re.search(r"变为.*(?:数值|数字)|恢复.*(?:计数|可读)|(?:等于|为)\s*0|zero.loss", affirmative, re.I))

    if unknown_loss and any(promises_measurement(check) for check in checks):
        return ["loss_measurement_capability_not_established"]
    return []


def annotate_plan(state: dict, plan: dict, evidence_ids: list[str]) -> dict:
    baseline = state.get("baseline") or {}
    prep = state.get("evidence_prep") or {}
    candidate = (prep.get("candidates") or [{}])[0]
    package = candidate.get("package_name") or baseline.get("package_name") or ""
    fixed = candidate.get("fixed_version") or ""
    vendor = candidate.get("vendor_patch") or {}
    allowed = {package}
    provenance = (prep.get("asset_facts") or {}).get("inventory_provenance") or {}
    for row in provenance.get("package_sources") or []:
        parts = row.split("|")
        if len(parts) == 3 and parts[1] == package:
            allowed.add(parts[0].split(":")[0])
    classifications, blockers = [], capability_blockers(state, plan)
    package_actions = [a for a in plan.get("actions") or [] if a.get("action") == "update_package"]
    # This is the proposed package direction, separate from risk_direction and
    # from whether any operation has actually been authorized or executed.
    package_change = ("upgrade" if package_actions and fixed and
        (candidate.get("version_compare") or {}).get("result") == "affected" else
        "undetermined" if package_actions else "none")
    verdict = ((state.get("decision") or {}).get("verdicts") or [{}])[0]
    model_package_change = verdict.get("package_change", "undetermined")
    if package_actions and model_package_change == "none":
        blockers.append("package_direction_conflicts_with_proposed_actions")
    for index, action in enumerate(plan.get("actions") or []):
        kind, target = action.get("action"), action.get("target", "")
        category = "risk_mitigation"
        if kind == "update_package":
            category = "vulnerability_fix"
            if target not in allowed:
                blockers.append("fix_target_not_affected_component")
            if not fixed:
                blockers.append("vendor_fixed_version_missing")
            params = action.get("params") or {}
            requested = [params[k] for k in ("version", "target_version", "fixed_version") if params.get(k)]
            if any(version != fixed for version in requested):
                blockers.append("fix_version_not_vendor_release_version")
            if vendor.get("release_status") == "not_affected" or (candidate.get("version_compare") or {}).get("result") == "fixed":
                blockers.append("fix_for_excluded_or_fixed_vulnerability")
        elif kind == "restart_service" and any(str(target).lower().startswith(name) for name in ("falco", "tetragon", "ebpf-collector", "openwrt-logread")):
            category = "collector_health_recovery"
        elif kind == "backup_file":
            category = "rollback_preparation"
        elif kind in {"verify_version", "check_service", "collect_evidence"}:
            category = "verification"
        classifications.append({"action_index": index, "category": category,
            "target": target, "requires_approval": True})
        action["requires_approval"] = True
    return {**plan, "requires_approval": True,
        "package_change": package_change, "model_package_change": model_package_change,
        "package_change_semantics": "proposed_package_operation_not_risk_change_or_execution",
        "resolved_risk_ref": baseline.get("object_id") or state.get("object_id"),
        "original_evidence_ids": evidence_ids,
        "affected_source_package": package, "vendor_release_fixed_version": fixed,
        "action_classification": classifications,
        "technical_gate": {"status": "blocked" if blockers else "pending_human_review",
            "reasons": sorted(set(blockers)), "executed": False},
        "execution_authorization": "none; shadow candidate never grants Harness approval"}
