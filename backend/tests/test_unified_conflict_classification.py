"""Disagreement is scoped to a CVE, evidence version and professional dimension."""
from copy import deepcopy

from app.services.unified.conflicts import detect_conflicts, merge_rereview


def base_state():
    return {"baseline": {}, "vulnerability": {"findings": [{"cve_id": "CVE-2099-1001",
        "package_name": "fixture", "applicability": "not_affected", "version_impact": "fixed",
        "supporting_evidence_ids": ["INV-new"]}]},
        "evidence_snapshot_id": "snapshot-new", "evidence_snapshot": {"snapshot_id": "snapshot-new",
            "created_at": "2026-10-20T12:00:00+00:00", "evidence_registry": {
                "INV-new": {"kind": "inventory"}, "SE-new": {"kind": "runtime",
                    "timestamp": "2026-10-20T11:00:00+00:00"}}},
        "runtime": {"behavior_level": "ACTIVE", "evidence_freshness": "fresh",
            "exploitation_relation": "suspicious_unlinked", "findings": [{
                "aspect": "process", "evidence_id": "SE-new", "relation": "suspicious_behavior"}]}}


def codes(result):
    return {item.code for item in result.conflicts}


def test_static_affected_and_no_observed_attack_are_dimension_difference():
    state = base_state()
    state["vulnerability"]["findings"][0].update(applicability="confirmed_affected", version_impact="affected")
    state["runtime"] = {"exploitation_relation": "not_observed", "behavior_level": "NORMAL"}
    result = detect_conflicts(state)
    assert not result.has_major_conflict and not result.unresolved
    assert result.conflicts[0].category == "dimension_difference"
    assert result.conflicts[0].involved_agents == []


def test_generic_suspicious_is_not_cve_specific_conflict():
    result = detect_conflicts(base_state())
    assert "runtime_alert_vs_not_affected" not in codes(result)
    assert not result.has_major_conflict
    assert {item.category for item in result.conflicts} == {"dimension_difference"}


def test_fresh_cve_specific_evidence_requires_both_roles():
    state = base_state()
    state["runtime"]["findings"][0]["relation"] = "cve_related_evidence"
    result = detect_conflicts(state)
    conflict = next(item for item in result.conflicts if item.code == "runtime_alert_vs_not_affected")
    assert conflict.category == "substantive_judgment"
    assert conflict.involved_agents == ["vulnerability_analyst", "runtime_analyst"]
    assert conflict.evidence_ids == ["INV-new", "SE-new"]


def test_stale_actual_timestamp_overrides_model_freshness():
    state = base_state()
    state["runtime"]["findings"][0]["relation"] = "confirmed_exploitation"
    state["evidence_snapshot"]["evidence_registry"]["SE-new"]["timestamp"] = "2026-10-01T00:00:00+00:00"
    assert "runtime_alert_vs_not_affected" not in codes(detect_conflicts(state))


def test_unknown_or_forged_runtime_evidence_cannot_trigger_major_conflict():
    state = base_state()
    state["runtime"]["findings"][0].update(relation="confirmed_exploitation", evidence_id="FORGED")
    result = detect_conflicts(state)
    assert not result.has_major_conflict
    assert all("FORGED" not in item.evidence_ids for item in result.conflicts)


def test_multiple_cves_require_specific_binding():
    state = base_state()
    state["vulnerability"]["findings"].append({"cve_id": "CVE-2099-1002", "applicability": "confirmed_affected"})
    state["runtime"]["findings"][0]["relation"] = "cve_related_evidence"
    assert "runtime_alert_vs_not_affected" not in codes(detect_conflicts(state))
    state["evidence_snapshot"]["evidence_registry"]["SE-new"]["cve_id"] = "CVE-2099-1002"
    assert "runtime_alert_vs_not_affected" not in codes(detect_conflicts(state))
    state["evidence_snapshot"]["evidence_registry"]["SE-new"]["cve_id"] = "CVE-2099-1001"
    assert "runtime_alert_vs_not_affected" in codes(detect_conflicts(state))


def test_second_candidate_is_checked_and_first_not_misattributed():
    state = base_state()
    state["runtime"] = {}
    state["vulnerability"]["findings"].append({"cve_id": "CVE-2099-1002", "applicability": "confirmed_affected"})
    state["evidence_prep"] = {"candidates": [
        {"cve_id": "CVE-2099-1001", "version_compare": {"result": "fixed"}},
        {"cve_id": "CVE-2099-1002", "version_compare": {"result": "affected"}}]}
    assert "deterministic_fact_vs_analyst_conclusion" not in codes(detect_conflicts(state))
    state["evidence_prep"]["candidates"][1]["version_compare"]["result"] = "fixed"
    result = detect_conflicts(state)
    item = next(i for i in result.conflicts if i.code == "deterministic_fact_vs_analyst_conclusion")
    assert "CVE-2099-1002" in item.description


def test_strong_official_exclusion_resolves_old_generic_baseline_without_replay():
    state = base_state()
    state["runtime"] = {}
    state["baseline"] = {"match_status": "potentially_affected", "preliminary_level": "High",
        "cve_id": "CVE-2099-1001"}
    state["evidence_prep"] = {"candidates": [{"cve_id": "CVE-2099-1001",
        "vendor_patch": {"release_status": "not_affected"}}]}
    assert not detect_conflicts(state).has_major_conflict


def test_confident_answer_does_not_resolve_official_source_conflict():
    state = base_state()
    state["runtime"] = {}
    state["vulnerability"]["findings"][0].update(applicability="confirmed_affected", confidence=0.99)
    state["evidence_prep"] = {"candidates": [{"cve_id": "CVE-2099-1001",
        "vendor_conflict": {"unresolved": True}}]}
    previous = detect_conflicts(state)
    assert "intelligence_source_conflict" in codes(previous) and previous.unresolved
    state["vulnerability"]["findings"][0]["rationale"] = "I am certain it is affected"
    assert merge_rereview(previous, state).unresolved
    state["evidence_prep"]["candidates"][0]["vendor_conflict"]["unresolved"] = False
    assert not merge_rereview(previous, state).unresolved


def test_reported_intel_conflict_is_retained_despite_clear_applicability():
    state = base_state()
    state["vulnerability"]["intelligence_conflicts"] = [{"description": "source revisions differ", "evidence_ids": ["INV-new"]}]
    assert "intelligence_source_conflict" in codes(detect_conflicts(state))


def test_fact_version_conflict_targets_only_stale_role():
    state = base_state()
    state["runtime"] = {}
    state["vulnerability"]["findings"][0]["installed_version"] = "old"
    state["evidence_prep"] = {"candidates": [{"cve_id": "CVE-2099-1001", "installed_version": "new"}]}
    result = detect_conflicts(state)
    item = next(i for i in result.conflicts if i.code == "inventory_version_mismatch")
    assert item.category == "fact_version" and item.involved_agents == ["vulnerability_analyst"]


def test_previously_reused_role_can_bind_current_snapshot_without_false_conflict():
    state = base_state()
    state["runtime"] = {}
    state["role_provenance"] = {"asset_investigator": {"snapshot_id": "old", "valid_for_snapshot_id": "snapshot-new", "reused": True}}
    assert "role_snapshot_version_mismatch" not in codes(detect_conflicts(state))
    state["role_provenance"]["asset_investigator"].pop("valid_for_snapshot_id")
    assert "role_snapshot_version_mismatch" in codes(detect_conflicts(state))


def test_harness_classifies_plan_feedback_separately_from_safety_stop():
    state = base_state()
    state["runtime"] = {}
    state["harness_feedback"] = {"feedback": [{"status": "missing_artifact",
        "technical_status": "missing_artifact", "terminal": False}]}
    result = detect_conflicts(state)
    assert result.conflicts[0].category == "plan_feasibility"
    assert result.conflicts[0].involved_agents == ["decision_planner"]
    state["harness_feedback"]["feedback"][0].update(status="policy_denied", terminal=True)
    result = detect_conflicts(state)
    assert result.conflicts[0].category == "safety_block"


def test_stale_runtime_is_fact_version_not_static_applicability_conflict():
    state = base_state()
    state["runtime"]["evidence_freshness"] = "stale"
    result = detect_conflicts(state)
    item = next(i for i in result.conflicts if i.code == "stale_evidence_active_behavior")
    assert item.category == "fact_version" and item.involved_agents == ["runtime_analyst"]
    assert "runtime_alert_vs_not_affected" not in codes(result)
