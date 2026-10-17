"""M5 contracts exercised against isolated real database, graph and HTTP gates."""
import copy
import importlib
import json
from pathlib import Path

import pytest
from app import config, models
from app.services.review_common import governance as G
from app.services.review_common.human_review import apply_human_review, adjudicate_history
from app.services.unified.adapter import formal_sink, generate_and_save_report_unified
from tests.test_unified_adapter import _setup_risk, _make_run_row
from tests.test_unified_pipeline import base_state


@pytest.fixture
def case(session_factory, monkeypatch):
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    risk_id = _setup_risk(session_factory)
    db = session_factory()
    yield db, db.get(models.RiskAssessment, risk_id)
    db.close()


def proof():
    return {"status": "not_affected", "release": "noble", "package": "nginx",
            "evidence_id": "ADV-test", "sha256": "a" * 64, "url": "https://ubuntu.com/security/CVE-2026-81001"}


@pytest.mark.parametrize("module", ["app.services.agents.orchestrator", "app.services.event_review_pipeline", "app.services.agent_group_chat"])
def test_retired_llm_cannot_import(module):
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module)


def test_product_imports_do_not_reference_retired_runtime():
    import ast
    for path in (Path(__file__).parents[1] / "app").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                assert not any((node.module or "").startswith(x) for x in
                    ("app.services.agents", "app.services.agent_group_chat", "app.services.event_review_pipeline"))


def test_official_correction_retains_history_and_revokes_approval(case):
    db, risk = case
    risk.active, risk.review_status, risk.risk_level = False, "inactive", "Critical"
    task = models.RemediationTask(asset_id=risk.asset_id, risk_id=risk.id, cve_id=risk.cve_id, package_name=risk.package_name, status="pending")
    run = models.HarnessRun(id="old-approved", risk_id=risk.id, asset_id=risk.asset_id,
        status="approved", plan_json='{"goal":"repair"}', plan_hash="old", approval_hash="old", approved_by="historic-operator")
    db.add_all([task, run]); db.commit()
    before = G.snapshot(risk)
    event = G.apply_official_correction(db, risk, proof()); db.commit()
    assert G.snapshot(risk) == before
    assert task.status == run.status == "invalidated" and run.approval_hash == ""
    assert json.loads(event.payload_json)["affected_candidates"][1]["original"]["approval_hash"] == "old"
    assert G.apply_official_correction(db, risk, proof()).id == event.id
    risk.active, risk.review_status = True, "human_confirmed"; db.commit()
    assert not G.execution_allowed(db, risk)
    from app.services.agent_harness import approve
    with pytest.raises(ValueError, match="officially_corrected"):
        approve(db, run, "old", "other", "retry")


def test_inactive_history_requires_separate_operator_endpoint(case, client, control_headers):
    db, risk = case
    risk.active, risk.review_status = False, "inactive"; db.commit()
    event = G.apply_official_correction(db, risk, proof()); db.commit()
    response = client.post(f"/api/analysis/risks/{risk.id}/human-review", headers=control_headers,
        json={"decision": "confirm", "actor": "operator", "reason": "checked", "expected_status": "inactive"})
    assert response.status_code == 409
    payload = {"decision": "confirm_archive", "actor": "operator", "reason": "checked precise official record", "correction_event_id": event.id}
    assert client.post(f"/api/analysis/risks/{risk.id}/historical-adjudication", json=payload).status_code == 401
    assert client.post(f"/api/analysis/risks/{risk.id}/historical-adjudication", json=payload, headers=control_headers).status_code == 200
    db.refresh(risk)
    assert risk.active is False and risk.review_status == "inactive"
    assert db.query(models.RiskGovernanceEvent).filter_by(kind="historical_adjudication").count() == 1
    assert G.explanation(db, risk)["historical_review_state"] == "confirm_archive"


def test_reanalysis_review_state_machine_rejects_premature_confirmation(case):
    db, risk = case
    risk.review_status = "reanalysis_required"; db.commit()
    with pytest.raises(ValueError, match="native_assessment"):
        apply_human_review(db, risk.id, "confirm", "reviewed", "operator", "reanalysis_required")
    apply_human_review(db, risk.id, "begin", "review started", "operator", "reanalysis_required")
    assert risk.review_status == "human_reviewing"
    apply_human_review(db, risk.id, "request_reanalysis", "new evidence needed", "operator", "human_reviewing")
    assert risk.review_status == "reanalysis_required" and not risk.review_verdict
    with pytest.raises(ValueError, match="expected_status"):
        apply_human_review(db, risk.id, "reject", "stale tab", "operator", "human_reviewing")


def test_model_has_no_operator_confirmation_and_legacy_semantics_preserved(case):
    db, risk = case
    risk.review_status, risk.risk_direction, risk.review_verdict = "pending_human_review", "upgrade_minor", "potentially_affected"
    db.commit()
    assert G.explanation(db, risk)["risk_direction_semantics"] == "legacy_unverified"
    with pytest.raises(ValueError, match="actor"):
        apply_human_review(db, risk.id, "confirm", "model suggestion")
    with pytest.raises(ValueError, match="legacy_direction"):
        apply_human_review(db, risk.id, "confirm", "old recommendation", "operator", "pending_human_review")
    assert risk.risk_direction == "upgrade_minor"


def test_no_model_confidence_rewriting_in_production():
    root = Path(__file__).parents[1] / "app/services/unified"
    assert "clamp_confidence(" not in (root / "graph.py").read_text(encoding="utf-8")


def test_off_mode_formal_is_fail_closed(case, client, control_headers, monkeypatch):
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "off")
    assert client.post("/api/analysis/runs", headers=control_headers).status_code == 503
    assert client.get("/api/agents/specs").status_code == 404


def test_harness_embedded_llm_rejected_before_work(case):
    from app.services.agent_harness import create_run
    db, risk = case
    with pytest.raises(ValueError, match="embedded_llm_retired"):
        create_run(db, risk.asset_id, risk.id, model_review=True)
    assert db.query(models.HarnessRun).count() == 0


def test_corrected_task_cannot_be_revived_by_patch(case, client, control_headers):
    db, risk = case
    task = models.RemediationTask(asset_id=risk.asset_id, risk_id=risk.id, cve_id=risk.cve_id, package_name=risk.package_name)
    db.add(task); db.commit()
    G.apply_official_correction(db, risk, proof()); db.commit()
    assert client.patch(f"/api/remediation/tasks/{task.id}", json={"status": "pending"}, headers=control_headers).status_code == 409
    db.refresh(task)
    assert task.status == "invalidated"


def test_mqtt_never_calls_llm(case):
    from app.services.mqtt_security_workflow import agent_plan
    db, _ = case
    def fail():
        pytest.fail("independent MQTT LLM path")
    result = agent_plan(db, "127.0.0.1", 1883, {}, client_factory=fail)
    assert result["source"] == "deterministic_policy"


def test_formal_queue_is_bounded_and_rejects_second_batch(case, session_factory, monkeypatch):
    import app.services.unified.adapter as adapter
    db, risk = case
    _setup_risk(session_factory, cve_id="CVE-2026-81002")
    class NoDispatch:
        def __init__(self, **kwargs):
            pass
        def start(self):
            pass
    monkeypatch.setattr(adapter.threading, "Thread", NoDispatch)
    result = generate_and_save_report_unified(db, "queue-test", background=True)
    assert result["selected_object_count"] == 1
    assert db.query(models.RiskAssessment).filter_by(review_status="candidate").count() == 1
    with pytest.raises(ValueError, match="formal_worker_busy"):
        generate_and_save_report_unified(db, "queue-test-2", background=True)


def test_same_facts_keeps_raw_confidence_and_separates_effective_direction(case):
    from app.services.unified.state import empty_state
    db, risk = case
    state = empty_state("UA-native-1", "risk_review", "edge-01", "linux_host", "formal")
    state.baseline = {"preliminary_score": 70}
    state.final = {"policy": {"status": "pending_human_review", "reasons": ["fixture_hold"], "adjustment": 0}}
    state.decision = {"verdicts": [{"impact_status": "confirmed_affected", "risk_direction": "maintain", "confidence": .65}]}
    row = models.UnifiedAnalysisRun(run_id=state.run_id, risk_id=risk.id, mode="formal", status="completed")
    db.add(row); db.commit()
    formal_sink(db, row, state)
    state.run_id = "UA-native-2"
    state.decision["verdicts"][0].update(confidence=.99, risk_direction="upgrade_major")
    row = models.UnifiedAnalysisRun(run_id=state.run_id, risk_id=risk.id, mode="formal", status="completed")
    db.add(row); db.commit()
    formal_sink(db, row, state)
    assert risk.review_confidence == .99
    assert state.decision["verdicts"][0]["risk_direction"] == "upgrade_major"
    assert risk.risk_direction == "maintain"
    assert "same_facts_model_variance_not_new_evidence" in json.loads(risk.audit_policy_reasons)
    assert db.query(models.RiskGovernanceEvent).filter_by(kind="native_assessment").count() == 2


def test_historical_draft_is_not_operator_adjudication(case):
    from app.services.unified.state import empty_state
    db, risk = case
    risk.active, risk.review_status, risk.risk_level = False, "inactive", "Critical"; db.commit()
    G.apply_official_correction(db, risk, proof()); db.commit()
    original = G.snapshot(risk)
    state = empty_state("UA-history", "risk_review", "edge-01", "linux_host", "historical")
    state.decision = {"verdicts": [{"impact_status": "not_affected", "confidence": .85}]}
    row = models.UnifiedAnalysisRun(run_id=state.run_id, risk_id=risk.id, mode="historical", status="completed")
    db.add(row); db.commit()
    G.historical_draft_sink(db, row, state)
    assert G.snapshot(risk) == original
    event = db.query(models.RiskGovernanceEvent).filter_by(kind="historical_assessment_draft").one()
    assert json.loads(event.payload_json)["operator_confirmed"] is False
    assert db.query(models.RiskGovernanceEvent).filter_by(kind="historical_adjudication").count() == 0
    assert G.explanation(db, risk)["historical_review_state"] == "awaiting_operator"
    with pytest.raises(ValueError, match="formal_source_required"):
        formal_sink(db, row, state)


def test_precise_not_affected_rejects_unrelated_usn_fix(case, session_factory):
    from app.services.unified.graph import RunContext, _vulnerability_evidence_validator
    from app.services.unified.agent_base import UsageMeter
    from app.services.unified.state import empty_state
    state = empty_state("v", "risk_review", "edge-01", "linux_host", "historical")
    state.evidence_prep = {"candidates": [{"cve_id": "CVE-2026-81001", "vendor_patch": {"release_status": "not_affected"}}]}
    ctx = RunContext(db_factory=session_factory, trace_id="", meter=UsageMeter(), client_factory=lambda: None)
    ctx.packet_evidence_ids = set()
    validate = _vulnerability_evidence_validator(ctx, state)
    assert validate({"findings": [{"cve_id": "CVE-2026-81001", "fixed_version": "unrelated-usn-version"}]})
    assert not validate({"findings": [{"cve_id": "CVE-2026-81001", "fixed_version": "", "version_impact": "not_affected"}]})


def test_workflow_overview_reads_native_roles_and_actual_confidence(case, client):
    db, risk = case
    row = models.UnifiedAnalysisRun(run_id="UA-overview", risk_id=risk.id, mode="formal", status="completed",
        state_json=json.dumps({"investigation": {"confidence": .65, "reason": "actual evidence"}}),
        agents_json=json.dumps({"asset_investigator": {"status": "succeeded"}}))
    db.add(row); db.commit()
    result = client.get("/api/workflow/overview")
    assert result.status_code == 200
    data = result.json()
    assert [a["id"] for a in data["agents"]] == ["asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"]
    assert data["agents"][0]["confidence"] == 65
    assert data["agents"][1]["confidence"] is None
    assert data["native_risk_id"] == risk.id


def test_formal_investigation_updates_report_pointer_without_overwriting_history(case):
    from app.services.unified.state import empty_state
    from app.services.unified.adapter import persist_investigation_report
    db, risk = case
    original = models.AnalysisReport(review_run_id="old-batch", status="human_review", answer="before collection")
    db.add(original)
    state = empty_state("UA-inv-child", "risk_review", "edge-01", "linux_host", "formal")
    state.object_id = f"risk-{risk.id}"
    state.final = {"policy": {"status": "pending_human_review"}}
    row = models.UnifiedAnalysisRun(run_id=state.run_id, risk_id=risk.id, mode="formal", status="completed")
    db.add(row); db.commit()
    persist_investigation_report(db, row, state)
    persist_investigation_report(db, row, state)
    assert original.answer == "before collection"
    assert db.query(models.AnalysisReport).count() == 2
    assert db.query(models.AnalysisReport).order_by(models.AnalysisReport.id.desc()).first().review_run_id == row.run_id


def test_package_direction_is_independent_of_risk_and_conflicts_block():
    from app.services.unified.plan_guard import annotate_plan
    state = {"decision": {"verdicts": [{"risk_direction": "downgrade_minor", "package_change": "none"}]},
        "evidence_prep": {"candidates": [{"package_name": "curl", "fixed_version": "2", "version_compare": {"result": "affected"}}]}}
    plan = annotate_plan(state, {"actions": [{"action": "update_package", "target": "curl", "params": {"version": "2"}}]}, [])
    assert plan["package_change"] == "upgrade"
    assert state["decision"]["verdicts"][0]["risk_direction"] == "downgrade_minor"
    assert "package_direction_conflicts_with_proposed_actions" in plan["technical_gate"]["reasons"]
    assert plan["requires_approval"] is True and plan["technical_gate"]["executed"] is False


def test_invalid_candidate_plan_cannot_auto_confirm(case, session_factory):
    from app.services.unified.graph import RunContext, node_finalize
    from app.services.unified.agent_base import UsageMeter
    from app.services.unified.state import empty_state
    state = empty_state("guard", "risk_review", "edge-01", "linux_host", "formal")
    state.baseline = {"installed_version": "1", "fixed_version": "2", "preliminary_score": 20, "match_status": "affected"}
    state.investigation = {"evidence_quality": "sufficient"}
    state.evidence_prep = {"candidates": [{"package_name": "nginx", "fixed_version": "2", "version_compare": {"result": "affected"}}]}
    state.decision = {"verdicts": [{"impact_status": "confirmed_affected", "risk_direction": "maintain", "confidence": .9,
        "recommended_priority": "low", "recommended_action": "scheduled_fix"}],
        "response_plan": {"actions": [{"action": "update_package", "target": "unrelated", "params": {"version": "2"}}]}}
    ctx = RunContext(db_factory=session_factory, trace_id="", meter=UsageMeter(), client_factory=lambda: None)
    result = node_finalize(ctx)(state)
    assert result["final"]["policy"]["status"] == "pending_human_review"
    assert result["final"]["policy"]["final_score"] is None
    assert "candidate_plan_technical_gate_blocked" in result["final"]["policy"]["reasons"]
