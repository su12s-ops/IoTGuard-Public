"""Prevent resource starvation and invalid handoffs from cascading into role failures."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from copy import deepcopy
import json
import threading

import pytest
from pydantic import ValidationError

from app import config, models
from app.services.unified.agent_base import BudgetExceeded, UnifiedToolLoopAgent
from app.services.unified.agents_def import DECISION_PLANNER_SPEC, ASSET_INVESTIGATOR_SPEC
from app.services.unified.state import empty_state
from app.services.unified.task_reports import scoped_spec
from app.services.unified.task_runtime import BatchRuntime


def test_complete_review_credit_is_held_separately_from_actual_model_usage(session_factory):
    batch = BatchRuntime("escrow", session_factory, lambda: None, max_tokens=200, output_tokens=10)
    assert batch.acquire_review("one", tokens=100, requests=4)
    assert batch.acquire_review("two", tokens=100, requests=4)
    amount = batch.reserve("one-expert", 60, "vulnerability_analyst", review_id="one")
    batch.settle(amount, {"total_tokens": 70}, review_id="one")
    # Other risks cannot take the decision credit of this already admitted risk.
    with pytest.raises(BudgetExceeded):
        batch.reserve("unadmitted", 30, "decision_planner")
    amount = batch.reserve("one-decision", 10, "decision_planner", review_id="one")
    batch.settle(amount, {"total_tokens": 20}, review_id="one")
    batch.release_review("one")
    amount = batch.reserve("two-expert", 60, "runtime_analyst", review_id="two")
    batch.settle(amount, {"total_tokens": 70}, review_id="two")
    amount = batch.reserve("two-decision", 10, "decision_planner", review_id="two")
    batch.settle(amount, {"total_tokens": 20}, review_id="two")
    batch.release_review("two")
    with session_factory() as db:
        ledger = db.get(models.AnalysisBudget, "escrow")
        assert ledger.charged_tokens == 180 and ledger.requests == 4
        assert ledger.reserved_tokens == 0 and ledger.unknown_usage_requests == 0


def test_waiting_review_uses_returned_credit_instead_of_being_prematurely_deferred(session_factory):
    batch = BatchRuntime("waiting", session_factory, lambda: None, max_tokens=120, output_tokens=10)
    assert batch.acquire_review("one", tokens=100, requests=4)
    entered = threading.Event()
    def acquire():
        entered.set()
        return batch.acquire_review("two", tokens=100, requests=4)
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(acquire)
        try:
            assert entered.wait(2)
            with pytest.raises(TimeoutError):
                pending.result(timeout=.05)
            amount = batch.reserve("task", 10, review_id="one")
            batch.settle(amount, {"total_tokens": 10}, review_id="one")
        finally:
            batch.release_review("one")
        assert pending.result(timeout=2)
    batch.release_review("two")


def test_whole_review_admission_does_not_count_as_a_model_request(session_factory):
    batch = BatchRuntime("receipt", session_factory, lambda: None)
    assert batch.acquire_review("one")
    with session_factory() as db:
        ledger = db.get(models.AnalysisBudget, "receipt")
        assert ledger.reserved_tokens == 200000 and ledger.charged_tokens == ledger.requests == 0
    assert batch.snapshot()["reserved_tokens"] == 0
    assert batch.snapshot()["review_reserved_tokens"] == 200000
    batch.release_review("one")


def test_late_usage_settles_after_review_release_without_restoring_unused_credit(session_factory):
    batch = BatchRuntime("late-usage", session_factory, lambda: None, workflow_id="flow")
    assert batch.acquire_review("one")
    amount = batch.reserve("late-request", 100, review_id="one")
    batch.release_review("one")
    assert batch.snapshot()["review_reserved_tokens"] == 0
    assert batch.snapshot()["reserved_tokens"] == amount
    batch.settle(amount, {"total_tokens": 42}, review_id="one")
    with session_factory() as db:
        ledger = db.get(models.AnalysisBudget, "late-usage")
        assert ledger.charged_tokens == 42 and ledger.reserved_tokens == 0
        assert ledger.requests == 1 and ledger.unknown_usage_requests == 0


def test_failed_dispatch_persistence_restores_whole_review_credit(session_factory, monkeypatch):
    batch = BatchRuntime("rollback", session_factory, lambda: None)
    assert batch.acquire_review("one")
    def fail():
        raise RuntimeError("ledger unavailable")
    monkeypatch.setattr(batch, "persist_budget", fail)
    with pytest.raises(RuntimeError, match="ledger unavailable"):
        batch.reserve("task", 10, review_id="one")
    assert batch.reviews["one"] == {"tokens": 200000, "requests": 16}
    assert batch.reserved == batch.requests == batch.consumed == 0
    with session_factory() as db:
        ledger = db.get(models.AnalysisBudget, "rollback")
        assert ledger.reserved_tokens == 200000 and ledger.requests == 0


@pytest.mark.parametrize("options,reason", [
    ({"max_tokens": 28025}, "analysis_budget_insufficient_for_review"),
    ({"max_requests": 15}, "analysis_budget_insufficient_for_review"),
    ({"seconds": 60}, "analysis_window_exhausted"),
])
def test_insufficient_full_review_allowance_defers_without_starting_any_role(session_factory, monkeypatch, options, reason):
    from app.services.unified import adapter
    from tests.test_unified_adapter import _setup_risk
    from app.routers.rounds import _sync_round_from_report
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    risk_id = _setup_risk(session_factory)
    batch = BatchRuntime("low-credit", session_factory,
        lambda: pytest.fail("no role should start without full review credit"), **options)
    with session_factory() as db:
        result = adapter.run_review_analysis_unified(db, "low-credit",
            selected_risks=[db.get(models.RiskAssessment, risk_id)], batch_runtime=batch)
        assert result["processed_object_count"] == 0
        assert result["status"] == "partial" and result["termination_reason"] == reason
        assert result["deferred_object_ids"] == [risk_id]
        assert db.get(models.RiskAssessment, risk_id).review_status == "candidate"
        assert not db.query(models.UnifiedAnalysisRun).count()
        assert not db.query(models.TraceEvent).count()
        assert batch.requests == 0 and not batch.reviews
        report = models.AnalysisReport(review_run_id="low-credit", status="partial",
            selected_object_count=1, selected_object_ids_json=json.dumps([f"risk-{risk_id}"]),
            processed_object_count=0, termination_reason=reason)
        linked = models.AnalysisRound(round_id="RND-low-credit", review_run_id="low-credit",
            selected_object_count=1, eligible_count=1)
        db.add_all([report, linked])
        db.commit()
        _sync_round_from_report(db, linked)
        assert linked.status == "partial" and linked.remaining_object_count == 1
        assert linked.blocked_reason == reason


def test_decision_handoff_contract_names_exactly_one_current_risk_and_corrects_extra_asset_verdict():
    state = empty_state("UA-test", "risk_review", "edge", "linux_host", "formal")
    state.object_id = "risk-9"
    spec = scoped_spec(DECISION_PLANNER_SPEC, state)
    valid = {"verdicts": [{"object_id": "risk-9", "impact_status": "insufficient_evidence",
        "risk_direction": "maintain", "recommended_action": "collect_more_evidence",
        "reason": "No sufficient evidence"}]}
    invalid = deepcopy(valid)
    invalid["verdicts"].append({**valid["verdicts"][0], "object_id": "edge"})
    messages_seen = []
    class Client:
        def complete(self, messages, tools=None):
            messages_seen.append(deepcopy(messages))
            return {"content": json.dumps(invalid if len(messages_seen) == 1 else valid),
                    "usage": {"total_tokens": 1}}
    agent = UnifiedToolLoopAgent(spec, Client(), collaboration_messages=False)
    result = agent.run(None, "Review risk-9 only; edge is the asset name.")
    assert result.status == "succeeded" and result.llm_calls == 2
    assert [v["object_id"] for v in result.output["verdicts"]] == ["risk-9"]
    system = messages_seen[0][0]["content"]
    assert '"const": "risk-9"' in system
    assert '"maxItems": 1' in system and '"maxItems": 0' in system
    assert "QUESTION 向指定角色" not in system
    assert "结构化报告交接" in system
    assert "未通过结构化校验" in messages_seen[1][-1]["content"]
    wrong = deepcopy(valid)
    wrong["verdicts"][0]["object_id"] = "risk-10"
    with pytest.raises(ValidationError):
        spec.output_model.model_validate(wrong)


def test_task_graph_roles_cannot_emit_unhandled_collaboration_messages():
    state = empty_state("UA-test", "risk_review", "edge", "linux_host", "formal")
    spec = scoped_spec(ASSET_INVESTIGATOR_SPEC, state)
    with pytest.raises(ValidationError):
        spec.output_model.model_validate({"device_id": "edge", "messages": [{}]})
    assert spec.output_model.model_validate({"device_id": "edge"}).messages == []
