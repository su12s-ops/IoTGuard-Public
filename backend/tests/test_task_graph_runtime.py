"""Isolated scope, budget, deadline and report-reuse contracts; no real model."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import threading
import time
import uuid

import pytest

from app import config, models
from app.services.unified.agent_base import BudgetExceeded
from app.services.unified.agents_def import ASSET_INVESTIGATOR_SPEC
from app.services.unified.graph import RunContext, node_analyze_runtime
from app.services.unified.state import empty_state
from app.services.unified.task_runtime import BatchRuntime, for_review
from app.services.unified import task_reports


def runtime(factory, client=lambda: None, **kwargs):
    return BatchRuntime("batch-" + uuid.uuid4().hex[:12], factory, client, **kwargs)


def state(risk=1, asset=1, version="1"):
    item = empty_state(f"UA-{risk}", "risk_review", "edge", "linux_host", "formal")
    item.candidate_context = [{"cve_id": f"CVE-2026-{risk:04}", "package_name": "daemon"}]
    item.evidence_snapshot = {"snapshot_id": f"ES-{risk}", "asset_id": asset,
        "categories": {"identity": {"hostname": "edge"},
            "inventory": {"components": [{"name": "daemon", "version": version}],
                "candidate_versions": item.candidate_context}},
        "evidence_registry": {}, "integrity_errors": []}
    item.evidence_prep = {"asset_facts": {"profile": {"device_id": "edge"}},
                         "runtime_facts": {"freshness": {"status": "none"}}}
    return item


def asset_report():
    return ASSET_INVESTIGATOR_SPEC.output_model(device_id="edge", evidence_quality="partial").model_dump()


def test_same_device_report_shared_across_risks_but_not_changed_inventory_or_other_asset(session_factory):
    batch = runtime(session_factory)
    calls = []
    def run(text, scoped, validator, task_id):
        assert not scoped.candidate_context
        assert "CVE-2026" not in text
        calls.append(task_id)
        return asset_report(), ""
    contexts = []
    for item in (state(1), state(2), state(3, version="2"), state(4, asset=2)):
        ctx = RunContext(session_factory, "", batch_runtime=batch)
        output, error = task_reports.execute(ctx, item, ASSET_INVESTIGATOR_SPEC, "risk context", None, run)
        assert output["device_id"] == "edge" and not error
        contexts.append(ctx)
    assert len(calls) == 3
    receipt = contexts[1].task_receipts["asset_investigator"]
    assert receipt["reused"] and receipt["origin_run_id"] == "UA-1"
    assert contexts[1].agent_logs["asset_investigator"]["llm_calls"] == 0
    with session_factory() as db:
        assert db.query(models.AnalysisTask).count() == 3


def test_runtime_freshness_and_coverage_invalidate_shared_asset_quality(session_factory):
    batch = runtime(session_factory)
    first = state()
    second = state(2)
    second.evidence_prep["runtime_facts"]["freshness"]["status"] = "stale"
    calls = []
    for item in (first, second):
        ctx = RunContext(session_factory, "", batch_runtime=batch)
        task_reports.execute(ctx, item, ASSET_INVESTIGATOR_SPEC, "", None,
            lambda *args: (calls.append(1) or asset_report(), ""))
    assert len(calls) == 2


def test_failed_report_is_not_reused_and_live_owner_cannot_be_stolen(session_factory):
    first, second = runtime(session_factory), runtime(session_factory)
    task_id, report, _, _ = first.claim("asset_investigator", 1, {"v": 1}, "UA-1")
    assert report is None
    assert second.claim("asset_investigator", 1, {"v": 1}, "UA-2")[0] is None
    first.finish(task_id, error="bad evidence")
    retry, cached, _, _ = second.claim("asset_investigator", 1, {"v": 1}, "UA-2")
    assert retry == task_id and cached is None
    first.finish(task_id, {"wrong_owner": True})
    second.finish(task_id, {"right_owner": True})
    with session_factory() as db:
        assert json.loads(db.get(models.AnalysisTask, task_id).report_json) == {"right_owner": True}


def test_parallel_identical_report_is_computed_once(session_factory):
    batch = runtime(session_factory)
    calls = []
    entered, release = threading.Event(), threading.Event()
    def run(*args):
        calls.append(1)
        entered.set()
        assert release.wait(2)
        return asset_report(), ""
    def execute(number):
        return task_reports.execute(RunContext(session_factory, "", batch_runtime=batch), state(number),
                                    ASSET_INVESTIGATOR_SPEC, "", None, run)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(execute, 1)
        assert entered.wait(2)
        second = pool.submit(execute, 2)
        release.set()
        assert first.result()[0] == second.result()[0]
    assert len(calls) == 1


@pytest.mark.parametrize("late_failure", [False, True])
def test_late_shared_execution_cannot_finish_replacement_lease_in_same_batch(session_factory, late_failure):
    batch = runtime(session_factory)
    old_started, old_release = threading.Event(), threading.Event()
    replacement_started, replacement_release = threading.Event(), threading.Event()
    task_ids = []
    contexts = {}

    def old_run(context, scoped, validator, task_id):
        task_ids.append(task_id)
        old_started.set()
        assert old_release.wait(5)
        contexts[1].log_agent(ASSET_INVESTIGATOR_SPEC.name,
            {"status": "succeeded", "llm_calls": 1, "latency_ms": 10, "output": asset_report()})
        if late_failure:
            return None, "expired worker failure"
        return {**asset_report(), "exposure_summary": "expired worker"}, ""

    def replacement_run(context, scoped, validator, task_id):
        task_ids.append(task_id)
        replacement_started.set()
        assert replacement_release.wait(5)
        return {**asset_report(), "exposure_summary": "current worker"}, ""

    def execute(number, run):
        ctx = RunContext(session_factory, "", batch_runtime=batch)
        contexts[number] = ctx
        return task_reports.execute(ctx, state(number), ASSET_INVESTIGATOR_SPEC, "", None, run)

    with ThreadPoolExecutor(2) as pool:
        old = pool.submit(execute, 1, old_run)
        try:
            assert old_started.wait(3)
            with session_factory() as db:
                db.get(models.AnalysisTask, task_ids[0]).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                db.commit()
            replacement = pool.submit(execute, 2, replacement_run)
            assert replacement_started.wait(3)
            old_release.set()
            assert old.result(timeout=3) == (None, "shared_task_lease_lost")
            log = contexts[1].agent_logs[ASSET_INVESTIGATOR_SPEC.name]
            assert log["status"] == "degraded" and log["output"] is None
            assert log["total_llm_calls"] == 1 and log["total_latency_ms"] == 10
            assert log["llm_calls"] == 1 and len(log["executions"]) == 1
            assert log["executions"][0]["status"] == "degraded"
            assert contexts[1].task_receipts[ASSET_INVESTIGATOR_SPEC.name]["status"] == "lease_lost"
            with session_factory() as db:
                row = db.get(models.AnalysisTask, task_ids[0])
                assert row.status == "running"
                assert row.origin_run_id == "UA-2"
                assert json.loads(row.report_json) == {}
        finally:
            old_release.set()
            replacement_release.set()
        assert replacement.result(timeout=3)[0]["exposure_summary"] == "current worker"
    assert task_ids[0] == task_ids[1]
    with session_factory() as db:
        row = db.get(models.AnalysisTask, task_ids[0])
        assert row.status == "completed"
        assert json.loads(row.report_json)["exposure_summary"] == "current worker"


@pytest.mark.parametrize("cached", [{"device_id": "edge", "components": "broken"}, {}, [], 42, "broken"])
def test_invalid_cached_schema_runs_fresh_scoped_validation(session_factory, cached):
    batch = runtime(session_factory)
    calls = []

    def run(context, scoped, validator, task_id):
        assert not scoped.candidate_context
        assert not validator(asset_report())
        calls.append(task_id)
        return asset_report(), ""

    for number in (1, 2):
        if number == 2:
            with session_factory() as db:
                row = db.query(models.AnalysisTask).one()
                row.report_json = json.dumps(cached)
                task_id = row.id
                db.commit()
        ctx = RunContext(session_factory, "", batch_runtime=batch)
        output, error = task_reports.execute(ctx, state(number), ASSET_INVESTIGATOR_SPEC, "", None, run)
        assert output == asset_report() and not error
    assert len(calls) == 2
    with session_factory() as db:
        row = db.get(models.AnalysisTask, task_id)
        assert row.origin_run_id == "UA-1"
        assert json.loads(row.report_json) == cached


def test_no_individual_runtime_evidence_skips_llm_without_claiming_safety(session_factory):
    ctx = RunContext(session_factory, "", batch_runtime=runtime(session_factory))
    item = state()
    item.evidence_snapshot["categories"]["runtime"] = {"events": [], "summarized": {"count": 99}}
    update = node_analyze_runtime(ctx)(item)
    assert update["stage_status"]["analyze_runtime"] == "skipped"
    assert update["runtime_program_fallback"]["runtime_status"] == "unavailable"
    assert not ctx.agent_logs


def test_reservations_are_atomic_and_unknown_usage_is_not_reported_as_actual(session_factory):
    batch = runtime(session_factory, max_tokens=100, output_tokens=40)
    def reserve(i):
        try:
            return batch.reserve(str(i), 10)
        except BudgetExceeded:
            return None
    with ThreadPoolExecutor(8) as pool:
        amounts = list(pool.map(reserve, range(8)))
    assert sum(x is not None for x in amounts) == 2
    for amount in amounts:
        if amount:
            batch.settle(amount, None)
    snapshot = batch.snapshot()
    assert snapshot["reserved_tokens"] == 0
    assert snapshot["budget_charged_tokens"] == 100
    assert snapshot["unknown_usage_requests"] == 2
    assert "total_tokens" not in snapshot


def test_task_request_cap_and_output_limit_are_applied(session_factory):
    class Client:
        _max_tokens = 32768
        def complete(self, messages, tools=None):
            assert self._max_tokens == 8
            return {"content": "{}", "usage": {"total_tokens": 5}}
    batch = runtime(session_factory, Client, output_tokens=8, task_requests=2)
    client = batch.client("task-one")
    client.complete([])
    client.complete([])
    with pytest.raises(BudgetExceeded, match="task_request"):
        client.complete([])
    assert batch.requests == 2 and batch.consumed == 10 and batch.reserved == 0


def test_global_two_request_limit_includes_different_batches(session_factory):
    lock = threading.Lock()
    current = peak = 0
    class Client:
        def complete(self, messages, tools=None):
            nonlocal current, peak
            with lock:
                current += 1
                peak = max(peak, current)
            time.sleep(.02)
            with lock:
                current -= 1
            return {"content": "{}", "usage": {"total_tokens": 1}}
    batches = [runtime(session_factory, Client) for _ in range(6)]
    with ThreadPoolExecutor(6) as pool:
        list(pool.map(lambda pair: pair[1].client(str(pair[0])).complete([]), enumerate(batches)))
    assert peak == 2


def test_expired_batch_cannot_dispatch(session_factory):
    batch = runtime(session_factory, lambda: pytest.fail("client factory must not dispatch"), seconds=0)
    with pytest.raises(BudgetExceeded, match="deadline"):
        batch.reserve("one", 1)


def test_console_deadline_and_prior_charges_carry_to_next_batch(session_factory):
    with session_factory() as db:
        start = datetime.now(timezone.utc) - timedelta(minutes=29)
        db.add(models.ConsoleWorkflow(id="flow", status="running", created_at=start))
        for i in range(2):
            db.add(models.UnifiedAnalysisRun(run_id=f"UA-old-{i}", created_at=start + timedelta(minutes=1),
                state_json=json.dumps({"final": {"batch_budget": {"batch_id": "old",
                    "budget_charged_tokens": 1000 + i, "requests": 3 + i}}})))
        db.commit()
        batch = for_review(db, "next", session_factory, lambda: None)
        assert 58 < batch.remaining() <= 60
        assert batch.max_tokens == 598999 and batch.max_requests == 156


def test_full_task_graph_uses_formal_sink_and_keeps_human_gate(session_factory, monkeypatch):
    from tests.test_unified_adapter import _setup_risk, FULL_SCRIPT
    from tests.test_unified_pipeline import ScriptedClient
    from app.services.unified import runner, adapter
    from copy import deepcopy
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr(runner, "SessionLocal", session_factory)
    risk_id = _setup_risk(session_factory)
    batch = runtime(session_factory, lambda: ScriptedClient(deepcopy(FULL_SCRIPT)))
    with session_factory() as db:
        result = adapter.run_review_analysis_unified(db, "integration",
            selected_risks=[db.get(models.RiskAssessment, risk_id)], batch_runtime=batch)
        assert result["processed_object_count"] == 1
        assert result["execution_profile"] == "task_graph"
        risk = db.get(models.RiskAssessment, risk_id)
        assert risk.review_status == "pending_human_review" and risk.human_review_required
        assert "task_graph_quality_validation_required" in json.loads(risk.audit_policy_reasons)
        assert risk.final_score is None
        row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=f"UA-integration-{risk_id}").one()
        assert row.status == "completed", row.error
        state_data = json.loads(row.state_json)
        assert state_data["execution_profile"] == "task_graph"
        assert state_data["budgets"]["message_rounds"] == 0
        assert state_data["budgets"]["follow_up_rounds"] == 0
        assert state_data["task_receipts"]
        assert batch.requests > 0


def test_expired_window_defers_risks_and_round_does_not_claim_all_processed(session_factory, monkeypatch):
    from tests.test_unified_adapter import _setup_risk
    from app.services.unified import adapter
    from app.routers.rounds import _sync_round_from_report
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    risk_id = _setup_risk(session_factory)
    batch = runtime(session_factory, seconds=0)
    with session_factory() as db:
        result = adapter.run_review_analysis_unified(db, "expired",
            selected_risks=[db.get(models.RiskAssessment, risk_id)], batch_runtime=batch)
        assert result["status"] == "partial" and result["processed_object_count"] == 0
        assert result["deferred_object_ids"] == [risk_id]
        assert db.get(models.RiskAssessment, risk_id).review_status == "candidate"
        assert not db.query(models.UnifiedAnalysisRun).count()
        report = models.AnalysisReport(review_run_id="expired", status="partial", selected_object_count=1,
            selected_object_ids_json=json.dumps([f"risk-{risk_id}"]), processed_object_count=0,
            termination_reason="analysis_window_exhausted")
        db.add(report)
        db.flush()
        linked = models.AnalysisRound(round_id="RND-expired", review_run_id="expired",
            selected_object_count=1, eligible_count=1)
        db.add(linked)
        db.commit()
        _sync_round_from_report(db, linked)
        assert linked.status == "partial"
        assert linked.processed_object_count == 0 and linked.remaining_object_count == 1


def test_late_response_keeps_global_slot_and_cannot_write_agent_output(session_factory):
    from pydantic import BaseModel
    from app.services.agent_infra import AgentSpec
    from app.services.unified.agent_base import UnifiedToolLoopAgent
    from app.services.unified import task_runtime
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    class Report(BaseModel):
        value: int
    class Client:
        def complete(self, messages, tools=None):
            entered.set()
            assert release.wait(3)
            return {"content": '{"value":1}', "usage": {"total_tokens": 10}}
    batch = runtime(session_factory, Client)
    agent = UnifiedToolLoopAgent(AgentSpec("test", "test", Report, llm_retries=0), batch.client("late"))
    # Snapshot the ledger before the temporary DB is disposed.
    result = agent.run(None, "facts", deadline_s=.1)
    assert entered.is_set() and result.output is None and result.status == "timeout"
    assert task_runtime._slots.acquire(blocking=False)
    assert not task_runtime._slots.acquire(blocking=False)
    task_runtime._slots.release()
    release.set()
    for _ in range(100):
        if batch.reserved == 0:
            finished.set()
            break
        time.sleep(.01)
    with batch.lock:
        assert finished.is_set() and agent._calls == 0


def test_console_intelligence_checks_analysis_window_before_dispatch(client, session_factory, monkeypatch, control_headers):
    from app.services import console_workflow
    monkeypatch.setattr(config, "REVIEW_EXECUTION_MODE", "task_graph")
    monkeypatch.setattr(console_workflow, "launch", lambda _: None)
    with session_factory() as db:
        db.add(models.LinuxAsset(hostname="expired-console", distribution="openwrt"))
        db.commit()
    flow = client.post("/api/console/start", json={}, headers=control_headers).json()["workflow"]
    with session_factory() as db:
        db.get(models.ConsoleWorkflow, flow["id"]).created_at = datetime.now(timezone.utc) - timedelta(minutes=31)
        db.commit()
    def intelligence(db, asset_id, progress):
        progress("intelligence", "before network")
        pytest.fail("expired window must not dispatch network work")
    monkeypatch.setattr(console_workflow, "fetch_intelligence", intelligence)
    console_workflow.run(flow["id"], session_factory)
    result = client.get("/api/console/current").json()["workflow"]
    assert result["status"] == "partial"


def test_durable_ledger_includes_inflight_reservations_on_next_batch(session_factory):
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(models.ConsoleWorkflow(id="ledger-flow", status="running", created_at=now))
        db.commit()
    first = BatchRuntime("ledger-first", session_factory, lambda: None, workflow_id="ledger-flow")
    amount = first.reserve("pending", 100)
    with session_factory() as db:
        next_batch = for_review(db, "ledger-next", session_factory, lambda: None)
        assert next_batch.max_tokens == 600000 - amount
        assert next_batch.max_requests == 159
    first.settle(amount, {"total_tokens": 42})
    with session_factory() as db:
        settled = for_review(db, "ledger-third", session_factory, lambda: None)
        assert settled.max_tokens == 600000 - 42


def test_specialists_leave_batch_credit_for_decision(session_factory):
    batch = runtime(session_factory, max_tokens=100, output_tokens=10)
    amount = batch.reserve("expert", 60, "asset_investigator")
    batch.settle(amount, {"total_tokens": 70})
    with pytest.raises(BudgetExceeded, match="reserved_for_decision"):
        batch.reserve("next-expert", 10, "vulnerability_analyst")
    amount = batch.reserve("decision", 10, "decision_planner")
    batch.settle(amount, {"total_tokens": 20})
    assert batch.consumed == 90


def test_real_parallel_graph_reuses_same_device_report(session_factory, monkeypatch):
    from tests.test_unified_adapter import _setup_risk, FULL_SCRIPT
    from tests.test_unified_pipeline import ScriptedClient
    from app.services.unified import runner, adapter
    from copy import deepcopy
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr(runner, "SessionLocal", session_factory)
    risk_ids = [_setup_risk(session_factory), _setup_risk(session_factory, cve_id="CVE-2026-81002")]
    batch = runtime(session_factory, lambda: ScriptedClient(deepcopy(FULL_SCRIPT)))
    with session_factory() as db:
        result = adapter.run_review_analysis_unified(db, "paired",
            selected_risks=[db.get(models.RiskAssessment, i) for i in risk_ids], batch_runtime=batch)
        assert result["processed_object_count"] == 2
        tasks = db.query(models.AnalysisTask).filter_by(role="asset_investigator", status="completed").all()
        runs = db.query(models.UnifiedAnalysisRun).all()
        if len(tasks) != 1:
            from app.services.unified.state import UnifiedAnalysisState
            from difflib import unified_diff
            dependencies = [task_reports.scoped_input(RunContext(session_factory, ""),
                UnifiedAnalysisState.model_validate_json(row.state_json), "asset_investigator", "")[2]
                for row in runs]
            pytest.fail("Asset dependencies differ: " + "\n".join(unified_diff(
                json.dumps(dependencies[0], ensure_ascii=False, indent=2).splitlines(),
                json.dumps(dependencies[1], ensure_ascii=False, indent=2).splitlines())))
        logs = [json.loads(row.agents_json).get("asset_investigator", {}).get("status") for row in runs]
        assert sorted(logs) == ["reused", "succeeded"]
        assert all(row.status == "completed" for row in runs)


def test_failed_shared_work_is_not_repeated_for_each_risk_in_same_batch(session_factory):
    batch = runtime(session_factory)
    calls = []
    def fail(*args):
        calls.append(1)
        return None, "invalid evidence"
    for number in (1, 2, 3):
        ctx = RunContext(session_factory, "", batch_runtime=batch)
        output, error = task_reports.execute(ctx, state(number), ASSET_INVESTIGATOR_SPEC, "", None, fail)
        assert output is None and "invalid evidence" in error
    assert len(calls) == 1


def test_vulnerability_and_decision_reports_are_checked_against_task_scope():
    item = state(2)
    item.object_id = "risk-2"
    assert task_reports.validate_scope("vulnerability_analyst", item,
        {"findings": [{"cve_id": "CVE-2026-0001", "package_name": "daemon"}]})
    assert task_reports.validate_scope("decision_planner", item,
        {"verdicts": [{"object_id": "risk-1"}]})
    assert task_reports.validate_scope("vulnerability_analyst", item, {})
    assert not task_reports.validate_scope("vulnerability_analyst", item,
        {"findings": [{"cve_id": "CVE-2026-0002", "package_name": "daemon"}]})


def test_expired_report_retains_immutable_origin_history(session_factory):
    first, second = runtime(session_factory), runtime(session_factory)
    task_id, *_ = first.claim("runtime_analyst", 1, {"facts": "same"}, "UA-old", "ES-old")
    first.finish(task_id, {"data_gaps": ["old observation"]})
    with session_factory() as db:
        db.get(models.AnalysisTask, task_id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    next_id, cached, _, _ = second.claim("runtime_analyst", 1, {"facts": "same"}, "UA-new", "ES-new")
    assert next_id == task_id and cached is None
    second.finish(task_id, {"data_gaps": ["new observation"]})
    with session_factory() as db:
        row = db.get(models.AnalysisTask, task_id)
        previous = json.loads(row.history_json)[0]
        assert previous["origin_run_id"] == "UA-old" and previous["origin_snapshot_id"] == "ES-old"
        assert previous["report"] == {"data_gaps": ["old observation"]}
        assert json.loads(row.report_json) == {"data_gaps": ["new observation"]}


@pytest.mark.parametrize("full_console", [False, True])
def test_reset_preserves_current_inventory_receipt_without_preserving_old_run_evidence(session_factory, full_console):
    from hashlib import sha256
    from app.services.experiment_lifecycle import clear_derived_data
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="retained", inventory_complete=True,
            inventory_metadata_json=json.dumps({"inventory_evidence_id": "INV-current"}))
        db.add(asset)
        db.flush()
        raw = '{"hostname":"retained","packages":[["daemon","1.0"]]}'
        for evidence_id in ("INV-current", "INV-obsolete"):
            db.add(models.CollectionEvidence(evidence_id=evidence_id, asset_id=asset.id,
                raw_text=raw, content_sha256=sha256(raw.encode()).hexdigest(), run_id="old-collection"))
        db.commit()
        counts = clear_derived_data(db, full_console=full_console)
        db.commit()
        assert counts["collection_evidence"] == 1
        remaining = db.query(models.CollectionEvidence).all()
        assert [item.evidence_id for item in remaining] == ["INV-current"]
        assert remaining[0].content_sha256 == sha256(remaining[0].raw_text.encode()).hexdigest()
        assert json.loads(asset.inventory_metadata_json)["inventory_evidence_id"] == "INV-current"
