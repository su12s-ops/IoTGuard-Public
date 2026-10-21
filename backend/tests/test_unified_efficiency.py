"""Efficiency changes must preserve evidence, failure history and review gates."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec
from app.services.unified.agent_base import BudgetExceeded, UnifiedToolLoopAgent, UsageMeter
from app.services.unified.graph import RunContext, _agent_deadline, _route_after_follow_ups
from app.services.unified.plan_guard import annotate_plan
from app.services.unified.schemas import AGENT_ASSET, AGENT_DECISION


def test_concurrent_requests_cannot_exceed_budget():
    meter = UsageMeter(3)
    def reserve(_):
        try:
            meter.reserve_request()
            return True
        except BudgetExceeded:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(20))) == 3
    assert meter.requests == 3
    assert meter.calls == 0  # requests are not fabricated successful responses


def test_repeated_role_retains_failure_and_totals():
    ctx = RunContext(db_factory=lambda: None, trace_id="")
    ctx.log_agent("role", {"status": "failed", "latency_ms": 10, "llm_calls": 1})
    ctx.log_agent("role", {"status": "succeeded", "latency_ms": 20, "llm_calls": 2})
    row = ctx.agent_logs["role"]
    assert [e["status"] for e in row["executions"]] == ["failed", "succeeded"]
    assert row["total_latency_ms"] == 30 and row["total_llm_calls"] == 3


def test_exhausted_request_budget_never_dispatches_or_retries():
    class Report(BaseModel):
        value: int
    class Client:
        def complete(self, messages, tools=None):
            raise AssertionError("must not dispatch")
    meter = UsageMeter(1)
    meter.reserve_request()
    agent = UnifiedToolLoopAgent(AgentSpec("test", "test", Report), Client(), meter)
    result = agent.run(None, "facts", deadline_s=2)
    assert result.status == "degraded"
    assert result.attempts == 1 and agent.request_log == []


def test_specialists_leave_decision_reserve():
    ctx = RunContext(db_factory=lambda: None, trace_id="", run_deadline_s=100)
    assert 74 < _agent_deadline(ctx, AGENT_ASSET) <= 75
    assert 99 < _agent_deadline(ctx, AGENT_DECISION) <= 100


def test_no_new_followup_result_skips_second_decision():
    for result in ({"error": "failed"}, {"status": "budget_reserved_for_decision"},
                   {"output": {"fact": 1}, "changed": False}):
        assert _route_after_follow_ups(SimpleNamespace(follow_up_results=[result])) == "finalize"
    assert _route_after_follow_ups(SimpleNamespace(follow_up_results=[
        {"output": {"fact": 2}, "changed": True}])) == "decide"


def test_schema_correction_has_original_report_and_does_not_restart():
    class Report(BaseModel):
        value: int
    class Client:
        messages = []
        def complete(self, messages, tools=None):
            self.messages.append(list(messages))
            return {"content": '{"value":"invalid"}'}
    client = Client()
    agent = UnifiedToolLoopAgent(AgentSpec("test", "test", Report), client)
    result = agent.run(None, "facts", deadline_s=2)
    assert result.status == "failed"
    assert len(client.messages) == 2
    assert any(m["role"] == "assistant" and "invalid" in m["content"]
               for m in client.messages[1])
    assert len(agent.request_log) == 2


def test_logread_loss_promise_blocks_plan_without_authorizing():
    state = {"runtime": {"source": "logread", "dropped_events": "unavailable"}}
    plan = {"actions": [{"action": "restart_service", "target": "openwrt-logread-4",
                         "expected_verification": "dropped_events 由 unavailable 变为可读数值"}]}
    result = annotate_plan(state, plan, [])
    assert result["technical_gate"]["status"] == "blocked"
    assert "loss_measurement_capability_not_established" in result["technical_gate"]["reasons"]
    assert result["requires_approval"] is True
    assert result["technical_gate"]["executed"] is False


def test_live_output_negated_loss_requirement_is_not_a_promise():
    state = {"runtime": {"source": "logread", "dropped_events": "unavailable"}}
    check = "logread 传感器重启后心跳与覆盖恢复；dropped_events 若仍为 unavailable 则如实保留能力缺口，不要求变为数值"
    plan = {"verification_plan": [{"check": check}]}
    assert annotate_plan(state, plan, [])["technical_gate"]["status"] == "pending_human_review"
    plan["verification_plan"][0]["check"] += "；但必须确保 dropped_events 变为数值"
    assert annotate_plan(state, plan, [])["technical_gate"]["status"] == "blocked"
