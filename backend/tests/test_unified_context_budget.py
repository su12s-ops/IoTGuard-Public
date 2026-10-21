"""上下文预算与角色预算：超限必须显式降级，而不是把提示词发给模型换回 400。

回归对象（2026-10-20 真实运行）：
- UA-20261020153207-617da0：漏洞/决策角色单次请求 7,233,731 / 7,153,666 字符，
  根因是把 28.5 万条注册证据 ID 全量序列化进提示词 → 模型侧 400 [1261]；
- UA-20261020232421-f0bbef：资产角色用掉 266,072 tokens 吃穿 run 上限 200,000，
  其余三个角色 0 次调用直接降级。
"""
import json

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec
from app.services.unified import context_budget
from app.services.unified.agent_base import BudgetExceeded, UnifiedToolLoopAgent, UsageMeter
from app.services.unified.graph import RunContext, _bounded_registry_ids, _run_specialist


class Report(BaseModel):
    value: int = 0


class _Db:
    def close(self):
        pass


def _ctx(**kwargs):
    return RunContext(db_factory=lambda: _Db(), trace_id="", **kwargs)


class _NeverCalledClient:
    def complete(self, messages, tools=None):
        raise AssertionError("超预算的提示词绝不能发给模型")


# ── 估算与有界渲染 ─────────────────────────────────────────────────────────


def test_estimate_tokens_is_conservative():
    assert context_budget.estimate_tokens("") == 0
    # 3 字符/token 的保守下界：宁可低估配额，也不低估占用
    assert context_budget.estimate_tokens("a" * 300) == 100
    assert context_budget.estimate_tokens("中" * 30) == 10


def test_bounded_ids_keeps_preferred_first_and_reports_total():
    values = [f"EV-{i}" for i in range(1000)]
    rendered = context_budget.bounded_ids(values, limit=5, preferred=["EV-999", "EV-7"])
    assert rendered["sample"] == ["EV-999", "EV-7", "EV-0", "EV-1", "EV-2"]
    assert rendered["total"] == 1000
    assert rendered["shown"] == 5
    assert rendered["truncated"] is True
    assert "1000" in rendered["note"]


def test_bounded_ids_lists_everything_when_small():
    rendered = context_budget.bounded_ids(["A", "B"], limit=80)
    assert rendered["sample"] == ["A", "B"]
    assert rendered["truncated"] is False
    assert rendered["total"] == 2


def test_enforce_context_budget_raises_with_measured_values():
    text = "x" * 6000
    with_budget = context_budget.enforce_context_budget(
        text, "vulnerability_analyst", {"vulnerability_analyst": 5000})
    assert with_budget["estimated_tokens"] == 2000
    try:
        context_budget.enforce_context_budget(
            text, "vulnerability_analyst", {"vulnerability_analyst": 1000})
    except context_budget.ContextBudgetExceeded as exc:
        assert exc.role == "vulnerability_analyst" and exc.limit == 1000
        assert "context_budget_exceeded" in exc.as_reason()
        assert "chars=6000" in exc.as_reason()
    else:  # pragma: no cover
        raise AssertionError("超额度必须失败")


def test_registry_ids_are_bounded_even_with_285k_entries():
    state = type("S", (), {
        "evidence_snapshot": {"evidence_registry": {f"EV-{i}": {} for i in range(5000)}},
        "baseline": {"packet_evidence_ids": [f"EV-{i}" for i in range(5000)]},
    })()
    rendered = _bounded_registry_ids(state)
    assert rendered["shown"] <= context_budget.DEFAULT_ID_RENDER_LIMIT
    assert rendered["total"] == 5000
    # 渲染后的体积必须有界：这正是 7.2M 字符提示词的来源
    assert len(json.dumps(rendered, ensure_ascii=False)) < 6000


# ── 角色执行：超限即降级，且不派发请求 ──────────────────────────────────────


def test_specialist_degrades_before_dispatch_when_context_exceeds_budget():
    ctx = _ctx(client_factory=lambda: _NeverCalledClient(),
               context_token_budgets={"vulnerability_analyst": 100})
    spec = AgentSpec("vulnerability_analyst", "漏洞分析师", Report)
    output, reason = _run_specialist(ctx, spec, "证" * 1000)
    assert output is None
    assert reason.startswith("context_budget_exceeded")
    assert "vulnerability_analyst" in reason
    assert ctx.agent_logs["vulnerability_analyst"]["status"] == "degraded"
    assert ctx.agent_logs["vulnerability_analyst"]["llm_calls"] == 0


def test_specialist_within_budget_dispatches_and_attributes_role_usage():
    class Client:
        def complete(self, messages, tools=None):
            return {"content": json.dumps({"value": 3}),
                    "usage": {"prompt_tokens": 40, "completion_tokens": 2, "total_tokens": 42}}

    meter = UsageMeter(role_token_limits={"vulnerability_analyst": 1000})
    ctx = _ctx(client_factory=lambda: Client(), meter=meter,
               context_token_budgets={"vulnerability_analyst": 1000})
    spec = AgentSpec("vulnerability_analyst", "漏洞分析师", Report)
    output, reason = _run_specialist(ctx, spec, "证据")
    assert reason == "" and output == {"value": 3}
    # 用量必须记到角色账上，否则角色配额无法生效
    assert meter.role_usage == {"vulnerability_analyst": 42}
    assert ctx.agent_logs["vulnerability_analyst"]["prompt_estimated_tokens"] == 1


# ── 角色级 token 配额与错误语义 ────────────────────────────────────────────


def test_role_quota_stops_a_single_role_from_eating_the_run_budget():
    meter = UsageMeter(max_tokens=200000, role_token_limits={"asset_investigator": 1000})
    meter.register_call({"total_tokens": 1000}, "asset_investigator")
    assert meter.exceeded is False            # run 级预算没被击穿
    try:
        meter.ensure_budget("asset_investigator")
    except BudgetExceeded as exc:
        assert "asset_investigator" in str(exc) and "预算" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("角色配额必须独立生效")
    meter.ensure_budget("runtime_analyst")    # 其他角色不受牵连


def test_budget_message_distinguishes_call_count_from_token_usage():
    calls = UsageMeter(max_llm_calls=1)
    calls.register_call({"total_tokens": 1})
    calls.register_call({"total_tokens": 1})
    assert calls.exhausted_kind == "calls"
    try:
        calls.ensure_budget()
    except BudgetExceeded as exc:
        assert "调用预算" in str(exc) and "2/1" in str(exc)

    tokens = UsageMeter(max_tokens=100)
    tokens.register_call({"total_tokens": 100}, "runtime_analyst")
    assert tokens.exhausted_kind == "tokens"
    assert tokens.exhausted_role == "runtime_analyst"
    try:
        tokens.ensure_budget()
    except BudgetExceeded as exc:
        assert "token 预算" in str(exc) and "runtime_analyst" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("token 击穿必须报 token 语义")


def test_agent_passes_its_role_to_the_meter():
    class Client:
        def complete(self, messages, tools=None):
            return {"content": json.dumps({"value": 1}), "usage": {"total_tokens": 7}}

    meter = UsageMeter()
    agent = UnifiedToolLoopAgent(AgentSpec("decision_planner", "决策规划师", Report), Client(), meter)
    agent.run(None, "facts", deadline_s=5)
    assert meter.role_usage.get("decision_planner") == 7
    assert meter.as_dict()["role_usage"] == {"decision_planner": 7}
