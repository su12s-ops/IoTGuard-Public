"""角色用量投影收敛 + 同会话重复工具调用压缩（2026-10-24 优化）。

回归对象：真实批次 UA-7b14f6e6bf3b。
- risk-130 vulnerability_analyst 3 次请求 56,598 tokens / 550s 在「跑完才判超」
  后被整体丢弃；risk-131 复审重试再丢 21,618 tokens / 245.6s。
- risk-131 runtime_analyst 单角色同会话重复调用 query_process_evidence /
  query_process_tree，每条 8k 字符结果在后续每轮请求中重复计费。

优化不改变任何预算数值、降级策略与成功判定标准：
- 投影只决定「下一轮工具请求是否发起」，越限时改走与上下文超限完全相同的
  唯一次无工具收敛；收敛请求本身仍受 meter 硬闸门约束。
- 重复调用压缩只影响「同一会话内参数一致且结果一致」的调用：完整结果已在
  上方对话，只回指不重复展开；结果变化仍全文返回。
"""
from __future__ import annotations

import json

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec, AgentTool
from app.services.unified.agent_base import UnifiedToolLoopAgent, UsageMeter


class Report(BaseModel):
    summary: str = ""
    evidence_ids: list[str] = []


class ScriptedClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def complete(self, messages, tools=None):
        import copy
        self.calls.append({"messages": copy.deepcopy(messages), "tools": tools})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def tool_call(call_id="call-1", name="query_huge", arguments=None, usage=None):
    return {"content": "", "tool_calls": [
        {"id": call_id, "name": name, "arguments": arguments or {}}], "usage": usage}


def final_answer(usage=None):
    return {"content": json.dumps({"summary": "done", "evidence_ids": []}),
            "usage": usage}


def make_spec(tools):
    return AgentSpec("vulnerability_analyst", "漏洞分析师", Report, tools=tools,
                     max_tool_rounds=6, llm_retries=0)


def static_tool(output):
    return AgentTool("query_huge", "查询", {}, lambda db, **kwargs: output)


def test_projection_diverts_to_single_finalize_within_role_budget():
    """剩余角色额度装不下下一轮工具请求时：不发起该请求，改走唯一一次收敛。"""
    counter = {"calls": 0}

    def counting_tool(db, **kwargs):
        counter["calls"] += 1
        return {"events": [{"id": number, "payload": "x" * 300} for number in range(20)]}

    tool = AgentTool("query_huge", "查询", {}, counting_tool)
    # 第一次请求返回工具调用并计 10,000 tokens；随后 messages 含 8k 字符级
    # 工具结果，投影（used + 2×估算 + 12k 预留）越过 25,000 限额。
    client = ScriptedClient([
        tool_call(usage={"total_tokens": 10000}),
        final_answer(usage={"total_tokens": 8000}),
        final_answer(usage={"total_tokens": 8000}),   # 不应被消费
    ])
    meter = UsageMeter(max_llm_calls=40, max_tokens=200000,
                       role_token_limits={"vulnerability_analyst": 25000})
    agent = UnifiedToolLoopAgent(make_spec([tool]), client, meter=meter)
    result = agent.run(None, "调查 CVE 影响", deadline_s=30)

    # 第二次请求是无工具收敛（带最终收敛指令），不是又一轮工具请求。
    assert len(client.calls) == 2
    assert client.calls[1]["tools"] is None
    assert any("不能再调用任何工具" in (message.get("content") or "")
               for message in client.calls[1]["messages"] if message["role"] == "user")
    assert counter["calls"] == 1
    # 收敛成功：产出经完整结构化校验的结构化结果，stop_reason 记录投影原因。
    assert result.status == "succeeded"
    assert result.output == {"summary": "done", "evidence_ids": []}
    assert "role_usage_projection" in (result.stop_reason or "")
    # meter 的硬闸门未被绕过：角色总用量仍被记录，且不再有第三次请求。
    assert meter.role_usage["vulnerability_analyst"] == 18000
    assert meter.role_exhausted("vulnerability_analyst") is False


def test_projection_absent_when_budget_fits_keeps_tool_rounds():
    """额度充足时不干预：工具循环按原语义继续。"""
    tool = static_tool({"events": [{"id": 1}]})
    client = ScriptedClient([
        tool_call(usage={"total_tokens": 1000}),
        final_answer(usage={"total_tokens": 1000}),
    ])
    meter = UsageMeter(role_token_limits={"vulnerability_analyst": 30000})
    agent = UnifiedToolLoopAgent(make_spec([tool]), client, meter=meter)
    result = agent.run(None, "调查", deadline_s=30)
    assert result.status == "succeeded"
    assert len(client.calls) == 2
    assert client.calls[1]["tools"] is not None
    assert result.stop_reason == ""


def test_exhausted_role_still_fails_closed_without_any_request():
    """角色已越限时不发任何请求（既有硬闸门语义不变）。"""
    tool = static_tool({"events": []})
    client = ScriptedClient([final_answer(usage={"total_tokens": 1000})])
    meter = UsageMeter(role_token_limits={"vulnerability_analyst": 5000})
    meter.register_call({"total_tokens": 6000}, "vulnerability_analyst")
    agent = UnifiedToolLoopAgent(make_spec([tool]), client, meter=meter)
    result = agent.run(None, "调查", deadline_s=30)
    assert result.status == "degraded"
    assert "token 预算已用尽" in result.error
    assert client.calls == []


def test_duplicate_tool_call_compacts_to_pointer():
    """同会话同参数且结果一致：第二次只回指，不重复展开 8k 结果。"""
    big = {"events": [{"id": number, "payload": "y" * 500} for number in range(30)]}
    tool = static_tool(big)
    client = ScriptedClient([
        tool_call(call_id="c1", arguments={"scope": "all"}, usage={"total_tokens": 100}),
        tool_call(call_id="c2", arguments={"scope": "all"}, usage={"total_tokens": 100}),
        final_answer(usage={"total_tokens": 100}),
    ])
    agent = UnifiedToolLoopAgent(make_spec([tool]), client)
    result = agent.run(None, "调查", deadline_s=30)

    assert result.status == "succeeded"
    tool_messages = [message for message in client.calls[2]["messages"]
                     if message.get("role") == "tool"]
    assert len(tool_messages) == 2
    first, second = tool_messages
    assert json.loads(first["content"])["data"]["events"]
    compact = json.loads(second["content"])
    assert compact["duplicate_call"] is True
    assert compact["same_parameters_as_call"] == 1
    # 压缩消息远小于有界结果上限，第二轮提示词不再为重复结果付费。
    assert len(second["content"]) < 400
    # 审计日志保留重复标记。
    duplicates = [call for call in result.tool_calls if call.get("duplicate_of")]
    assert len(duplicates) == 1 and duplicates[0]["duplicate_of"] == 1


def test_changed_tool_result_is_returned_in_full():
    """同参数但结果变化（如运行时新事件）：仍全文返回，不静默省略。"""
    def growing_tool(db, **kwargs):
        growing_tool.seen = getattr(growing_tool, "seen", 0) + 1
        return {"events": [{"id": number, "round": growing_tool.seen} for number in range(3)]}

    tool = AgentTool("query_huge", "查询", {}, growing_tool)
    client = ScriptedClient([
        tool_call(call_id="c1", usage={"total_tokens": 100}),
        tool_call(call_id="c2", usage={"total_tokens": 100}),
        final_answer(usage={"total_tokens": 100}),
    ])
    agent = UnifiedToolLoopAgent(make_spec([tool]), client)
    result = agent.run(None, "调查", deadline_s=30)

    tool_messages = [message for message in client.calls[2]["messages"]
                     if message.get("role") == "tool"]
    assert len(tool_messages) == 2
    parsed = json.loads(tool_messages[1]["content"])
    assert "duplicate_call" not in parsed
    assert not any(call.get("duplicate_of") for call in result.tool_calls)


def test_different_arguments_are_not_duplicates():
    """参数不同不是重复调用：两条完整结果都进入对话。"""
    tool = static_tool({"events": [{"id": 1}]})
    client = ScriptedClient([
        tool_call(call_id="c1", arguments={"scope": "a"}, usage={"total_tokens": 100}),
        tool_call(call_id="c2", arguments={"scope": "b"}, usage={"total_tokens": 100}),
        final_answer(usage={"total_tokens": 100}),
    ])
    agent = UnifiedToolLoopAgent(make_spec([tool]), client)
    result = agent.run(None, "调查", deadline_s=30)
    tool_messages = [message for message in client.calls[2]["messages"]
                     if message.get("role") == "tool"]
    assert len(tool_messages) == 2
    # 小结果不触发截断信封：直接校验事件字段存在且未被压缩。
    for message in tool_messages:
        parsed = json.loads(message["content"])
        assert parsed["events"] or parsed.get("data", {}).get("events")
    assert not any(call.get("duplicate_of") for call in result.tool_calls)
