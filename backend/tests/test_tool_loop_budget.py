"""A2/A3：工具循环累计提示词预算 + 工具结果有界截断 + 每次 attempt 记录。

使用纯假客户端/假工具，不调用真实模型或设备。回归对象：决策角色首轮
21,701 字符，工具结果不断累积到 400,331 字符并超时 800s；同一角色只保留
最后一次 log，使首轮 117,800 tokens 在 API 中不可见。
"""
from __future__ import annotations

from copy import deepcopy
import json

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec, AgentTool
from app.services.unified.agent_base import (
    TOOL_RESULT_MAX_CHARS,
    UnifiedToolLoopAgent,
    UsageMeter,
    bounded_tool_result,
)
from app.services.unified.graph import RunContext, _run_specialist


class Report(BaseModel):
    summary: str = ""
    evidence_ids: list[str] = []


class ScriptedClient:
    """按脚本返回响应；异常实例会在对应调用点抛出。"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def complete(self, messages, tools=None):
        self.calls.append({"messages": deepcopy(messages), "tools": tools})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def tool_call(call_id="call-1", name="query_huge", arguments=None, usage=None):
    return {"content": "", "tool_calls": [
        {"id": call_id, "name": name, "arguments": arguments or {}}], "usage": usage}


def final_answer(value=3, usage=None):
    return {"content": json.dumps({"summary": f"done-{value}", "evidence_ids": []}),
            "usage": usage}


def huge_tool(db, **kwargs):
    return {"count": 200, "events": [
        {"id": number, "payload": "x" * 400, "source": "sensor"}
        for number in range(200)]}


def spec(*, rounds=4, retries=0, tools=None):
    return AgentSpec("runtime_analyst", "运行时分析师", Report,
                     tools=tools if tools is not None else [
                         AgentTool("query_huge", "返回超大运行时结果", {}, huge_tool)],
                     max_tool_rounds=rounds, llm_retries=retries)


def test_tool_loop_stops_tools_and_degrades_when_cumulative_budget_exceeded():
    tool_calls = []
    tool = AgentTool("query_huge", "返回超大运行时结果", {}, lambda db, **kw: (
        tool_calls.append("called") or huge_tool(db)))
    client = ScriptedClient([tool_call(usage={"total_tokens": 100})])
    agent = UnifiedToolLoopAgent(spec(tools=[tool]), client,
                                 context_token_budgets={"runtime_analyst": 1000})

    result = agent.run(None, "调查运行时行为", deadline_s=10)

    # 只有第一次请求真正发出；工具结果把 messages 推过 1000 tokens 后，
    # 不再发第二次工具请求，也不发超限的收敛请求。
    assert len(client.calls) == 1
    assert tool_calls == ["called"]
    assert result.status == "degraded"
    assert "context_budget_exceeded" in result.error
    assert "stage=conversation" in result.error
    assert "final_answer_over_budget" in result.error
    # 任何已发送请求都在额度内（1000 tokens ≈ 3000 字符）。
    assert all(sum(len(json.dumps(message, ensure_ascii=False, default=str))
                   for message in call["messages"]) <= 3000 for call in client.calls)
    rejected = [record for record in agent.request_log if record["status"] == "budget_rejected"]
    assert rejected and rejected[-1]["estimated_tokens"] > rejected[-1]["limit_tokens"]
    assert result.stop_reason.startswith("context_budget_exceeded")


def test_tool_result_is_structurally_truncated_with_explicit_original_length():
    payload = {
        "count": 3,
        "events": [{"id": number, "payload": "y" * 5000} for number in range(3)],
        "meta": {"source": "sensor", "sensor_id": "s-1"},
    }
    text = bounded_tool_result(payload)
    assert len(text) <= TOOL_RESULT_MAX_CHARS
    parsed = json.loads(text)
    assert parsed["truncated"] is True
    assert parsed["original_chars"] > TOOL_RESULT_MAX_CHARS
    # 结构/字段名保留，长字段有显式截断标记与原始长度。
    assert parsed["data"]["meta"]["sensor_id"] == "s-1"
    assert parsed["data"]["count"] == 3
    assert len(parsed["data"]["events"]) >= 1
    first = parsed["data"]["events"][0]
    assert "payload" in first and "已截断" in first["payload"] and "原始" in first["payload"]


def test_tool_result_entering_messages_is_bounded_and_marked():
    client = ScriptedClient([
        tool_call(usage={"total_tokens": 10}),
        final_answer(usage={"total_tokens": 20}),
    ])
    agent = UnifiedToolLoopAgent(spec(), client)
    result = agent.run(None, "调查运行时行为", deadline_s=10)

    assert result.status == "succeeded"
    tool_messages = [message for message in client.calls[1]["messages"]
                     if message.get("role") == "tool"]
    assert len(tool_messages) == 1
    content = tool_messages[0]["content"]
    assert len(content) <= TOOL_RESULT_MAX_CHARS
    parsed = json.loads(content)
    assert parsed["truncated"] is True
    assert parsed["original_chars"] > TOOL_RESULT_MAX_CHARS
    assert "events" in parsed["data"]
    # 原始结果仍完整保留在工具缓存/审计边界（这里由工具返回值本身验证）。
    assert len(json.dumps(huge_tool(None), ensure_ascii=False)) > TOOL_RESULT_MAX_CHARS


def test_attempts_history_keeps_first_round_usage_without_double_counting_meter():
    client = ScriptedClient([
        tool_call(usage={"total_tokens": 100}),
        TimeoutError("upstream read timeout"),
        final_answer(usage={"total_tokens": 50}),
    ])
    meter = UsageMeter()
    agent = UnifiedToolLoopAgent(spec(retries=1), client, meter=meter, role="runtime_analyst")

    result = agent.run(None, "调查运行时行为", deadline_s=10)

    assert result.status == "succeeded"
    assert result.attempts == 2
    history = result.attempts_history
    assert [entry["attempt"] for entry in history] == [1, 2]
    # 首轮（失败）的真实 usage 不再被最后一次成功记录覆盖。
    assert history[0]["status"] == "timeout"
    assert history[0]["llm_calls"] == 1
    assert history[0]["usage"]["total_tokens"] == 100
    assert history[1]["status"] == "succeeded"
    assert history[1]["llm_calls"] == 1
    assert history[1]["usage"]["total_tokens"] == 50
    # meter 只在请求响应点计量一次：两次调用共 150，不是 300。
    assert meter.calls == 2
    assert meter.usage["total_tokens"] == 150
    assert sum(entry["usage"].get("total_tokens", 0) for entry in history) == 150
    assert sum(entry["llm_calls"] for entry in history) == 2


class _Db:
    def close(self):
        pass


def test_agent_log_keeps_last_run_primary_and_adds_attempts_history():
    class Client:
        def __init__(self):
            self.calls = 0

        def complete(self, messages, tools=None):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("upstream read timeout")
            return {"content": json.dumps({"summary": "done"}),
                    "usage": {"total_tokens": 42}}

    ctx = RunContext(db_factory=lambda: _Db(), trace_id="",
                     client_factory=lambda: Client())
    agent_spec = AgentSpec("runtime_analyst", "运行时分析师", Report, llm_retries=1)
    output, reason = _run_specialist(ctx, agent_spec, "调查运行时行为")

    assert reason == ""
    assert output == {"summary": "done", "evidence_ids": []}
    log = ctx.agent_logs["runtime_analyst"]
    # 顶层仍以最后一次结果为主。
    assert log["status"] == "succeeded"
    assert log["llm_calls"] == 1
    assert log["llm_usage"]["total_tokens"] == 42
    # 首轮失败的 attempt 记录不会被最后一次覆盖。
    history = log["attempts_history"]
    assert [entry["attempt"] for entry in history] == [1, 2]
    assert history[0]["status"] == "timeout"
    assert "upstream read timeout" in history[0]["error"]
    assert history[1]["status"] == "succeeded"
    assert history[1]["usage"]["total_tokens"] == 42
