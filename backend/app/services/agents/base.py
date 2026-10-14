"""智能体基础设施：职责 + 专属工具 + 结构化输出的通用工具循环。

设计约束（阶段三重构）：
- 智能体之间的差异来自「职责 + 工具集 + 输出模型」，不是四份不同提示词；
- LLM 只负责分析：它只能调用所属 Spec 注册的工具、只能产出结构化 JSON；
- 程序负责执行顺序、状态、超时、失败、重试与输出校验（见 orchestrator.py）。
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from pydantic import BaseModel
from sqlalchemy.orm import Session


@dataclass
class AgentTool:
    """一个智能体专属的只读（或白名单）工具。"""

    name: str
    description: str
    parameters: dict[str, Any]                       # JSON Schema
    handler: Callable[..., dict[str, Any]]           # def handler(db, **kwargs) -> dict

    def invoke(self, db: Session, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.handler(db, **arguments)


@dataclass
class AgentSpec:
    """智能体规格：职责、专属工具与结构化输出模型。"""

    name: str
    role: str                                          # 一句话职责（系统消息用）
    output_model: type[BaseModel]
    tools: list[AgentTool] = field(default_factory=list)
    max_tool_rounds: int = 8
    llm_retries: int = 1                               # 输出校验失败后的整体重试次数
    request_timeout_s: int = 60


class ChatClient(Protocol):
    """最小 LLM 客户端协议（真实实现为 DeepSeek/OpenAI；测试可注入假实现）。"""

    def complete(self, messages: list[dict[str, Any]],
                 tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """返回 {"content": str|None, "tool_calls": [{"id","name","arguments"}]}"""
        ...


class DeepSeekChatClient:
    """真实客户端：openai SDK 直连 DeepSeek 兼容接口。"""

    def __init__(self, model: str, api_key: str, base_url: str, timeout: int = 60):
        from openai import OpenAI
        self._model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url.rstrip("/"), timeout=timeout)

    def complete(self, messages, tools=None):
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": 0.1,
        }
        if tools:
            kwargs["tools"] = [
                {"type": "function",
                 "function": {"name": tool["name"], "description": tool["description"],
                              "parameters": tool["parameters"]}}
                for tool in tools
            ]
        response = self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        tool_calls = []
        for call in choice.message.tool_calls or []:
            try:
                arguments = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
            tool_calls.append({"id": call.id, "name": call.function.name, "arguments": arguments})
        # 真实用量仅在响应携带 usage 时透出（第八阶段追踪消费；缺失时不编造）
        usage = None
        raw_usage = getattr(response, "usage", None)
        if raw_usage is not None:
            usage = {"prompt_tokens": getattr(raw_usage, "prompt_tokens", None),
                     "completion_tokens": getattr(raw_usage, "completion_tokens", None),
                     "total_tokens": getattr(raw_usage, "total_tokens", None)}
        return {"content": choice.message.content, "tool_calls": tool_calls,
                "model": self._model, "usage": usage}


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def parse_structured_output(content: str) -> dict[str, Any]:
    """从模型回复中提取 JSON 对象；容忍 ```json 围栏与前后说明文字。"""
    text = (content or "").strip()
    if not text:
        raise ValueError("模型返回为空")
    fenced = _JSON_FENCE_RE.search(text)
    candidate = fenced.group(1) if fenced else text
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("模型回复中未找到 JSON 对象")
        parsed = json.loads(candidate[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("模型输出必须是 JSON 对象")
    return parsed


@dataclass
class AgentResult:
    agent: str
    status: str                      # succeeded / failed / timeout
    output: dict[str, Any] | None    # 已通过 output_model 校验的结构化结果
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0
    latency_ms: int = 0
    error: str = ""
    # LLM 调用统计（第八阶段追踪）：仅真实客户端提供时填充，测试假客户端为空
    llm_calls: int = 0
    llm_model: str = ""
    llm_usage: dict[str, Any] | None = None   # 真实 token 用量；无依据时保持 None


class ToolLoopAgent:
    """通用执行器：工具循环 + 结构化输出校验 + 超时/重试控制。"""

    def __init__(self, spec: AgentSpec, client: ChatClient):
        self.spec = spec
        self.client = client

    def _system_message(self) -> str:
        tool_lines = "\n".join(f"- {tool.name}: {tool.description}" for tool in self.spec.tools)
        schema = json.dumps(self.spec.output_model.model_json_schema(), ensure_ascii=False)
        return (
            f"你是{self.spec.role}。\n"
            "你只能使用下面列出的专属工具获取事实，不得假设工具未返回的数据：\n"
            f"{tool_lines}\n"
            "先调用工具取得真实数据，再基于数据完成分析。"
            "最终必须只输出一个 JSON 对象（不要输出多余文字），结构必须严格符合：\n"
            f"{schema}\n"
            "禁止编造 evidence_id、CVE、端口、版本等事实；工具没有返回的内容写进 data_gaps。"
        )

    def _tool_schemas(self) -> list[dict[str, Any]]:
        return [{"name": tool.name, "description": tool.description,
                 "parameters": tool.parameters} for tool in self.spec.tools]

    def run(self, db: Session, context: str, deadline_s: float = 150.0) -> AgentResult:
        started = time.monotonic()
        deadline = started + deadline_s
        last_error = ""
        stats = {"calls": 0, "model": "", "usage": None}   # 真实客户端才填充
        for attempt in range(1 + self.spec.llm_retries):
            if time.monotonic() > deadline:
                return AgentResult(self.spec.name, "timeout", None, attempts=attempt,
                                   latency_ms=int((time.monotonic() - started) * 1000),
                                   error=f"超过总时限 {deadline_s}s",
                                   llm_calls=stats["calls"], llm_model=stats["model"],
                                   llm_usage=stats["usage"])
            try:
                result = self._run_once(db, context, deadline, stats)
                result.llm_calls = stats["calls"]
                result.llm_model = stats["model"]
                result.llm_usage = stats["usage"]
                if result.status == "succeeded":
                    result.attempts = attempt + 1
                    result.latency_ms = int((time.monotonic() - started) * 1000)
                    return result
                last_error = result.error
            except TimeoutError as exc:
                last_error = str(exc) or "timeout"
            except Exception as exc:  # LLM 网络错误、解析失败等，交由重试策略
                last_error = f"{type(exc).__name__}: {exc}"
        return AgentResult(self.spec.name, "failed", None, attempts=1 + self.spec.llm_retries,
                           latency_ms=int((time.monotonic() - started) * 1000), error=last_error,
                           llm_calls=stats["calls"], llm_model=stats["model"],
                           llm_usage=stats["usage"])

    def _run_once(self, db: Session, context: str, deadline: float,
                  stats: dict[str, Any]) -> AgentResult:
        tool_calls_log: list[dict[str, Any]] = []
        allowed = {tool.name: tool for tool in self.spec.tools}
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_message()},
            {"role": "user", "content": context},
        ]
        for _ in range(self.spec.max_tool_rounds):
            if time.monotonic() > deadline:
                raise TimeoutError("工具循环超时")
            response = self.client.complete(messages, tools=self._tool_schemas() or None)
            # 汇总真实 LLM 统计（假客户端无 usage/model 字段 → 保持空，不编造）
            stats["calls"] = stats.get("calls", 0) + 1
            if response.get("model"):
                stats["model"] = response["model"]
            if response.get("usage"):
                merged = dict(stats.get("usage") or {})
                for key, value in response["usage"].items():
                    if value is not None:
                        merged[key] = (merged.get(key) or 0) + value
                stats["usage"] = merged
            calls = response.get("tool_calls") or []
            if not calls:
                parsed = parse_structured_output(response.get("content") or "")
                validated = self.spec.output_model.model_validate(parsed)
                return AgentResult(self.spec.name, "succeeded", validated.model_dump(),
                                   tool_calls=tool_calls_log)
            assistant = {"role": "assistant", "content": response.get("content") or ""}
            assistant["tool_calls"] = [
                {"id": call["id"], "type": "function",
                 "function": {"name": call["name"],
                              "arguments": json.dumps(call["arguments"], ensure_ascii=False)}}
                for call in calls
            ]
            messages.append(assistant)
            for call in calls:
                entry = {"name": call["name"], "arguments": call["arguments"], "ok": False}
                tool = allowed.get(call["name"])
                if tool is None:
                    entry["error"] = "未注册到当前智能体的工具被拒绝"
                    messages.append({"role": "tool", "tool_call_id": call["id"],
                                     "content": json.dumps({"error": entry["error"]}, ensure_ascii=False)})
                else:
                    try:
                        output = tool.invoke(db, call["arguments"])
                        entry["ok"] = True
                        entry["summary"] = _brief(output)
                        messages.append({"role": "tool", "tool_call_id": call["id"],
                                         "content": json.dumps(output, ensure_ascii=False, default=str)[:12000]})
                    except Exception as exc:
                        entry["error"] = f"{type(exc).__name__}: {exc}"
                        messages.append({"role": "tool", "tool_call_id": call["id"],
                                         "content": json.dumps({"error": entry["error"]}, ensure_ascii=False)})
                tool_calls_log.append(entry)
        raise TimeoutError(f"工具调用轮次超过上限 {self.spec.max_tool_rounds}")


def _brief(output: dict[str, Any], limit: int = 160) -> str:
    text = json.dumps(output, ensure_ascii=False, default=str)
    return text[:limit] + ("…" if len(text) > limit else "")
