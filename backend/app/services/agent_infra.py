"""智能体基础设施（M5 中立模块）：LLM 客户端协议 + 结构化输出解析。

从旧 System A `services/agents/base.py` 迁出的通用确定性组件，供唯一正式
编排器（services/unified/）使用。本模块不含任何编排流程：
- 执行顺序/状态/超时/预算由 unified.graph 与 unified.runner 负责；
- 工具集定义见 services/agent_tools.py（同样与编排器解耦）。
"""
from __future__ import annotations

import json
import re
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
    """最小 LLM 客户端协议（真实实现为 DeepSeek/OpenAI 兼容或 Anthropic 协议；测试可注入假实现）。"""

    def complete(self, messages: list[dict[str, Any]],
                 tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """返回 {"content": str|None, "tool_calls": [{"id","name","arguments"}]}"""
        ...


class DeepSeekChatClient:
    """真实客户端：openai SDK 直连 DeepSeek 兼容接口。"""

    def __init__(self, model: str, api_key: str, base_url: str, timeout: int = 60,
                 max_retries: int = 1):
        from openai import OpenAI
        self._model = model
        # max_retries=1：限流退化时单次调用不再指数退避多次（实验实测单智能体
        # 曾因此拖到 17 分钟）；整体时限由编排器的 deadline 协同约束
        self._client = OpenAI(api_key=api_key, base_url=base_url.rstrip("/"), timeout=timeout,
                              max_retries=max_retries)

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
        # 真实用量仅在响应携带 usage 时透出（追踪消费；缺失时不编造）
        usage = None
        raw_usage = getattr(response, "usage", None)
        if raw_usage is not None:
            usage = {"prompt_tokens": getattr(raw_usage, "prompt_tokens", None),
                     "completion_tokens": getattr(raw_usage, "completion_tokens", None),
                     "total_tokens": getattr(raw_usage, "total_tokens", None)}
        return {"content": choice.message.content, "tool_calls": tool_calls,
                "model": self._model, "usage": usage}


class AnthropicProtocolChatClient:
    """真实客户端：Anthropic Messages 协议端点（BigModel GLM 套餐计费路径等）。

    对外保持与 DeepSeekChatClient 完全一致的 complete(messages, tools) 契约，
    内部完成 OpenAI 风格消息/工具 ↔ Anthropic 协议的双向转换：
    - system 首消息 → 独立 system 字段；
    - assistant.tool_calls → assistant 轮 tool_use 内容块；
    - role=tool 结果 → user 轮 tool_result 内容块（相邻合并保持轮次交替）；
    - 响应中 text 块拼接为 content，tool_use 块还原为工具调用，
      thinking 块不计入 content（推理与结论分离，不丢弃也不冒充结论）。
    """

    def __init__(self, model: str, api_key: str, base_url: str, timeout: int = 400,
                 max_retries: int = 1, max_tokens: int = 32768,
                 thinking: dict[str, Any] | None = None):
        import anthropic
        self._model = model
        self._max_tokens = max_tokens
        self._thinking = thinking
        # timeout 默认 400s：GLM 等模型生成完整结构化报告（5-15k 输出 tokens，
        # 实测 ~120-165s/报告）加上排队抖动，DeepSeek 时代的 60s 会系统性超时。
        # max_retries=1：与 DeepSeekChatClient 相同的限流退化策略
        self._client = anthropic.Anthropic(api_key=api_key, base_url=base_url.rstrip("/"),
                                           timeout=timeout, max_retries=max_retries)

    def _convert_messages(self, messages) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        turns: list[dict[str, Any]] = []
        for message in messages:
            role, content = message.get("role"), message.get("content")
            if role == "system":
                if content:
                    system_parts.append(str(content))
            elif role == "assistant":
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for call in message.get("tool_calls") or []:
                    function = call.get("function") or {}
                    try:
                        arguments = json.loads(function.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        arguments = {}
                    blocks.append({"type": "tool_use", "id": call.get("id") or "",
                                   "name": function.get("name") or "", "input": arguments})
                turns.append({"role": "assistant",
                              "content": blocks or [{"type": "text", "text": ""}]})
            elif role == "tool":
                turns.append({"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": message.get("tool_call_id") or "",
                    "content": str(content or "")}]})
            else:
                turns.append({"role": "user", "content": str(content or "")})
        merged: list[dict[str, Any]] = []
        for turn in turns:
            if merged and merged[-1]["role"] == turn["role"]:
                if isinstance(merged[-1]["content"], list) and isinstance(turn["content"], list):
                    merged[-1]["content"].extend(turn["content"])
                elif isinstance(merged[-1]["content"], str) and isinstance(turn["content"], str):
                    merged[-1]["content"] += "\n" + turn["content"]
                else:
                    merged.append(turn)
            else:
                merged.append(turn)
        return "\n".join(system_parts), merged

    def complete(self, messages, tools=None):
        system, turns = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": self._model, "max_tokens": self._max_tokens,
            "messages": turns, "temperature": 0.1,
        }
        if system:
            kwargs["system"] = system
        if self._thinking is not None:
            kwargs["thinking"] = self._thinking
        if tools:
            kwargs["tools"] = [{"name": tool["name"], "description": tool["description"],
                                "input_schema": tool["parameters"]} for tool in tools]
        response = self._client.messages.create(**kwargs)
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in response.content or []:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(block.text)
            elif block_type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name,
                                   "arguments": dict(block.input or {})})
        usage = None
        raw_usage = getattr(response, "usage", None)
        if raw_usage is not None:
            prompt = getattr(raw_usage, "input_tokens", None)
            completion = getattr(raw_usage, "output_tokens", None)
            total = prompt + completion if prompt is not None and completion is not None else None
            usage = {"prompt_tokens": prompt, "completion_tokens": completion,
                     "total_tokens": total}
        return {"content": "".join(text_parts) or None, "tool_calls": tool_calls,
                "model": self._model, "usage": usage}


def build_llm_client():
    """按 DEEPSEEK_API_PROTOCOL（openai|anthropic）构造真实 LLM 客户端。"""
    from app import config
    if not config.DEEPSEEK_API_KEY:
        raise RuntimeError("未配置 DEEPSEEK_API_KEY，无法调用智能体 LLM")
    protocol = getattr(config, "DEEPSEEK_API_PROTOCOL", "openai").strip().lower()
    if protocol == "anthropic":
        thinking = ({"type": "disabled"}
                    if getattr(config, "DEEPSEEK_THINKING", "").strip().lower() == "off"
                    else None)
        return AnthropicProtocolChatClient(model=config.DEEPSEEK_MODEL,
                                           api_key=config.DEEPSEEK_API_KEY,
                                           base_url=config.DEEPSEEK_BASE_URL,
                                           thinking=thinking)
    if protocol != "openai":
        raise RuntimeError(f"不支持的 DEEPSEEK_API_PROTOCOL：{protocol}")
    return DeepSeekChatClient(model=config.DEEPSEEK_MODEL, api_key=config.DEEPSEEK_API_KEY,
                              base_url=config.DEEPSEEK_BASE_URL)


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def parse_structured_output(content: str) -> dict[str, Any]:
    """从模型回复中提取 JSON 对象；容忍 ```json 围栏、前后说明与尾部多余文字。"""
    text = (content or "").strip()
    if not text:
        raise ValueError("模型返回为空")
    fenced = _JSON_FENCE_RE.search(text)
    candidate = fenced.group(1) if fenced else text
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        # 依次尝试：首尾大括号切片 → 从每个 '{' 起点的平衡解析（容忍
        # 尾部说明文字/第二个对象，"Extra data" 类失败不再整体报废）
        start, end = candidate.find("{"), candidate.rfind("}")
        parsed = None
        if 0 <= start < end:
            try:
                parsed = json.loads(candidate[start:end + 1])
            except json.JSONDecodeError:
                decoder = json.JSONDecoder()
                for pos in (index for index, char in enumerate(candidate) if char == "{"):
                    try:
                        parsed, _ = decoder.raw_decode(candidate[pos:])
                        break
                    except json.JSONDecodeError:
                        continue
        if parsed is None:
            raise ValueError("模型回复中未找到可解析的 JSON 对象")
    if not isinstance(parsed, dict):
        raise ValueError("模型输出必须是 JSON 对象")
    return parsed
