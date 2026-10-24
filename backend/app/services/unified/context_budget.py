"""上下文预算：把「提示词大小」当成可强制、可观测的运行约束。

动机（2026-10-20 实测，run UA-20261020153207-617da0）：
漏洞分析师与决策规划师的单次请求被渲染成 7,233,731 / 7,153,666 字符——
根因不是证据多，而是把证据注册表的**全部 ID**（约 28.5 万条）序列化进提示词，
模型侧直接返回 400 `[1261][prompt is too long]`。两个角色因此各浪费两次重试后降级。

同一批运行校准出的字符/token 比（1 次真实模型调用 = 1 个样本）：
7.04、6.65、3.57 字符/token。中英混排 JSON 取保守下界，见 `CHARS_PER_TOKEN`。

本模块只做三件确定性的事情，不做任何语义裁剪：

1. `bounded_ids`：把「可引用 ID 全集」渲染成有界样本 + 总数 + 截断标记，
   避免把十万级 ID 塞进提示词；
2. `enforce_context_budget`：请求前估算 token，超过角色额度时**显式失败**
   （降级原因写明实测值与上限），而不是把 7MB 提示词发给模型换一个 400；
3. `enforce_conversation_budget`：工具循环每次请求前对**完整 messages**
   估算 token。首轮提示词通过闸门不代表后续轮次有界——实测首轮 21,701
   字符在工具结果累积后膨胀到 400,331 字符并超时 800s。
"""
from __future__ import annotations

import json
import math
from typing import Any, Iterable

# 保守估算：中英混排 JSON 实测 3.57–7.04 字符/token，取 3.0 作为下界，
# 宁可低估配额也不低估占用（低估 token 会让请求再次撞上模型侧上限）。
CHARS_PER_TOKEN = 3.0

# 角色级提示词额度（估算 token）。默认值来自真实运行观测：
# 成功运行的单次最大请求约 36,133 字符（≈12k token），失败运行达 7.2M 字符。
# 额度留出 4 倍余量，仍远低于模型侧上限。
DEFAULT_ROLE_TOKEN_BUDGET = {
    "asset_investigator": 48_000,
    "vulnerability_analyst": 48_000,
    "runtime_analyst": 40_000,
    "decision_planner": 56_000,
}
FALLBACK_ROLE_TOKEN_BUDGET = 48_000

# 可引用 ID 的渲染上限：决策/漏洞角色只需要看到「可引用的样例」，
# 全集由校验器在服务端比对，不需要进提示词。
DEFAULT_ID_RENDER_LIMIT = 80


class ContextBudgetExceeded(RuntimeError):
    """提示词超过角色额度：调用方应把该角色显式降级，而不是发送后等模型侧拒绝。"""

    def __init__(self, role: str, tokens: int, limit: int, chars: int, *, stage: str = ""):
        self.role = role
        self.tokens = tokens
        self.limit = limit
        self.chars = chars
        self.stage = stage
        super().__init__(
            f"role={role} 估算 {tokens} tokens（{chars} 字符）超过角色额度 {limit} tokens")

    def as_reason(self) -> str:
        stage = f" stage={self.stage}" if self.stage else ""
        return (f"context_budget_exceeded:{stage} role={self.role} estimated_tokens={self.tokens} "
                f"limit={self.limit} chars={self.chars}")


def estimate_tokens(text: str) -> int:
    """保守估算 token 数；空串为 0。"""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / CHARS_PER_TOKEN))


def role_token_budget(role: str, overrides: dict[str, int] | None = None) -> int:
    if overrides:
        value = overrides.get(role)
        if isinstance(value, int) and value > 0:
            return value
    return DEFAULT_ROLE_TOKEN_BUDGET.get(role, FALLBACK_ROLE_TOKEN_BUDGET)


def enforce_context_budget(text: str, role: str,
                           overrides: dict[str, int] | None = None) -> dict[str, Any]:
    """请求前闸门：返回估算记录；超额度抛 ContextBudgetExceeded。"""
    tokens = estimate_tokens(text)
    limit = role_token_budget(role, overrides)
    if tokens > limit:
        raise ContextBudgetExceeded(role, tokens, limit, len(text))
    return {"role": role, "estimated_tokens": tokens, "chars": len(text), "limit_tokens": limit}


def messages_chars(messages: Iterable[Any]) -> int:
    """完整 messages 的字符数（与 agent_base 请求日志的 input_chars 同口径）。"""
    return sum(len(json.dumps(message, ensure_ascii=False, default=str)) for message in messages)


def enforce_conversation_budget(messages: Iterable[Any], role: str,
                                overrides: dict[str, int] | None = None,
                                *, stage: str = "conversation") -> dict[str, Any]:
    """累计对话预算：每次发起请求前对**完整 messages**估算 token。

    工具循环里 messages 会持续累积；只有首轮经过 ``enforce_context_budget``
    不足以保证后续轮次有界（实测 21,701 字符的首轮提示词在工具循环中膨胀到
    400,331 字符并超时 800s）。这里使用与单次提示词相同的角色额度，不新增/
    不修改任何预算数值；超限时抛 ``ContextBudgetExceeded``，调用方必须在
    发送前停止工具循环并显式降级。
    """
    materialized = list(messages)
    chars = messages_chars(materialized)
    # 直接复用同一 CHARS_PER_TOKEN 口径，避免为 400k 长度构造字符串。
    tokens = max(1, math.ceil(chars / CHARS_PER_TOKEN)) if chars else 0
    limit = role_token_budget(role, overrides)
    if tokens > limit:
        raise ContextBudgetExceeded(role, tokens, limit, chars, stage=stage)
    return {"role": role, "estimated_tokens": tokens, "chars": chars, "limit_tokens": limit,
            "message_count": len(materialized), "stage": stage}


def bounded_ids(values: Iterable[Any], *, limit: int = DEFAULT_ID_RENDER_LIMIT,
                preferred: Iterable[Any] = ()) -> dict[str, Any]:
    """把可引用 ID 全集渲染成有界结构。

    `preferred`（本次报告已引用/与候选直接相关的 ID）优先出现，保证模型
    能核对承重证据；其余按字典序补齐到 `limit`。截断时显式标注总数，
    避免「没列出来 = 不存在」的误读。
    """
    uniq: dict[str, None] = {}
    for item in values:
        if item is not None:
            text = str(item)
            if text:
                uniq.setdefault(text, None)
    total = len(uniq)
    cap = max(0, limit)
    sample: list[str] = []
    seen: set[str] = set()

    def push(item: Any) -> None:
        if len(sample) >= cap:
            return
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            sample.append(text)

    for item in preferred:            # 承重证据优先，保证模型能核对本次引用的 ID
        push(item)
    for item in uniq:                 # 其余按快照插入序补齐（不排序：28.5 万条排序纯属浪费）
        if len(sample) >= cap:
            break
        push(item)
    return {
        "sample": sample,
        "total": total,
        "shown": len(sample),
        "truncated": len(sample) < total,
        "note": (f"注册证据 ID 全集共 {total} 条，此处仅列出 {len(sample)} 条（与本次候选/已引用"
                 " ID 优先）。工具真实返回的其他注册 ID 同样可以在引用字段中使用，"
                 "但 CVE 编号、URL、哈希不是证据 ID。"
                 if len(sample) < total else
                 f"注册证据 ID 全集共 {total} 条，已全部列出。"),
    }


def dumps_compact(value: Any, *, max_chars: int = 4000) -> str:
    """渲染任意值；超过 max_chars 时截断并标注原始长度（不静默丢内容）。"""
    text = json.dumps(value, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"…（已截断，原始 {len(text)} 字符）"
