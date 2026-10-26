"""唯一正式编排器：LangGraph StateGraph（Stage 9B）。

图结构（docs/architecture/overview.md）：

    START → prepare → prepare_evidence → investigate_asset
          → {analyze_vulnerability ∥ analyze_runtime}
          → detect_conflicts → [route: directed_rereview?] → decide
          → [route: execute_follow_ups?] → finalize → END

纪律：
- 节点是普通函数：确定性程序步骤（证据预取/冲突检测/审计门禁/聚合）与
  LLM 步骤同为节点；LLM 永不写最终分数/授权/执行权限；
- prepare_evidence 是确定性预取节点（非第五个 Agent）：一次性事实查询前置，
  Agent 只对歧义/冲突/缺口深查（M4.1 校准）；
- 路由跳过的角色由程序填充降级语义（unavailable/基线维持），不虚增风险；
- 并行分支各自持有线程独立 DB 会话（SQLite 会话不跨线程共享）；
- run 级预算（LLM 调用数/时限/补查轮数）由 UsageMeter 与 deadline 统一强制。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable

from langgraph.graph import END, START, StateGraph
from sqlalchemy.orm import Session

from app import models
from app.services import trace_service as tracing
from app.services.agent_infra import AgentSpec, ChatClient
from app.services.unified import (
    aggregator,
    audit_policy,
    conflicts as conflicts_mod,
    evidence_prep,
    routing as routing_mod,
    collaboration as collaboration_mod,
    collaboration_flow as collaboration_flow,
    harness_bridge,
)
from app.services.unified import context_budget
from app.services.unified.prompt_views import inventory_provenance as _inventory_prompt_view
from app.services.unified.agent_base import (
    BudgetExceeded,
    UnifiedToolLoopAgent,
    UsageMeter,
)
from app.services.unified.agents_def import (
    ASSET_INVESTIGATOR_SPEC,
    DECISION_PLANNER_SPEC,
    RUNTIME_ANALYST_SPEC,
    SPEC_BY_NAME,
    VULNERABILITY_ANALYST_SPEC,
)
from app.services.unified.schemas import (
    AGENT_ASSET,
    AGENT_DECISION,
    AGENT_RUNTIME,
    AGENT_VULNERABILITY,
    PIPELINE_VERSION,
    DecisionResponseReport,
)
from app.services.unified.state import (
    TASK_DEVICE_SURFACE,
    TASK_RISK_REVIEW,
    UnifiedAnalysisState,
)

ClientFactory = Callable[[], ChatClient]

FRESHNESS_HOURS = {"process": 24, "network": 24, "file": 168}

STAGE_TOPOLOGY = {
    "prepare": ["prepare_evidence"],
    "prepare_evidence": ["investigate_asset"],
    "investigate_asset": ["analyze_vulnerability", "analyze_runtime"],
    "analyze_vulnerability": ["detect_conflicts"],
    "analyze_runtime": ["detect_conflicts"],
    "detect_conflicts": ["directed_rereview?", "decide"],
    "directed_rereview": ["decide"],
    "decide": ["execute_follow_ups?", "finalize"],
    "execute_follow_ups": ["decide"],
    "finalize": [],
}


@dataclass
class RunContext:
    """一次编排运行的共享上下文（线程安全）。"""

    db_factory: Callable[[], Session]
    trace_id: str
    meter: UsageMeter = field(default_factory=UsageMeter)
    client_factory: ClientFactory | None = None
    risk: models.RiskAssessment | None = None
    packet_evidence_ids: set[str] = field(default_factory=set)
    force_full_review: bool = False
    run_deadline_s: float = 3600.0   # 与 BudgetState.run_deadline_s 同步（生成速度护栏）
    agent_logs: dict[str, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _started: float = field(default_factory=time.monotonic)
    persisted_stage: dict[str, str] = field(default_factory=dict)
    # 深度控制（测试可注入）；与 BudgetState.agent_deadline_s 同步——GLM-5.3
    # 等模型生成完整结构化报告单调用可超 120s，多轮工具+重试需要更长护栏
    agent_budget_s: float = 900.0
    # 语义消融（M4.2 实验专用，生产恒空）：被列入的角色报告不进入决策输入
    # （角色本身照常执行；这是「贡献度量」钩子，不是失败/降级路径）
    ablation_mask: frozenset[str] = frozenset()
    # Stage-10 效率：请求内确定性工具缓存（仅 CACHEABLE_TOOLS；随 run 生命周期
    # 创建销毁——新采集/官方重取属运行外操作员动作，跨时点事实不进入缓存）
    tool_cache: dict[str, Any] = field(default_factory=dict)
    # Stage-10 效率：各角色首次运行的完整上下文（定向复议继承，避免从零重建）
    first_contexts: dict[str, str] = field(default_factory=dict)
    # 上下文预算（估算 token/角色）：超额度显式降级，不发百万字符提示词换 400
    context_token_budgets: dict[str, int] = field(default_factory=dict)
    # 对照实验用策略（生产恒为 four_agents）。single_agent：只有决策角色调用模型，
    # 事实仍来自同一确定性预取，用于「四智能体 vs 单智能体」的同事实对照。
    strategy: str = "four_agents"
    replay_parent: dict[str, Any] = field(default_factory=dict)
    snapshot_id: str = ""
    batch_runtime: Any = None
    task_receipts: dict[str, Any] = field(default_factory=dict)

    def session(self) -> Session:
        return self.db_factory()

    def remaining_s(self) -> float:
        return self.run_deadline_s - (time.monotonic() - self._started)

    def log_agent(self, name: str, entry: dict[str, Any]) -> None:
        with self._lock:
            history = list(self.agent_logs.get(name, {}).get("executions", []))
            history.append({**entry, "execution": len(history) + 1})
            self.agent_logs[name] = {**entry, "executions": history,
                "total_latency_ms": sum(x.get("latency_ms", 0) for x in history),
                "total_llm_calls": sum(x.get("llm_calls", 0) for x in history)}

    def emit(self, db: Session, event_type: str, actor: str, status: str,
             payload: dict[str, Any] | None = None, **kwargs: Any) -> None:
        if not self.trace_id:
            return
        tracing.emit(db, self.trace_id, event_type, actor=actor, status=status,
                     payload=payload or {}, **kwargs)


# ── 通用专家执行（证据校验 + 一次反馈重试 + 降级语义） ────────────────────────


def _agent_deadline(ctx: RunContext, role: str = "") -> float:
    reserve = min(300.0, ctx.run_deadline_s * 0.25) if role and role != AGENT_DECISION else 0
    return max(0.0, min(ctx.agent_budget_s, ctx.remaining_s() - reserve))


def _run_specialist(ctx: RunContext, spec: AgentSpec, context_text: str,
                    validate_fn: Callable[[dict[str, Any]], list[str]] | None = None,
                    extra_instruction: str = "", state=None) -> tuple[dict[str, Any] | None, str]:
    if ctx.batch_runtime is not None and state is not None:
        from app.services.unified import task_reports
        spec = task_reports.scoped_spec(spec, state)
        task_deadline = time.monotonic() + min(240, _agent_deadline(ctx, spec.name), ctx.batch_runtime.remaining())
        return task_reports.execute(ctx, state, spec, context_text, validate_fn,
            lambda text, scoped, validator, task_id: _run_specialist_impl(
                ctx, spec, text, validator, extra_instruction, scoped, task_id, task_deadline),
            deadline=task_deadline)
    return _run_specialist_impl(ctx, spec, context_text, validate_fn, extra_instruction, state)


def _run_specialist_impl(ctx: RunContext, spec: AgentSpec, context_text: str,
                    validate_fn=None, extra_instruction="", state=None, task_id="", task_deadline=None):
    """执行一个专家：结构化输出 → 证据事实校验（一次带反馈重试）→ 失败降级。

    返回 (output_dict | None, degraded_reason)。None 表示该角色降级，
    其意见缺失但其余角色结果保留（F7：部分失败不全丢）。
    """
    db = ctx.session()
    try:
        if ctx.batch_runtime is not None and state is not None and spec.name == AGENT_RUNTIME:
            from app.services.unified.prompt_views import bind_runtime_snapshot
            bind_runtime_snapshot(db, state.evidence_snapshot)
            context_text += ("\n本轮取证工具限定在本次已登记快照；随后到达的新事件留到下一轮。"
                             "工具返回空或样例不含某行为，只表示本快照未取得该证据，不表示行为未发生。")
        if state is not None and state.evidence_snapshot:
            context_text += "\n共享协作状态：" + json.dumps(collaboration_mod.compact_context(
                spec.name, state.evidence_snapshot, state.shared_findings, state.collaboration_messages), ensure_ascii=False)
            original_validator = validate_fn
            def checked(output):
                errors = list(original_validator(output)) if original_validator else []
                errors.extend(collaboration_mod.validate_evidence_ids(
                    collaboration_mod.collect_evidence_ids(output), state.evidence_snapshot))
                _, message_errors = collaboration_mod.validate_messages(output.get("messages", []),
                    spec.name, state.evidence_snapshot, state.shared_findings)
                return errors + message_errors
            validate_fn = checked
        try:
            prompt_budget = context_budget.enforce_context_budget(
                context_text, spec.name, ctx.context_token_budgets)
        except context_budget.ContextBudgetExceeded as exc:
            # 请求前闸门：显式降级并把实测值写进原因，绝不把超限提示词发给模型
            # 换回 400（实测 7.2M 字符提示词的唯一结果就是浪费两次重试后降级）。
            ctx.emit(db, "context_budget_exceeded", actor=spec.name, status="failed",
                     payload={"reason": exc.as_reason()})
            ctx.log_agent(spec.name, {
                "status": "degraded", "attempts": 0, "latency_ms": 0,
                "error": exc.as_reason(), "llm_calls": 0, "llm_usage": {},
                "attempts_history": [], "stop_reason": exc.as_reason(),
                "requests": [], "output": None, "tool_calls": [],
                "feedback_history": [], "triaged_fields": [],
            })
            return None, exc.as_reason()
        started_at = models.utcnow()
        ctx.emit(db, "agent_started", actor=spec.name, status="running", is_llm_step=True,
                 payload={"agent": spec.name, "prompt_estimated_tokens": prompt_budget["estimated_tokens"],
                          "prompt_chars": prompt_budget["chars"]}, started_at=started_at)
        agent_started = time.monotonic()
        role_deadline = agent_started + _agent_deadline(ctx, spec.name)
        if task_deadline is not None:
            role_deadline = min(role_deadline, task_deadline)
        if ctx.batch_runtime is not None:
            spec = replace(spec, max_tool_rounds=2, llm_retries=0, finalize_on_tool_limit=True)
            context_text += ("\n本模式不开展消息循环，messages 请留空。若引用已有 finding_id，"
                             "只能使用共享区实际提供的 ID，不得自行命名。")
        def observer(kind, detail):
            # Observation only: no model text/arguments or graph writes. Each
            # callback owns its session; the HTTP worker never shares agent DB.
            try:
                with ctx.session() as observation_db:
                    ctx.emit(observation_db, kind, actor=spec.name, status="observed", payload=detail)
            except Exception:
                import logging
                logging.getLogger(__name__).warning("Agent activity persistence failed", exc_info=True)
        client = ctx.batch_runtime.client(task_id, spec.name, observer=observer,
            review_id=state.run_id if state is not None else "") if ctx.batch_runtime is not None else ctx.client_factory()
        normalizer = None
        if ctx.batch_runtime is not None and state is not None and spec.name == AGENT_RUNTIME:
            from app.services.unified.prompt_views import conservative_runtime_status
            normalizer = lambda report: conservative_runtime_status(report, state.evidence_snapshot)
        agent = UnifiedToolLoopAgent(spec, client, meter=ctx.meter,
                                     tool_cache=ctx.tool_cache, snapshot_id=ctx.snapshot_id,
                                     role=spec.name,
                                     tool_result_max_chars=4000 if ctx.batch_runtime is not None else 8000,
                                     observer=observer if ctx.batch_runtime is not None else None,
                                     output_normalizer=normalizer,
                                     collaboration_messages=ctx.batch_runtime is None,
                                     context_token_budgets=ctx.context_token_budgets)
        with ctx._lock:
            ctx.first_contexts.setdefault(spec.name, context_text)
        result = agent.run(db, context=context_text, deadline_s=max(0.0, role_deadline - time.monotonic()))
        degraded_reason = ""
        if result.status != "succeeded":
            degraded_reason = result.error or result.status
        elif validate_fn is not None:
            errors = validate_fn(result.output or {})
            if errors:
                # 一次带事实反馈的重试（继承 System A RUNTIME 阶段语义，F3 反馈）
                retry_context = (
                    f"{context_text}\n\n上一次输出未通过证据事实校验：{'; '.join(errors)}。"
                    "请只引用真实存在的 evidence_id，重新输出完整 JSON。"
                    "这是引用/事实纠错，不要重复已完成的工具调查；不能支持的结论必须降为证据不足。"
                    f"\n待纠正的原始报告：{json.dumps(result.output, ensure_ascii=False)}")
                ctx.emit(db, "evidence_validation_failed", actor=spec.name, status="failed",
                         payload={"errors": errors, "output_summary": _summary(result.output)})
                # Correct the supplied report without reopening the investigation.
                try:
                    context_budget.enforce_context_budget(
                        retry_context, spec.name, ctx.context_token_budgets)
                except context_budget.ContextBudgetExceeded as exc:
                    # 反馈重试会把原报告再塞回提示词：同样先过预算闸门。
                    degraded_reason = exc.as_reason()
                    ctx.emit(db, "context_budget_exceeded", actor=spec.name, status="failed",
                             payload={"reason": exc.as_reason(), "stage": "evidence_retry"})
                    retry = None
                else:
                    agent.spec = replace(spec, tools=[], llm_retries=0)
                    retry = agent.run(db, context=retry_context,
                                      deadline_s=max(0.0, min(role_deadline - time.monotonic(), ctx.remaining_s())))
                if retry is not None and retry.status != "succeeded":
                    degraded_reason = retry.error or retry.status
                if retry is not None and retry.status == "succeeded":
                    retry_errors = validate_fn(retry.output or {})
                    if not retry_errors:
                        result, errors = retry, []
                    else:
                        # 保留重试报告及其自身校验错误，交由统一降级处理。
                        result, errors = retry, retry_errors
                if errors:
                    # Removing an ID is not proof of the claim it supported.
                    # Keep the failed report in the audit trail and fail closed.
                    # 若重试本身没跑起来（上下文超预算），两个原因都要留在记录里。
                    detail = "; ".join(errors)
                    degraded_reason = (f"{degraded_reason}; {detail}" if degraded_reason
                                       else detail)
        elapsed_ms = int((time.monotonic() - agent_started) * 1000)
        # 事实校验未通过（degraded_reason 非空）时绝不放行原始输出——
        # 即使模型调用自身的 result.status 仍为 succeeded
        output = result.output if (result.status == "succeeded" and not degraded_reason) else None
        if output is not None and state is not None:
            from app.services.unified.selective_replay import ROLE_KEYS
            previous = getattr(state, ROLE_KEYS[spec.name], None)
            provenance = state.role_provenance.get(spec.name, {})
            if previous and provenance.get("snapshot_id") == state.evidence_snapshot_id:
                # Retain raw model output in agent_logs; effective confidence
                # cannot rise on a second interpretation of identical evidence.
                from copy import deepcopy
                output = deepcopy(output)
                def cap(current, prior):
                    if not isinstance(current, dict) or not isinstance(prior, dict):
                        return
                    if isinstance(current.get("confidence"), (int, float)) and isinstance(prior.get("confidence"), (int, float)):
                        current["confidence"] = min(current["confidence"], prior["confidence"])
                    for key, value in current.items():
                        if isinstance(value, dict):
                            cap(value, prior.get(key, {}))
                        elif isinstance(value, list) and key in {"findings", "verdicts"}:
                            old = prior.get(key, [])
                            for item in value:
                                if not isinstance(item, dict):
                                    continue
                                subject = item.get("cve_id") or item.get("object_id") or item.get("evidence_id")
                                match = next((x for x in old if isinstance(x, dict) and
                                    (x.get("cve_id") or x.get("object_id") or x.get("evidence_id")) == subject), {})
                                cap(item, match)
                cap(output, previous)
        ctx.log_agent(spec.name, {
            "status": result.status if not degraded_reason else "degraded",
            "attempts": result.attempts,
            "latency_ms": elapsed_ms,
            "error": (degraded_reason or result.error or "")[:800],
            "llm_calls": result.llm_calls,
            "llm_usage": result.llm_usage,
            # A3：同一角色每次 run 内的 _run_once attempt 明细（首轮 usage 不再
            # 被最后一次「预算已用尽、0 调用」覆盖）；最终字段仍以最后一次为主。
            "attempts_history": list(result.attempts_history),
            "stop_reason": result.stop_reason,
            "prompt_estimated_tokens": prompt_budget["estimated_tokens"],
            "prompt_chars": prompt_budget["chars"],
            "requests": list(agent.request_log),
            "normalized_reports": list(agent.normalized_reports),
            "output": result.output,
            "tool_calls": [{"name": call["name"], "ok": call.get("ok", False),
                            "cached": call.get("cached", False),
                            "arguments_hash": collaboration_mod.fingerprint(call.get("arguments", {}))}
                           for call in result.tool_calls],
            "feedback_history": result.feedback_history[:4],
            "triaged_fields": result.triaged_fields[:6],
        })
        refs: list[str] = list((output or {}).get("evidence_ids") or [])
        for finding in (output or {}).get("findings") or []:
            if isinstance(finding, dict):
                refs.extend(finding.get("supporting_evidence_ids") or [])
                if finding.get("cve_id"):
                    refs.append(str(finding["cve_id"]))
                if finding.get("evidence_id"):
                    refs.append(str(finding["evidence_id"]))
        def collect_refs(value):
            if isinstance(value, dict):
                for key, entry in value.items():
                    if key in {"supporting_evidence_ids", "evidence_ids"} and isinstance(entry, list):
                        refs.extend(str(ref) for ref in entry)
                    elif key == "evidence_id" and entry:
                        refs.append(str(entry))
                    else:
                        collect_refs(entry)
            elif isinstance(value, list):
                for entry in value:
                    collect_refs(entry)
        collect_refs(output)
        refs = list(dict.fromkeys(refs))
        ctx.emit(db, "agent_finished" if output is not None else "agent_failed",
                 actor=spec.name, status="succeeded" if output is not None else "failed",
                 is_llm_step=True,
                 payload={
                     "agent": spec.name,
                     "attempts": result.attempts,
                     "latency_ms": elapsed_ms,
                     "error": (degraded_reason or result.error or "")[:800],
                     "tool_calls": [{"name": c["name"], "ok": c.get("ok", False)}
                                    for c in result.tool_calls],
                     "output_summary": _summary(output),
                 },
                 evidence_refs=refs, duration_ms=elapsed_ms)
        return output, degraded_reason
    except BudgetExceeded as exc:
        return None, f"budget_exceeded: {exc}"
    finally:
        db.close()


def _bounded_registry_ids(state, ctx=None, preferred=()) -> dict[str, Any]:
    """可引用证据 ID 的有界渲染（全集留在服务端校验，不进提示词）。

    实测 run UA-20261020153207-617da0 的注册表有 284,748 条证据：把全集
    `json.dumps(sorted(...))` 进提示词会渲染成 7.2M 字符，模型侧必然 400。
    """
    values = collaboration_mod.evidence_registry_ids(state.evidence_snapshot)
    if ctx is not None:
        values |= set(getattr(ctx, "packet_evidence_ids", ()) or ())
    candidates = list(preferred) or list(state.baseline.get("packet_evidence_ids") or [])
    return context_budget.bounded_ids(
        values, preferred=candidates, limit=context_budget.DEFAULT_ID_RENDER_LIMIT)


def _summary(output: dict[str, Any] | None, limit: int = 12) -> dict[str, Any]:
    if not isinstance(output, dict):
        return {}
    summary: dict[str, Any] = {}
    for key, value in list(output.items())[:limit]:
        if isinstance(value, list):
            summary[key] = {"count": len(value), "sample": value[:3]}
        elif isinstance(value, dict):
            summary[key] = {"keys": list(value)[:8]}
        else:
            summary[key] = value
    return summary


# ── 节点实现 ─────────────────────────────────────────────────────────────────


def node_prepare(ctx: RunContext):
    def prepare(state: UnifiedAnalysisState) -> dict[str, Any]:
        db = ctx.session()
        try:
            risk = ctx.risk
            candidates = _candidate_context(db, state, risk)
            marks = _capability_marks(db, state)
            routing = routing_mod.decide_routing(
                db, state.task_type, state.target_ref, state.target_type,
                risk=risk, capability_marks=marks, candidates=candidates)
            if ctx.force_full_review:
                recommendation = routing.model_dump()
                routing.tier = "standard"
                routing.include_asset = routing.include_vulnerability = routing.include_runtime = routing.include_decision = True
                routing.skipped_agents = []
                routing.reason = "显式完整四角色研判；程序聚合与人审门禁独立执行"
                ctx.emit(db, "routing_recommendation", actor="orchestrator", status="succeeded",
                         payload={"recommended": recommendation, "applied": "full_review",
                                  "reason": "simplified_formal_path_requires_comparative_validation"})
            if ctx.strategy == "single_agent":
                routing.tier = "focused"
                routing.include_asset = routing.include_vulnerability = routing.include_runtime = False
                routing.include_decision = True
                routing.skipped_agents = [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_RUNTIME]
                routing.reason = ("single_agent_baseline：仅决策角色调用模型，"
                                  "事实来自同一确定性预取（对照实验，不用于正式入口）")
                ctx.emit(db, "routing_recommendation", actor="orchestrator", status="succeeded",
                         payload={"applied": "single_agent_baseline",
                                  "reason": routing.reason})
            baseline = _baseline_snapshot(db, state, risk, candidates)
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "prepare", "routing": routing.model_dump(),
                              "baseline": {k: baseline.get(k) for k in
                                           ("preliminary_score", "preliminary_level", "match_status")}})
            return {
                "routing": routing,
                "capability_marks": marks,
                "baseline": baseline,
                "candidate_context": candidates,
                "object_id": state.object_id or (f"risk-{risk.id}" if risk else state.target_ref),
                "stage_status": state.record_stage("prepare", "succeeded"),
            }
        finally:
            db.close()
    return prepare


def node_prepare_evidence(ctx: RunContext):
    """确定性证据预取节点（M4.1）：一次性事实查询前置，无 LLM、无裁量。

    失败不击穿图：预取失败时证据包置空，各角色退回自主工具查询（原行为），
    仅记录 stage_status=failed 与 error 留痕。
    """
    def prepare_evidence(state: UnifiedAnalysisState) -> dict[str, Any]:
        db = ctx.session()
        try:
            packet = evidence_prep.build_evidence_prep_packet(
                db, state.target_ref, state.target_type, state.candidate_context)
            collaboration_update = collaboration_flow.prepare(ctx, state, db, packet.model_dump())
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "prepare_evidence",
                              "as_of": packet.as_of,
                              "candidates": len(packet.candidates),
                              "runtime_freshness": (packet.runtime_facts or {}).get("freshness")})
            return {
                **collaboration_update,
                "evidence_prep": packet.model_dump(),
                "stage_status": state.record_stage("prepare_evidence", "succeeded"),
            }
        except Exception as exc:   # 预取是优化不是安全依赖：失败退回自主查询
            ctx.emit(db, "stage_finished", actor="orchestrator", status="failed",
                     payload={"stage": "prepare_evidence", "error": str(exc)[:300]})
            return {
                "evidence_prep": None,
                "error": f"evidence_prep failed (退回自主工具查询): {type(exc).__name__}: {exc}"[:400],
                "stage_status": state.record_stage("prepare_evidence", "failed"),
            }
        finally:
            db.close()
    return prepare_evidence


def _prep(state: UnifiedAnalysisState) -> dict[str, Any]:
    return state.evidence_prep or {}


def _prep_header(state: UnifiedAnalysisState) -> str:
    packet = _prep(state)
    if not packet:
        return ""
    notes = "；".join(packet.get("reuse_note") or [])
    return (f"\n【确定性预取事实（程序节点 {packet.get('as_of', '')} 取得，"
            f"运行内只读复用）】{notes}\n")


def _asset_prep_context(state: UnifiedAnalysisState) -> str:
    packet = _prep(state)
    facts = packet.get("asset_facts") or {}
    runtime = packet.get("runtime_facts") or {}
    if not facts and not runtime:
        return ""
    # 预取已含画像/暴露面/数据质量；角色只需对缺口与歧义深查
    return (
        f"{_prep_header(state)}"
        f"资产画像: {json.dumps(facts.get('profile') or {}, ensure_ascii=False)}\n"
        f"真实清单身份与原始证据: {json.dumps(_inventory_prompt_view(facts.get('inventory_provenance') or {}), ensure_ascii=False)}\n"
        f"服务暴露面: {json.dumps(facts.get('services') or [], ensure_ascii=False)}\n"
        f"组件清单(截断={facts.get('components_truncated')}): "
        f"{json.dumps((facts.get('components') or [])[:20], ensure_ascii=False)}\n"
        f"运行时数据质量(as_of={runtime.get('as_of', '')}): "
        f"{json.dumps({'coverage': runtime.get('coverage'), 'freshness': runtime.get('freshness')}, ensure_ascii=False)}\n"
        "以上基础事实已由程序核实；只有当事实存在缺口、歧义或与你需要核验的细节"
        "（如逐条证据内容、进程树、具体端口行为）相关时才调用专属工具深查，"
        "不要重复查询已提供的基础事实。evidence_inventory 可直接引用上述数据质量事实。"
    )


def _vulnerability_prep_context(state: UnifiedAnalysisState) -> str:
    packet = _prep(state)
    candidates = packet.get("candidates") or []
    if not candidates:
        return ""
    lines = [_prep_header(state)]
    for item in candidates:
        lines.append(json.dumps({
            "cve_id": item.get("cve_id"),
            "package_name": item.get("package_name"),
            "installed_version": item.get("installed_version"),
            "fixed_version": item.get("fixed_version"),
            "match_status": item.get("match_status"),
            "reason_code": item.get("reason_code"),
            "match_reason": item.get("match_reason"),
            "version_compare": item.get("version_compare"),
            "branch_check": item.get("branch_check"),
            "vendor_conflict": item.get("vendor_conflict"),
            "vendor_patch": item.get("vendor_patch"),
            "urgency_amplifiers": item.get("urgency_amplifiers"),
            "intel_summary": item.get("intel_summary"),
            "source_bundle": item.get("source_bundle"),
        }, ensure_ascii=False))
    lines.append(
        "以上版本比较/分支声明/厂商补丁语义/多源状态均为程序确定性核验结果："
        "分支排除声明（branch_check=branch_excluded/below_stated_affected_range）、"
        "已修复判定（version_compare=fixed）与厂商精确公告的 not_affected 声明"
        "（vendor_patch.release_status，含 backport）不得被通用候选匹配推翻；"
        "厂商适用性冲突（vendor_conflict.unresolved）在消解前不得判 confirmed_affected。"
        "version_compare 出现 caveat 时表示上游口径与厂商 release 口径相左——"
        "以厂商口径优先，并在 rationale 说明 backport 语义。"
        "OpenWrt 官方范围必须按 scope 对应的固件/release、branch 或 commit 域解释，"
        "不可用普通包版本比较覆盖官方结论；main 分支无 fix 且有 ~commit 时 affected、"
        "fixed_version 为空是合法结论，不得捏造修复版本，须保留 match_reason 中的原因。"
        "只有对上述事实存在疑问或需要补齐缺口时才调用专属工具深查。"
    )
    return "\n".join(lines)


def _runtime_prep_context(state: UnifiedAnalysisState) -> str:
    packet = _prep(state)
    runtime = packet.get("runtime_facts") or {}
    if not runtime:
        return ""
    quality_view = json.dumps({"coverage": runtime.get("coverage"),
                               "freshness": runtime.get("freshness"),
                               "data_gaps": runtime.get("data_gaps")}, ensure_ascii=False)
    return (
        f"{_prep_header(state)}"
        f"运行时数据质量(as_of={runtime.get('as_of', '')}): {quality_view}\n"
        "新鲜度/覆盖/心跳事实已按当前时间由程序重算；你仍需用专属工具深查具体行为"
        "证据（进程/网络/文件/进程树）后才能给出行为等级，不得仅凭本摘要下 ACTIVE/SUSPICIOUS 结论。"
    )


def _runtime_freshness_of(state: UnifiedAnalysisState) -> str:
    """运行时证据新鲜度：优先运行时分析师结论，缺省回退预取事实。"""
    runtime = state.runtime or {}
    freshness = str(runtime.get("evidence_freshness") or "")
    if freshness:
        return freshness
    packet_freshness = ((_prep(state).get("runtime_facts") or {}).get("freshness") or {})
    buckets = {view.get("freshness") for view in packet_freshness.values()
               if isinstance(view, dict)}
    if "fresh" in buckets:
        return "fresh"
    if buckets and buckets != {"no_evidence"}:
        return "stale"
    return "none" if not buckets else "no_evidence"


def _candidate_context(db: Session, state: UnifiedAnalysisState,
                       risk: models.RiskAssessment | None) -> list[dict[str, Any]]:
    """漏洞分析师的候选清单（规则命中，只读；不含规则分数——防锚定）。"""
    if risk is not None:
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        current = db.query(models.AssetPackage).filter_by(asset_id=risk.asset_id, package_name=risk.package_name).first()
        return [{
            "cve_id": risk.cve_id,
            "package_name": risk.package_name,
            "installed_version": current.package_version if current else (match.installed_version if match else ""),
            "historical_installed_version": match.installed_version if match else "",
            "fixed_version": match.fixed_version if match else "",
            "match_status": match.match_status if match else risk.affected_status,
            "reason_code": match.reason_code if match else "",
            "match_reason": match.match_reason if match else "",
        }]
    return [dict(item) for item in state.candidate_context]


def _capability_marks(db: Session, state: UnifiedAnalysisState) -> dict[str, Any]:
    if state.capability_marks:
        return state.capability_marks
    if state.target_type != "device":
        return {}
    device = db.query(models.IotDevice).filter_by(device_id=state.target_ref).one_or_none()
    if device is None:
        return {}
    from app.services.discovery_pipeline import _capability_marks as compute
    return compute(device) or {}


def _baseline_snapshot(db: Session, state: UnifiedAnalysisState,
                       risk: models.RiskAssessment | None,
                       candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """规则基线（只读引用）。risk_review 事件含 packet 证据 ID 全集供防幻觉校验。"""
    if risk is not None:
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        asset = db.get(models.LinuxAsset, risk.asset_id)
        packet_ids: set[str] = set()
        try:
            payload = json.loads(risk.evidence_packet_json or "{}")
            for item in payload.get("evidence_items") or []:
                if isinstance(item, dict) and item.get("evidence_id"):
                    packet_ids.add(str(item["evidence_id"]))
        except ValueError:
            pass
        return {
            "object_id": f"risk-{risk.id}",
            "preliminary_score": risk.preliminary_score,
            "preliminary_level": risk.preliminary_level,
            "preliminary_decision": risk.preliminary_decision,
            "preliminary_reason": risk.preliminary_reason,
            "match_status": match.match_status if match else risk.affected_status,
            "installed_version": match.installed_version if match else risk.package_name and "",
            "fixed_version": match.fixed_version if match else "",
            "package_name": risk.package_name,
            "cve_id": risk.cve_id,
            "business_level": asset.business_level if asset else "",
            # 已人工复核的结论必须进入门禁输入：改判它需要人工确认，
            # 否则「与已签收结论相反」的裁定会被 auto_confirmed（实测 risk 272）。
            "review_status": risk.review_status or "",
            "review_verdict": risk.review_verdict or "",
            "packet_evidence_ids": sorted(packet_ids),
        }
    # 没有绑定风险时不得把调用方已持有的基线清空：程序取不到的字段留空，
    # 已有基线保留——否则冲突检测与审计门禁会静默退化成「无基线」。
    snapshot = {
        "object_id": state.target_ref,
        "preliminary_score": None,
        "preliminary_level": "",
        "match_status": "",
        "installed_version": "",
        "fixed_version": "",
        "packet_evidence_ids": [],
    }
    previous = state.baseline or {}
    for key, value in previous.items():
        if key == "packet_evidence_ids":
            continue
        if snapshot.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
            snapshot[key] = value
    snapshot["packet_evidence_ids"] = sorted(
        set(previous.get("packet_evidence_ids") or []) | set(snapshot["packet_evidence_ids"]))
    return snapshot


def node_investigate_asset(ctx: RunContext):
    def investigate_asset(state: UnifiedAnalysisState) -> dict[str, Any]:
        reuse = collaboration_flow.reused(ctx, state, AGENT_ASSET, "investigate_asset")
        if reuse is not None:
            return reuse
        if not state.routing.include_asset:
            return {"stage_status": state.record_stage("investigate_asset", "skipped")}
        context_text = (
            f"调查目标资产: {state.target_ref}（类型 {state.target_type}）。\n"
            f"业务调查问题: {state.investigation_goal}\n"
            f"本次候选包（完整清单截断时仍须逐一调查）: {json.dumps(state.candidate_context, ensure_ascii=False)}\n"
            "优先使用程序预取的真实画像、暴露面与运行时数据质量；仅对缺失或冲突信息调用工具。\n"
            "evidence_inventory 必须来自预取质量包或 query_runtime_data_quality 的真实返回；"
            "evidence_quality 按覆盖/新鲜度/缺口如实评级。\n"
            "证据分级纪律（M4.2）：结论必须区分三个等级并分别落到对应字段——\n"
            "- verified_facts：当前运行内由工具真实返回且来源明确的事实（标注 source）；\n"
            "- unverified_observations：来源不明确/单一来源/未经交叉核实的数据（标注 reason，"
            "如清单不完整的资产上「包未列出」不能直接当作「包不存在」）；\n"
            "- conflicting_facts：来源之间互相矛盾的事实（列出双方来源）。\n"
            "不得把未核实数据写进 verified_facts；清单不完整（inventory_complete=false）时"
            "必须在 missing_evidence 声明，不得把「没看到」当成「不存在」。"
            + _asset_prep_context(state)
        )
        output, degraded = _run_specialist(ctx, ASSET_INVESTIGATOR_SPEC, context_text, state=state)
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "investigate_asset", "failed" if degraded else "succeeded")}
        if output is not None:
            update["investigation"] = output
            update.update(collaboration_flow.publish(ctx, state, AGENT_ASSET, output))
        else:
            update["degraded_roles"] = state.degraded_roles + [AGENT_ASSET]
            update["error"] = degraded
        return update
    return investigate_asset


def _runtime_evidence_validator(ctx: RunContext, state=None):
    def validate(output: dict[str, Any]) -> list[str]:
        db = ctx.session()
        try:
            errors: list[str] = []
            ids = set(output.get("evidence_ids") or [])
            ids.update(f.get("evidence_id") for f in output.get("findings", []) if f.get("evidence_id"))
            if state is not None and state.evidence_snapshot:
                errors.extend(collaboration_mod.validate_evidence_ids(ids, state.evidence_snapshot, kinds={"runtime"}))
            level = output.get("behavior_level")
            if level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and not ids:
                errors.append(f"{level} 结论没有任何 evidence_id")
            if ids:
                existing = {
                    row.evidence_id
                    for row in db.query(models.SecurityEvidence)
                    .filter(models.SecurityEvidence.evidence_id.in_(ids)).all()
                }
                fabricated = sorted(ids - existing)
                if fabricated:
                    errors.append(f"引用了不存在的 evidence_id: {fabricated[:5]}")
            return errors
        finally:
            db.close()
    return validate


def _vulnerability_evidence_validator(ctx: RunContext, state=None):
    def validate(output: dict[str, Any]) -> list[str]:
        known = set(ctx.packet_evidence_ids)
        errors: list[str] = []
        candidates = ((state.evidence_prep or {}).get("candidates") or []) if state else []
        for candidate in candidates:
            if (candidate.get("vendor_patch") or {}).get("release_status") != "not_affected":
                continue
            for finding in output.get("findings") or []:
                if finding.get("cve_id", "").split(":")[0] == candidate.get("cve_id", "").split(":")[0]:
                    if finding.get("fixed_version") or finding.get("version_impact") == "fixed":
                        errors.append("精确官方 not_affected：无本 CVE 专属修复版本；不得将综合 USN 版本解释为该 CVE 已修复")
        cited: set[str] = set()
        for finding in output.get("findings") or []:
            if isinstance(finding, dict):
                cited.update(finding.get("supporting_evidence_ids") or [])
        unknown = sorted(cited - known)
        # A source can refresh while the run is active. Accept an actual stored
        # official snapshot only for this run's candidate CVE; fabricated and
        # unrelated official IDs remain rejected.
        if unknown and ctx.risk is not None and not (state and state.evidence_snapshot):
            db = ctx.session()
            try:
                actual = {row.evidence_id for row in db.query(models.OfficialCveRecord).filter(
                    models.OfficialCveRecord.evidence_id.in_(unknown),
                    models.OfficialCveRecord.cve_id == ctx.risk.cve_id.split(":")[0],
                    models.OfficialCveRecord.evidence_status == "available").all()}
                unknown = sorted(set(unknown) - actual)
            finally:
                db.close()
        if unknown:
            errors.append(f"引用了证据包之外的分析师自造证据 ID（防幻觉校验失败）: {unknown}; "
                          f"可引用的注册证据 ID: {sorted(known)}。CVE/GHSA 编号、URL 和哈希是来源属性，不是 evidence_id")
        return errors
    return validate


def node_analyze_vulnerability(ctx: RunContext):
    def analyze_vulnerability(state: UnifiedAnalysisState) -> dict[str, Any]:
        reuse = collaboration_flow.reused(ctx, state, AGENT_VULNERABILITY, "analyze_vulnerability")
        if reuse is not None:
            return reuse
        if not state.routing.include_vulnerability:
            return {"stage_status": state.record_stage("analyze_vulnerability", "skipped")}
        asset_summary = ""
        if state.investigation:
            investigation = state.investigation
            asset_summary = (
                f"\n资产画像摘要（来自资产调查员）: device_type={investigation.get('device_type')} "
                f"firmware={investigation.get('firmware_version')} "
                f"os={investigation.get('os')} 组件数={len(investigation.get('components') or [])} "
                f"证据质量={investigation.get('evidence_quality')}\n"
                f"已调查组件及版本（最多20项，非完整性证明）: {json.dumps((investigation.get('components') or [])[:20], ensure_ascii=False)}\n"
                f"原始清单来源: {json.dumps(_inventory_prompt_view(((_prep(state).get('asset_facts') or {}).get('inventory_provenance') or {})), ensure_ascii=False)}\n"
                "候选为空仅表示现有匹配范围内零命中，不得虚构 CVE，亦不得将画像显示截断误认为原始清单不完整。")
        context_text = (
            f"分析目标: {state.target_ref} 的候选 CVE 适用性。\n"
            f"本次调查与补证上下文: {state.investigation_goal}\n"
            f"候选清单（规则命中，供核查——规则结论本身可能误报）:\n"
            f"{json.dumps(state.candidate_context, ensure_ascii=False)}"
            f"{asset_summary}\n"
            "要求：优先使用下方程序预取的版本核验与多源情报，核对厂商/NVD/KEV/EPSS 各源状态。"
            "只有缺项、来源冲突或版本语义歧义时才调用 query_version_impact / query_intelligence_sources；"
            "已取得的相同事实不重复查询。输入故意不包含规则分数，不要猜测基线结论；"
            "适用分支与装机版本不符时明确判 not_affected 并说明理由（E3 类假阳性识别）。\n"
            "适用性专业维度（M4.2，逐 finding 如实填写，不得留 unknown 而给出高置信结论）：\n"
            "- version_range_relation：装机版本与公告受影响区间的关系（区间语义独立于"
            " fixed_version 单点比较——低于区间下界同样不受影响）；\n"
            "- branch_relation：装机发行分支与公告作用分支是否一致；\n"
            "- patch_semantics：厂商补丁与 backport 语义——发行版把上游修复回移植进"
            "历史版本时，「装机版本 < 上游修复版本」不等于受影响（厂商精确公告优先）；\n"
            "- advisory_specificity：本结论依据的是厂商精确公告（release 作用域）还是"
            " NVD 通用候选匹配——两者矛盾时厂商精确公告优先，但必须在 "
            "intelligence_conflicts 如实记录。\n"
            "applicability 只能为 confirmed_affected / potentially_affected / not_affected / insufficient_evidence。"
            "fixed 仅属于 version_impact，不能当作 applicability 枚举。官方精确发行版、源包、版本和授权清单"
            "足够时可确认静态受影响；触发条件与实际利用另外表达，缺少利用痕迹不否定静态适用性。"
            "branch_check 未定或冲突必须保留，不能通过提高置信度消除分歧。"
            f"\n可引用的注册证据 ID：{context_budget.dumps_compact(_bounded_registry_ids(state, ctx), max_chars=6000)}\n"
            "CVE/GHSA 编号、URL、SHA256 不是注册证据 ID；写入 rationale 说明来源，不能放进引用字段。"
            "没有注册证据时引用列表留空并明确证据缺口，禁止自造引用。"
            + _vulnerability_prep_context(state)
        )
        output, degraded = _run_specialist(ctx, VULNERABILITY_ANALYST_SPEC, context_text,
                                           validate_fn=_vulnerability_evidence_validator(ctx, state), state=state)
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "analyze_vulnerability", "failed" if degraded else "succeeded")}
        if output is not None:
            update["vulnerability"] = output
            update.update(collaboration_flow.publish(ctx, state, AGENT_VULNERABILITY, output))
        else:
            update["degraded_roles"] = state.degraded_roles + [AGENT_VULNERABILITY]
            update["error"] = degraded
        return update
    return analyze_vulnerability


def node_analyze_runtime(ctx: RunContext):
    def analyze_runtime(state: UnifiedAnalysisState) -> dict[str, Any]:
        reuse = collaboration_flow.reused(ctx, state, AGENT_RUNTIME, "analyze_runtime")
        if reuse is not None:
            return reuse
        routing = state.routing
        if ctx.batch_runtime is not None:
            runtime_facts = (state.evidence_prep or {}).get("runtime_facts") or {}
            categories = (state.evidence_snapshot.get("categories") or {}).get("runtime") or {}
            if not categories.get("events"):
                return {"runtime_program_fallback": {
                    "behavior_level": "NORMAL", "runtime_status": "unavailable",
                    "capability_limited": True, "evidence_freshness": "none",
                    "exploitation_relation": "monitoring_unavailable", "evidence_ids": [], "findings": [],
                    "coverage": runtime_facts.get("coverage"),
                    "note": "当前快照没有可逐条核验的运行时证据；历史汇总和采集缺口不代表安全"},
                    "stage_status": state.record_stage("analyze_runtime", "skipped")}
        if not routing.include_runtime:
            capability_limited = routing_mod._runtime_capability_unsupported(state.capability_marks)
            fallback = {
                "behavior_level": "NORMAL",
                "runtime_status": "unavailable" if capability_limited else "waiting",
                "capability_limited": capability_limited,
                "evidence_freshness": "none",
                "evidence_ids": [],
                "findings": [],
                "note": ("目标能力边界：无 eBPF 运行时观测（unavailable≠未观察到）"
                         if capability_limited else
                         "目标无运行时证据源；未接入采集，不能解释为安全"),
            }
            return {"runtime_program_fallback": fallback,
                    "stage_status": state.record_stage("analyze_runtime", "skipped")}
        watched = sorted({item.get("package_name", "") for item in state.candidate_context
                          if isinstance(item, dict) and item.get("package_name")})
        inventory_note = ""
        if state.investigation:
            inventory = state.investigation.get("evidence_inventory") or {}
            inventory_note = (f"\n证据盘点（来自资产调查员）: presence={inventory.get('runtime_evidence_present')} "
                              f"freshness={inventory.get('evidence_freshness')} "
                              f"coverage={inventory.get('coverage_status')}")
        context_text = (
            f"分析目标: {state.target_ref} 的运行时行为与证据质量。"
            f"本次调查与补证上下文: {state.investigation_goal}\n"
            f"关注软件包: {watched or '（无特定包，观察整体行为链）'}"
            f"{inventory_note}\n"
            "要求：用多标识键查询（device_id/IP/主机名均可）；引用 evidence_id 必须来自工具真实返回；"
            "先看 query_runtime_data_quality 再判定——证据全部过期时用 stale_verified，"
            "能力不支持用 unavailable；包活动不等于漏洞被利用。\n"
            "动态证据关联语义（M4.2，逐 finding 与报告级结论都必须区分）：\n"
            "- relation（逐条证据）：component_present（组件进程存在）/service_active（服务活跃）/"
            "attack_precondition（攻击前置条件具备，如暴露端口）/suspicious_behavior（可疑行为）/"
            "cve_related_evidence（与候选 CVE 攻击模式直接相关）/confirmed_exploitation"
            "（已确认利用）/unrelated（与候选无关）；每条 finding 必须写 observed_at"
            "（真实时间戳）与 source_quality；\n"
            "- exploitation_relation（报告级总结）：整体动态证据与候选 CVE 的关联程度——"
            "「可疑但与该 CVE 无关」是 suspicious_unlinked 不是 cve_related_evidence；"
            "「组件在跑」是 service_active/component_present 不是利用证据。\n"
            "两条铁律：运行时异常不得直接解释为该 CVE 已被利用（confirmed_exploitation 需要"
            "与攻击模式直接匹配的证据链）；缺少运行时事件不得解释为漏洞不存在——"
            "监控缺失/能力受限时如实标注 monitoring_missing/monitoring_unavailable。"
            + _runtime_prep_context(state)
        )
        if ctx.batch_runtime is not None:
            from app.services.unified.prompt_views import runtime_observations
            from app.services.unified.agent_base import bounded_tool_result
            with ctx.session() as evidence_db:
                observations = runtime_observations(evidence_db, state.evidence_snapshot)
            context_text += ("\n程序已查询本快照的真实逐条证据（含原时间与注册ID）："
                + bounded_tool_result(observations, max_chars=6000)
                + "\n上面已提供数据质量与原始行为，无需再次查询相同事实。"
                  "可以直接生成最终报告；仅有具体缺口需要核查时使用工具。"
                  "样例不覆盖全量，不能据此宣告设备安全或不存在利用。")
        output, degraded = _run_specialist(ctx, RUNTIME_ANALYST_SPEC, context_text,
                                           validate_fn=_runtime_evidence_validator(ctx, state), state=state)
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "analyze_runtime", "failed" if degraded else "succeeded")}
        if output is not None:
            update["runtime"] = output
            update.update(collaboration_flow.publish(ctx, state, AGENT_RUNTIME, output))
        else:
            update["degraded_roles"] = state.degraded_roles + [AGENT_RUNTIME]
            update["runtime_program_fallback"] = {
                "behavior_level": "NORMAL", "runtime_status": "waiting",
                "capability_limited": False, "evidence_freshness": "none",
                "note": f"运行时分析师失败，按无证据处理（不升级风险）: {degraded[:200]}"}
            update["error"] = degraded
        return update
    return analyze_runtime


def node_detect_conflicts(ctx: RunContext):
    def detect_conflicts(state: UnifiedAnalysisState) -> dict[str, Any]:
        snapshot = state.model_dump()
        conflict = conflicts_mod.detect_conflicts(snapshot)
        db = ctx.session()
        try:
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "detect_conflicts", "conflicts": conflict.model_dump()})
        finally:
            db.close()
        return {"conflict_result": conflict,
                "stage_status": state.record_stage("detect_conflicts", "succeeded")}
    return detect_conflicts


def _route_after_conflicts(state: UnifiedAnalysisState) -> str:
    if collaboration_flow.inbox(state) and state.collaboration_rounds < state.budgets.message_rounds:
        return "exchange_messages"
    if (state.conflict_result.has_major_conflict
            and any(item.category in {"fact_version", "substantive_judgment"} for item in state.conflict_result.conflicts)
            and state.rereview_used < state.budgets.rereview_rounds):
        return "directed_rereview"
    return "decide"


def _is_empty_default(output: dict[str, Any] | None) -> bool:
    """空默认输出（{}通过全部默认值校验）不能覆盖既有结论。"""
    if not output:
        return True
    has_content = (
        output.get("findings")
        or output.get("evidence_ids")
        or output.get("verdicts")
        or output.get("notes")
        or output.get("data_gaps")
        or output.get("missing_evidence")
        or output.get("intelligence_conflicts")
    )
    return not has_content


def node_directed_rereview(ctx: RunContext):
    def directed_rereview(state: UnifiedAnalysisState) -> dict[str, Any]:
        involved = sorted({agent for item in state.conflict_result.conflicts if item.category in {"fact_version", "substantive_judgment"}
                           for agent in item.involved_agents})
        descriptions = [item.description for item in state.conflict_result.conflicts]
        update: dict[str, Any] = {
            "rereview_used": state.rereview_used + 1,
            "stage_status": state.record_stage("directed_rereview", "succeeded"),
        }
        degraded = list(state.degraded_roles)
        spec_map = {
            AGENT_VULNERABILITY: (VULNERABILITY_ANALYST_SPEC, state.vulnerability,
                                  _vulnerability_evidence_validator(ctx, state)),
            AGENT_RUNTIME: (RUNTIME_ANALYST_SPEC, state.runtime,
                            _runtime_evidence_validator(ctx, state)),
            AGENT_ASSET: (ASSET_INVESTIGATOR_SPEC, state.investigation, None),
        }
        for name in involved:
            if name not in spec_map:
                continue
            spec, previous, validator = spec_map[name]
            # Stage-10 效率契约：定向复议继承该角色首次运行的完整上下文（含预取
            # 事实/候选清单/工具指引），不再只给冲突描述——从零重建上下文曾导致
            # 复议角色耗时翻倍且以校验失败告终。复议只处理冲突点，维持原结论
            # 时须给出更强的证据理由。
            original_context = ctx.first_contexts.get(name, "")
            context_text = (
                f"{original_context}"
                f"\n\n【定向复议（仅此一次）】针对以下已识别冲突进行核对：\n"
                f"{json.dumps(descriptions, ensure_ascii=False)}\n"
                f"你此前的结论: {json.dumps(previous, ensure_ascii=False)[:2000]}\n"
                "只需依据已提供的事实与必要的专属工具核对上述冲突点；"
                "如维持原结论，请给出更强的证据理由；如需修改，仅修改与冲突相关的字段。"
                "仍须输出完整结构化结果。"
            )
            output, degraded_reason = _run_specialist(ctx, spec, context_text,
                                                      validate_fn=validator, state=state)
            key = {AGENT_VULNERABILITY: "vulnerability",
                   AGENT_RUNTIME: "runtime",
                   AGENT_ASSET: "investigation"}[name]
            if output is None:
                # 复议执行失败必须记录降级；保留原有效报告，不伪造本轮成功。
                degraded.append(name)
                if not _is_empty_default(previous):
                    ctx.log_agent(spec.name + "_rereview", {
                        "status": "failed_kept_original",
                        "note": "复议失败：保留原结论；未消解冲突走人工复核",
                        "error": (degraded_reason or "")[:400]})
            elif _is_empty_default(output) and not _is_empty_default(previous):
                # 复议产出为空默认值时不得覆盖既有丰富结论（保留原意见）
                ctx.log_agent(spec.name + "_rereview", {
                    "status": "discarded_empty_rereview", "note": "复议输出为空默认值，保留原结论"})
            else:
                update[key] = output
                published = collaboration_flow.publish(ctx, state, name, output)
                for field in ("shared_findings", "collaboration_messages"):
                    update[field] = collaboration_mod.merge_immutable(update.get(field, []), published[field])
                update.setdefault("role_provenance", {}).update(published["role_provenance"])
                update.setdefault("message_receipts", {}).update(published["message_receipts"])
        update["degraded_roles"] = degraded
        refreshed = conflicts_mod.merge_rereview(state.conflict_result, {
            **state.model_dump(), **update})
        update["conflict_result"] = refreshed
        return update
    return directed_rereview


def _route_after_decide(state: UnifiedAnalysisState) -> str:
    return "harness_precheck"


def _route_after_precheck(state: UnifiedAnalysisState) -> str:
    feedback = state.harness_feedback
    if feedback.get("terminal"):
        return "finalize"
    if (feedback.get("status") not in {"executable", "authorization_required", "no_action"}
            and state.candidate_intents and state.plan_feedback_used < state.budgets.plan_feedback_rounds):
        return "plan_feedback"
    if collaboration_flow.inbox(state) and state.collaboration_rounds < state.budgets.message_rounds:
        return "exchange_messages"
    decision = state.decision or {}
    requests = decision.get("follow_up_requests") or []
    # Stage-10 效率契约：inventory 类补查申请是操作员门控采集——本轮内新证据
    # 为空是确定性事实。若全部申请都属于该类，重跑执行与完整决策只会原样复读
    # （基线运行曾因此多花约 5 分钟与数万 token）；申请仍由 finalize 登记。
    # 针对既有证据的定向复查（target_agent / database）保留原路径——它们能
    # 产生本轮内可核验的新视图。
    only_operator_gated = bool(requests) and all(
        isinstance(request, dict) and request.get("collection_capability") == "inventory"
        for request in requests)
    if requests and not only_operator_gated and state.follow_ups_used < state.budgets.follow_up_rounds:
        return "execute_follow_ups"
    return "finalize"


def _route_after_follow_ups(state: UnifiedAnalysisState) -> str:
    # A failed, deferred or identical investigation cannot justify another full decision.
    return "decide" if any(item.get("output") and item.get("changed", True)
                           for item in state.follow_up_results) else "finalize"


def node_decide(ctx: RunContext):
    def decide(state: UnifiedAnalysisState) -> dict[str, Any]:
        reuse = collaboration_flow.reused(ctx, state, AGENT_DECISION, "decide")
        if reuse is not None:
            return reuse
        with ctx.session() as db:
            capabilities = harness_bridge.query_capabilities(db, state)
        facts = _deterministic_facts(state)
        # 语义消融（实验专用）：被屏蔽角色的报告不进入决策输入——角色照常执行，
        # 决策端按「该维度信息缺失」研判，用于度量各角色的独立分析贡献
        masked = sorted(ctx.ablation_mask)
        asset_report = None if AGENT_ASSET in ctx.ablation_mask else state.investigation
        vulnerability_report = (None if AGENT_VULNERABILITY in ctx.ablation_mask
                                else state.vulnerability)
        runtime_report = (None if AGENT_RUNTIME in ctx.ablation_mask
                          else (state.runtime or state.runtime_program_fallback))
        registry_ids = _bounded_registry_ids(state, ctx, preferred=_decision_known_ids(state))
        decision_context = {
            "object_id": state.object_id,
            "task_type": state.task_type,
            "baseline": {k: v for k, v in state.baseline.items()
                         if k not in {"packet_evidence_ids"}},
            "asset_report": collaboration_flow.compact_report(asset_report),
            "vulnerability_report": collaboration_flow.compact_report(vulnerability_report),
            "runtime_report": collaboration_flow.compact_report(runtime_report),
            "harness_capabilities": capabilities,
            "harness_feedback": state.harness_feedback,
            "runtime_report_is_program_fallback": state.runtime is None,
            "conflict_result": state.conflict_result.model_dump(),
            "degraded_roles": state.degraded_roles,
            "capability_marks": state.capability_marks,
            # M4.1：确定性核验事实（分支适用性/版本比较/厂商冲突/运行时新鲜度）。
            # 这些是程序核验结果，模型不得凭一般性推理推翻（约束见下方要求）。
            "deterministic_facts": facts,
            "follow_up_results": state.follow_up_results or None,
            "follow_up_round_used": state.follow_ups_used,
            # 防幻觉：可引用证据 ID 的有界渲染（全集仅用于服务端校验，不进提示词——
            # 实测把 28.5 万条 ID 全量序列化会产出 7.15M 字符提示词，模型侧直接 400）。
            # 仍然保持"顶层是数组"的形状，避免破坏既有消费方（检测器正则、离线脚本）。
            "available_evidence_ids": registry_ids["sample"],
            "available_evidence_ids_total": registry_ids["total"],
            "available_evidence_ids_note": registry_ids["note"],
        }
        if masked:
            decision_context["semantic_ablation_masked"] = masked
        context_text = (
            "综合以下结构化材料完成研判与处置规划。\n"
            "Harness 能力是当前执行约束；policy_denied 不得重试绕过。缺产物、依赖或恢复点时调整为补证/人工处置，"
            "不要重复不可执行计划。metadata dry-run 不代表现场依赖已验证，更不代表批准。\n"
            f"{json.dumps(decision_context, ensure_ascii=False, default=str)}\n"
            "要求：\n"
            "采集能力约束：unavailable 不等于服务故障；不得承诺通过重启获得采集器不支持的指标。"
            "logread 环形日志的历史丢失量可能不可知，验证条件应保留 unavailable 和能力缺口，"
            "不能要求重启后 dropped_events 必须变为数值。不要重复已完成调查。\n"
            "1. impact_status/risk_direction/recommended_action 只能取 schema 枚举；"
            "available_evidence_ids 是本次可引用注册 ID 的有界样例，"
            "available_evidence_ids_total 是注册表全集条数（截断不等于不存在）；"
            "supporting_evidence_ids 只能引用**已注册**的证据 ID（样例之外、由工具真实返回的"
            "注册 ID 同样有效；CVE 编号、版本号、URL、哈希、主机名都不是证据 ID，禁止填入）；\n"
            "2. 分层研判模型（M4.2）——四个维度各自独立评估、各自表达证据不足，"
            "在 verdict 的三个 dimension 字段中分开填写（status/conclusion/confidence/"
            "supporting_evidence_ids/gaps）：\n"
            "   - applicability_dimension：漏洞是否适用于装机组件（静态版本/情报证据）；\n"
            "   - runtime_dimension：运行时证据现状及其与该漏洞的关联（组件存在/服务活跃/"
            "攻击条件/可疑行为/CVE 相关动态证据/已确认利用；证据过期与监控缺失也要如实写）；\n"
            "   - exposure_dimension：暴露面与利用条件（公网可达/仅内网/仅本地/已缓解/"
            "证据不足）；\n"
            "   - 处置维度由 recommended_action/recommended_priority/urgency_basis 承载。\n"
            "   维度纪律：运行时异常不得直接解释为该 CVE 已被利用；缺少运行时事件不得"
            "解释为漏洞不存在；某一维度证据不足不得连带否定其他维度已成立的结论；"
            "unsatisfied_conditions 列出处置前置条件中仍不满足的项。\n"
            "3. 字段语义必须分离：impact_status 只回答「漏洞是否适用于该组件"
            "（静态版本/情报证据）」；runtime_evidence_validity 只回答「运行时证据现在的"
            "有效性」；recommended_action/urgency_basis 回答处置与紧迫度。"
            "运行时证据过期（stale_verified/stale）不得推导为适用性不足，也不得作为"
            "当前活跃利用的充分依据；\n"
            "4. deterministic_facts 是程序确定性核验结果：分支排除"
            "（branch_check=branch_excluded/below_stated_affected_range）与已修复"
            "（version_compare=fixed）不得被通用候选匹配或 KEV 状态推翻；厂商精确公告"
            "声明本 release not_affected（vendor_patch.release_status，含 backport）时"
            "同样优先于 NVD 通用候选；厂商适用性冲突未消解（vendor_conflict."
            "unresolved）时「组件已安装」不等于「CVE 适用已确认」，impact 不得为 "
            "confirmed_affected，处置只能取 monitor/collect_more_evidence/mitigate/defer；\n"
            "5. 处置紧迫度通用推理（不以单一字段为无条件充分依据）：immediate_fix 需要"
            "新鲜运行时利用证据（urgency_basis=fresh_runtime_evidence），或静态证据"
            "独立支撑（urgency_basis=static_evidence_only）且存在确定性放大因子"
            "（deterministic_facts.urgency_amplifiers：KEV 收录，或受影响组件自身公网"
            "监听×CVSS≥9.0）并在 reason 说明；无放大因子的静态证据组合（厂商 affected+"
            "高 CVSS+装机受影响）只支撑 scheduled_fix；已缓解（exposure_dimension="
            "已缓解/仅本地）或触发条件不满足时紧迫度进一步降低；\n"
            "6. risk_direction 是「相对规则基线的证据修正方向」建议——最终分数由程序按"
            "有界映射计算并封顶 [0,100]，与你的方向建议无关：即使基线分数已接近满分，"
            "若证据强度支持上调，仍应如实给出 upgrade 方向，不得因『分数已高不能再升』"
            "而给 maintain；同理证据变弱也不得因『分数已低』而回避 downgrade；\n"
            "7. 独立核对关键证据：对承重证据逐条给 key_evidence_checks（存在性/相关性/时效性）；\n"
            "8. 冲突处理：conflict_result 存在冲突时，必须在 resolved_conflicts/"
            "unresolved_conflicts 显式声明消解状态与依据（引用具体证据）；未消解的"
            "冲突不得静默偏向任何一方；\n"
            "9. 关键事实缺口可用 follow_up_requests 申请定向补充调查（本轮之后仍可用次数："
            f"{state.budgets.follow_up_rounds - state.follow_ups_used}），必须写明"
            "expected_effect（该补查消除哪个缺口、结果如何改变研判）；已提供 "
            "需要重新核实当前安装包/资产身份时，collection_capability=inventory，向资产调查员或漏洞分析师提出"
            "具体问题。程序只登记申请，须操作员授权后由固定 Collector 采集；不得要求命令、密钥、扩大白名单。"
            "运行时进程/网络/心跳缺口不能用 inventory 解决，应标明当前能力不支持。collection_capability=database 仅重读既有库。"
            "follow_up_results 时：先评估每个补查结果与所提问题的相关性——答非所问的"
            "补查不得计入证据，补查返回更多信息本身不构成提高置信度的依据，只有当补查"
            "实质性改变关键事实时才调整结论/置信度并在 reason 说明改变点；不要重复申请；\n"
            "10. 给出候选修复计划 response_plan：只能使用白名单动作，必须包含回滚计划与验证条件；"
            "计划只能待审批（requires_approval=true），不得生成 shell；\n"
            "分别标明漏洞修复、风险缓解、采集器健康恢复、只读验证和回滚准备；"
            "修复只针对候选实际源包/已安装二进制包，使用同发行版官方修复版本；"
            "不要把 Falco 重启描述为 CVE 修复。rationale 说明前置条件与可能影响。\n"
            "11. 任一专家角色缺失（degraded_roles 非空，或 semantic_ablation_masked "
            "标注的实验性隐藏）时如实声明并在 reason 中说明影响。"
            f"\n业务调查问题（未满足须明确申请支持的补采）：{state.investigation_goal}"
        )
        evidence_validator = _decision_evidence_validator(ctx, state)

        def combined_validator(output: dict[str, Any]) -> list[str]:
            # 完备性（空 verdicts 伪成功）+ 防幻觉 + 确定性安全语义约束，
            # 一起反馈重试（反馈信息即约束语义，模型必须修正而非重复）
            errors = list(evidence_validator(output))
            if state.task_type == TASK_RISK_REVIEW and not (output.get("verdicts") or []):
                errors.append(
                    "verdicts 为空：risk_review 任务必须给出至少一条裁定；"
                    "无法研判时输出 impact_status=insufficient_evidence 并在 reason 说明")
            verdict = (output.get("verdicts") or [{}])[0]
            if isinstance(verdict, dict):
                _normalize_urgency_basis(verdict, output, _runtime_freshness_of(state))
                errors.extend(_decision_semantic_errors(verdict, facts,
                                                        _runtime_freshness_of(state)))
            return errors

        output, degraded = _run_specialist(ctx, DECISION_PLANNER_SPEC, context_text,
                                           validate_fn=combined_validator, state=state)
        update: dict[str, Any] = {"stage_status": state.record_stage("decide", "succeeded"),
                                  "harness_capabilities": capabilities}
        if output is not None:
            update["decision"] = output
            update.update(collaboration_flow.publish(ctx, state, AGENT_DECISION, output))
        else:
            # 程序兜底（继承 System B fail-safe）：保留角色降级信息，不虚构裁定。
            # program_fallback 显式标记：实验统计/消费方据此把兜底口径与 LLM 判定
            # 分离（M4.1 校准：不得混入 LLM 研判准确率）
            fallback = DecisionResponseReport(
                verdicts=[{
                    "object_id": state.object_id,
                    "impact_status": "insufficient_evidence",
                    "risk_direction": "maintain",
                    "recommended_action": "collect_more_evidence",
                    "recommended_priority": "medium",
                    "confidence": 0,
                    "reason": f"decision planner failed: {degraded[:200]}",
                }] if state.task_type == TASK_RISK_REVIEW else [],
                degraded_roles=list(state.degraded_roles) + ([AGENT_DECISION] if degraded else []),
                data_gaps=["决策智能体失败；以上为程序兜底结论，必须人工复核"],
                reason="程序兜底：决策智能体输出未通过校验",
            ).model_dump()
            # program_fallback 标记在 schema 外补写（VerdictItem extra=ignore 会
            # 丢弃未知键；该标记供实验统计/消费方分离「程序兜底」与「LLM 判定」口径）
            for fallback_verdict in fallback.get("verdicts") or []:
                fallback_verdict["program_fallback"] = True
            update["decision"] = fallback
            if degraded:
                update["degraded_roles"] = list(dict.fromkeys(
                    list(state.degraded_roles) + [AGENT_DECISION]))
            update["stage_status"] = state.record_stage("decide", "failed")
        return update
    return decide


def _deterministic_facts(state: UnifiedAnalysisState) -> dict[str, Any]:
    """预取包 → 决策约束事实视图（无预取包时给显式空语义，不编造）。"""
    packet = _prep(state)
    if not packet:
        return {"available": False,
                "note": "证据预取包不可用；版本比较/分支核验请用 query_version_impact 自查"}
    candidates = packet.get("candidates") or []
    first = candidates[0] if candidates else {}
    freshness = (packet.get("runtime_facts") or {}).get("freshness") or {}
    buckets = {view.get("freshness") for view in freshness.values() if isinstance(view, dict)}
    if "fresh" in buckets:
        hint = "fresh_available"
    elif buckets and buckets != {"no_evidence"}:
        hint = "stale_only"
    else:
        hint = "not_observed"
    return {
        "available": True,
        "as_of": packet.get("as_of", ""),
        "version_compare": first.get("version_compare") or {"result": "unknown"},
        "branch_check": first.get("branch_check") or {"result": "undetermined"},
        "vendor_conflict": first.get("vendor_conflict") or {"unresolved": False},
        "vendor_patch": first.get("vendor_patch") or {"release_status": "", "backport": False},
        "urgency_amplifiers": first.get("urgency_amplifiers") or {"any_present": False},
        "runtime_freshness": freshness,
        "runtime_status_hint": hint,
    }


def _normalize_urgency_basis(verdict: dict[str, Any], output: dict[str, Any],
                             freshness: str) -> None:
    """immediate_fix 未声明紧迫依据时的程序归一：新鲜运行时证据可自动归因，
    其余交由模型显式声明（校验失败反馈）——不替模型做裁量决定。"""
    if verdict.get("recommended_action") != "immediate_fix":
        return
    if verdict.get("urgency_basis") not in {None, "", "unknown"}:
        return
    if freshness == "fresh":
        verdict["urgency_basis"] = "fresh_runtime_evidence"
        output["notes"] = list(output.get("notes") or []) + [
            "urgency_basis 由程序归一为 fresh_runtime_evidence（运行时证据新鲜且模型未另行声明）"]


def _decision_semantic_errors(verdict: dict[str, Any], facts: dict[str, Any],
                              freshness: str) -> list[str]:
    """确定性安全语义约束（M4.1 校准 + M4.2 深化，全部为通用规则，无案例编号）。

    返回错误列表（非空 → 带反馈重试；仍不合规 → 审计门禁按同语义 fail-closed）。

    M4.2 新增：
    - 厂商精确公告 not_affected（含 backport）被通用候选推翻（Y1/Y2/E3 家族）；
    - 已修复（version_compare=fixed）仍给修复类处置（X2 加固）；
    - 静态紧迫性无确定性放大因子（E2 整改：KEV 或 公网暴露×CVSS≥9.0）；
    - 分支排除/低于区间 与 potentially_affected 矛盾（E3a 整改：不再只拦 confirmed）。
    """
    errors: list[str] = []
    impact = verdict.get("impact_status")
    action = verdict.get("recommended_action")
    branch = facts.get("branch_check") or {}
    compare = facts.get("version_compare") or {}
    conflict = facts.get("vendor_conflict") or {}
    vendor_patch = facts.get("vendor_patch") or {}
    amplifiers = facts.get("urgency_amplifiers") or {}

    if facts.get("available"):
        branch_excluded = branch.get("result") in {
            "branch_excluded", "below_stated_affected_range"}
        if branch_excluded and impact == "confirmed_affected":
            errors.append(
                "确定性分支排除核验（branch_check=branch_excluded/below_stated_affected_range）"
                "与 confirmed_affected 矛盾：可信来源已显式声明装机分支不受影响或装机版本低于"
                "受影响区间，不得仅凭通用 NVD 候选匹配确认受影响；如认为排除证据不适用于"
                "该组件，请依据具体版本证据改判 potentially_affected/insufficient_evidence "
                "并在 reason 说明")
        if branch_excluded and impact == "potentially_affected":
            errors.append(
                "确定性分支排除核验与 potentially_affected 矛盾：装机分支已被可信来源显式"
                "排除（或装机版本低于声明的受影响区间），「可能受影响」需要指出排除声明"
                "不成立的具体证据；无此类证据时请改判 not_affected/insufficient_evidence"
                "（该矛盾若维持将触发强制人工复核）")
        if compare.get("result") == "fixed" and impact in {"confirmed_affected", "potentially_affected"}:
            errors.append(
                "确定性版本比较判定装机版本不低于修复版本（version_compare=fixed，即已修复）："
                "KEV 收录/厂商历史受影响状态不改变已修复事实，impact 必须为 "
                "not_affected 或 insufficient_evidence")
        if compare.get("result") == "fixed" and action in {"immediate_fix", "scheduled_fix"}:
            errors.append(
                "确定性已修复判定（version_compare=fixed）下给出修复类处置"
                f"（{action}）自相矛盾：已修复组件不存在待修复范围，请改用 "
                "monitor/collect_more_evidence/defer 并在 reason 说明已修复事实")
        if (vendor_patch.get("release_status") == "not_affected"
                and impact in {"confirmed_affected", "potentially_affected"}):
            errors.append(
                "厂商精确公告（release 作用域）已声明本 release not_affected"
                + ("（含 backport 修复——「装机版本<上游修复版本」不等于受影响）"
                   if vendor_patch.get("backport") else "")
                + "：厂商精确公告优先于 NVD 通用候选匹配，impact 必须为 not_affected/"
                "insufficient_evidence；如坚持受影响结论，必须在 reason 给出推翻厂商"
                "公告的具体证据（否则将触发强制人工复核）")
        if conflict.get("unresolved"):
            if impact == "confirmed_affected":
                errors.append(
                    "厂商适用性冲突未消解（vendor_conflict.unresolved）：组件已安装不等于 "
                    "CVE 适用已确认，impact 不得为 confirmed_affected；"
                    "请改判 potentially_affected/insufficient_evidence 并在 missing_evidence "
                    "列出消解冲突所需证据")
            if action in {"scheduled_fix", "immediate_fix"}:
                errors.append(
                    "厂商适用性冲突未消解时不得直接进入修复处置：请改用 "
                    "monitor/collect_more_evidence/mitigate/defer（冲突消解前修复范围未定，"
                    "该事件将被强制人工复核）")

    if action == "immediate_fix":
        basis = verdict.get("urgency_basis") or "unknown"
        if basis == "fresh_runtime_evidence" and freshness not in {"fresh"}:
            errors.append(
                "urgency_basis=fresh_runtime_evidence 但运行时证据并非新鲜"
                f"（freshness={freshness}）：stale_verified 不得作为当前活跃利用的充分依据；"
                "请降级处置或改判 urgency_basis=static_evidence_only 并在 reason 给出"
                "独立支撑紧迫性的静态证据（如预认证可达+厂商确认+KEV）")
        if basis == "unknown":
            errors.append(
                "recommended_action=immediate_fix 必须显式声明 urgency_basis"
                "（fresh_runtime_evidence 或 static_evidence_only），不得留空")
        if basis == "static_evidence_only" and impact in {"confirmed_affected", "potentially_affected"} \
                and facts.get("available") and not amplifiers.get("any_present"):
            errors.append(
                "静态证据独立支撑 immediate_fix（urgency_basis=static_evidence_only）"
                "缺乏确定性放大因子（urgency_amplifiers：KEV 均为 false 且受影响组件"
                "无公网监听×CVSS≥9.0 组合）：厂商 affected+高 CVSS+装机受影响的静态组合"
                "本身只支撑排期处置——请降级为 scheduled_fix（或收集到放大因子证据后"
                "重新申请）；如认为存在本清单之外的紧迫性依据，必须在 reason 显式列举"
                "并可被审计")

    if impact == "insufficient_evidence" and compare.get("result") == "affected" \
            and freshness == "stale":
        errors.append(
            "运行时证据过期不得直接推导为漏洞适用性不足：静态版本核验已判定适用"
            "（version_compare=affected）。请区分 applicability（impact_status，"
            "由静态证据决定）与 runtime_status（证据有效性）——如无其他静态证据缺口，"
            "impact 应为 potentially_affected/confirmed_affected，并在 "
            "runtime_evidence_validity=stale_verified 下选择相应处置紧迫度")
    return errors


def _decision_known_ids(state: UnifiedAnalysisState) -> set[str]:
    """决策者可引用的证据全集：事件证据包 + 运行时证据 + 预取证据清单 +
    各专家报告已引用项。摘要标记 RUNTIME-SUMMARY 不是证据 ID，必须排除。"""
    if state.evidence_snapshot:
        return collaboration_mod.evidence_registry_ids(state.evidence_snapshot)
    known: set[str] = set(state.baseline.get("packet_evidence_ids") or [])
    inventory_id = ((_prep(state).get("asset_facts") or {}).get("inventory_provenance") or {}).get("inventory_evidence_id")
    if inventory_id:
        known.add(inventory_id)
    known.update((_prep(state).get("runtime_facts") or {}).get("evidence_ids") or [])
    for candidate in (_prep(state).get("candidates") or []):
        for source in (candidate.get("source_bundle") or {}).values():
            value = source.get("value") or {}
            for record in value.get("records", [value]) if isinstance(value, dict) else []:
                if record.get("evidence_id"):
                    known.add(record["evidence_id"])
    runtime = state.runtime or state.runtime_program_fallback or {}
    known.update(runtime.get("evidence_ids") or [])
    for finding in runtime.get("findings") or []:
        if isinstance(finding, dict):
            known.add(finding.get("evidence_id", "") or "")
    for report in (state.investigation, state.vulnerability):
        for finding in (report or {}).get("findings") or []:
            if isinstance(finding, dict):
                known.update(finding.get("supporting_evidence_ids") or [])
    known.discard("")
    return known


def _decision_evidence_validator(ctx: RunContext, state: UnifiedAnalysisState):
    """防幻觉校验：决策者引用必须在可引用全集内（错误信息附合法 ID 清单）。"""
    known = _decision_known_ids(state)

    def validate(output: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        cited: set[str] = set()
        for verdict in output.get("verdicts") or []:
            cited.update(verdict.get("supporting_evidence_ids") or [])
            # M4.2：分层研判维度的支撑引用同样纳入防幻觉校验
            for dimension_key in ("applicability_dimension", "runtime_dimension",
                                  "exposure_dimension"):
                dimension = verdict.get(dimension_key) or {}
                if isinstance(dimension, dict):
                    cited.update(dimension.get("supporting_evidence_ids") or [])
        for check in output.get("key_evidence_checks") or []:
            cited.add(check.get("evidence_id", "") or "")
        cited.discard("")
        if state.evidence_snapshot:
            # 摘要掉的历史 runtime ID 仍是真实证据（known_but_summarized），
            # 不能判成捏造；但它也不会被 _fresh_related 当作新鲜证据。
            unknown = sorted(ref for ref in cited
                             if collaboration_mod.classify_evidence_id(
                                 ref, state.evidence_snapshot) in {"unknown", "wrong_kind"})
        else:
            unknown = sorted(cited - known)
        if unknown:
            # 反馈必须附带合法 ID 清单（实验发现：不附清单时模型会用 CVE/版本号填充）
            errors.append(
                f"引用了材料中不存在的证据 ID（防幻觉校验失败）: {sorted(unknown)[:5]}；"
                f"supporting_evidence_ids/key_evidence_checks/各维度 supporting_evidence_ids "
                f"只能取: {sorted(known)[:20]}")
        return errors
    return validate


def node_execute_follow_ups(ctx: RunContext):
    def execute_follow_ups(state: UnifiedAnalysisState) -> dict[str, Any]:
        decision = state.decision or {}
        requests = (decision.get("follow_up_requests") or [])[:2]
        results: list[dict[str, Any]] = list(state.follow_up_results)
        update: dict[str, Any] = {"follow_ups_used": state.follow_ups_used + 1}
        degraded = list(state.degraded_roles)
        for request in requests:
            if ctx.remaining_s() <= min(300.0, ctx.run_deadline_s * 0.25):
                results.append({"question": request.get("question"), "status": "budget_reserved_for_decision",
                                "resolved": False})
                continue
            if request.get("collection_capability") == "inventory":
                db = ctx.session()
                try:
                    from app.services.unified.investigation import propose
                    try:
                        item = propose(db, state.run_id, request)
                        results.append({"request_id": item.id, "question": request.get("question"),
                            "status": "awaiting_authorization", "resolved": False,
                            "note": "仅提出固定清单采集申请；须操作员授权，尚无新证据，不得提高置信度"})
                    except ValueError as exc:
                        results.append({"question": request.get("question"), "status": "policy_rejected", "resolved": False, "error": str(exc)})
                finally:
                    db.close()
                continue
            spec = SPEC_BY_NAME.get(request.get("target_agent", ""))
            if spec is None or spec.name == AGENT_DECISION:
                results.append({"agent": request.get("target_agent", ""), "error": "unknown target"})
                continue
            previous = {
                AGENT_ASSET: state.investigation,
                AGENT_VULNERABILITY: state.vulnerability,
                AGENT_RUNTIME: state.runtime,
            }.get(spec.name)
            context_text = (
                f"决策规划师请求你做一次定向补充调查（有界，仅此一轮）：\n"
                f"问题: {request.get('question', '')}\n"
                f"线索: {request.get('evidence_hint', '')}\n"
                f"预期效果: {request.get('expected_effect', '（未说明）')}\n"
                f"你此前的结论（供参考）: {json.dumps(previous, ensure_ascii=False, default=str)[:2000]}\n"
                "请用你的专属工具查证该问题，输出完整结构化结果（与此前相同的 schema）。\n"
                "相关性纪律：只查证所问的具体事实缺口，与本问题无关的常规信息不要展开；"
                "若你的工具无法回答该问题，在 data_gaps 如实说明而不是给出推断。"
            )
            validator = {
                AGENT_RUNTIME: _runtime_evidence_validator(ctx, state),
                AGENT_VULNERABILITY: _vulnerability_evidence_validator(ctx, state),
                AGENT_ASSET: None,
            }.get(spec.name)
            output, degraded_reason = _run_specialist(ctx, spec, context_text,
                                                      validate_fn=validator, state=state)
            entry: dict[str, Any] = {"agent": spec.name, "question": request.get("question", "")}
            if output is not None:
                entry["output"] = output
                from app.services.unified.investigation import judgment
                entry["changed"] = judgment(output) != judgment(previous)
                entry["new_evidence"] = False
                update[{AGENT_ASSET: "investigation", AGENT_VULNERABILITY: "vulnerability", AGENT_RUNTIME: "runtime"}[spec.name]] = output
                published = collaboration_flow.publish(ctx, state, spec.name, output)
                for field in ("shared_findings", "collaboration_messages"):
                    update[field] = collaboration_mod.merge_immutable(update.get(field, []), published[field])
                update.setdefault("role_provenance", {}).update(published["role_provenance"])
            else:
                entry["error"] = degraded_reason
                degraded.append(spec.name)
            results.append(entry)
        update["follow_up_results"] = results
        update["degraded_roles"] = list(dict.fromkeys(degraded))
        update["stage_status"] = state.record_stage("execute_follow_ups", "succeeded")
        return update
    return execute_follow_ups


def _role_validator(ctx, state, role):
    return {AGENT_RUNTIME: _runtime_evidence_validator(ctx, state),
            AGENT_VULNERABILITY: _vulnerability_evidence_validator(ctx, state)}.get(role)


def node_harness_precheck(ctx):
    def precheck(state):
        intents = harness_bridge.build_candidate_intents(state, (state.decision or {}).get("response_plan") or {})
        with ctx.session() as db:
            feedback = harness_bridge.precheck_intents(db, state, intents)
        messages = collaboration_flow.system_message(ctx, state, "PLAN_FEEDBACK",
            json.dumps({k: feedback.get(k) for k in ("status", "terminal", "reasons", "feedback")}, ensure_ascii=False),
            action="Respect terminal policy denial; otherwise revise only the disposition against concrete missing conditions.")
        return {"candidate_intents": intents, "harness_feedback": feedback,
            "collaboration_messages": messages, "stage_status": {"harness_precheck": "succeeded"},
            **({"collaboration_stop_reason": "policy_denied"} if feedback.get("terminal") else {})}
    return precheck


def node_plan_feedback(ctx):
    def feedback(state):
        return {"plan_feedback_used": state.plan_feedback_used + 1,
            "reuse_roles": [r for r in state.reuse_roles if r != AGENT_DECISION]}
    return feedback


def node_finalize(ctx: RunContext):
    def finalize(state: UnifiedAnalysisState) -> dict[str, Any]:
        # Keep every external proposal even if the last bounded decision still
        # requests collection. Persisted rows are idempotent and never dispatch.
        db = ctx.session()
        try:
            from app.services.unified.investigation import propose
            for request in (state.decision or {}).get("follow_up_requests") or []:
                if request.get("collection_capability") == "inventory":
                    try:
                        propose(db, state.run_id, request)
                    except ValueError:
                        pass  # rejected capability never becomes an authorized task
            link = db.query(models.InvestigationRequest).filter_by(reanalysis_run_id=state.run_id).first()
            if link:
                from app.services.unified.investigation import evidence_view, substantive_change
                if not substantive_change(json.loads(link.before_json), evidence_view(db, link.asset_id)):
                    # Same facts: retain raw outputs and require review of variance.
                    state.final["model_variance_only"] = True
        finally:
            db.close()
        snapshot = state.model_dump()
        final: dict[str, Any] = {"pipeline_version": PIPELINE_VERSION}
        final["evidence_snapshot_id"] = state.evidence_snapshot_id
        final["candidate_intents"] = state.candidate_intents
        final["harness_feedback"] = state.harness_feedback
        final["collaboration"] = {"message_count": len(state.collaboration_messages),
            "receipts": state.message_receipts, "replay_roles": state.replay_roles,
            "reused_roles": state.reuse_roles, "stop_reason": state.collaboration_stop_reason,
            "full_four_role_execution": all(state.role_provenance.get(role, {}).get("status") == "executed"
                for role in (AGENT_ASSET, AGENT_VULNERABILITY, AGENT_RUNTIME, AGENT_DECISION))}
        if state.task_type == TASK_RISK_REVIEW:
            policy = audit_policy.apply_unified_audit_policy(snapshot)
            if ctx.batch_runtime is not None:
                policy.status = "pending_human_review"
                policy.final_score = policy.final_level = None
                policy.reasons.append("task_graph_quality_validation_required")
            if state.mode == "historical":
                policy.status = "pending_human_review"
                policy.final_score = policy.final_level = None
                policy.reasons.append("historical_draft_requires_operator_adjudication")
            if state.final.get("model_variance_only"):
                policy.status = "pending_human_review"
                policy.final_score = policy.final_level = None
                policy.reasons.append("same_facts_model_variance_not_new_evidence")
                final["model_variance_only"] = True
            final["policy"] = policy.model_dump()
        else:
            final["aggregate"] = aggregator.aggregate_device_risk(
                state.investigation, state.vulnerability, state.runtime or state.runtime_program_fallback)
        plan = (state.decision or {}).get("response_plan") or {}
        if plan:
            from app.services.unified.plan_guard import annotate_plan
            plan = annotate_plan(snapshot, dict(plan), sorted(_decision_known_ids(state)))
            if (plan.get("technical_gate") or {}).get("status") == "blocked" and final.get("policy"):
                final["policy"]["status"] = "pending_human_review"
                final["policy"]["final_score"] = final["policy"]["final_level"] = None
                final["policy"]["reasons"].append("candidate_plan_technical_gate_blocked")
            plan["requires_approval"] = True   # 程序强制：LLM 计划永远待审批
            final["plan"] = plan
            final["plan_execution_mode"] = "pending_approval"
        if state.harness_feedback.get("terminal"):
            final["plan_execution_mode"] = "blocked"
        if state.evidence_snapshot.get("integrity_errors") or state.collaboration_stop_reason in {"policy_denied", "message_budget_exhausted", "evidence_partial"} or collaboration_flow.inbox(state):
            if final.get("policy"):
                final["policy"]["status"] = "pending_human_review"
                final["policy"]["final_score"] = final["policy"]["final_level"] = None
                final["policy"]["reasons"].append("collaboration_requires_human_review")
        final["usage"] = ctx.meter.as_dict()
        if ctx.batch_runtime is not None:
            from app.services.unified.task_runtime import VERSION
            final["pipeline_version"] = f"{PIPELINE_VERSION}+{VERSION}"
            final["execution_profile"] = "task_graph"
            final["task_receipts"] = dict(ctx.task_receipts)
            final["batch_budget"] = ctx.batch_runtime.snapshot()
        final["degraded_roles"] = list(dict.fromkeys(state.degraded_roles))
        db = ctx.session()
        try:
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "finalize",
                              "policy": final.get("policy"),
                              "aggregate": final.get("aggregate")})
        finally:
            db.close()
        return {"final": final, "decision": state.decision, "investigation": state.investigation,
                "vulnerability": state.vulnerability, "runtime": state.runtime,
                "stage_status": state.record_stage("finalize", "succeeded")}
    return finalize


# ── 图构建 ───────────────────────────────────────────────────────────────────


def build_graph(ctx: RunContext):
    graph = StateGraph(UnifiedAnalysisState)
    graph.add_node("prepare", node_prepare(ctx))
    graph.add_node("prepare_evidence", node_prepare_evidence(ctx))
    graph.add_node("investigate_asset", node_investigate_asset(ctx))
    graph.add_node("analyze_vulnerability", node_analyze_vulnerability(ctx))
    graph.add_node("analyze_runtime", node_analyze_runtime(ctx))
    graph.add_node("detect_conflicts", node_detect_conflicts(ctx))
    graph.add_node("directed_rereview", node_directed_rereview(ctx))
    graph.add_node("exchange_messages", collaboration_flow.node_exchange(ctx))
    graph.add_node("decide", node_decide(ctx))
    graph.add_node("harness_precheck", node_harness_precheck(ctx))
    graph.add_node("plan_feedback", node_plan_feedback(ctx))
    graph.add_node("execute_follow_ups", node_execute_follow_ups(ctx))
    graph.add_node("finalize", node_finalize(ctx))

    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "prepare_evidence")
    graph.add_edge("prepare_evidence", "investigate_asset")
    # Agent 2 ∥ Agent 3 并行（共同仅依赖 Agent 1）
    graph.add_edge("investigate_asset", "analyze_vulnerability")
    graph.add_edge("investigate_asset", "analyze_runtime")
    graph.add_edge(["analyze_vulnerability", "analyze_runtime"], "detect_conflicts")
    graph.add_conditional_edges("detect_conflicts", _route_after_conflicts,
                                {"directed_rereview": "directed_rereview", "decide": "decide", "exchange_messages": "exchange_messages"})
    graph.add_edge("exchange_messages", "detect_conflicts")
    graph.add_edge("directed_rereview", "decide")
    graph.add_conditional_edges("decide", _route_after_decide,
                                {"harness_precheck": "harness_precheck"})
    graph.add_conditional_edges("harness_precheck", _route_after_precheck,
        {name: name for name in ("plan_feedback", "exchange_messages", "execute_follow_ups", "finalize")})
    graph.add_edge("plan_feedback", "decide")
    graph.add_conditional_edges("execute_follow_ups", _route_after_follow_ups,
                                {"decide": "decide", "finalize": "finalize"})
    graph.add_edge("finalize", END)
    return graph.compile()


def new_run_id() -> str:
    return "UA-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
