"""唯一正式编排器：LangGraph StateGraph（Stage 9B）。

图结构（IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md §4.1）：

    START → prepare → investigate_asset → {analyze_vulnerability ∥ analyze_runtime}
          → detect_conflicts → [route: directed_rereview?] → decide
          → [route: execute_follow_ups?] → finalize → END

纪律：
- 节点是普通函数：确定性程序步骤（冲突检测/审计门禁/聚合）与 LLM 步骤同为
  一等节点；LLM 永不写最终分数/授权/执行权限；
- 路由跳过的角色由程序填充降级语义（unavailable/基线维持），不虚增风险；
- 并行分支各自持有线程独立 DB 会话（SQLite 会话不跨线程共享）；
- run 级预算（LLM 调用数/时限/补查轮数）由 UsageMeter 与 deadline 统一强制。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models
from app.services import trace_service as tracing
from app.services.agents.base import AgentSpec, ChatClient
from app.services.unified import (
    aggregator,
    audit_policy,
    conflicts as conflicts_mod,
    routing as routing_mod,
)
from app.services.unified.agent_base import (
    BudgetExceeded,
    UnifiedAgentResult,
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
    "prepare": ["investigate_asset"],
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
    run_deadline_s: float = 900.0
    agent_logs: dict[str, Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _started: float = field(default_factory=time.monotonic)
    persisted_stage: dict[str, str] = field(default_factory=dict)
    # 深度控制（测试可注入）
    agent_budget_s: float = 150.0

    def session(self) -> Session:
        return self.db_factory()

    def remaining_s(self) -> float:
        return self.run_deadline_s - (time.monotonic() - self._started)

    def log_agent(self, name: str, entry: dict[str, Any]) -> None:
        with self._lock:
            self.agent_logs[name] = entry

    def emit(self, db: Session, event_type: str, actor: str, status: str,
             payload: dict[str, Any] | None = None, **kwargs: Any) -> None:
        if not self.trace_id:
            return
        tracing.emit(db, self.trace_id, event_type, actor=actor, status=status,
                     payload=payload or {}, **kwargs)


# ── 通用专家执行（证据校验 + 一次反馈重试 + 降级语义） ────────────────────────


def _agent_deadline(ctx: RunContext) -> float:
    return max(5.0, min(ctx.agent_budget_s, ctx.remaining_s()))


def _run_specialist(ctx: RunContext, spec: AgentSpec, context_text: str,
                    validate_fn: Callable[[dict[str, Any]], list[str]] | None = None,
                    extra_instruction: str = "") -> tuple[dict[str, Any] | None, str]:
    """执行一个专家：结构化输出 → 证据事实校验（一次带反馈重试）→ 失败降级。

    返回 (output_dict | None, degraded_reason)。None 表示该角色降级，
    其意见缺失但其余角色结果保留（F7：部分失败不全丢）。
    """
    db = ctx.session()
    try:
        started_at = models.utcnow()
        ctx.emit(db, "agent_started", actor=spec.name, status="running", is_llm_step=True,
                 payload={"agent": spec.name}, started_at=started_at)
        agent_started = time.monotonic()
        agent = UnifiedToolLoopAgent(spec, ctx.client_factory(), meter=ctx.meter)
        result = agent.run(db, context=context_text, deadline_s=_agent_deadline(ctx))
        degraded_reason = ""
        if result.status != "succeeded":
            degraded_reason = result.error or result.status
        elif validate_fn is not None:
            errors = validate_fn(result.output or {})
            if errors:
                # 一次带事实反馈的重试（继承 System A RUNTIME 阶段语义，F3 反馈）
                retry_context = (
                    f"{context_text}\n\n上一次输出未通过证据事实校验：{'; '.join(errors)}。"
                    "请只引用真实存在的 evidence_id，重新输出完整 JSON。")
                retry = agent.run(db, context=retry_context, deadline_s=_agent_deadline(ctx))
                if retry.status == "succeeded":
                    retry_errors = validate_fn(retry.output or {})
                    if not retry_errors:
                        result, errors = retry, []
                    else:
                        # 重试输出仍含伪造引用：strip 必须与「它自己的错误」配对
                        result, errors = retry, retry_errors
                if errors:
                    stripped = _strip_invalid_evidence_refs(result, errors)
                    if stripped is not None:
                        result = stripped
                    else:
                        degraded_reason = "; ".join(errors)
        elapsed_ms = int((time.monotonic() - agent_started) * 1000)
        # 事实校验未通过（degraded_reason 非空）时绝不放行原始输出——
        # 即使 result.status 仍为 succeeded（strip 失败的场景）
        output = result.output if (result.status == "succeeded" and not degraded_reason) else None
        ctx.log_agent(spec.name, {
            "status": result.status if not degraded_reason else "degraded",
            "attempts": result.attempts,
            "latency_ms": elapsed_ms,
            "error": (degraded_reason or result.error or "")[:800],
            "tool_calls": [{"name": call["name"], "ok": call.get("ok", False)}
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


def _strip_invalid_evidence_refs(result: UnifiedAgentResult,
                                 errors: list[str]) -> UnifiedAgentResult | None:
    """剔除引用了不存在 ID 的字段后重新校验；剔除后仍非法则放弃（降级）。

    保留其余有效内容（F7：部分失败不全丢），剔除记录写入 notes。
    """
    output = dict(result.output or {})
    import re as _re

    invalid_ids: set[str] = set()
    for error in errors:
        invalid_ids.update(_re.findall(r"EV-[A-Za-z0-9._\-]+", error))
        invalid_ids.update(_re.findall(r"SE-[A-Za-z0-9._\-]+", error))
    if not invalid_ids:
        return None

    def _clean(ids: list[str]) -> list[str]:
        cleaned = [i for i in ids if i not in invalid_ids]
        return cleaned

    output["evidence_ids"] = _clean(list(output.get("evidence_ids") or []))
    findings = []
    for finding in output.get("findings") or []:
        if isinstance(finding, dict):
            finding = dict(finding)
            finding["supporting_evidence_ids"] = _clean(
                list(finding.get("supporting_evidence_ids") or []))
        findings.append(finding)
    output["findings"] = findings
    output["notes"] = list(output.get("notes") or []) + [
        f"stripped_invalid_evidence_refs: {sorted(invalid_ids)[:5]}"]
    try:
        revalidated = result_output_model(result).model_validate(output)
    except Exception:
        return None
    result.output = revalidated.model_dump()
    result.status = "succeeded"
    return result


def result_output_model(result: UnifiedAgentResult) -> type[BaseModel]:
    return SPEC_BY_NAME[result.agent].output_model


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


def _candidate_context(db: Session, state: UnifiedAnalysisState,
                       risk: models.RiskAssessment | None) -> list[dict[str, Any]]:
    """漏洞分析师的候选清单（规则命中，只读；不含规则分数——防锚定）。"""
    if risk is not None:
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        return [{
            "cve_id": risk.cve_id,
            "package_name": risk.package_name,
            "installed_version": match.installed_version if match else "",
            "fixed_version": match.fixed_version if match else "",
            "match_status": match.match_status if match else risk.affected_status,
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
            "packet_evidence_ids": sorted(packet_ids),
        }
    return {
        "object_id": state.target_ref,
        "preliminary_score": None,
        "preliminary_level": "",
        "match_status": "",
        "installed_version": "",
        "fixed_version": "",
        "packet_evidence_ids": [],
    }


def node_investigate_asset(ctx: RunContext):
    def investigate_asset(state: UnifiedAnalysisState) -> dict[str, Any]:
        if not state.routing.include_asset:
            return {"stage_status": state.record_stage("investigate_asset", "skipped")}
        context_text = (
            f"调查目标资产: {state.target_ref}（类型 {state.target_type}）。\n"
            "请先调用工具获取真实画像、暴露面与运行时数据质量，再输出结构化结论。\n"
            "evidence_inventory 必须来自 query_runtime_data_quality 的真实返回；"
            "evidence_quality 按覆盖/新鲜度/缺口如实评级。"
        )
        output, degraded = _run_specialist(ctx, ASSET_INVESTIGATOR_SPEC, context_text)
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "investigate_asset", "failed" if degraded else "succeeded")}
        if output is not None:
            update["investigation"] = output
        else:
            update["degraded_roles"] = state.degraded_roles + [AGENT_ASSET]
            update["error"] = degraded
        return update
    return investigate_asset


def _runtime_evidence_validator(ctx: RunContext):
    def validate(output: dict[str, Any]) -> list[str]:
        db = ctx.session()
        try:
            errors: list[str] = []
            ids = set(output.get("evidence_ids") or [])
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


def _vulnerability_evidence_validator(ctx: RunContext):
    def validate(output: dict[str, Any]) -> list[str]:
        known = set(ctx.packet_evidence_ids)
        if not known:
            return []
        errors: list[str] = []
        cited: set[str] = set()
        for finding in output.get("findings") or []:
            if isinstance(finding, dict):
                cited.update(finding.get("supporting_evidence_ids") or [])
        unknown = sorted(cited - known)
        if unknown:
            errors.append(f"引用了证据包之外的分析师自造证据 ID（防幻觉校验失败）: {unknown[:5]}")
        return errors
    return validate


def node_analyze_vulnerability(ctx: RunContext):
    def analyze_vulnerability(state: UnifiedAnalysisState) -> dict[str, Any]:
        if not state.routing.include_vulnerability:
            return {"stage_status": state.record_stage("analyze_vulnerability", "skipped")}
        asset_summary = ""
        if state.investigation:
            investigation = state.investigation
            asset_summary = (
                f"\n资产画像摘要（来自资产调查员）: device_type={investigation.get('device_type')} "
                f"firmware={investigation.get('firmware_version')} "
                f"os={investigation.get('os')} 组件数={len(investigation.get('components') or [])} "
                f"证据质量={investigation.get('evidence_quality')}")
        context_text = (
            f"分析目标: {state.target_ref} 的候选 CVE 适用性。\n"
            f"候选清单（规则命中，供核查——规则结论本身可能误报）:\n"
            f"{json.dumps(state.candidate_context, ensure_ascii=False)}"
            f"{asset_summary}\n"
            "要求：用 query_version_impact 做真实版本比较；用 query_intelligence_sources 核对"
            "厂商/NVD/KEV/EPSS 各源状态是否互相矛盾；输入故意不包含规则分数，不要猜测基线结论；"
            "适用分支与装机版本不符时明确判 not_affected 并说明理由（E3 类假阳性识别）。"
        )
        output, degraded = _run_specialist(ctx, VULNERABILITY_ANALYST_SPEC, context_text,
                                           validate_fn=_vulnerability_evidence_validator(ctx))
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "analyze_vulnerability", "failed" if degraded else "succeeded")}
        if output is not None:
            update["vulnerability"] = output
        else:
            update["degraded_roles"] = state.degraded_roles + [AGENT_VULNERABILITY]
            update["error"] = degraded
        return update
    return analyze_vulnerability


def node_analyze_runtime(ctx: RunContext):
    def analyze_runtime(state: UnifiedAnalysisState) -> dict[str, Any]:
        routing = state.routing
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
            f"关注软件包: {watched or '（无特定包，观察整体行为链）'}"
            f"{inventory_note}\n"
            "要求：用多标识键查询（device_id/IP/主机名均可）；引用 evidence_id 必须来自工具真实返回；"
            "先看 query_runtime_data_quality 再判定——证据全部过期时用 stale_verified，"
            "能力不支持用 unavailable；包活动不等于漏洞被利用。"
        )
        output, degraded = _run_specialist(ctx, RUNTIME_ANALYST_SPEC, context_text,
                                           validate_fn=_runtime_evidence_validator(ctx))
        update: dict[str, Any] = {"stage_status": state.record_stage(
            "analyze_runtime", "failed" if degraded else "succeeded")}
        if output is not None:
            update["runtime"] = output
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
    if (state.conflict_result.has_major_conflict
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
        involved = sorted({agent for item in state.conflict_result.conflicts
                           for agent in item.involved_agents})
        descriptions = [item.description for item in state.conflict_result.conflicts]
        update: dict[str, Any] = {
            "rereview_used": state.rereview_used + 1,
            "stage_status": state.record_stage("directed_rereview", "succeeded"),
        }
        degraded = list(state.degraded_roles)
        spec_map = {
            AGENT_VULNERABILITY: (VULNERABILITY_ANALYST_SPEC, state.vulnerability,
                                  _vulnerability_evidence_validator(ctx)),
            AGENT_RUNTIME: (RUNTIME_ANALYST_SPEC, state.runtime,
                            _runtime_evidence_validator(ctx)),
            AGENT_ASSET: (ASSET_INVESTIGATOR_SPEC, state.investigation, None),
        }
        for name in involved:
            if name not in spec_map:
                continue
            spec, previous, validator = spec_map[name]
            context_text = (
                f"针对以下已识别冲突进行定向复议（仅此一次），输出完整结构化结果：\n"
                f"{json.dumps(descriptions, ensure_ascii=False)}\n"
                f"你此前的结论: {json.dumps(previous, ensure_ascii=False)[:2000]}\n"
                "请重新核对工具/事实后给出结论；如维持原结论，请给出更强的证据理由。"
            )
            output, degraded_reason = _run_specialist(ctx, spec, context_text,
                                                      validate_fn=validator)
            key = {AGENT_VULNERABILITY: "vulnerability",
                   AGENT_RUNTIME: "runtime",
                   AGENT_ASSET: "investigation"}[name]
            if output is None:
                degraded.append(name)   # 复议失败：保留原结论但标记降级（门禁转人工）
            elif _is_empty_default(output) and not _is_empty_default(previous):
                # 复议产出为空默认值时不得覆盖既有丰富结论（保留原意见）
                ctx.log_agent(spec.name + "_rereview", {
                    "status": "discarded_empty_rereview", "note": "复议输出为空默认值，保留原结论"})
            else:
                update[key] = output
        update["degraded_roles"] = degraded
        refreshed = conflicts_mod.merge_rereview(state.conflict_result, {
            **state.model_dump(), **update})
        update["conflict_result"] = refreshed
        return update
    return directed_rereview


def _route_after_decide(state: UnifiedAnalysisState) -> str:
    decision = state.decision or {}
    requests = decision.get("follow_up_requests") or []
    if requests and state.follow_ups_used < state.budgets.follow_up_rounds:
        return "execute_follow_ups"
    return "finalize"


def node_decide(ctx: RunContext):
    def decide(state: UnifiedAnalysisState) -> dict[str, Any]:
        decision_context = {
            "object_id": state.object_id,
            "task_type": state.task_type,
            "baseline": {k: v for k, v in state.baseline.items()
                         if k not in {"packet_evidence_ids"}},
            "asset_report": state.investigation,
            "vulnerability_report": state.vulnerability,
            "runtime_report": state.runtime or state.runtime_program_fallback,
            "runtime_report_is_program_fallback": state.runtime is None,
            "conflict_result": state.conflict_result.model_dump(),
            "degraded_roles": state.degraded_roles,
            "capability_marks": state.capability_marks,
            "follow_up_results": state.follow_up_results or None,
            "follow_up_round_used": state.follow_ups_used,
            # 防幻觉：可引用的证据 ID 全集（引用之外一律视为编造）
            "available_evidence_ids": sorted(_decision_known_ids(state)),
        }
        context_text = (
            "综合以下结构化材料完成研判与处置规划。\n"
            f"{json.dumps(decision_context, ensure_ascii=False, default=str)}\n"
            "要求：\n"
            "1. impact_status/risk_direction/recommended_action 只能取 schema 枚举；"
            "supporting_evidence_ids 只能引用 available_evidence_ids 中列出的证据 ID"
            "（CVE 编号、版本号、主机名都不是证据 ID，禁止填入）；\n"
            "2. 独立核对关键证据：对承重证据逐条给 key_evidence_checks（存在性/相关性/时效性）；\n"
            "3. 关键事实缺口可用 follow_up_requests 申请定向补充调查（本轮之后仍可用次数："
            f"{state.budgets.follow_up_rounds - state.follow_ups_used}）；已提供 follow_up_results 时优先使用，不要重复申请；\n"
            "4. 给出候选修复计划 response_plan：只能使用白名单动作，必须包含回滚计划与验证条件；"
            "计划只能待审批（requires_approval=true），不得生成 shell；\n"
            "5. 任一专家角色缺失（degraded_roles 非空）时如实声明并在 reason 中说明影响。"
        )
        evidence_validator = _decision_evidence_validator(ctx, state)

        def combined_validator(output: dict[str, Any]) -> list[str]:
            # 完备性（实验发现：规划师曾输出空 verdicts 仍通过校验，只能靠
            # 门禁 structured_result_incomplete 兜底）+ 防幻觉，一起反馈重试
            errors = list(evidence_validator(output))
            if state.task_type == TASK_RISK_REVIEW and not (output.get("verdicts") or []):
                errors.append(
                    "verdicts 为空：risk_review 任务必须给出至少一条裁定；"
                    "无法研判时输出 impact_status=insufficient_evidence 并在 reason 说明")
            return errors

        output, degraded = _run_specialist(ctx, DECISION_PLANNER_SPEC, context_text,
                                           validate_fn=combined_validator)
        update: dict[str, Any] = {"stage_status": state.record_stage("decide", "succeeded")}
        if output is not None:
            update["decision"] = output
        else:
            # 程序兜底（继承 System B fail-safe）：保留角色降级信息，不虚构裁定
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
            update["decision"] = fallback
            if degraded:
                update["degraded_roles"] = list(dict.fromkeys(
                    list(state.degraded_roles) + [AGENT_DECISION]))
            update["stage_status"] = state.record_stage("decide", "failed")
        return update
    return decide


def _decision_known_ids(state: UnifiedAnalysisState) -> set[str]:
    """决策者可引用的证据全集：事件证据包 + 运行时证据 + 各专家报告已引用项。"""
    known: set[str] = set(state.baseline.get("packet_evidence_ids") or [])
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
        for check in output.get("key_evidence_checks") or []:
            cited.add(check.get("evidence_id", "") or "")
        cited.discard("")
        unknown = sorted(cited - known)
        if unknown:
            # 反馈必须附带合法 ID 清单（实验发现：不附清单时模型会用 CVE/版本号填充）
            errors.append(
                f"引用了材料中不存在的证据 ID（防幻觉校验失败）: {sorted(unknown)[:5]}；"
                f"supporting_evidence_ids/key_evidence_checks.evidence_id 只能取: {sorted(known)[:20]}")
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
            spec = SPEC_BY_NAME.get(request.get("target_agent", ""))
            if spec is None:
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
                f"你此前的结论（供参考）: {json.dumps(previous, ensure_ascii=False, default=str)[:2000]}\n"
                "请用你的专属工具查证该问题，输出完整结构化结果（与此前相同的 schema）。"
            )
            validator = {
                AGENT_RUNTIME: _runtime_evidence_validator(ctx),
                AGENT_VULNERABILITY: _vulnerability_evidence_validator(ctx),
                AGENT_ASSET: None,
            }.get(spec.name)
            output, degraded_reason = _run_specialist(ctx, spec, context_text,
                                                      validate_fn=validator)
            entry: dict[str, Any] = {"agent": spec.name, "question": request.get("question", "")}
            if output is not None:
                entry["output"] = output
            else:
                entry["error"] = degraded_reason
                degraded.append(spec.name)
            results.append(entry)
        update["follow_up_results"] = results
        update["degraded_roles"] = list(dict.fromkeys(degraded))
        update["stage_status"] = state.record_stage("execute_follow_ups", "succeeded")
        return update
    return execute_follow_ups


def node_finalize(ctx: RunContext):
    def finalize(state: UnifiedAnalysisState) -> dict[str, Any]:
        snapshot = state.model_dump()
        final: dict[str, Any] = {"pipeline_version": PIPELINE_VERSION}
        if state.task_type == TASK_RISK_REVIEW:
            policy = audit_policy.apply_unified_audit_policy(snapshot)
            final["policy"] = policy.model_dump()
        else:
            final["aggregate"] = aggregator.aggregate_device_risk(
                state.investigation, state.vulnerability, state.runtime or state.runtime_program_fallback)
        plan = (state.decision or {}).get("response_plan") or {}
        if plan:
            plan = dict(plan)
            plan["requires_approval"] = True   # 程序强制：LLM 计划永远待审批
            final["plan"] = plan
            final["plan_execution_mode"] = "pending_approval"
        final["usage"] = ctx.meter.as_dict()
        final["degraded_roles"] = list(dict.fromkeys(state.degraded_roles))
        db = ctx.session()
        try:
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "finalize",
                              "policy": final.get("policy"),
                              "aggregate": final.get("aggregate")})
        finally:
            db.close()
        return {"final": final, "stage_status": state.record_stage("finalize", "succeeded")}
    return finalize


# ── 图构建 ───────────────────────────────────────────────────────────────────


def build_graph(ctx: RunContext):
    graph = StateGraph(UnifiedAnalysisState)
    graph.add_node("prepare", node_prepare(ctx))
    graph.add_node("investigate_asset", node_investigate_asset(ctx))
    graph.add_node("analyze_vulnerability", node_analyze_vulnerability(ctx))
    graph.add_node("analyze_runtime", node_analyze_runtime(ctx))
    graph.add_node("detect_conflicts", node_detect_conflicts(ctx))
    graph.add_node("directed_rereview", node_directed_rereview(ctx))
    graph.add_node("decide", node_decide(ctx))
    graph.add_node("execute_follow_ups", node_execute_follow_ups(ctx))
    graph.add_node("finalize", node_finalize(ctx))

    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "investigate_asset")
    # Agent 2 ∥ Agent 3 并行（共同仅依赖 Agent 1）
    graph.add_edge("investigate_asset", "analyze_vulnerability")
    graph.add_edge("investigate_asset", "analyze_runtime")
    graph.add_edge("analyze_vulnerability", "detect_conflicts")
    graph.add_edge("analyze_runtime", "detect_conflicts")
    graph.add_conditional_edges("detect_conflicts", _route_after_conflicts,
                                {"directed_rereview": "directed_rereview", "decide": "decide"})
    graph.add_edge("directed_rereview", "decide")
    graph.add_conditional_edges("decide", _route_after_decide,
                                {"execute_follow_ups": "execute_follow_ups", "finalize": "finalize"})
    graph.add_edge("execute_follow_ups", "decide")
    graph.add_edge("finalize", END)
    return graph.compile()


def new_run_id() -> str:
    return "UA-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
