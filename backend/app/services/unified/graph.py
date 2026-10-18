"""唯一正式编排器：LangGraph StateGraph（Stage 9B）。

图结构（IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md §4.1）：

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel
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
    return max(0.0, min(ctx.agent_budget_s, ctx.remaining_s()))


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
        role_deadline = agent_started + _agent_deadline(ctx)
        agent = UnifiedToolLoopAgent(spec, ctx.client_factory(), meter=ctx.meter,
                                     tool_cache=ctx.tool_cache)
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
                    "请只引用真实存在的 evidence_id，重新输出完整 JSON。")
                retry = agent.run(db, context=retry_context,
                                  deadline_s=max(0.0, min(role_deadline - time.monotonic(), ctx.remaining_s())))
                if retry.status != "succeeded":
                    degraded_reason = retry.error or retry.status
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
            "llm_calls": result.llm_calls,
            "llm_usage": result.llm_usage,
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
            if ctx.force_full_review:
                routing.tier = "standard"
                routing.include_asset = routing.include_vulnerability = routing.include_runtime = routing.include_decision = True
                routing.skipped_agents = []
                routing.reason = "显式完整四角色研判；程序聚合与人审门禁独立执行"
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
            inventory_id = (packet.asset_facts.get("inventory_provenance") or {}).get("inventory_evidence_id")
            if inventory_id:
                ctx.packet_evidence_ids.add(inventory_id)
            for candidate in packet.candidates:
                for source in candidate.source_bundle.values():
                    value = source.get("value") or {}
                    records = value.get("records", [value]) if isinstance(value, dict) else []
                    for record in records:
                        if record.get("evidence_id"):
                            ctx.packet_evidence_ids.add(record["evidence_id"])
            ctx.emit(db, "stage_finished", actor="orchestrator", status="succeeded",
                     payload={"stage": "prepare_evidence",
                              "as_of": packet.as_of,
                              "candidates": len(packet.candidates),
                              "runtime_freshness": (packet.runtime_facts or {}).get("freshness")})
            return {
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
        f"真实清单身份与原始证据: {json.dumps(facts.get('inventory_provenance') or {}, ensure_ascii=False)}\n"
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
            f"业务调查问题: {state.investigation_goal}\n"
            f"本次候选包（完整清单截断时仍须逐一调查）: {json.dumps(state.candidate_context, ensure_ascii=False)}\n"
            "请先调用工具获取真实画像、暴露面与运行时数据质量，再输出结构化结论。\n"
            "evidence_inventory 必须来自 query_runtime_data_quality 的真实返回；"
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
        if not known:
            return errors
        cited: set[str] = set()
        for finding in output.get("findings") or []:
            if isinstance(finding, dict):
                cited.update(finding.get("supporting_evidence_ids") or [])
        unknown = sorted(cited - known)
        # A source can refresh while the run is active. Accept an actual stored
        # official snapshot only for this run's candidate CVE; fabricated and
        # unrelated official IDs remain rejected.
        if unknown and ctx.risk is not None:
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
                f"证据质量={investigation.get('evidence_quality')}\n"
                f"已调查组件及版本（最多20项，非完整性证明）: {json.dumps((investigation.get('components') or [])[:20], ensure_ascii=False)}\n"
                f"原始清单来源: {json.dumps(((_prep(state).get('asset_facts') or {}).get('inventory_provenance') or {}), ensure_ascii=False)}\n"
                "候选为空仅表示现有匹配范围内零命中，不得虚构 CVE，亦不得将画像显示截断误认为原始清单不完整。")
        context_text = (
            f"分析目标: {state.target_ref} 的候选 CVE 适用性。\n"
            f"本次调查与补证上下文: {state.investigation_goal}\n"
            f"候选清单（规则命中，供核查——规则结论本身可能误报）:\n"
            f"{json.dumps(state.candidate_context, ensure_ascii=False)}"
            f"{asset_summary}\n"
            "要求：用 query_version_impact 做真实版本比较；用 query_intelligence_sources 核对"
            "厂商/NVD/KEV/EPSS 各源状态是否互相矛盾；输入故意不包含规则分数，不要猜测基线结论；"
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
            + _vulnerability_prep_context(state)
        )
        output, degraded = _run_specialist(ctx, VULNERABILITY_ANALYST_SPEC, context_text,
                                           validate_fn=_vulnerability_evidence_validator(ctx, state))
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
                                                      validate_fn=validator)
            key = {AGENT_VULNERABILITY: "vulnerability",
                   AGENT_RUNTIME: "runtime",
                   AGENT_ASSET: "investigation"}[name]
            if output is None:
                # Stage-10 效率契约：复议失败不降级原结论——原报告有效时保留，
                # 未消解冲突已由 merge_rereview 确定性转人工，角色本身不应被
                # 标记降级（基线运行中复议失败曾把成功角色误标为 degraded）。
                if _is_empty_default(previous):
                    degraded.append(name)
                else:
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
        update["degraded_roles"] = degraded
        refreshed = conflicts_mod.merge_rereview(state.conflict_result, {
            **state.model_dump(), **update})
        update["conflict_result"] = refreshed
        return update
    return directed_rereview


def _route_after_decide(state: UnifiedAnalysisState) -> str:
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


def node_decide(ctx: RunContext):
    def decide(state: UnifiedAnalysisState) -> dict[str, Any]:
        facts = _deterministic_facts(state)
        # 语义消融（实验专用）：被屏蔽角色的报告不进入决策输入——角色照常执行，
        # 决策端按「该维度信息缺失」研判，用于度量各角色的独立分析贡献
        masked = sorted(ctx.ablation_mask)
        asset_report = None if AGENT_ASSET in ctx.ablation_mask else state.investigation
        vulnerability_report = (None if AGENT_VULNERABILITY in ctx.ablation_mask
                                else state.vulnerability)
        runtime_report = (None if AGENT_RUNTIME in ctx.ablation_mask
                          else (state.runtime or state.runtime_program_fallback))
        decision_context = {
            "object_id": state.object_id,
            "task_type": state.task_type,
            "baseline": {k: v for k, v in state.baseline.items()
                         if k not in {"packet_evidence_ids"}},
            "asset_report": asset_report,
            "vulnerability_report": vulnerability_report,
            "runtime_report": runtime_report,
            "runtime_report_is_program_fallback": state.runtime is None,
            "conflict_result": state.conflict_result.model_dump(),
            "degraded_roles": state.degraded_roles,
            "capability_marks": state.capability_marks,
            # M4.1：确定性核验事实（分支适用性/版本比较/厂商冲突/运行时新鲜度）。
            # 这些是程序核验结果，模型不得凭一般性推理推翻（约束见下方要求）。
            "deterministic_facts": facts,
            "follow_up_results": state.follow_up_results or None,
            "follow_up_round_used": state.follow_ups_used,
            # 防幻觉：可引用的证据 ID 全集（引用之外一律视为编造）
            "available_evidence_ids": sorted(_decision_known_ids(state)),
        }
        if masked:
            decision_context["semantic_ablation_masked"] = masked
        context_text = (
            "综合以下结构化材料完成研判与处置规划。\n"
            f"{json.dumps(decision_context, ensure_ascii=False, default=str)}\n"
            "要求：\n"
            "1. impact_status/risk_direction/recommended_action 只能取 schema 枚举；"
            "supporting_evidence_ids 只能引用 available_evidence_ids 中列出的证据 ID"
            "（CVE 编号、版本号、主机名都不是证据 ID，禁止填入）；\n"
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
                                           validate_fn=combined_validator)
        update: dict[str, Any] = {"stage_status": state.record_stage("decide", "succeeded")}
        if output is not None:
            update["decision"] = output
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
    各专家报告已引用项。"""
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
                f"预期效果: {request.get('expected_effect', '（未说明）')}\n"
                f"你此前的结论（供参考）: {json.dumps(previous, ensure_ascii=False, default=str)[:2000]}\n"
                "请用你的专属工具查证该问题，输出完整结构化结果（与此前相同的 schema）。\n"
                "相关性纪律：只查证所问的具体事实缺口，与本问题无关的常规信息不要展开；"
                "若你的工具无法回答该问题，在 data_gaps 如实说明而不是给出推断。"
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
        if state.task_type == TASK_RISK_REVIEW:
            policy = audit_policy.apply_unified_audit_policy(snapshot)
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
    graph.add_node("decide", node_decide(ctx))
    graph.add_node("execute_follow_ups", node_execute_follow_ups(ctx))
    graph.add_node("finalize", node_finalize(ctx))

    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "prepare_evidence")
    graph.add_edge("prepare_evidence", "investigate_asset")
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
