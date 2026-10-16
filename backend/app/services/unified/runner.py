"""统一编排器运行生命周期：建行 → 后台执行 → 快照落库 → Trace 收尾。

- 影子模式（mode=shadow）：结果只写 UnifiedAnalysisRun 影子表，绝不触碰
  RiskAssessment 正式字段（专项测试锁定）；
- 正式模式（mode=formal）：由兼容适配层传入 sink 回调，经审计门禁后写入
  正式链路（M4 起）；
- 每个节点边界以 graph.stream 逐值快照（state_json），供 API 轮询与崩溃留痕。
"""
from __future__ import annotations

import json
import threading
import time
import traceback
from typing import Any, Callable

from sqlalchemy.orm import Session

from app import models
from app.database import SessionLocal
from app.services import trace_service as tracing
from app.services.unified import graph as graph_mod
from app.services.unified.agent_base import ChatClient, UsageMeter, default_client_factory
from app.services.unified.graph import RunContext, build_graph, new_run_id
from app.services.unified.schemas import PIPELINE_VERSION
from app.services.unified.state import (
    TASK_RISK_REVIEW,
    UnifiedAnalysisState,
    empty_state,
)

ClientFactory = Callable[[], ChatClient]
PersistSink = Callable[[Session, models.UnifiedAnalysisRun, UnifiedAnalysisState], None]


def _simple_tier_state(state: UnifiedAnalysisState) -> UnifiedAnalysisState:
    """简单分层：0 次 LLM，规则基线直通（审计 R8）。结论显式标注来源。"""
    baseline = state.baseline
    rule_action = baseline.get("preliminary_decision") or "monitor"
    # 与主门禁一致：immediate_fix 属于高影响操作，规则直通也不得自动确认
    needs_human = ((baseline.get("preliminary_level") or "") in {"High", "Critical"}
                   or rule_action == "immediate_fix")
    state.decision = {
        "verdicts": [{
            "object_id": state.object_id or baseline.get("object_id", state.target_ref),
            "impact_status": "rule_baseline",
            "risk_direction": "maintain",
            "recommended_action": rule_action,
            "recommended_priority": "high" if needs_human else "low",
            "confidence": 0.5,
            "supporting_evidence_ids": [],
            "reason": "规则分层直通：低复杂度候选不经 LLM 评审（成本分层，理由入 Trace 可审计）",
        }],
    }
    state.final = {
        "pipeline_version": PIPELINE_VERSION,
        "rule_tier_simple": True,
        "policy": {
            "status": "pending_human_review" if needs_human else "auto_confirmed",
            "reasons": ["rule_tier_simple"] + (["high_impact_operation_requires_human"] if rule_action == "immediate_fix" else []),
            "adjustment": 0,
            "final_score": baseline.get("preliminary_score"),
            "final_level": baseline.get("preliminary_level"),
        },
        "usage": {"llm_calls": 0, "max_llm_calls": 0, "usage": None, "budget_exceeded": False},
        "degraded_roles": [],
    }
    state.stage_status = {**state.stage_status, "prepare": "succeeded", "finalize": "succeeded"}
    return state


def run_unified_sync(db: Session, run_row: models.UnifiedAnalysisRun,
                     client_factory: ClientFactory = default_client_factory,
                     sink: PersistSink | None = None,
                     run_deadline_s: float = 900.0,
                     ablation_mask: frozenset[str] = frozenset(),
                     force_full_review: bool = False,
                     investigation_goal: str = "") -> models.UnifiedAnalysisRun:
    """同步执行一次统一编排（worker 线程/测试/实验共用）。

    ablation_mask（M4.2 实验专用，生产恒空）：被列入的角色报告不进入决策
    输入（角色照常执行）——用于语义消融度量各角色独立贡献，不是失败路径。
    """
    if run_row.mode == "shadow" and sink is not None:
        raise ValueError("shadow_sink_forbidden")
    state = empty_state(
        run_row.run_id, run_row.task_type, run_row.target_ref,
        run_row.target_type, run_row.mode)
    state.budgets.run_deadline_s = run_deadline_s
    state.investigation_goal = investigation_goal
    risk = None
    if run_row.task_type == TASK_RISK_REVIEW and run_row.risk_id:
        risk = db.get(models.RiskAssessment, run_row.risk_id)
        if risk is not None:
            state.object_id = f"risk-{risk.id}"

    def persist_snapshot(current: UnifiedAnalysisState) -> None:
        run_row.state_json = current.model_dump_json()
        run_row.agents_json = json.dumps(ctx.agent_logs, ensure_ascii=False, default=str)
        run_row.usage_json = json.dumps(ctx.meter.as_dict(), ensure_ascii=False)
        run_row.updated_at = models.utcnow()
        db.commit()

    meter = UsageMeter(max_llm_calls=state.budgets.max_llm_calls)
    ctx = RunContext(
        db_factory=SessionLocal, trace_id=run_row.trace_id, meter=meter,
        client_factory=client_factory, risk=risk, run_deadline_s=run_deadline_s,
        ablation_mask=frozenset(ablation_mask), force_full_review=force_full_review and run_row.mode == "shadow")
    if risk is not None:
        baseline_ids = json.loads(risk.evidence_packet_json or "{}") if risk.evidence_packet_json else {}
        ctx.packet_evidence_ids = {
            str(item.get("evidence_id"))
            for item in (baseline_ids.get("evidence_items") or [])
            if isinstance(item, dict) and item.get("evidence_id")}
    else:
        ctx.packet_evidence_ids = set()

    try:
        if risk is None and run_row.task_type == TASK_RISK_REVIEW:
            raise ValueError("risk_review 任务缺少有效风险事件")
        compiled = build_graph(ctx)
        # 简单分层不进图：0 次 LLM 直通
        probe = None if ctx.force_full_review else routing_probe(db, run_row, risk)
        if probe is not None:
            state = probe
            state = _simple_tier_state(state)
            # 与 LLM 路径字段对齐：simple 直通也必须留痕 routing/decision，
            # 否则消费方（API/实验分级）只能从 state_json 反推分层结论
            run_row.decision_json = json.dumps(state.decision or {}, ensure_ascii=False, default=str)
            run_row.routing_json = state.routing.model_dump_json()
            persist_snapshot(state)
            if sink is not None:
                sink(db, run_row, state)
            _complete(db, run_row, state, "completed", "")
            return run_row

        last_state: UnifiedAnalysisState = state
        for snapshot in compiled.stream(state, stream_mode="values"):
            if isinstance(snapshot, dict):
                snapshot = UnifiedAnalysisState.model_validate(snapshot)
            last_state = snapshot
            persist_snapshot(last_state)
        final_state = last_state
        run_row.decision_json = json.dumps(final_state.decision or {}, ensure_ascii=False, default=str)
        plan = (final_state.final or {}).get("plan")
        run_row.plan_json = json.dumps(plan or {}, ensure_ascii=False, default=str)
        run_row.routing_json = final_state.routing.model_dump_json()
        persist_snapshot(final_state)
        if sink is not None:
            sink(db, run_row, final_state)
        _complete(db, run_row, final_state, "completed", "")
    except Exception as exc:
        traceback.print_exc()
        state.error = f"unified orchestrator: {type(exc).__name__}: {exc}"
        state.degraded_roles = list(dict.fromkeys(state.degraded_roles))
        persist_snapshot(state)
        _complete(db, run_row, state, "failed", state.error)
    return run_row


def routing_probe(db: Session, run_row: models.UnifiedAnalysisRun,
                  risk: models.RiskAssessment | None) -> UnifiedAnalysisState | None:
    """建初始状态并判定是否 simple 分层；非 simple 返回 None 走图。"""
    from app.services.unified.routing import decide_routing

    state = empty_state(run_row.run_id, run_row.task_type, run_row.target_ref,
                        run_row.target_type, run_row.mode)
    if run_row.routing_json and run_row.routing_json != "{}":
        state.routing = state.routing.__class__.model_validate_json(run_row.routing_json)
        if state.routing.tier != "simple":
            return None
        state.baseline = _baseline_for_probe(db, run_row, risk)
        return state
    candidates = _candidate_rows(db, risk)
    routing = decide_routing(db, run_row.task_type, run_row.target_ref,
                             run_row.target_type, risk=risk, candidates=candidates)
    state.routing = routing
    state.baseline = _baseline_for_probe(db, run_row, risk, candidates)
    state.candidate_context = candidates
    state.object_id = f"risk-{risk.id}" if risk is not None else run_row.target_ref
    if routing.tier != "simple":
        return None
    return state


def _candidate_rows(db: Session, risk: models.RiskAssessment | None) -> list[dict[str, Any]]:
    if risk is None:
        return []
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    return [{
        "cve_id": risk.cve_id, "package_name": risk.package_name,
        "installed_version": match.installed_version if match else "",
        "fixed_version": match.fixed_version if match else "",
        "match_status": match.match_status if match else "",
    }]


def _baseline_for_probe(db: Session, run_row: models.UnifiedAnalysisRun,
                        risk: models.RiskAssessment | None,
                        candidates: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if risk is None:
        return {"object_id": run_row.target_ref}
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    asset = db.get(models.LinuxAsset, risk.asset_id)
    return {
        "object_id": f"risk-{risk.id}",
        "preliminary_score": risk.preliminary_score,
        "preliminary_level": risk.preliminary_level,
        "preliminary_decision": risk.preliminary_decision,
        "preliminary_reason": risk.preliminary_reason,
        "match_status": match.match_status if match else risk.affected_status,
        "installed_version": match.installed_version if match else "",
        "fixed_version": match.fixed_version if match else "",
        "package_name": risk.package_name,
        "cve_id": risk.cve_id,
        "business_level": asset.business_level if asset else "",
    }


def _complete(db: Session, run_row: models.UnifiedAnalysisRun,
              state: UnifiedAnalysisState, status: str, error: str) -> None:
    run_row.status = status
    run_row.error = error[:2000]
    run_row.completed_at = models.utcnow()
    db.commit()
    if run_row.trace_id:
        summary = {
            "stages": state.stage_status,
            "degraded_roles": state.degraded_roles,
            "usage": state.final.get("usage"),
        }
        if state.final.get("policy"):
            summary["policy"] = state.final["policy"]
        if state.final.get("aggregate"):
            summary["aggregate"] = state.final["aggregate"]
        tracing.finish_trace(db, run_row.trace_id, status, error=error, summary=summary)


def start_unified_run(task_type: str, target_ref: str, target_type: str,
                      risk_id: int | None = None, mode: str = "shadow",
                      client_factory: ClientFactory = default_client_factory,
                      sink: PersistSink | None = None,
                      force_full_review: bool = False,
                      investigation_goal: str = "") -> models.UnifiedAnalysisRun:
    """API 入口：创建运行记录 + Trace，后台线程执行。"""
    db = SessionLocal()
    try:
        trace = tracing.start_trace(
            db, task_type="unified_four_agent", target_type=target_type,
            target_ref=target_ref, run_ref_type="unified_analysis",
            run_ref_id="pending", metadata={"mode": mode, "task_type": task_type})
        run_row = models.UnifiedAnalysisRun(
            run_id=new_run_id(), task_type=task_type, target_type=target_type,
            target_ref=target_ref, mode=mode, status="running",
            risk_id=risk_id, trace_id=trace.trace_id)
        db.add(run_row)
        db.commit()
        trace.run_ref_id = run_row.run_id
        db.commit()

        def worker() -> None:
            worker_db = SessionLocal()
            try:
                row = worker_db.query(models.UnifiedAnalysisRun).filter_by(
                    run_id=run_row.run_id).one()
                run_unified_sync(worker_db, row, client_factory=client_factory, sink=sink,
                                 force_full_review=force_full_review, investigation_goal=investigation_goal)
            except Exception as exc:   # 编排级异常：整体失败并保留快照
                try:
                    row.status = "failed"
                    row.error = f"unified runner: {type(exc).__name__}: {exc}"[:2000]
                    row.completed_at = models.utcnow()
                    worker_db.commit()
                    tracing.finish_trace(worker_db, row.trace_id, "failed",
                                         error=row.error, summary={"stage": "runner_crash"})
                except Exception:
                    pass
            finally:
                worker_db.close()

        threading.Thread(target=worker, daemon=True).start()
        time.sleep(0.2)
        return run_row
    finally:
        db.close()
