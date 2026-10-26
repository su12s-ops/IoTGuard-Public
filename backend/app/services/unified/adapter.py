"""兼容适配层（Stage 9B M4）：把既有 /api/analysis 正式入口接到统一编排器。

原则：
- 仅当 LINUXGUARD_UNIFIED_PIPELINE=on 时由路由切换到本模块；off/shadow
  模式下拒绝正式任务；旧 LLM 产品代码已退役；
- 响应契约与 System B 的 generate_and_save_report 兼容（前端/调用方无感）；
- 正式落库经 formal_sink：审计门禁结论写 RiskAssessment（语义与 System B
  的 _persist_event_result 一致），影子表同时保留完整状态；
- 设备级结论按 R1/F2 只读附加写 device_context_json，不参与既有门禁。
"""
from __future__ import annotations

import json
import hashlib
import threading
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app import config, models
from app.database import SessionLocal
from app.services.unified.agent_base import default_client_factory
from app.services.unified.runner import run_unified_sync
from app.services.unified.schemas import (
    AGENT_DECISION,
    PIPELINE_VERSION,
    AuditPolicyDecisionRecord,
)
from app.services.unified.state import TASK_RISK_REVIEW, UnifiedAnalysisState
from app.services.unified.task_runtime import VERSION as TASK_GRAPH_VERSION

UNIFIED_ADAPTER_VERSION = f"{PIPELINE_VERSION}+analysis-compat"
# A formal batch stays bounded, but "all eligible" is no longer silently
# truncated to one object. Objects beyond this cap remain explicitly listed as
# remaining/bounded_queue for a later round.
MAX_REVIEW_BATCH = 20


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def formal_sink(db: Session, run_row: models.UnifiedAnalysisRun,
                state: UnifiedAnalysisState) -> None:
    """正式模式落库：门禁结论 → RiskAssessment（fail-closed 语义不变）。"""
    if config.UNIFIED_PIPELINE_MODE != "on" or run_row.mode != "formal" or state.mode != "formal":
        raise ValueError("formal_source_required")
    risk = db.get(models.RiskAssessment, run_row.risk_id) if run_row.risk_id else None
    if risk is None:
        return
    from app.services.review_common import governance
    if not risk.active:
        admission = db.query(models.RiskGovernanceEvent).filter_by(
            risk_id=risk.id, kind="post_repair_reassessment_request").all()
        if not any(json.loads(e.payload_json).get("run_id") == run_row.run_id for e in admission):
            raise ValueError("inactive_risk_requires_historical_adjudication")
        governance.record(db, risk, "post_repair_assessment", "unified_four_agent", {
            "run_id": run_row.run_id, "trace_id": run_row.trace_id,
            "decision": state.decision, "policy": state.final.get("policy"),
            "degraded_roles": state.degraded_roles,
            "original_risk_preserved": True, "repair_authorization": False,
            "business_accepted": False})
        db.commit()
        return
    event = governance.assessment_record(db, risk, run_row, state)
    baseline = state.baseline or {}
    final = state.final or {}
    policy = AuditPolicyDecisionRecord.model_validate(final.get("policy") or {})
    facts_hash = json.loads(event.payload_json)["facts_hash"]
    previous_events = db.query(models.RiskGovernanceEvent.id).filter(
        models.RiskGovernanceEvent.risk_id == risk.id, models.RiskGovernanceEvent.kind == "native_assessment",
        models.RiskGovernanceEvent.id < event.id).order_by(models.RiskGovernanceEvent.id.desc()).first()
    if previous_events and db.get_bind().dialect.name == "sqlite":
        from sqlalchemy import func
        # Historical receipts may embed the entire telemetry store. Read only
        # comparison metadata rather than materializing that JSON in Python.
        schema, prior_hash = db.query(
            func.json_extract(models.RiskGovernanceEvent.payload_json, "$.facts_schema"),
            func.json_extract(models.RiskGovernanceEvent.payload_json, "$.facts_hash")
        ).filter(models.RiskGovernanceEvent.id == previous_events.id).one()
        previous_payload = {"facts_schema": schema, "facts_hash": prior_hash}
    else:
        previous_payload = json.loads(db.get(models.RiskGovernanceEvent, previous_events.id).payload_json) if previous_events else {}
    if previous_events and previous_payload.get("facts_schema") != json.loads(event.payload_json).get("facts_schema"):
        policy.status = "pending_human_review"
        policy.final_score = policy.final_level = None
        policy.reasons.append("facts_comparison_schema_changed_requires_review")
    if previous_events and previous_payload.get("facts_hash") == facts_hash:
        policy.status = "pending_human_review"
        policy.final_score = policy.final_level = None
        policy.reasons.append("same_facts_model_variance_not_new_evidence")
    if db.query(models.RiskGovernanceEvent).filter_by(risk_id=risk.id, kind="object_review_hold").first():
        policy.status = "pending_human_review"
        policy.final_score = policy.final_level = None
        policy.reasons.append("object_review_hold_requires_operator")
    decision = state.decision or {}
    verdicts = decision.get("verdicts") or []
    verdict = verdicts[0] if verdicts else {}
    if final.get("rule_tier_simple") and verdict:
        # 规则分层直通：决策取规则基线，不经 LLM；impact_status 非智能体枚举
        verdict = {**verdict, "impact_status": "potentially_affected",
                   "risk_direction": "maintain",
                   "recommended_priority": "low" if (baseline.get("preliminary_level") or "") not in {"High", "Critical"} else "high"}

    runtime = state.runtime or state.runtime_program_fallback or {}
    missing: list[str] = []
    for report in (state.investigation, state.vulnerability, decision):
        for item in (report or {}).get("missing_evidence") or []:
            missing.append(str(item))
    for verdict_item in verdicts:
        missing.extend(verdict_item.get("missing_evidence") or [])

    if governance.correction(db, risk):
        policy.status = "pending_human_review"
        policy.reasons.append("official_correction_execution_blocked")
        policy.final_score = policy.final_level = None
    risk.review_status = policy.status
    risk.human_review_required = policy.status == "pending_human_review"
    risk.review_adjustment = policy.adjustment
    risk.review_completed_at = datetime.now(timezone.utc)
    risk.review_failed_agents = json.dumps(
        list(dict.fromkeys(state.degraded_roles)), ensure_ascii=False)
    risk.review_conflicts = json.dumps(
        [item.get("description") for item in
         (state.conflict_result.model_dump().get("conflicts") or [])], ensure_ascii=False)
    risk.review_missing_evidence = json.dumps(list(dict.fromkeys(missing)), ensure_ascii=False)

    if verdict:
        risk.review_confidence = float(verdict.get("confidence") or 0)
        risk.review_verdict = verdict.get("impact_status") or "insufficient_evidence"
        risk.review_evidence_ids = json.dumps(
            verdict.get("supporting_evidence_ids") or [], ensure_ascii=False)
        risk.review_reason = verdict.get("reason") or ""
        risk.recommended_priority = verdict.get("recommended_priority") or ""
        risk.recommended_action = verdict.get("recommended_action") or ""
        risk.risk_direction = verdict.get("risk_direction") or "maintain"
        if "same_facts_model_variance_not_new_evidence" in policy.reasons:
            risk.risk_direction = json.loads(event.payload_json)["previous"].get("risk_direction") or "maintain"
    else:
        risk.review_confidence = 0
        risk.review_verdict = "insufficient_evidence"
        risk.review_evidence_ids = "[]"
        risk.review_reason = "; ".join(policy.reasons)
        risk.recommended_action = "collect_more_evidence"
        risk.risk_direction = "maintain"

    if policy.status == "auto_confirmed":
        risk.final_score = policy.final_score
        risk.risk_level = policy.final_level
        risk.decision = risk.recommended_action
        risk.reason = risk.review_reason
    else:
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
        risk.reason = risk.review_reason or "统一审计门禁要求人工审核"
    risk.audit_policy_reasons = json.dumps(policy.reasons, ensure_ascii=False)
    state.final["policy"] = policy.model_dump()
    run_row.state_json = state.model_dump_json()
    risk.evidence_packet_json = json.dumps(state.evidence_prep or {}, ensure_ascii=False, default=str)
    risk.agent_results_json = json.dumps({"asset_investigator": state.investigation,
        "vulnerability_analyst": state.vulnerability, "runtime_analyst": state.runtime, "decision_planner": state.decision}, ensure_ascii=False)
    risk.conflict_result_json = state.conflict_result.model_dump_json()

    # F2/R1 对账：设备级运行时结论只读附加（不参与既有门禁语义）
    risk.device_context_json = json.dumps({
        "pipeline_version": PIPELINE_VERSION,
        "unified_run_id": run_row.run_id,
        "runtime_status": runtime.get("runtime_status"),
        "behavior_level": runtime.get("behavior_level"),
        "evidence_ids": (runtime.get("evidence_ids") or [])[:20],
        "evidence_freshness": runtime.get("evidence_freshness"),
        "written_at": _utc_now_iso(),
    }, ensure_ascii=False)

    _write_agent_audit_records(db, run_row, state, risk)
    db.commit()


def _write_agent_audit_records(db: Session, run_row: models.UnifiedAnalysisRun,
                               state: UnifiedAnalysisState,
                               risk: models.RiskAssessment) -> None:
    """逐智能体审计记录（与 System B AgentAuditRecord 同表同语义）。"""
    from app.config import DEEPSEEK_MODEL

    structured_by_agent = {
        "asset_investigator": state.investigation,
        "vulnerability_analyst": state.vulnerability,
        "runtime_analyst": state.runtime,
        "decision_planner": state.decision,
    }
    logs = json.loads(run_row.agents_json or "{}")
    for name, log in logs.items():
        output = structured_by_agent.get(name)
        refs: list[str] = []
        if isinstance(output, dict):
            refs.extend(output.get("evidence_ids") or [])
            for finding in output.get("findings") or []:
                if isinstance(finding, dict):
                    refs.extend(finding.get("supporting_evidence_ids") or [])
                    if finding.get("evidence_id"):
                        refs.append(str(finding["evidence_id"]))
            for verdict in output.get("verdicts") or []:
                if isinstance(verdict, dict):
                    refs.extend(verdict.get("supporting_evidence_ids") or [])
        db.add(models.AgentAuditRecord(
            run_id=run_row.run_id,
            risk_id=risk.id,
            object_id=state.object_id,
            agent_name=name,
            model=DEEPSEEK_MODEL,
            evidence_ids_json=json.dumps(sorted(set(refs)), ensure_ascii=False),
            structured_output_json=json.dumps(output, ensure_ascii=False, default=str),
            raw_response="",
            parse_status="reused" if log.get("status") == "reused" else
                         "valid" if log.get("status") == "succeeded" else "invalid",
            retry_count=max(0, int(log.get("attempts") or 1) - 1),
            latency_ms=int(log.get("latency_ms") or 0),
            error=(log.get("error") or "")[:1200],
        ))


def _event_result(run_row: models.UnifiedAnalysisRun, state: UnifiedAnalysisState) -> dict[str, Any]:
    decision = state.decision or {}
    verdicts = decision.get("verdicts") or []
    return {
        "object_id": state.object_id,
        "risk_id": run_row.risk_id,
        "run_id": run_row.run_id,
        "coordinator": verdicts[0] if verdicts else None,
        "audit_policy": (state.final or {}).get("policy"),
        "conflict": state.conflict_result.model_dump(),
        "degraded_roles": state.degraded_roles,
        "routing": state.routing.model_dump(),
        "plan": (state.final or {}).get("plan"),
        "pipeline_version": PIPELINE_VERSION,
    }


def _ordered_selected_risks(db: Session, risk_ids: list[int]) -> list[models.RiskAssessment]:
    """Fetch selected risks while preserving the priority order chosen by the API.

    SQL ``IN`` does not guarantee row order; the background worker must review
    the same order the operator saw, otherwise the lowest-priority object can
    be processed first without any report saying so.
    """
    rows = (db.query(models.RiskAssessment)
            .filter(models.RiskAssessment.id.in_(risk_ids)).all() if risk_ids else [])
    by_id = {row.id: row for row in rows}
    return [by_id[risk_id] for risk_id in risk_ids if risk_id in by_id]


def _aggregate_agent_executions(rows: list[models.UnifiedAnalysisRun]) -> dict[str, Any]:
    aggregate: dict[str, Any] = {}
    for name in ("asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"):
        logs = [json.loads(row.agents_json or "{}").get(name) for row in rows]
        logs = [log for log in logs if log]
        aggregate[name] = {
            "status": "failed" if any(log.get("status") not in {"succeeded", "reused"} for log in logs)
            else ("completed" if logs else "skipped"),
            "attempts": sum(int(log.get("attempts") or 0) for log in logs),
            "duration_ms": sum(int(log.get("latency_ms") or 0) for log in logs),
            "opinion_count": sum(log.get("status") == "succeeded" for log in logs),
            "reused_count": sum(log.get("status") == "reused" for log in logs),
            "error": "; ".join(log.get("error", "") for log in logs if log.get("error")),
        }
    return aggregate


def run_review_analysis_unified(db: Session, run_id: str | None = None,
                                selected_risks=None, selection_result=None,
                                progress_callback=None,
                                client_factory=None, investigation_goal: str = "",
                                asset_id: int = 0, batch_runtime=None) -> dict[str, Any]:
    """System B run_review_analysis 的统一编排器实现（正式模式）。

    每事件一次完整四智能体编排，经 formal_sink 写正式字段。
    task_graph 在完整资源准入后使用独立会话并发执行；响应形状与 System B 兼容。
    """
    from app.services.review_common import select_candidates

    if config.UNIFIED_PIPELINE_MODE != "on":
        raise ValueError("formal_unified_mode_required")
    del selection_result
    selected = list(select_candidates(db, asset_id=asset_id)["_selected_risks"]
                    if selected_risks is None else selected_risks)
    if asset_id:
        outside = [risk.id for risk in selected if risk.asset_id != asset_id]
        if outside:
            raise ValueError(f"risk_outside_asset_scope:{outside}")
    run_id = run_id or uuid.uuid4().hex[:12]
    if not selected:
        return {"status": "no_candidates", "review_run_id": run_id, "model_called": False}

    if batch_runtime is None and config.REVIEW_EXECUTION_MODE == "task_graph":
        from sqlalchemy.orm import sessionmaker
        from app.services.unified.task_runtime import for_review
        batch_runtime = for_review(db, run_id, sessionmaker(bind=db.get_bind(), autoflush=False),
                                   client_factory or default_client_factory)

    rows: list[models.UnifiedAnalysisRun] = []
    states: list[UnifiedAnalysisState] = []
    deferred = []

    def execute_one(worker_db, risk):
        if batch_runtime is not None and batch_runtime.remaining() <= 0:
            return None
        receipt = worker_db.query(models.RiskGovernanceEvent).filter_by(
            risk_id=risk.id, kind="post_repair_reassessment_request").all()
        post_repair = any(json.loads(e.payload_json).get("run_id") == f"UA-{run_id}-{risk.id}" for e in receipt)
        if not post_repair and (not risk.active or risk.review_status in {"inactive", "resolved", "human_reviewing"}):
            raise ValueError("risk_not_eligible_for_formal_analysis")
        if batch_runtime is not None and not post_repair:
            risk.review_status = "agent_reviewing"
            worker_db.commit()
        run_row = models.UnifiedAnalysisRun(
            run_id=f"UA-{run_id}-{risk.id}", task_type=TASK_RISK_REVIEW,
            target_type="linux_host",
            target_ref=(worker_db.get(models.LinuxAsset, risk.asset_id).hostname
                        if worker_db.get(models.LinuxAsset, risk.asset_id) else ""),
            mode="formal", status="running", risk_id=risk.id)
        worker_db.add(run_row)
        from app.services import trace_service as tracing
        trace = tracing.start_trace(worker_db, task_type="unified_four_agent", target_type="linux_host",
            target_ref=run_row.target_ref, run_ref_type="unified_analysis", run_ref_id=run_row.run_id,
            metadata={"mode": "formal", "formal_entry": "/api/analysis", "risk_id": risk.id})
        run_row.trace_id = trace.trace_id
        worker_db.commit()
        options = {"batch_runtime": batch_runtime} if batch_runtime is not None else {}
        run_unified_sync(worker_db, run_row, sink=formal_sink, force_full_review=True,
                         investigation_goal=investigation_goal,
                         client_factory=client_factory or default_client_factory, **options)
        if run_row.status == "failed" and not post_repair:
            # runner 会捕获编排级异常并把运行标记 failed（不抛出、不落 sink）。
            # 正式路径必须与 System B 的 _fail_selected 同语义：fail-closed 落
            # 人工门禁，不能把风险停留在 agent_reviewing。
            risk.review_status = "pending_human_review"
            risk.human_review_required = True
            risk.review_reason = f"unified_orchestrator_failed:{(run_row.error or 'unknown')[:1000]}"
            risk.final_score = None
            risk.risk_level = None
            risk.decision = None
            worker_db.commit()
        return run_row.run_id

    def record(risk_id, completed_run_id):
        db.expire_all()
        if completed_run_id is None:
            risk = db.get(models.RiskAssessment, risk_id)
            risk.review_status = "candidate"
            reason = batch_runtime.admission_stop_reason or "analysis_window_exhausted"
            risk.review_reason = reason + "; 未启动研判，保留候选等待继续"
            deferred.append(risk_id)
            db.commit()
            return
        run_row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=completed_run_id).one()
        rows.append(run_row)
        states.append(UnifiedAnalysisState.model_validate_json(run_row.state_json))
        if progress_callback:
            progress_callback(
                current_stage="audit_policy",
                agent_executions=_aggregate_agent_executions(rows),
                processed_object_count=len(rows),
                current_object_id=f"risk-{risk_id}",
                progress_message=f"unified review done risk-{risk_id}",
                progress_percent=round(90 * len(rows) / len(selected)),
            )

    if batch_runtime is None:
        for risk in selected:
            record(risk.id, execute_one(db, risk))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        risk_ids = [risk.id for risk in selected]
        def work(risk_id):
            review_id = f"UA-{run_id}-{risk_id}"
            if not batch_runtime.acquire_review(review_id):
                return None
            try:
                with batch_runtime.session_factory() as worker_db:
                    return execute_one(worker_db, worker_db.get(models.RiskAssessment, risk_id))
            finally:
                batch_runtime.release_review(review_id)
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="risk-task") as pool:
            pending = {pool.submit(work, risk_id): risk_id for risk_id in risk_ids}
            for future in as_completed(pending):
                record(pending[future], future.result())

    completed = sum(1 for state in states
                    if (state.final or {}).get("policy", {}).get("status") == "auto_confirmed")
    human = len(states) - completed
    status = "completed" if human == 0 else ("partial" if completed else "human_review")
    if deferred:
        status = "partial"
    event_results = [_event_result(row, state) for row, state in zip(rows, states)]
    total_tokens = 0
    for row in rows:
        usage = json.loads(row.usage_json or "{}")
        total_tokens += int((usage.get("usage") or {}).get("total_tokens") or 0)
    return {
        "status": status,
        "valid_verdicts": [event["coordinator"] for event in event_results if event["coordinator"]],
        "event_results": event_results,
        "candidate_count": len(selected),
        "selected_object_count": len(selected),
        "processed_object_count": len(rows),
        "completed_object_count": completed,
        "human_review_object_count": human,
        "agent_executions": _aggregate_agent_executions(rows),
        "answer": f"本批选入 {len(selected)} 条，已处理 {len(rows)} 条：自动确认 {completed} 条，人工审核 {human} 条，延期 {len(deferred)} 条。",
        "termination_reason": ((batch_runtime.admission_stop_reason or "analysis_window_exhausted") if deferred else
                               "pipeline_completed" if human == 0 else "audit_policy_human_review"),
        "current_stage": "audit_policy",
        "pipeline_version": UNIFIED_ADAPTER_VERSION,
        "unified_run_ids": [row.run_id for row in rows],
        "total_tokens": total_tokens,
        "review_run_id": run_id,
        "model_called": any(json.loads(row.usage_json or "{}").get("llm_requests", 0) for row in rows),
        "deferred_object_ids": deferred,
        "execution_profile": "task_graph" if batch_runtime is not None else "legacy",
    }


_admission_lock = threading.RLock()


def _admission(function):
    from functools import wraps
    @wraps(function)
    def dispatch(db, *args, **kwargs):
        with _admission_lock:
            if db.query(models.AnalysisReport).filter_by(status="running").first():
                raise ValueError("formal_worker_busy")
            return function(db, *args, **kwargs)
    return dispatch


@_admission
def generate_and_save_report_unified(db: Session, run_id: str | None = None,
                                     background: bool = False,
                                     client_factory=None, risk_id: int = 0, batch_size: int = 1,
                                     investigation_goal: str = "", post_repair: bool = False,
                                     asset_id: int = 0) -> dict[str, Any]:
    """System B generate_and_save_report 的统一编排器实现（正式模式入口）。"""
    from app.services.review_common import select_candidates

    if config.UNIFIED_PIPELINE_MODE != "on":
        raise ValueError("formal_unified_mode_required")
    selection = select_candidates(db, asset_id=asset_id)
    eligible = selection["_selected_risks"]
    if post_repair:
        risk = db.get(models.RiskAssessment, risk_id) if risk_id else None
        evidence = db.query(models.CollectionEvidence).filter_by(asset_id=risk.asset_id).filter(
            models.CollectionEvidence.evidence_id.startswith("INV-")).order_by(
            models.CollectionEvidence.id.desc()).first() if risk else None
        from app.services.review_common.governance import correction
        if not risk or (asset_id and risk.asset_id != asset_id) or risk.active or risk.review_status != "resolved" or correction(db, risk) or not evidence:
            raise ValueError("resolved_repaired_risk_with_inventory_required")
        if not evidence.evidence_id.startswith("INV-") or hashlib.sha256(evidence.raw_text.encode()).hexdigest() != evidence.content_sha256:
            raise ValueError("intact_inventory_required")
        eligible = [risk]
    if risk_id:
        eligible = [risk for risk in eligible if risk.id == risk_id]
        if not eligible:
            raise ValueError("risk_not_eligible_for_formal_analysis")
    if asset_id:
        outside = [risk.id for risk in eligible if risk.asset_id != asset_id]
        if outside:
            raise ValueError(f"risk_outside_asset_scope:{outside}")
    # Explicit scope: 0 = all eligible up to the bounded cap; positive = an
    # operator-requested smaller batch. Never a hidden default of one.
    requested_batch = int(batch_size or 0)
    limit = (MAX_REVIEW_BATCH if requested_batch == 0
             else max(1, min(requested_batch, MAX_REVIEW_BATCH)))
    ordered = sorted(
        eligible,
        key=lambda risk: (risk.priority_rank if risk.priority_rank is not None else 10 ** 9, risk.id),
    )
    chosen = ordered[:limit]
    selected_ids = {r.id for r in chosen}
    selection["skipped_objects"] = [item for item in selection["skipped_objects"]
                                    if item.get("object_id") not in {f"risk-{i}" for i in selected_ids}]
    selection["skipped_objects"] += [
        {"object_id": f"risk-{r.id}", "reason": "bounded_queue",
         "detail": f"batch_cap={MAX_REVIEW_BATCH}"}
        for r in ordered if r.id not in selected_ids
    ]
    selection["_selected_risks"] = chosen
    selection["selected_object_ids"] = [f"risk-{r.id}" for r in chosen]
    selection["selected_object_count"] = len(chosen)
    selection["eligible_object_count"] = len(ordered)
    selection["remaining_object_count"] = max(0, len(ordered) - len(chosen))
    selection["requested_batch_size"] = requested_batch
    selection["batch_cap"] = MAX_REVIEW_BATCH
    selection["selection_mode"] = "single_risk" if risk_id else "all_eligible"
    selected = selection["_selected_risks"]
    run_id = run_id or uuid.uuid4().hex[:12]
    if not selected:
        return {
            "run_id": "", "status": "no_candidates",
            "candidate_count": selection["candidate_count"],
            "selected_object_count": 0,
            "eligible_object_count": selection.get("eligible_object_count", 0),
            "remaining_object_count": 0,
            "requested_batch_size": requested_batch,
            "batch_cap": MAX_REVIEW_BATCH,
            "selection_mode": selection["selection_mode"],
            "total_risks_in_db": selection["total_risks_in_db"],
            "skipped_objects": selection["skipped_objects"], "selected_object_ids": [],
            "pipeline_version": UNIFIED_ADAPTER_VERSION, "model_called": False,
            "message": "当前没有可进入智能研判的候选对象",
        }
    report = models.AnalysisReport(
        model=config.DEEPSEEK_MODEL, status="running", review_run_id=run_id,
        pipeline_version=(UNIFIED_ADAPTER_VERSION + "+" + TASK_GRAPH_VERSION
            if config.REVIEW_EXECUTION_MODE == "task_graph" else UNIFIED_ADAPTER_VERSION), current_stage="agent_reviewing",
        candidate_count=selection["candidate_count"],
        selected_object_count=len(selected),
        selected_object_ids_json=json.dumps(selection["selected_object_ids"], ensure_ascii=False),
        skipped_objects_json=json.dumps(selection["skipped_objects"], ensure_ascii=False),
        progress_percent=10, progress_message="Unified four-agent review started",
        progress_sequence=1, progress_updated_at=datetime.now(timezone.utc))
    db.add(report)
    for risk in selected:
        from app.services.review_common.governance import invalidate_prior_authorizations
        if post_repair:
            from app.services.review_common.governance import record, snapshot
            record(db, risk, "post_repair_reassessment_request", "authenticated_control_api", {
                "run_id": f"UA-{run_id}-{risk.id}", "inventory_id": evidence.evidence_id,
                "inventory_sha256": evidence.content_sha256, "original": snapshot(risk),
                "repair_authorization": False, "business_accepted": False})
            continue
        invalidate_prior_authorizations(db, risk, "new_formal_assessment_requires_new_approval")
        risk.review_status = "queued" if config.REVIEW_EXECUTION_MODE == "task_graph" else "agent_reviewing"
    db.commit()
    db.refresh(report)
    risk_ids = [risk.id for risk in selected]

    def _finish(worker_db: Session, worker_report: models.AnalysisReport,
                result: dict[str, Any]) -> None:
        worker_report.status = result["status"]
        worker_report.answer = result.get("answer", "")
        worker_report.verdict_json = json.dumps({
            "pipeline_version": UNIFIED_ADAPTER_VERSION,
            "event_results": result.get("event_results", []),
            "object_verdicts": result.get("valid_verdicts", []),
            "overall_summary": result.get("answer", ""),
        }, ensure_ascii=False, default=str)
        # opinions_json 保持 v3 的逐事件列表形态（report_service F1 修复已兼容）
        worker_report.opinions_json = json.dumps(result.get("event_results", []),
                                                 ensure_ascii=False, default=str)
        worker_report.agent_executions_json = json.dumps(
            result.get("agent_executions", {}), ensure_ascii=False)
        worker_report.termination_reason = result.get("termination_reason", "")
        worker_report.current_stage = result.get("current_stage", "audit_policy")
        worker_report.processed_object_count = result.get(
            "processed_object_count", result.get("selected_object_count", 0))
        worker_report.completed_object_count = result.get("completed_object_count", 0)
        worker_report.human_review_object_count = result.get("human_review_object_count", 0)
        worker_report.object_verdict_count = len(result.get("valid_verdicts", []))
        worker_report.progress_percent = (round(90 * len(result.get("unified_run_ids", [])) /
            max(1, worker_report.selected_object_count)) if result.get("deferred_object_ids") else 100)
        worker_report.progress_message = ("完整研判所需的预算或时间不足，未启动项保留为候选" if result.get("deferred_object_ids")
                                          else "Unified review completed")
        worker_report.progress_sequence = int(worker_report.progress_sequence or 0) + 1
        worker_report.progress_updated_at = datetime.now(timezone.utc)
        worker_report.completed_at = datetime.now(timezone.utc)
        worker_db.commit()

    if background:
        def worker() -> None:
            worker_db = SessionLocal()
            try:
                worker_report = worker_db.query(models.AnalysisReport).filter_by(
                    review_run_id=run_id).one()
                # Preserve the operator-visible priority order; an IN query
                # does not guarantee order and previously caused the lowest
                # priority object (highest id) to be reviewed first.
                worker_selected = _ordered_selected_risks(worker_db, risk_ids)
                result = run_review_analysis_unified(
                    worker_db, run_id, worker_selected,
                    progress_callback=lambda **payload: _progress(worker_db, run_id, **payload),
                    client_factory=client_factory, investigation_goal=investigation_goal,
                    asset_id=asset_id)
                _finish(worker_db, worker_report, result)
            except Exception as exc:
                traceback.print_exc()
                worker_selected = worker_db.query(models.RiskAssessment).filter(
                    models.RiskAssessment.id.in_(risk_ids)).all()
                for risk in worker_selected:
                    if post_repair:
                        continue
                    risk.review_status = "pending_human_review"
                    risk.human_review_required = True
                    risk.review_reason = f"unified_background_failure:{exc}"
                    risk.final_score = None
                    risk.risk_level = None
                    risk.decision = None
                worker_report = worker_db.query(models.AnalysisReport).filter_by(
                    review_run_id=run_id).one_or_none()
                if worker_report:
                    worker_report.status = "human_review"
                    worker_report.error = str(exc)[:2000]
                    worker_report.progress_percent = 100
                    worker_report.completed_at = datetime.now(timezone.utc)
                    worker_db.commit()
            finally:
                worker_db.close()

        threading.Thread(target=worker, daemon=True).start()
        return {
            "run_id": run_id, "report_id": report.id, "model": report.model,
            "status": "running", "candidate_count": selection["candidate_count"],
            "selected_object_count": len(selected),
            "eligible_object_count": selection.get("eligible_object_count", len(selected)),
            "remaining_object_count": selection.get("remaining_object_count", 0),
            "requested_batch_size": requested_batch,
            "batch_cap": MAX_REVIEW_BATCH,
            "selection_mode": selection["selection_mode"],
            "total_risks_in_db": selection["total_risks_in_db"],
            "skipped_objects": selection["skipped_objects"],
            "selected_object_ids": selection["selected_object_ids"],
            "pipeline_version": UNIFIED_ADAPTER_VERSION,
            "current_stage": "agent_reviewing", "progress_percent": report.progress_percent,
            "current_object_id": "", "progress_message": report.progress_message,
            "progress_sequence": report.progress_sequence,
            "model_called": True,
            "created_at": report.created_at.isoformat() if report.created_at else "",
        }

    result = run_review_analysis_unified(db, run_id, selected, client_factory=client_factory,
                                         investigation_goal=investigation_goal, asset_id=asset_id)
    _finish(db, report, result)
    result.update({
        "report_id": report.id,
        "eligible_object_count": selection.get("eligible_object_count", len(selected)),
        "remaining_object_count": selection.get("remaining_object_count", 0),
        "requested_batch_size": requested_batch,
        "batch_cap": MAX_REVIEW_BATCH,
        "selection_mode": selection["selection_mode"],
    })
    return result


def _progress(db: Session, run_id: str, **payload: Any) -> None:
    report = db.query(models.AnalysisReport).filter_by(review_run_id=run_id).one_or_none()
    if report:
        report.current_stage = payload.get("current_stage", "")
        report.processed_object_count = payload.get("processed_object_count", 0)
        report.current_object_id = payload.get("current_object_id", "")
        report.progress_message = payload.get("progress_message", "")
        report.progress_percent = max(int(report.progress_percent or 0),
                                      int(payload.get("progress_percent") or 0))
        report.progress_sequence = int(report.progress_sequence or 0) + 1
        report.progress_updated_at = datetime.now(timezone.utc)
        db.commit()


def persist_investigation_report(db, row, state):
    """Publish a formal reanalysis receipt through the existing report read model.

    The original batch report stays historical; /analysis/latest and exported
    reports must point to the new INV-driven run, not the pre-collection draft.
    """
    if row.mode != "formal" or state.mode != "formal":
        raise ValueError("formal_investigation_report_required")
    if db.query(models.AnalysisReport).filter_by(review_run_id=row.run_id).first():
        return
    event = _event_result(row, state)
    human = (state.final.get("policy") or {}).get("status") != "auto_confirmed"
    db.add(models.AnalysisReport(review_run_id=row.run_id, model=config.DEEPSEEK_MODEL,
        pipeline_version=UNIFIED_ADAPTER_VERSION, status="human_review" if human else "completed",
        current_stage="audit_policy", candidate_count=1, selected_object_count=1,
        processed_object_count=1, completed_object_count=0 if human else 1,
        human_review_object_count=1 if human else 0, object_verdict_count=bool(event["coordinator"]),
        selected_object_ids_json=json.dumps([state.object_id]), progress_percent=100,
        agent_executions_json=json.dumps(_aggregate_agent_executions([row]), ensure_ascii=False),
        verdict_json=json.dumps({"pipeline_version": UNIFIED_ADAPTER_VERSION, "event_results": [event],
            "object_verdicts": [event["coordinator"]] if event["coordinator"] else [],
            "overall_summary": "授权只读补采后的统一四角色正式再研判；人工门禁与修复授权仍然独立。"}, ensure_ascii=False),
        opinions_json=json.dumps([event], ensure_ascii=False),
        answer="授权只读补采后的统一四角色正式再研判；原报告作为历史保留。",
        termination_reason="investigation_reanalysis", completed_at=models.utcnow()))
    db.commit()
