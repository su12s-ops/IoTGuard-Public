"""统一任务追踪 API（第八阶段）。

只读查询 + 汇总统计，数据全部来自 trace_run / trace_event 真实记录：
- 列表分页 + 任务类型/状态过滤（trace_id/created_at 有索引）；
- 详情/时间线/智能体事件/Harness 事件/证据关联；
- payload 已在写入端脱敏（敏感键递归剔除、长度截断），本层只做序列化；
- 访问口径与既有只读端点一致（写入仍需控制令牌，由任务创建入口负责）。
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services import trace_service as tracing

router = APIRouter(prefix="/traces", tags=["Unified task trace"])


def _get_trace(db: Session, trace_id: str) -> models.TraceRun:
    if not trace_id or len(trace_id) > 48:
        raise HTTPException(404, "追踪记录不存在")
    row = tracing.get_trace(db, trace_id)
    if not row:
        raise HTTPException(404, "追踪记录不存在")
    return row


@router.get("")
def list_traces(task_type: str = "", status: str = "",
                page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                db: Session = Depends(get_db)):
    items, total = tracing.list_traces(db, task_type=task_type, status=status,
                                       page=page, page_size=page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size,
            "task_types": sorted(tracing.TASK_TYPES)}


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    """任务总览统计（AgentOps A 区数据源：真实记录聚合）。"""
    return tracing.summary_stats(db)


@router.get("/{trace_id}")
def trace_detail(trace_id: str, db: Session = Depends(get_db)):
    row = _get_trace(db, trace_id)
    data = tracing.serialize_run(row)
    data["events"] = tracing.trace_events(db, trace_id)
    data["evidence_index"] = tracing.evidence_for_trace(db, trace_id)
    return data


@router.get("/{trace_id}/timeline")
def timeline(trace_id: str, db: Session = Depends(get_db)):
    _get_trace(db, trace_id)
    return {"trace_id": trace_id, "events": tracing.trace_events(db, trace_id)}


@router.get("/{trace_id}/agents")
def agent_events(trace_id: str, db: Session = Depends(get_db)):
    """四智能体运行事件（agent_*），含 LLM 真实统计与输出摘要。"""
    _get_trace(db, trace_id)
    events = tracing.trace_events(db, trace_id)
    return {"trace_id": trace_id,
            "agents": [e for e in events if e["event_type"].startswith("agent_")]}


@router.get("/{trace_id}/harness")
def harness_events(trace_id: str, db: Session = Depends(get_db)):
    """Harness 安全执行事件 + 关联的 HarnessRun 真实状态。

    未关联 Harness（如只读分析任务）时如实返回 not_applicable/not_requested，
    不伪造修复状态。
    """
    row = _get_trace(db, trace_id)
    events = tracing.trace_events(db, trace_id)
    harness_items = [e for e in events if e["event_type"].startswith("harness_")]
    linked = None
    if row.harness_run_id:
        run = db.get(models.HarnessRun, row.harness_run_id)
        if run:
            linked = {
                "id": run.id, "asset_id": run.asset_id, "risk_id": run.risk_id,
                "status": run.status, "plan_hash": run.plan_hash,
                "approval_hash": run.approval_hash, "approved_by": run.approved_by,
                "attempts": run.attempts, "error": (run.error or "")[:500],
                "created_at": run.created_at, "completed_at": run.completed_at,
                "tool_calls": [
                    {"id": c.id, "tool": c.tool, "status": c.status,
                     "side_effect": c.side_effect, "duration_ms": c.duration_ms,
                     "phase": json.loads(c.arguments_json or "{}").get("_phase", "main"),
                     "error": (c.error or "")[:200]}
                    for c in db.query(models.HarnessToolCall)
                    .filter_by(run_id=run.id).order_by(models.HarnessToolCall.id)],
            }
    return {"trace_id": trace_id, "harness": linked, "events": harness_items,
            "association": ("linked" if linked else
                            "not_requested" if row.task_type == "four_agent_analysis"
                            else "not_applicable")}


@router.get("/{trace_id}/evidence")
def evidence(trace_id: str, db: Session = Depends(get_db)):
    """证据关联：事件引用的 SecurityEvidence 与 CVE 如实解析（缺失标 unresolved）。"""
    _get_trace(db, trace_id)
    return tracing.evidence_for_trace(db, trace_id)
