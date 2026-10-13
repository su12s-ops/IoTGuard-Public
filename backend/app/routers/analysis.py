"""四智能体联合研判 API —— 任务式接口 + 状态查询。"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db, recover_stale_running
from app.services.device_access import require_control
from app.services.agent_group_chat import (
    PIPELINE_VERSION,
    generate_and_save_report,
    latest_analysis,
    preflight_check,
    review_status,
    _explain_candidate_selection,
    apply_human_review,
)

router = APIRouter(prefix="/analysis", tags=["Multi-Agent Review"])


# ═══════════════════════════════════════════════════════════════════════════
# 共享序列化器
# ═══════════════════════════════════════════════════════════════════════════

def _safe_json(raw: str | None, default=None):
    if default is None:
        default = {}
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        return default


def _safe_json_list(raw: str | None):
    try:
        return json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []


def _serialize_run(report) -> dict:
    """将 AnalysisReport 序列化为统一响应格式。"""
    executions = _safe_json(report.agent_executions_json, {})
    verdict_data = _safe_json(report.verdict_json, {})
    selected_ids = _safe_json_list(report.selected_object_ids_json)
    skipped = _safe_json_list(report.skipped_objects_json)

    pipeline_ver = getattr(report, "pipeline_version", "") or ""
    is_legacy = not pipeline_ver or "max_turns" in (report.termination_reason or "").lower()

    # 状态修正
    display_status = report.status
    if is_legacy and report.status == "running":
        display_status = "interrupted"
    elif is_legacy and report.status not in ("failed", "skipped", "no_candidates", "interrupted"):
        # 旧报告标记
        pass

    return {
        "run_id": report.review_run_id or str(report.id),
        "report_id": report.id,
        "status": display_status,
        "pipeline_version": pipeline_ver or "legacy",
        "current_stage": getattr(report, "current_stage", "") or "",
        "candidate_count": report.candidate_count or 0,
        "selected_object_count": getattr(report, "selected_object_count", 0) or 0,
        "processed_object_count": getattr(report, "processed_object_count", 0) or 0,
        "completed_object_count": getattr(report, "completed_object_count", 0) or 0,
        "human_review_object_count": getattr(report, "human_review_object_count", 0) or 0,
        "object_verdict_count": report.object_verdict_count or 0,
        "progress_percent": getattr(report, "progress_percent", 0) or 0,
        "current_object_id": getattr(report, "current_object_id", "") or "",
        "progress_message": getattr(report, "progress_message", "") or "",
        "progress_sequence": getattr(report, "progress_sequence", 0) or 0,
        "progress_updated_at": (
            report.progress_updated_at.isoformat()
            if getattr(report, "progress_updated_at", None) else ""
        ),
        "selected_object_ids": selected_ids,
        "skipped_objects": skipped,
        "agent_executions": executions,
        "agent_metrics": executions,
        "verdict": verdict_data,
        "answer": report.answer,
        "error": report.error,
        "termination_reason": report.termination_reason or "",
        "created_at": report.created_at.isoformat() if report.created_at else "",
        "completed_at": report.completed_at.isoformat() if report.completed_at else "",
    }


# ═══════════════════════════════════════════════════════════════════════════
# 状态与配置
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/status")
def status():
    """返回智能研判模块的配置状态（含流水线步骤与裁定类型）。"""
    return review_status()


@router.get("/preflight")
def preflight(db: Session = Depends(get_db)):
    """候选预检：返回进入智能研判前的关键统计指标。

    包含对象选择解释：总风险数、选中数、跳过对象及原因。
    """
    result = preflight_check(db)
    selection = _explain_candidate_selection(db)
    result["total_risks_in_db"] = selection["total_risks_in_db"]
    result["selected_object_count"] = selection["selected_object_count"]
    result["unselected_count"] = selection["unselected_count"]
    result["skipped_objects"] = selection["skipped_objects"]
    result["selected_object_ids"] = selection["selected_object_ids"]
    result["pipeline_version"] = PIPELINE_VERSION
    return result


# ═══════════════════════════════════════════════════════════════════════════
# 任务式接口（推荐）
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/runs")
def create_run(retry_failed: bool = False, db: Session = Depends(get_db)):
    """启动一次四智能体联合研判任务（后台执行）。

    返回 run_id 和当前状态，前端应轮询 GET /runs/{run_id} 获取进度。
    若候选为 0，快速返回 no_candidates 状态（不调用模型）。
    """
    # 先恢复超时的 running 状态
    recovered = recover_stale_running(max_minutes=30)

    retry_reset_count = 0
    if retry_failed:
        retry_reset_count = _reset_latest_failed_objects(db)

    # 候选选择
    selection = _explain_candidate_selection(db)
    candidate_raw = db.query(models.RiskAssessment).filter_by(review_status="candidate").count()

    running_count = db.query(models.RiskAssessment).filter(
        models.RiskAssessment.review_status.in_([
            "running", "evidence_preparing", "agent_reviewing", "conflict_review", "coordinator_review"
        ])
    ).count()
    if running_count > 0:
        raise HTTPException(
            status_code=409,
            detail=f"已有 {running_count} 条候选正在研判中。已恢复 {recovered} 条超时记录。请等待或稍后重试。",
        )

    if selection["selected_object_count"] == 0:
        return {
            "run_id": "",
            "status": "no_candidates",
            "candidate_count": candidate_raw,
            "selected_object_count": 0,
            "total_risks_in_db": selection["total_risks_in_db"],
            "skipped_objects": selection["skipped_objects"],
            "selected_object_ids": [],
            "pipeline_version": PIPELINE_VERSION,
            "model_called": False,
            "message": "当前没有可进入智能研判的候选对象",
            "retry_reset_count": retry_reset_count,
        }

    # 防并发
    # 启动后台研判
    import uuid as _uuid
    run_id = _uuid.uuid4().hex[:12]
    result = generate_and_save_report(db, run_id=run_id, background=True)

    return {
        "run_id": result.get("run_id", run_id),
        "report_id": result.get("report_id"),
        "status": result.get("status", "running"),
        "candidate_count": result.get("candidate_count", 0),
        "selected_object_count": result.get("selected_object_count", 0),
        "total_risks_in_db": result.get("total_risks_in_db", 0),
        "skipped_objects": result.get("skipped_objects", []),
        "selected_object_ids": result.get("selected_object_ids", []),
        "pipeline_version": PIPELINE_VERSION,
        "current_stage": result.get("current_stage", "candidate_preflight"),
        "model_called": True,
        "created_at": result.get("created_at", ""),
        "message": "已启动，请轮询 GET /api/analysis/runs/{run_id} 获取进度",
        "recovered_stale": recovered,
        "retry_reset_count": retry_reset_count,
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    """查询指定研判任务的进度和结果。

    返回四个智能体的实时执行状态、裁定进度和最终结果。
    包含 pipeline_version 用于确认运行的是新代码。
    """
    report = (
        db.query(models.AnalysisReport)
        .filter(
            (models.AnalysisReport.review_run_id == run_id)
            | (models.AnalysisReport.id == _safe_int(run_id))
        )
        .order_by(models.AnalysisReport.id.desc())
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail=f"未找到研判任务: {run_id}")

    return _serialize_run(report)


# ═══════════════════════════════════════════════════════════════════════════
# 历史查询
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/latest")
def get_latest(db: Session = Depends(get_db)):
    """返回最近一次四智能体联合研判报告。

    旧报告（无 pipeline_version）会标记为 legacy 或 interrupted。
    """
    result = latest_analysis(db)
    if result is None:
        return {
            "status": "none",
            "pipeline_version": PIPELINE_VERSION,
            "message": "暂无智能研判报告，请先运行一次验证流程",
        }
    return result


@router.get("/runs")
def list_runs(limit: int = 10, db: Session = Depends(get_db)):
    """列出最近的研判任务。"""
    reports = (
        db.query(models.AnalysisReport)
        .order_by(models.AnalysisReport.id.desc())
        .limit(limit)
        .all()
    )
    return [_serialize_run(r) for r in reports]


@router.post("/risks/{risk_id}/human-review", dependencies=[Depends(require_control)])
def human_review(risk_id: int, payload: schemas.HumanReviewRequest, db: Session = Depends(get_db)):
    """Apply the final human decision for one risk event only."""
    try:
        risk = apply_human_review(db, risk_id, payload.decision, payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "risk_id": risk.id,
        "object_id": f"risk-{risk.id}",
        "review_status": risk.review_status,
        "final_score": risk.final_score,
        "risk_level": risk.risk_level,
        "decision": risk.decision,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 同步接口（向后兼容）
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/run")
def run_analysis(db: Session = Depends(get_db)):
    """【向后兼容】启动一次四智能体联合研判（同步等待完成）。

    与 POST /runs 调用同一个核心函数 generate_and_save_report。
    新代码请使用 POST /runs + GET /runs/{run_id} 任务式接口。
    """
    try:
        result = generate_and_save_report(db, background=False)
        if result["status"] == "no_candidates":
            return result
        if result["status"] == "running":
            raise HTTPException(status_code=409, detail=result.get("error", "已有研判任务进行中"))
        if result["status"] == "skipped":
            raise HTTPException(status_code=503, detail=result.get("error", "DeepSeek API key 未配置"))
        if result["status"] == "failed":
            raise HTTPException(status_code=500, detail=result.get("error", "智能研判失败"))
        if result["status"] in ("human_review", "partial", "completed"):
            return result
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ═══════════════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════════════

def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _reset_latest_failed_objects(db: Session) -> int:
    """Reset retryable objects from the latest unsuccessful run to candidate."""
    report = (
        db.query(models.AnalysisReport)
        .filter(models.AnalysisReport.status.in_(["failed", "partial", "human_review", "interrupted"]))
        .order_by(models.AnalysisReport.id.desc())
        .first()
    )
    if report is None:
        return 0

    object_ids = _safe_json_list(report.selected_object_ids_json)
    reset_count = 0
    for object_id in object_ids:
        value = str(object_id)
        risk = None
        if value.startswith("risk-"):
            try:
                risk = db.get(models.RiskAssessment, int(value.removeprefix("risk-")))
            except ValueError:
                continue
        else:
            parts = value.removeprefix("asset-").split("-", 1)
            if len(parts) != 2:
                continue
            try:
                asset_id = int(parts[0])
            except ValueError:
                continue
            candidates = db.query(models.RiskAssessment).filter_by(asset_id=asset_id, cve_id=parts[1]).all()
            risk = candidates[0] if len(candidates) == 1 else None
        if risk is None:
            continue
        has_task = db.query(models.RemediationTask).filter_by(risk_id=risk.id).one_or_none()
        if has_task:
            continue
        retryable_reasons = _safe_json_list(risk.audit_policy_reasons)
        retryable = any(
            str(reason).startswith(("agent_or_schema_failure", "pipeline_failure", "background_failure", "evidence_packet_failed"))
            or reason == "structured_result_incomplete"
            for reason in retryable_reasons
        )
        if risk.review_status not in ("failed", "human_review", "interrupted", "pending_human_review") or not retryable:
            continue
        risk.review_status = "reanalysis_required"
        risk.review_verdict = ""
        risk.review_confidence = 0
        risk.review_adjustment = 0
        risk.review_evidence_ids = "[]"
        risk.review_conflicts = "[]"
        risk.review_missing_evidence = "[]"
        risk.review_reason = ""
        risk.review_completed_at = None
        risk.human_review_required = False
        risk.review_failed_agents = "[]"
        risk.final_score = 0
        risk.risk_level = "Low"
        risk.decision = "monitor"
        reset_count += 1

    if reset_count:
        db.commit()
    return reset_count
