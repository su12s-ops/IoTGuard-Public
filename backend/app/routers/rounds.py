"""分析轮次 API：当前轮工作台状态与一键发起新一轮。

归档/重置由实验生命周期（/api/experiment，见 ExperimentModal 与
result_archive / experiment_lifecycle）统一负责：先写结果存档，再删除
派生数据、保留设备与采集配置。本路由只补齐「开始执行」链路——
匹配 → 风险计算 → 四智能体研判（复用 /api/analysis 唯一正式入口），
不引入第二套归档机制。

2026-10 第二阶段：轮次状态持久化到 analysis_round。资产详情页可以从
同一入口连续执行三个确定性/模型阶段；刷新后按 round_id 恢复，重复点击
返回同一轮而不是再建一个批次。轮次只记录计数与标识，风险与报告事实仍
留在 risk_assessment / analysis_report。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import config, models
from app.database import get_db
from app.services.device_access import require_control
from app.services.result_archive import list_result_archives

router = APIRouter(prefix="/rounds", tags=["Analysis rounds"])

# A round is intentionally bounded: the browser must show exactly how many
# eligible objects were left for a later round instead of silently truncating.
REVIEW_MAX_BATCH = 20
ROUND_ACTIVE_STATUS = "running"
ROUND_TERMINAL_STATUSES = frozenset(
    {"completed", "partial", "failed", "blocked", "no_candidates", "interrupted"}
)
REVIEWABLE_STATUSES = frozenset({"candidate", "reanalysis_required"})
IN_PROGRESS_STATUSES = frozenset(
    {"running", "evidence_preparing", "agent_reviewing", "conflict_review", "coordinator_review"}
)


def _iso(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _utc(value: datetime | None) -> datetime | None:
    if not value:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _json_list(raw: str | None) -> list:
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except json.JSONDecodeError:
        return []


def _asset_inventory(db: Session, asset: models.LinuxAsset | None) -> dict:
    if asset is None:
        return {"collected_at": "", "sha256": "", "evidence_id": "", "evidence_sha256": "",
                "identity_source": "", "complete": False}
    evidence = (
        db.query(models.CollectionEvidence)
        .filter(models.CollectionEvidence.asset_id == asset.id)
        .filter(models.CollectionEvidence.evidence_id.startswith("INV-"))
        .order_by(models.CollectionEvidence.id.desc())
        .first()
    )
    return {
        "collected_at": _iso(asset.inventory_collected_at),
        "sha256": asset.inventory_sha256 or "",
        "evidence_id": evidence.evidence_id if evidence else "",
        "evidence_sha256": evidence.content_sha256 if evidence else "",
        "identity_source": asset.identity_source or "",
        "complete": bool(asset.inventory_complete),
    }


def _intel_timestamp(db: Session, cve_ids: list[str] | None = None) -> tuple[datetime | None, str]:
    """Latest stored intelligence fact used for this scope, across all sources.

    OpenWrt advisories are normalized into ``openwrt_advisory`` and
    ``official_cve_record``; they intentionally do not create
    ``vulnerability_intelligence_source`` rows (that cache is the NVD/KEV/EPSS/
    Canonical source set). Looking only at the latter produced an empty basis
    for the OpenWrt lab even though official advisories had a real fetched_at.
    """
    cves = sorted({str(item) for item in (cve_ids or []) if item})
    values: list[datetime] = []
    sources: list[str] = []

    def collect(label: str, query) -> None:
        value = query.scalar()
        if value:
            values.append(value)
            sources.append(label)

    query = db.query(func.max(models.VulnerabilityIntelligenceSource.fetched_at))
    if cves:
        query = query.filter(models.VulnerabilityIntelligenceSource.cve_id.in_(cves))
    collect("vulnerability_intelligence_source", query)

    query = db.query(func.max(models.OpenWrtAdvisory.updated_at))
    if cves:
        query = query.filter(models.OpenWrtAdvisory.cve_id.in_(cves))
    collect("openwrt_advisory", query)

    query = db.query(func.max(models.OfficialCveRecord.fetched_at))
    if cves:
        query = query.filter(models.OfficialCveRecord.cve_id.in_(cves))
    collect("official_cve_record", query)

    query = db.query(func.max(models.ThreatIntelSource.updated_at))
    if cves:
        query = query.filter(models.ThreatIntelSource.cve_id.in_(cves))
    collect("threat_intel_source", query)

    if not values:
        return None, "unavailable"
    scope = ("selected_cves:" if cves else "global_latest:") + ",".join(sources)
    return max(values), scope[:64]


def _runtime_basis(db: Session, asset_id: int | None) -> dict:
    if not asset_id:
        return {"fresh": None, "latest_event_age_seconds": None, "window_seconds": None,
                "coverage": None, "basis": "not_scoped"}
    try:
        from app.services.runtime_telemetry import coverage, evidence_freshness

        freshness = evidence_freshness(db, asset_id)
        sensor_coverage = coverage(db, asset_id)
        return {
            **freshness,
            "coverage": {
                "status": sensor_coverage.get("status"),
                "sensors": [
                    {"sensor_id": item.get("sensor_id"), "source": item.get("source"),
                     "status": item.get("status"), "age_seconds": item.get("age_seconds")}
                    for item in (sensor_coverage.get("sensors") or [])
                ],
                "absence_proves_safe": False,
            },
        }
    except Exception as exc:  # telemetry absence is reported, never converted to "safe"
        return {"fresh": None, "latest_event_age_seconds": None, "window_size": None,
                "coverage": None, "basis": "unavailable", "error": str(exc)[:240]}


def _risk_failed(risk: models.RiskAssessment) -> bool:
    """An object-level failure, not an ordinary human-review gate."""
    if risk.review_status == "failed":
        return True
    reason = (risk.review_reason or "").strip().lower()
    if reason.startswith("unified_") or reason.startswith("pipeline_failure") or reason.startswith("background_failure"):
        return True
    for item in _json_list(risk.audit_policy_reasons):
        text = str(item)
        if text.startswith(("pipeline_failure", "background_failure", "unified_orchestrator_failed",
                            "agent_or_schema_failure", "evidence_packet_failed")):
            return True
    return False


def _risk_disposition(risk: models.RiskAssessment) -> str:
    if _risk_failed(risk):
        return "failed"
    if risk.review_status == "auto_confirmed":
        return "auto_confirmed"
    if risk.review_status in ("pending_human_review", "human_confirmed") or risk.human_review_required:
        return "human_review"
    if risk.review_status in IN_PROGRESS_STATUSES:
        return "processing"
    if risk.review_status in REVIEWABLE_STATUSES:
        return "eligible_not_processed"
    return risk.review_status or "unknown"


def _risk_payload(db: Session, risk: models.RiskAssessment, *, in_round: bool,
                  reason: str = "") -> dict:
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    return {
        "risk_id": risk.id,
        "object_id": f"risk-{risk.id}",
        "cve_id": risk.cve_id,
        "package_name": (match.package_name if match else risk.package_name) or "",
        "match_id": risk.match_id,
        "active": bool(risk.active),
        "in_round": in_round,
        "reason": reason,
        "review_status": risk.review_status,
        "disposition": _risk_disposition(risk),
        "human_review_required": bool(risk.human_review_required),
        "preliminary_score": risk.preliminary_score,
        "preliminary_level": risk.preliminary_level,
        "preliminary_decision": risk.preliminary_decision,
        "final_score": risk.final_score,
        "risk_level": risk.risk_level,
        "decision": risk.decision,
        "review_verdict": risk.review_verdict or "",
        "review_confidence": risk.review_confidence,
        "review_reason": risk.review_reason or "",
        "review_evidence_ids": _json_list(risk.review_evidence_ids),
        "review_failed_agents": _json_list(risk.review_failed_agents),
        "review_missing_evidence": _json_list(risk.review_missing_evidence),
        "audit_policy_reasons": _json_list(risk.audit_policy_reasons),
        "reanalysis_count": int(risk.reanalysis_count or 0),
        "review_completed_at": _iso(risk.review_completed_at),
        "applicability_source": risk.applicability_source or "",
    }


def _selected_ids(row: models.AnalysisRound) -> list[int]:
    values = []
    for item in _json_list(row.selected_object_ids_json):
        text = str(item)
        if text.startswith("risk-"):
            try:
                values.append(int(text.removeprefix("risk-")))
            except ValueError:
                continue
    return values


def _report_for_round(db: Session, row: models.AnalysisRound) -> models.AnalysisReport | None:
    if not row.review_run_id:
        return None
    return (
        db.query(models.AnalysisReport)
        .filter_by(review_run_id=row.review_run_id)
        .order_by(models.AnalysisReport.id.desc())
        .first()
    )


def _sync_round_from_report(db: Session, row: models.AnalysisRound) -> None:
    """Merge live report/risk facts into the durable round row."""
    report = _report_for_round(db, row)
    if report is None:
        return
    row.processed_object_count = max(int(row.processed_object_count or 0),
                                     int(report.processed_object_count or 0))
    if report.status == "running":
        row.stage = "reviewing"
        row.remaining_object_count = max(0, int(row.eligible_count or 0)
                                         - int(row.processed_object_count or 0))
        return

    ids = []
    for item in _json_list(report.selected_object_ids_json):
        text = str(item)
        if text.startswith("risk-"):
            try:
                ids.append(int(text.removeprefix("risk-")))
            except ValueError:
                continue
    if not ids:
        ids = _selected_ids(row)
    risks = db.query(models.RiskAssessment).filter(models.RiskAssessment.id.in_(ids)).all() if ids else []
    dispositions = [_risk_disposition(risk) for risk in risks]
    failed = sum(item == "failed" for item in dispositions)
    auto = sum(item == "auto_confirmed" for item in dispositions)
    human = sum(item == "human_review" for item in dispositions)
    processing = sum(item == "processing" for item in dispositions)

    selected = int(report.selected_object_count or len(ids) or row.selected_object_count or 0)
    processed = int(report.processed_object_count or 0)
    if report.status in ("completed", "partial", "human_review", "no_candidates"):
        processed = max(processed, selected)
    row.selected_object_count = selected
    row.processed_object_count = min(processed, selected) if selected else processed
    row.failed_object_count = failed
    row.auto_confirmed_count = auto
    row.human_review_count = human
    row.remaining_object_count = max(0, int(row.eligible_count or 0) - int(row.processed_object_count or 0))
    row.stage = "completed"
    row.completed_at = report.completed_at or row.completed_at or datetime.now(timezone.utc)
    row.error = report.error or row.error

    if report.status in ("failed", "interrupted"):
        row.status = "failed"
        row.blocked_reason = (report.error or report.termination_reason
                              or "formal_review_failed_before_terminal_conclusion")[:2000]
    elif failed and failed >= max(1, processed):
        row.status = "failed"
        row.blocked_reason = "all_selected_objects_failed"
    elif failed or processing:
        row.status = "partial"
        row.blocked_reason = "some_selected_objects_failed_or_unfinished"
    elif report.status == "no_candidates":
        row.status = "no_candidates"
    else:
        row.status = "completed"
        row.blocked_reason = ""


def _recover_stale_round(db: Session, row: models.AnalysisRound, *, max_idle_minutes: int = 10) -> None:
    if row.status != ROUND_ACTIVE_STATUS:
        return
    report = _report_for_round(db, row)
    if report is not None:
        _sync_round_from_report(db, row)
        return
    updated = _utc(row.updated_at or row.started_at)
    if updated is None:
        return
    if datetime.now(timezone.utc) - updated > timedelta(minutes=max_idle_minutes):
        row.status = "interrupted"
        row.stage = "failed"
        row.blocked_reason = "round_interrupted_without_formal_report"
        row.completed_at = datetime.now(timezone.utc)


def _latest_round(db: Session, asset_id: int | None) -> models.AnalysisRound | None:
    query = db.query(models.AnalysisRound)
    if asset_id is not None:
        if asset_id:
            query = query.filter(models.AnalysisRound.asset_id == asset_id,
                                 models.AnalysisRound.scope == "asset")
        else:
            query = query.filter(models.AnalysisRound.scope == "fleet")
    return query.order_by(models.AnalysisRound.id.desc()).first()


def _active_round(db: Session, asset_id: int | None) -> models.AnalysisRound | None:
    query = db.query(models.AnalysisRound).filter_by(status=ROUND_ACTIVE_STATUS)
    if asset_id:
        query = query.filter_by(asset_id=asset_id, scope="asset")
    else:
        query = query.filter_by(scope="fleet")
    rows = query.order_by(models.AnalysisRound.id.desc()).all()
    for row in rows:
        _recover_stale_round(db, row)
        db.commit()
        if row.status == ROUND_ACTIVE_STATUS:
            return row
    return None


def _round_payload(db: Session, row: models.AnalysisRound) -> dict:
    asset = db.get(models.LinuxAsset, row.asset_id) if row.asset_id else None
    selected = _selected_ids(row)
    risks = (
        db.query(models.RiskAssessment)
        .filter(models.RiskAssessment.id.in_(selected))
        .all() if selected else []
    )
    by_id = {risk.id: risk for risk in risks}
    objects = [_risk_payload(db, by_id[risk_id], in_round=True)
               for risk_id in selected if risk_id in by_id]

    skipped = _json_list(row.skipped_objects_json)
    skipped_ids = []
    for item in skipped:
        text = str((item or {}).get("object_id") or "")
        if text.startswith("risk-"):
            try:
                skipped_ids.append(int(text.removeprefix("risk-")))
            except ValueError:
                continue
    skipped_risks = (
        db.query(models.RiskAssessment)
        .filter(models.RiskAssessment.id.in_(skipped_ids))
        .all() if skipped_ids else []
    )
    skipped_by_id = {risk.id: risk for risk in skipped_risks}
    skipped_objects = []
    for item in skipped:
        text = str((item or {}).get("object_id") or "")
        risk = skipped_by_id.get(int(text.removeprefix("risk-"))) if text.startswith("risk-") else None
        base = _risk_payload(db, risk, in_round=False, reason=str((item or {}).get("reason") or "")) if risk else {
            "risk_id": None, "object_id": text, "in_round": False,
            "reason": str((item or {}).get("reason") or ""),
        }
        base["detail"] = str((item or {}).get("detail") or "")
        skipped_objects.append(base)

    history = []
    if row.scope == "asset" and row.asset_id:
        in_round_ids = set(selected) | set(skipped_ids)
        others = (
            db.query(models.RiskAssessment)
            .filter(models.RiskAssessment.asset_id == row.asset_id,
                    models.RiskAssessment.active.is_(True))
            .order_by(models.RiskAssessment.priority_rank, models.RiskAssessment.id)
            .limit(100)
            .all()
        )
        for risk in others:
            if risk.id in in_round_ids:
                continue
            reason = ("status_not_reviewable" if risk.review_status not in REVIEWABLE_STATUSES
                      else "not_selected_in_this_round")
            history.append(_risk_payload(db, risk, in_round=False, reason=reason))

    report = _report_for_round(db, row)
    review_run = None
    if report is not None:
        review_run = {
            "run_id": report.review_run_id,
            "status": report.status,
            "current_stage": report.current_stage or "",
            "selected_object_count": report.selected_object_count or 0,
            "processed_object_count": report.processed_object_count or 0,
            "completed_object_count": report.completed_object_count or 0,
            "human_review_object_count": report.human_review_object_count or 0,
            "progress_percent": report.progress_percent or 0,
            "current_object_id": report.current_object_id or "",
            "progress_message": report.progress_message or "",
            "termination_reason": report.termination_reason or "",
            "error": report.error or "",
            "agent_executions": json.loads(report.agent_executions_json or "{}"),
            "created_at": _iso(report.created_at),
            "completed_at": _iso(report.completed_at),
        }
    elif row.review_run_id:
        review_run = {"run_id": row.review_run_id, "status": "unknown",
                      "missing_report": True}

    failed = int(row.failed_object_count or 0)
    auto = int(row.auto_confirmed_count or 0)
    human = int(row.human_review_count or 0)
    if failed:
        outcome = "failed" if failed >= max(1, int(row.processed_object_count or 1)) else "partial"
    elif auto and human:
        outcome = "mixed"
    elif auto:
        outcome = "auto_confirmed"
    elif human:
        outcome = "human_review"
    else:
        outcome = "no_result" if row.status != "no_candidates" else "no_candidates"
    degraded = sum(1 for risk in risks if _json_list(risk.review_failed_agents))

    return {
        "round_id": row.round_id,
        "asset_id": row.asset_id,
        "asset_hostname": asset.hostname if asset else "",
        "asset_distribution": asset.distribution if asset else "",
        "asset_version": asset.os_version if asset else "",
        "scope": row.scope,
        "status": row.status,
        "stage": row.stage,
        "completed": row.status in ROUND_TERMINAL_STATUSES,
        "selection_mode": row.selection_mode or "all_eligible",
        "requested_risk_id": int(row.requested_risk_id or 0),
        "requested_batch_size": int(row.requested_batch_size or 0),
        "batch_cap": int(row.batch_cap or 0),
        "counts": {
            "matches": int(row.match_count or 0),
            "risks_calculated": int(row.risk_count or 0),
            "candidates": int(row.candidate_count or 0),
            "eligible": int(row.eligible_count or 0),
            "selected": int(row.selected_object_count or 0),
            "processed": int(row.processed_object_count or 0),
            "remaining": int(row.remaining_object_count or 0),
            "failed": failed,
            "auto_confirmed": auto,
            "human_review": human,
            "degraded": degraded,
        },
        "outcome": outcome,
        "blocked_reason": row.blocked_reason or "",
        "error": row.error or "",
        "selected_object_ids": [f"risk-{item}" for item in selected],
        "skipped_objects": skipped_objects,
        "objects": objects,
        "history_objects": history,
        "review_run": review_run,
        "review_run_id": row.review_run_id or "",
        "inventory": _asset_inventory(db, asset),
        "intel": {
            "updated_at": _iso(row.intel_updated_at),
            "scope": row.intel_scope or "",
        },
        "runtime_evidence": _runtime_basis(db, row.asset_id),
        "pipeline": {
            "mode": row.pipeline_mode or config.UNIFIED_PIPELINE_MODE,
            "model": row.model or config.DEEPSEEK_MODEL,
            "api_protocol": row.api_protocol or getattr(config, "DEEPSEEK_API_PROTOCOL", ""),
        },
        "started_at": _iso(row.started_at),
        "updated_at": _iso(row.updated_at),
        "completed_at": _iso(row.completed_at),
    }


def _round_response(db: Session, row: models.AnalysisRound, **extra) -> dict:
    return {"round_id": row.round_id, "round": _round_payload(db, row), **extra}


@router.get("/current")
def current_round(asset_id: int | None = Query(default=None, ge=0),
                  db: Session = Depends(get_db)):
    """轮次工作台状态：接入设备、本轮数据量、流水线配置与历史存档概况。

    ``asset_id`` 给出时额外返回该资产的最新持久化轮次，供资产详情页刷新后
    恢复；不给出时保持原工作台契约，并附带最新活跃轮次的摘要。
    """
    assets = db.query(models.LinuxAsset).order_by(models.LinuxAsset.id).all()
    match_counts = {
        asset_id_value: int(count)
        for asset_id_value, count in (
            db.query(models.VulnerabilityMatch.asset_id, func.count(models.VulnerabilityMatch.id))
            .filter(models.VulnerabilityMatch.active.is_(True))
            .group_by(models.VulnerabilityMatch.asset_id).all()
        )
    }
    risk_counts = {
        asset_id_value: int(count)
        for asset_id_value, count in (
            db.query(models.RiskAssessment.asset_id, func.count(models.RiskAssessment.id))
            .filter(models.RiskAssessment.active.is_(True))
            .group_by(models.RiskAssessment.asset_id).all()
        )
    }
    devices = [
        {
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "ip": asset.ip_address or "",
            "distribution": asset.distribution or "",
            "os_version": asset.os_version or "",
            "device_type": asset.device_type or "",
            "package_count": len(asset.packages),
            "active_matches": match_counts.get(asset.id, 0),
            "active_risks": risk_counts.get(asset.id, 0),
            "inventory_complete": bool(asset.inventory_complete),
            "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else "",
        }
        for asset in assets
    ]
    running = db.query(models.UnifiedAnalysisRun).filter(
        models.UnifiedAnalysisRun.status.in_(("running", "queued", "queued_remote", "pending"))
    ).count()
    archives = list_result_archives(8)

    latest_round = _latest_round(db, asset_id)
    if latest_round is not None:
        _recover_stale_round(db, latest_round)
        _sync_round_from_report(db, latest_round)
        db.commit()
    active_round = _active_round(db, asset_id)
    if active_round is not None:
        _sync_round_from_report(db, active_round)
        db.commit()

    return {
        "devices": devices,
        "device_count": len(devices),
        "active": {
            "unified_runs": db.query(models.UnifiedAnalysisRun).count(),
            "risks": db.query(models.RiskAssessment).filter(
                models.RiskAssessment.active.is_(True)).count(),
            "candidates": db.query(models.RiskAssessment).filter(
                models.RiskAssessment.active.is_(True),
                models.RiskAssessment.review_status.in_(REVIEWABLE_STATUSES),
            ).count(),
            "running": bool(running),
        },
        "intel": {
            "vulnerability_count": db.query(models.VulnerabilityInfo).count(),
        },
        "pipeline": {
            "mode": config.UNIFIED_PIPELINE_MODE,
            "model_configured": bool(getattr(config, "DEEPSEEK_API_KEY", "")),
            "model": config.DEEPSEEK_MODEL,
            "api_protocol": getattr(config, "DEEPSEEK_API_PROTOCOL", ""),
        },
        "archives": {
            "count": len(archives),
            "latest": archives[0] if archives else None,
        },
        "round": _round_payload(db, latest_round) if latest_round else None,
        "active_round": _round_payload(db, active_round) if active_round else None,
    }


class RoundStartInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int = Field(default=0, ge=0)
    risk_id: int = Field(default=0, ge=0)
    # 0 means "all eligible risks in scope" up to REVIEW_MAX_BATCH; a positive
    # value is an explicit smaller batch, never a hidden default of 1.
    batch_size: int = Field(default=0, ge=0, le=REVIEW_MAX_BATCH)
    investigation_goal: str = Field(default="", max_length=2000)


@router.post("/start", dependencies=[Depends(require_control)])
def start_round(payload: RoundStartInput, db: Session = Depends(get_db)):
    """发起一轮：匹配 → 风险计算 → 对范围内全部符合条件风险发起研判。

    语义：
    - ``asset_id>0`` 时整个链路只作用于该资产；``asset_id=0`` 是显式的
      全设备范围（scope=fleet），不是“随便挑资产”。
    - ``risk_id=0`` 表示资产内全部符合条件风险（受批次上限约束，剩余项
      明确记入 remaining/skipped），``risk_id>0`` 表示只研判该单条风险，
      且必须属于本资产。
    - 同一资产已有运行中的轮次时直接返回该轮（reused=true），不重复匹配、
      不重复建批次。
    """
    from app.routers import analysis as analysis_router
    from app.services.matching_engine import run_matching
    from app.services.review_common import select_candidates
    from app.services.risk_engine import calculate_risk

    asset = None
    if payload.asset_id:
        asset = db.get(models.LinuxAsset, payload.asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="资产不存在")
    if payload.risk_id:
        if not payload.asset_id:
            raise HTTPException(status_code=400, detail="asset_id_required_for_single_risk_scope")
        risk = db.get(models.RiskAssessment, payload.risk_id)
        if risk is None or risk.asset_id != payload.asset_id:
            raise HTTPException(status_code=409, detail="risk_not_in_asset_scope")

    existing = _active_round(db, payload.asset_id or None)
    if existing is not None:
        if payload.risk_id and int(existing.requested_risk_id or 0) != payload.risk_id:
            raise HTTPException(
                status_code=409,
                detail=json.dumps({
                    "error": "asset_round_already_running_with_different_scope",
                    "round_id": existing.round_id,
                    "requested_risk_id": int(existing.requested_risk_id or 0),
                }, ensure_ascii=False),
            )
        _sync_round_from_report(db, existing)
        db.commit()
        review = None
        if existing.review_run_id:
            report = _report_for_round(db, existing)
            review = {
                "run_id": existing.review_run_id,
                "status": report.status if report else "unknown",
                "selected_object_ids": _json_list(existing.selected_object_ids_json),
                "candidate_count": int(existing.candidate_count or 0),
                "selected_object_count": int(existing.selected_object_count or 0),
            }
        return _round_response(
            db, existing, reused=True, review=review,
            review_unavailable_reason=existing.blocked_reason or None,
            match_count=int(existing.match_count or 0),
            risk_count=int(existing.risk_count or 0),
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=[],
        )

    inventory = _asset_inventory(db, asset)
    intel_at, intel_scope = _intel_timestamp(db)
    row = models.AnalysisRound(
        round_id=f"RND-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id if asset else None,
        scope="asset" if asset else "fleet",
        status="running",
        stage="matching",
        requested_batch_size=payload.batch_size,
        requested_risk_id=payload.risk_id,
        selection_mode="single_risk" if payload.risk_id else "all_eligible",
        batch_cap=REVIEW_MAX_BATCH,
        selected_object_ids_json="[]",
        skipped_objects_json="[]",
        inventory_collected_at=asset.inventory_collected_at if asset else None,
        inventory_sha256=asset.inventory_sha256 if asset else "",
        inventory_evidence_id=inventory["evidence_id"],
        intel_updated_at=intel_at,
        intel_scope=intel_scope,
        pipeline_mode=config.UNIFIED_PIPELINE_MODE,
        model=config.DEEPSEEK_MODEL,
        api_protocol=getattr(config, "DEEPSEEK_API_PROTOCOL", ""),
        started_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()

    openwrt_stats: dict = {}
    match_count = 0
    risk_count = 0
    selection: dict = {}
    try:
        match_count = run_matching(db, asset_id=payload.asset_id or None,
                                   openwrt_stats=openwrt_stats)
        row.match_count = match_count
        row.stage = "risk_calculation"
        db.commit()

        risk_count = calculate_risk(db, asset_id=payload.asset_id or None)
        row.risk_count = risk_count
        row.stage = "candidate_selection"
        db.commit()

        selection = select_candidates(db, asset_id=payload.asset_id or 0)
        ordered_all = sorted(
            selection["_selected_risks"],
            key=lambda risk: (risk.priority_rank if risk.priority_rank is not None else 10 ** 9, risk.id),
        )
        if payload.risk_id:
            chosen = [risk for risk in ordered_all if risk.id == payload.risk_id]
            if not chosen:
                raise HTTPException(status_code=409, detail="risk_not_eligible_for_formal_analysis")
            # Single-risk semantics are explicit: the other eligible objects
            # are not silently hidden; they are listed as out of this scope.
            beyond = [risk for risk in ordered_all if risk.id != payload.risk_id]
            beyond_reason, beyond_detail = "single_risk_scope", f"requested_risk_id={payload.risk_id}"
        else:
            limit = (REVIEW_MAX_BATCH if payload.batch_size == 0
                     else max(1, min(payload.batch_size, REVIEW_MAX_BATCH)))
            chosen = ordered_all[:limit]
            beyond = ordered_all[limit:]
            beyond_reason, beyond_detail = "bounded_queue", f"batch_cap={REVIEW_MAX_BATCH}"
        skipped = list(selection["skipped_objects"]) + [
            {"object_id": f"risk-{risk.id}", "reason": beyond_reason,
             "detail": beyond_detail}
            for risk in beyond
        ]
        row.candidate_count = int(selection["candidate_count"])
        row.eligible_count = len(ordered_all)
        row.selected_object_count = len(chosen)
        row.processed_object_count = 0
        row.remaining_object_count = len(ordered_all)
        row.selected_object_ids_json = json.dumps(
            [f"risk-{risk.id}" for risk in chosen], ensure_ascii=False)
        row.skipped_objects_json = json.dumps(skipped, ensure_ascii=False)
        selected_cves = [risk.cve_id for risk in ordered_all]
        intel_at, intel_scope = _intel_timestamp(db, selected_cves)
        row.intel_updated_at = intel_at
        row.intel_scope = intel_scope
        db.commit()
    except HTTPException as exc:
        row.status = "blocked"
        row.stage = "blocked"
        row.blocked_reason = str(exc.detail)
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=None,
            review_unavailable_reason=str(exc.detail),
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )
    except Exception as exc:
        row.status = "failed"
        row.stage = "failed"
        row.error = str(exc)[:2000]
        row.blocked_reason = "deterministic_pipeline_failed"
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=None,
            review_unavailable_reason=str(exc)[:500],
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )

    if not selection.get("selected_object_count"):
        row.status = "no_candidates"
        row.stage = "completed"
        row.remaining_object_count = 0
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=None,
            review_unavailable_reason=None,
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )

    if payload.risk_id and not row.selected_object_count:
        row.status = "blocked"
        row.stage = "blocked"
        row.blocked_reason = "risk_not_eligible_for_formal_analysis"
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=None,
            review_unavailable_reason="risk_not_eligible_for_formal_analysis",
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )

    review = None
    review_unavailable_reason = ""
    if config.UNIFIED_PIPELINE_MODE != "on":
        review_unavailable_reason = "formal_unified_mode_required; legacy LLM retired"
    elif not getattr(config, "DEEPSEEK_API_KEY", ""):
        review_unavailable_reason = "model_not_configured"
    else:
        try:
            review = analysis_router.create_run(
                retry_failed=False, risk_id=payload.risk_id,
                # Preserve the operator's requested scope: 0 = all eligible,
                # positive = explicit smaller batch. The adapter applies the
                # same cap and returns the exact selected object IDs.
                batch_size=payload.batch_size, post_repair=False,
                investigation_goal=payload.investigation_goal, db=db,
                asset_id=payload.asset_id,
            )
        except HTTPException as exc:
            review_unavailable_reason = str(exc.detail)
        except Exception as exc:  # never fabricate a started review
            review_unavailable_reason = f"formal_review_start_failed: {exc}"[:500]

    if review is None:
        row.status = "blocked"
        row.stage = "blocked"
        row.blocked_reason = review_unavailable_reason or "formal_review_unavailable"
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=None,
            review_unavailable_reason=review_unavailable_reason,
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )

    if review.get("status") == "no_candidates" or not review.get("run_id"):
        row.status = "no_candidates"
        row.stage = "completed"
        row.selected_object_ids_json = "[]"
        row.selected_object_count = 0
        row.remaining_object_count = 0
        row.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _round_response(
            db, row, reused=False, review=review,
            review_unavailable_reason=None,
            match_count=match_count, risk_count=risk_count,
            vulnerability_count=db.query(models.VulnerabilityInfo).count(),
            pipeline_mode=config.UNIFIED_PIPELINE_MODE,
            openwrt=openwrt_stats.get("assets", []),
        )

    selected_ids = review.get("selected_object_ids") or []
    row.review_run_id = review.get("run_id") or ""
    row.selected_object_ids_json = json.dumps(selected_ids, ensure_ascii=False)
    row.candidate_count = int(review.get("candidate_count") or row.candidate_count or 0)
    row.selected_object_count = int(review.get("selected_object_count") or len(selected_ids))
    # remaining means "not yet processed in this round", not "not selected":
    # at start all selected objects are still unprocessed. Objects left out by
    # the batch cap remain in skipped_objects with bounded_queue.
    row.processed_object_count = 0
    row.remaining_object_count = max(0, int(row.eligible_count or 0) - row.processed_object_count)
    row.status = "running"
    row.stage = "reviewing"
    db.commit()

    return _round_response(
        db, row, reused=False, review=review,
        review_unavailable_reason=None,
        match_count=match_count, risk_count=risk_count,
        vulnerability_count=db.query(models.VulnerabilityInfo).count(),
        pipeline_mode=config.UNIFIED_PIPELINE_MODE,
        openwrt=openwrt_stats.get("assets", []),
    )


@router.get("/{round_id}")
def get_round(round_id: str, db: Session = Depends(get_db)):
    """读取一轮的持久化状态；刷新/重复进入页面均走此接口恢复。"""
    row = db.query(models.AnalysisRound).filter_by(round_id=round_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="轮次不存在")
    _recover_stale_round(db, row)
    _sync_round_from_report(db, row)
    db.commit()
    return _round_payload(db, row)
