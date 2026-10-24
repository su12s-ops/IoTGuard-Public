"""统一四智能体 API：规格、发起运行、状态与影子对照查询。

- `POST /api/unified/analyze`：按 LINUXGUARD_UNIFIED_PIPELINE 开关运行；
  off → 503；shadow → 影子运行；on → 拒绝第二正式入口，须走 /api/analysis。
- POST /shadow 是受控制令牌保护的隔离入口，可在全局 off 下验证。
- 影子结论与补查审计独立保存，不写正式风险或授予修复权限。
"""
from __future__ import annotations

import json
import threading
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import config, models
from app.database import get_db
from app.services.unified import runner
from app.services.unified.agents_def import specs_summary
from app.services.unified.graph import PIPELINE_VERSION, STAGE_TOPOLOGY
from app.services.unified.schemas import ALL_AGENT_IDS
from app.services.unified.state import TASK_TYPES
from app.services.device_access import require_control
from app.services.unified import investigation
from app.services.unified.read_model import project_live_roles

router = APIRouter(prefix="/unified", tags=["Unified four-agent orchestration"])


class ShadowInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int = Field(gt=0)
    risk_id: int = Field(default=0, ge=0)
    investigation_goal: str = Field(default="", max_length=2000)


@router.post("/shadow", status_code=202, dependencies=[Depends(require_control)])
def isolated_shadow(payload: ShadowInput, db: Session = Depends(get_db)):
    asset = db.get(models.LinuxAsset, payload.asset_id)
    risk = db.get(models.RiskAssessment, payload.risk_id) if payload.risk_id else None
    if not asset or (payload.risk_id and (not risk or risk.asset_id != asset.id)):
        raise HTTPException(422, "资产与风险不一致")
    row = runner.start_unified_run(task_type="risk_review" if risk else "device_surface",
        target_ref=asset.hostname, target_type="linux_host", risk_id=risk.id if risk else None,
        mode="shadow", force_full_review=True, investigation_goal=payload.investigation_goal)
    return {"run_id": row.run_id, "mode": "shadow", "formal_authority": False}


class InvestigationAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    connection_id: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2000)
    auto_resume: bool = False


def _investigation(db, request_id):
    item = db.get(models.InvestigationRequest, request_id)
    if not item:
        raise HTTPException(404, "调查申请不存在")
    return item


@router.get("/investigations", dependencies=[Depends(require_control)])
def investigations(source_run_id: str = "", db: Session = Depends(get_db)):
    query = db.query(models.InvestigationRequest)
    if source_run_id:
        query = query.filter_by(source_run_id=source_run_id)
    return [investigation.serialize(item) for item in query.order_by(models.InvestigationRequest.created_at.desc()).limit(100)]


@router.post("/investigations/{request_id}/authorize", dependencies=[Depends(require_control)])
def authorize_investigation(request_id: str, payload: InvestigationAuthorization, db: Session = Depends(get_db)):
    try:
        item = investigation.authorize(db, _investigation(db, request_id), **payload.model_dump())
        return investigation.serialize(item)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/investigations/{request_id}/resume", dependencies=[Depends(require_control)])
def resume_investigation(request_id: str, db: Session = Depends(get_db)):
    # Model runs can take minutes; the HTTP request only dispatches a worker.
    item = _investigation(db, request_id)
    if item.reanalysis_run_id:
        return investigation.serialize(item)
    collection = db.get(models.HarnessRun, item.collection_run_id) if item.collection_run_id else None
    if item.status != "authorized" or not collection or collection.status != "completed":
        raise HTTPException(409, "须完成已授权采集")
    def worker():
        with runner.SessionLocal() as session:
            current = session.get(models.InvestigationRequest, request_id)
            try:
                investigation.resume(session, current)
            except ValueError as exc:
                session.rollback()
                if str(exc) == "reanalysis_already_claimed":
                    return
                current.status = "reanalysis_failed"
                current.result_json = json.dumps({"error": str(exc)})
                session.commit()
            except Exception as exc:
                session.rollback()
                current.status = "reanalysis_failed"
                current.result_json = json.dumps({"error": type(exc).__name__})
                session.commit()
    threading.Thread(target=worker, daemon=True).start()
    parent = db.query(models.UnifiedAnalysisRun).filter_by(run_id=item.source_run_id).one()
    return {"id": item.id, "status": "resume_requested", "mode": parent.mode}


class UnifiedAnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(default="", max_length=128)
    hostname: str = Field(default="", max_length=128)
    risk_id: int = Field(default=0, ge=0)
    task_type: str = Field(default="risk_review")

    def resolved(self) -> tuple[str, str]:
        if self.device_id:
            return self.device_id, "device"
        if self.hostname:
            return self.hostname, "linux_host"
        raise ValueError("必须提供 device_id 或 hostname 之一")


@router.get("/specs")
def unified_specs():
    """唯一四智能体的职责/工具/输出模型与图拓扑（可核验）。"""
    return {
        "pipeline_version": PIPELINE_VERSION,
        "mode": config.UNIFIED_PIPELINE_MODE,
        "agents": specs_summary(),
        "topology": STAGE_TOPOLOGY,
        "task_types": list(TASK_TYPES),
        "formal_entry": "/api/analysis",
        "formal_writer": "unified" if config.UNIFIED_PIPELINE_MODE == "on" else "disabled",
        "pid": os.getpid(),
        "device_repair_enabled": os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") == "1",
        "ubuntu_lab_repair_enabled": os.getenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0") == "1",
        "ubuntu_lab_asset_scope_declared": bool((os.getenv("LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE", "") or "").strip()),
        "migration_contract": "m5-native-review-v2",
        "formal_batch_default": 1,
        "formal_batch_max": 4,
        "note": "统一四角色复用 LangGraph；mode!=on 时正式业务 fail-closed，旧 LLM 已退役。",
    }


@router.post("/analyze", status_code=202, dependencies=[Depends(require_control)])
def analyze(payload: UnifiedAnalyzeInput, db: Session = Depends(get_db)):
    if config.UNIFIED_PIPELINE_MODE == "off":
        raise HTTPException(503, "统一编排器未启用（LINUXGUARD_UNIFIED_PIPELINE=off）")
    if config.UNIFIED_PIPELINE_MODE == "on":
        raise HTTPException(409, "正式研判唯一入口为 /api/analysis；此入口仅用于 shadow")
    try:
        target_ref, target_type = payload.resolved()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    task_type = payload.task_type
    if task_type not in TASK_TYPES:
        raise HTTPException(422, f"task_type 必须是 {sorted(TASK_TYPES)} 之一")
    risk_id = None
    if task_type == "risk_review":
        if not payload.risk_id:
            raise HTTPException(422, "risk_review 必须提供 risk_id")
        risk = db.get(models.RiskAssessment, payload.risk_id)
        if risk is None:
            raise HTTPException(404, "风险事件不存在")
        risk_id = risk.id
        if target_type != "linux_host" or not db.query(models.LinuxAsset).filter_by(id=risk.asset_id, hostname=target_ref).first():
            raise HTTPException(422, "风险与目标资产不一致")
    elif payload.risk_id:
        raise HTTPException(422, "只有 risk_review 任务可以指定 risk_id")
    if target_type == "device":
        if not db.query(models.IotDevice).filter_by(device_id=target_ref).first():
            raise HTTPException(404, "设备不存在，请先在设备中心完成发现")
    elif not db.query(models.LinuxAsset).filter_by(hostname=target_ref).first():
        raise HTTPException(404, "主机资产不存在")
    try:
        run = runner.start_unified_run(
            task_type=task_type, target_ref=target_ref, target_type=target_type,
            risk_id=risk_id, mode="shadow")
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return {"run_id": run.run_id, "trace_id": run.trace_id, "status": run.status,
            "mode": run.mode, "task_type": run.task_type, "target": target_ref}


def _serialize_run(row: models.UnifiedAnalysisRun, include_state: bool = True) -> dict:
    state = json.loads(row.state_json or "{}")
    payload = {
        "run_id": row.run_id, "task_type": row.task_type,
        "trace_id": row.trace_id,
        "target_type": row.target_type, "target_ref": row.target_ref,
        "mode": row.mode, "status": row.status,
        "pipeline_version": row.pipeline_version,
        "risk_id": row.risk_id, "error": row.error,
        "routing": json.loads(row.routing_json or "{}"),
        "agents": json.loads(row.agents_json or "{}"),
        "usage": json.loads(row.usage_json or "{}"),
        "created_at": row.created_at, "completed_at": row.completed_at,
    }
    if include_state:
        payload.update({
            "stage_status": state.get("stage_status", {}),
            "degraded_roles": state.get("degraded_roles", []),
            "final": state.get("final", {}),
            "decision": json.loads(row.decision_json or "{}"),
            "plan": json.loads(row.plan_json or "{}"),
            "conflict_result": state.get("conflict_result", {}),
            "investigation": state.get("investigation"),
            "vulnerability": state.get("vulnerability"),
            "runtime": state.get("runtime"),
            "runtime_program_fallback": state.get("runtime_program_fallback"),
            "follow_up_results": state.get("follow_up_results", []),
        })
    return payload


@router.get("/runs")
def list_runs(limit: int = 20, mode: str = "", risk_id: int = 0,
              target_ref: str = "", db: Session = Depends(get_db)):
    """运行列表（只读）。risk_id/target_ref 供风险详情与资产页关联展示。"""
    query = db.query(models.UnifiedAnalysisRun).order_by(models.UnifiedAnalysisRun.id.desc())
    if mode in {"shadow", "formal", "historical"}:
        query = query.filter(models.UnifiedAnalysisRun.mode == mode)
    if risk_id:
        query = query.filter(models.UnifiedAnalysisRun.risk_id == risk_id)
    if target_ref:
        query = query.filter(models.UnifiedAnalysisRun.target_ref == target_ref)
    rows = query.limit(max(1, min(limit, 100))).all()
    return [{"run_id": row.run_id, "task_type": row.task_type, "target_ref": row.target_ref,
             "mode": row.mode, "status": row.status, "risk_id": row.risk_id,
             "created_at": row.created_at, "completed_at": row.completed_at}
            for row in rows]


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id).one_or_none()
    if row is None:
        raise HTTPException(404, "运行不存在")
    result = project_live_roles(db, row, _serialize_run(row))
    linked = []
    if row.risk_id:
        for run in db.query(models.HarnessRun).filter_by(risk_id=row.risk_id).order_by(models.HarnessRun.created_at.desc()).limit(100):
            plan = json.loads(run.plan_json or "{}")
            if (plan.get("shadow_candidate") or {}).get("run_id") == row.run_id:
                linked.append({"id": run.id, "status": run.status, "trace_id": run.trace_id,
                    "goal": plan.get("goal"), "plan_hash": run.plan_hash,
                    "asset_id": run.asset_id, "plan": plan, "approved_by": run.approved_by,
                    "approved": bool(run.approval_hash and run.approval_hash == run.plan_hash),
                    "blocked_reasons": plan.get("blocked_reasons", []),
                    "result": json.loads(run.result_json or "{}")})
    result["harness_checks"] = linked
    result["investigations"] = [investigation.serialize(item) for item in db.query(models.InvestigationRequest).filter(
        (models.InvestigationRequest.source_run_id == row.run_id) | (models.InvestigationRequest.reanalysis_run_id == row.run_id))]
    return result


@router.get("/runs/{run_id}/comparison")
def compare_run(run_id: str, db: Session = Depends(get_db)):
    """影子运行与同事件正式链路结论的对照（影子只读，不改正式字段）。"""
    row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id).one_or_none()
    if row is None:
        raise HTTPException(404, "运行不存在")
    if row.mode != "shadow" or not row.risk_id:
        return {"run_id": run_id, "comparable": False,
                "reason": "仅影子模式的 risk_review 运行可对照"}
    state = json.loads(row.state_json or "{}")
    formal = db.get(models.RiskAssessment, row.risk_id)
    unified_policy = (state.get("final") or {}).get("policy") or {}
    return {
        "run_id": run_id,
        "comparable": True,
        "risk_id": row.risk_id,
        "unified": {
            "policy": unified_policy,
            "decision": json.loads(row.decision_json or "{}"),
            "degraded_roles": state.get("degraded_roles", []),
        },
        "formal_snapshot": {
            "review_status": formal.review_status if formal else None,
            "final_score": formal.final_score if formal else None,
            "risk_level": formal.risk_level if formal else None,
            "decision": formal.decision if formal else None,
            "recommended_action": formal.recommended_action if formal else None,
            "note": "正式字段仅由正式链路写入；影子结果只读对照。",
        },
    }
