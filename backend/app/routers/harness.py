import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services import agent_harness as harness
from app.services import trace_service as tracing
from app.services.device_access import require_control

router = APIRouter(prefix="/harness", tags=["Agent task harness"])


class CreateRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int = Field(gt=0)
    risk_id: int | None = Field(default=None, gt=0)
    goal: Literal["collect", "investigate", "repair"] = "investigate"
    artifact_id: str = Field(default="", max_length=64)
    model_review: bool = False
    shadow_run_id: str = Field(default="", max_length=128)


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_hash: str = Field(min_length=64, max_length=64)
    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=1000)


def serialize(row, db=None):
    value = {key: getattr(row, key) for key in ("id", "asset_id", "risk_id", "connection_id", "status", "current_step", "plan_hash", "approved_by", "approval_reason", "error", "attempts", "trace_id", "created_at", "updated_at", "completed_at")}
    value.update(plan=json.loads(row.plan_json), result=json.loads(row.result_json), snapshot=json.loads(row.snapshot_json))
    if db is not None:
        value["tool_calls"] = [{"id": c.id, "tool": c.tool, "status": c.status, "side_effect": c.side_effect,
                                "arguments": json.loads(c.arguments_json), "output": json.loads(c.output_json),
                                "error": c.error, "duration_ms": c.duration_ms, "created_at": c.created_at, "completed_at": c.completed_at}
                               for c in db.query(models.HarnessToolCall).filter_by(run_id=row.id).order_by(models.HarnessToolCall.id)]
    return value


def get_run(db, run_id):
    row = db.get(models.HarnessRun, run_id)
    if not row:
        raise HTTPException(404, "任务不存在")
    return row


@router.get("/runs")
def list_runs(db: Session = Depends(get_db)):
    return [serialize(row) for row in db.query(models.HarnessRun).order_by(models.HarnessRun.created_at.desc()).limit(100)]


@router.get("/runs/{run_id}")
def detail(run_id: str, db: Session = Depends(get_db)):
    return serialize(get_run(db, run_id), db)


@router.get("/artifacts")
def artifacts():
    try:
        registry, _ = harness.artifact_registry()
        return [{key: item.get(key, "") for key in ("id", "package_name", "version", "release", "board_name", "sha256", "rollback_artifact_id")} for item in registry.values()]
    except (ValueError, OSError) as exc:
        raise HTTPException(400, "修复产物清单不可用，请检查后端配置") from exc


@router.post("/runs", dependencies=[Depends(require_control)])
def create(payload: CreateRun, db: Session = Depends(get_db)):
    """创建 Harness 任务并生成统一 Trace（第八阶段）。

    计划生成/审批/工具调用/回滚事件经 agent_harness 服务写入同一 trace_id；
    不改变任何既有安全行为（审批绑定、互斥锁、预算、写开关）。
    """
    task_type = {"collect": "harness_collect", "investigate": "harness_investigate",
                 "repair": "harness_repair"}[payload.goal]
    trace = tracing.start_trace(db, task_type=task_type, target_type="asset",
                                target_ref=f"asset-{payload.asset_id}", run_ref_type="harness",
                                run_ref_id="pending",
                                metadata={"goal": payload.goal, "risk_id": payload.risk_id,
                                          "model_review": payload.model_review})
    try:
        run = harness.create_run(db, **payload.model_dump(), trace_id=trace.trace_id)
    except (ValueError, OSError) as exc:
        tracing.finish_trace(db, trace.trace_id, "failed", error=str(exc),
                             summary={"harness_status": "create_failed"})
        raise HTTPException(400, str(exc)) from exc
    trace.run_ref_id, trace.harness_run_id = run.id, run.id
    db.commit()
    if run.status == "blocked":
        # 计划在生成阶段即被安全策略拦截（缺连接/未授权/产物不一致等）：
        # 任务无法推进，Trace 以 blocked 收口，原因见 harness_policy_blocked 事件。
        tracing.finish_trace(db, trace.trace_id, "blocked",
                             summary={"harness_status": "blocked",
                                      "reasons": json.loads(run.plan_json).get("blocked_reasons", [])})
    return serialize(run, db)


@router.post("/runs/{run_id}/approve", dependencies=[Depends(require_control)])
def approve(run_id: str, payload: Approval, db: Session = Depends(get_db)):
    row = get_run(db, run_id)
    try:
        harness.approve(db, row, payload.plan_hash, payload.actor, payload.reason)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return serialize(row, db)


@router.post("/runs/{run_id}/execute", dependencies=[Depends(require_control)])
def execute(run_id: str, db: Session = Depends(get_db)):
    try:
        return serialize(harness.execute(db, get_run(db, run_id)), db)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/runs/{run_id}/verify", dependencies=[Depends(require_control)])
def verify(run_id: str, db: Session = Depends(get_db)):
    try:
        return serialize(harness.execute(db, get_run(db, run_id), verify_only=True), db)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/runs/{run_id}/cancel", dependencies=[Depends(require_control)])
def cancel(run_id: str, db: Session = Depends(get_db)):
    row = get_run(db, run_id)
    try:
        harness.cancel(db, row)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return serialize(row, db)


@router.post("/recover", dependencies=[Depends(require_control)])
def recover(db: Session = Depends(get_db)):
    return {"recovered": harness.recover_interrupted(db)}


@router.post("/runs/{run_id}/rollback", dependencies=[Depends(require_control)])
def rollback(run_id: str, payload: Approval, db: Session = Depends(get_db)):
    try:
        return serialize(harness.rollback(db, get_run(db, run_id), payload.plan_hash, payload.actor, payload.reason), db)
    except (ValueError, OSError) as exc:
        raise HTTPException(409, str(exc)) from exc
