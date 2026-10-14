"""重构后四智能体的 API：规格查询、发起编排、运行状态。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.agents import orchestrator, specs_summary

router = APIRouter(prefix="/agents", tags=["Agent orchestration"])


class AnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(default="", max_length=128)
    hostname: str = Field(default="", max_length=128)

    def resolved_target(self) -> tuple[str, str]:
        if self.device_id:
            return self.device_id, "device"
        if self.hostname:
            return self.hostname, "linux_host"
        raise ValueError("必须提供 device_id 或 hostname 之一")


@router.get("/specs")
def agent_specs():
    """四个智能体的职责与专属工具清单（可核验工具互不重叠）。"""
    return {
        "orchestration": orchestrator.STAGES,
        "note": "智能体差异来自职责+工具集+输出模型；流程/超时/重试/校验由 Python 编排器负责。",
        "agents": specs_summary(),
    }


@router.post("/analyze", status_code=202)
def analyze(payload: AnalyzeInput, db: Session = Depends(get_db)):
    try:
        target_ref, target_type = payload.resolved_target()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if target_type == "device":
        if not db.query(models.IotDevice).filter_by(device_id=target_ref).first():
            raise HTTPException(404, "设备不存在，请先在设备中心完成发现")
    else:
        if not db.query(models.LinuxAsset).filter_by(hostname=target_ref).first():
            raise HTTPException(404, "主机资产不存在")
    try:
        run = orchestrator.start_analysis(target_ref, target_type)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return {"run_id": run.run_id, "trace_id": getattr(run, "trace_id", ""),
            "status": run.status, "target": target_ref,
            "stages": orchestrator.STAGES}


def _serialize_run(row: models.AgentOrchestrationRun) -> dict:
    return {
        "run_id": row.run_id, "target_type": row.target_type, "target_ref": row.target_ref,
        "status": row.status, "error": row.error,
        "stages": json.loads(row.stages_json or "{}"),
        "agents": json.loads(row.agents_json or "{}"),
        "risk": json.loads(row.risk_json or "{}"),
        "remediation": json.loads(row.remediation_json or "{}"),
        "verify": json.loads(row.verify_json or "{}"),
        "created_at": row.created_at, "completed_at": row.completed_at,
    }


@router.get("/runs")
def list_runs(limit: int = 20, db: Session = Depends(get_db)):
    rows = (db.query(models.AgentOrchestrationRun)
            .order_by(models.AgentOrchestrationRun.id.desc()).limit(max(1, min(limit, 100))).all())
    return [{"run_id": row.run_id, "target_ref": row.target_ref, "status": row.status,
             "created_at": row.created_at, "completed_at": row.completed_at} for row in rows]


@router.get("/runs/{run_id}")
def run_detail(run_id: str, db: Session = Depends(get_db)):
    row = db.query(models.AgentOrchestrationRun).filter_by(run_id=run_id).one_or_none()
    if not row:
        raise HTTPException(404, "运行记录不存在")
    return _serialize_run(row)
