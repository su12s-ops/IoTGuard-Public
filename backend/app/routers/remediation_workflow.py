"""MQTT 匿名接入修复工作流 API（阶段四）。

- 创建工作流：真实探测 MQTT → configuration evidence → Agent 方案 → DETECTED；
- 设备侧执行器上报真实动作与验证结果，驱动状态机；
- 平台在 verify 阶段独立复核（重新真实探测），不信任单方面上报。
"""
from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.device_access import allowed_host, require_control
from app.services import mqtt_security_workflow as W

router = APIRouter(prefix="/remediation/workflow", tags=["Remediation workflow"])


class WorkflowStartInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(max_length=64)
    port: int = Field(default=1883, ge=1, le=65535)


class WorkflowReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phase: Literal["action", "after", "verify", "rollback"]
    payload: dict[str, Any] = Field(default_factory=dict)
    commands: list[str] | None = Field(default=None, max_length=100)


@router.post("/mqtt-anonymous", dependencies=[Depends(require_control)])
def start_mqtt_workflow(payload: WorkflowStartInput, db: Session = Depends(get_db)):
    """真实检测 MQTT 匿名接入；若允许匿名则建立工作流（DETECTED）并生成修复方案。"""
    try:
        host = allowed_host(payload.host)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    detection = W.detect_mqtt_security(host, payload.port)
    if not detection["anonymous_allowed"]:
        return {"status": "not_vulnerable", "detection": detection,
                "message": "MQTT 不允许匿名连接（或无法连接），无需修复"}
    evidence_id = W.create_configuration_evidence(db, detection)
    plan = W.agent_plan(db, host, payload.port, detection)
    run = W.create_workflow_run(db, host, payload.port, plan, detection, evidence_id)
    return {"run_id": run.run_id, "status": run.status, "evidence_id": evidence_id,
            "detection": detection, "plan": plan}


@router.post("/{run_id}/report", dependencies=[Depends(require_control)])
def report_phase(run_id: str, payload: WorkflowReportInput, db: Session = Depends(get_db)):
    run = db.query(models.RemediationWorkflowRun).filter_by(run_id=run_id).one_or_none()
    if not run:
        raise HTTPException(404, "工作流不存在")
    if payload.phase == "verify":
        # 平台侧复核：重新真实探测，设备上报仅供参考
        recheck = W.backend_verify(run.target_host, run.target_port,
                                   payload.payload.get("expectation",
                                                       {"anonymous_allowed": False, "auth_works": True}))
        payload.payload["platform_recheck"] = recheck
        payload.payload.setdefault("verified", recheck["verified"])
    if payload.phase == "rollback":
        # 回滚复核：恢复原配置后匿名应重新可用（回到 Before 状态）
        recheck = W.detect_mqtt_security(run.target_host, run.target_port)
        payload.payload["platform_recheck"] = recheck
    run = W.apply_report(db, run, payload.phase, payload.payload, payload.commands)
    return W.serialize_run(run)


@router.get("/runs/{run_id}")
def workflow_detail(run_id: str, db: Session = Depends(get_db)):
    run = db.query(models.RemediationWorkflowRun).filter_by(run_id=run_id).one_or_none()
    if not run:
        raise HTTPException(404, "工作流不存在")
    return W.serialize_run(run)


@router.get("/runs")
def workflow_list(limit: int = 20, db: Session = Depends(get_db)):
    rows = (db.query(models.RemediationWorkflowRun)
            .order_by(models.RemediationWorkflowRun.id.desc())
            .limit(max(1, min(limit, 100))).all())
    return [{"run_id": r.run_id, "target": f"{r.target_host}:{r.target_port}",
             "status": r.status, "scenario": r.scenario, "created_at": r.created_at}
            for r in rows]
