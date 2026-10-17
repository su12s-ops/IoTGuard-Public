from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.services.remediation_engine import generate_remediation_tasks, _authorized
from app.services.device_access import require_control

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.post("/generate")
def generate(allow_human_override: bool = False, db: Session = Depends(get_db)):
    """生成修复任务。

    仅对 auto_confirmed/human_confirmed（及其后续修复状态）生成正式任务。
    ``allow_human_override`` 仅为旧客户端兼容参数，不能绕过逐事件人工审核。
    """
    count = generate_remediation_tasks(db, allow_human_override=allow_human_override)
    return {"message": "Remediation tasks generated", "count": count}


@router.get("/tasks")
def tasks(db: Session = Depends(get_db)):
    rows = []
    for task in db.query(models.RemediationTask).order_by(models.RemediationTask.id).all():
        asset = db.get(models.LinuxAsset, task.asset_id)
        risk = db.get(models.RiskAssessment, task.risk_id) if task.risk_id else None
        rows.append(
            {
                "id": task.id,
                "hostname": asset.hostname if asset else "",
                "asset_id": task.asset_id,
                "risk_id": task.risk_id,
                "distribution": asset.distribution if asset else "",
                "cve_id": task.cve_id,
                "package_name": task.package_name,
                "current_version": task.current_version,
                "target_version": task.target_version,
                "risk_level": risk.risk_level if risk else "",
                "decision": risk.decision if risk else "",
                "decision_reason": risk.decision_reason if risk else "",
                "review_status": risk.review_status if risk else "",
                "review_verdict": risk.review_verdict if risk else "",
                "human_review_required": risk.human_review_required if risk else False,
                "remediation_command": task.remediation_command,
                "mitigation": task.mitigation,
                "verification_command": task.verification_command,
                "status": task.status,
            }
        )
    return rows


@router.patch("/tasks/{task_id}", dependencies=[Depends(require_control)])
def update_task(task_id: int, payload: schemas.TaskStatusUpdate, db: Session = Depends(get_db)):
    task = db.get(models.RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    from app.services.review_common.governance import execution_allowed
    risk = db.get(models.RiskAssessment, task.risk_id) if task.risk_id else None
    if task.status == "invalidated" or not execution_allowed(db, risk) or not _authorized(risk):
        raise HTTPException(409, "risk_or_remediation_authorization_invalid")
    asset = db.get(models.LinuxAsset, task.asset_id)
    if asset and asset.distribution == "openwrt":
        raise HTTPException(409, "OpenWrt 修复状态由设备任务的执行、版本、漏洞回归和业务复查更新，不能手动修改。")
    task.status = payload.status
    risk = db.get(models.RiskAssessment, task.risk_id) if task.risk_id else None
    if risk:
        risk.review_status = {
            "pending": "remediation_ready",
            "blocked": "remediation_ready",
            "in_progress": "remediation_in_progress",
            "fixed": "verification",
            "verified": "resolved",
        }[payload.status]
    db.commit()
    return {"message": "Task updated", "id": task.id, "status": task.status}
