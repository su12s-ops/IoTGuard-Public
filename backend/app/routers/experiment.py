"""Experiment lifecycle API: archive the current results and start a clean round.

Device inventory, connections, sensors and policy stay in place. Derived run
artifacts (vulnerabilities, matches, risks, agent runs, repair tasks, runtime
events, traces) are archived as a compact result snapshot before deletion.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services import result_archive
from app.services.device_access import require_control
from app.services.experiment_lifecycle import clear_derived_data

router = APIRouter(prefix="/experiment", tags=["Experiment lifecycle"])


class ArchiveInput(BaseModel):
    label: str = Field(default="", max_length=80)


class ResetInput(ArchiveInput):
    archive: bool = True


def require_console_refresh(request: Request):
    # A non-simple header prevents cross-site forms from triggering a reset.
    # This narrow console action never grants device-control permissions.
    origin = request.headers.get("origin")
    allowed = {str(request.base_url).rstrip("/"),
               "http://localhost:5173", "http://127.0.0.1:5173",
               "http://localhost:5174", "http://127.0.0.1:5174"}
    if request.headers.get("X-Experiment-Action") != "refresh" or (origin and origin not in allowed):
        raise HTTPException(403, "请通过控制台的刷新本轮按钮操作")


@router.post("/refresh", dependencies=[Depends(require_console_refresh)])
def refresh_experiment(db: Session = Depends(get_db)):
    from app.services import console_workflow
    from app.services.task_runner import has_active_jobs
    with console_workflow.lock:
        for row in db.query(models.ConsoleWorkflow).filter_by(status="running").all():
            console_workflow.synchronize(db, row)
        if db.query(models.ConsoleWorkflow).filter_by(status="running").count() or has_active_jobs():
            raise HTTPException(409, "流程或情报同步正在运行，结束后才能刷新本轮")
        if any(result_archive.active_runs(db).values()) or db.query(models.AnalysisReport).filter_by(status="running").count():
            raise HTTPException(409, "仍有任务运行，结束后才能刷新本轮")
        # Delete only application-generated archive files inside their configured
        # directory. Never traverse device credentials or deployment materials.
        root = result_archive.archive_dir().resolve()
        archives = [path for path in root.glob("exp-*.json")
                    if path.is_file() and path.resolve().parent == root]
        try:
            cleared = clear_derived_data(db, full_console=True)
            from app.services.ebpf_event_collector import EVENT_FILE
            EVENT_FILE.unlink(missing_ok=True)
            for path in archives:
                path.unlink(missing_ok=True)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except OSError as exc:
            raise HTTPException(507, "本轮数据已清理，但部分旧归档文件未能删除，请检查存储权限") from exc
        return {"cleared": cleared, "archives_deleted": len(archives),
                "kept": {"assets": db.query(models.LinuxAsset).count(),
                         "iot_devices": db.query(models.IotDevice).count()}}


@router.get("/state")
def experiment_state(db: Session = Depends(get_db)):
    return result_archive.lifecycle_state(db)


@router.get("/archives", dependencies=[Depends(require_control)])
def experiment_archives():
    return {"archives": result_archive.list_result_archives(30)}


@router.post("/archive", dependencies=[Depends(require_control)])
def archive_results(payload: ArchiveInput, db: Session = Depends(get_db)):
    label = payload.label.strip() or "当前结果"
    try:
        return result_archive.write_result_archive(db, label=label, kind="manual")
    except OSError as exc:
        raise HTTPException(507, f"结果存档写入失败：{exc}") from exc


@router.post("/reset", dependencies=[Depends(require_control)])
def reset_experiment(payload: ResetInput, db: Session = Depends(get_db)):
    active = result_archive.active_runs(db)
    if any(active.values()):
        raise HTTPException(409, f"仍有运行中的任务，暂不能开始新一轮：{active}")

    archive_meta = None
    if payload.archive:
        try:
            archive_meta = result_archive.write_result_archive(
                db, label=payload.label.strip() or "新一轮开始前", kind="before-reset"
            )
        except OSError as exc:
            raise HTTPException(507, f"结果存档写入失败，未清理任何数据：{exc}") from exc

    try:
        cleared = clear_derived_data(db)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc

    return {
        "archive": archive_meta,
        "cleared": cleared,
        "kept": {
            "assets": db.query(models.LinuxAsset).count(),
            "iot_devices": db.query(models.IotDevice).count(),
            "sensors": db.query(models.RuntimeSensor).count(),
        },
    }


@router.get("/archives/{filename}", dependencies=[Depends(require_control)])
def download_archive(filename: str):
    try:
        path = result_archive.archive_path(filename)
    except FileNotFoundError as exc:
        raise HTTPException(404, "存档不存在") from exc
    return FileResponse(path, media_type="application/json", filename=path.name)
