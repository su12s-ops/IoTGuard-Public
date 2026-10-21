"""Experiment lifecycle API: archive the current results and start a clean round.

Device inventory, connections, sensors and policy stay in place. Derived run
artifacts (vulnerabilities, matches, risks, agent runs, repair tasks, runtime
events, traces) are archived as a compact result snapshot before deletion.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
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
