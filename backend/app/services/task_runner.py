from __future__ import annotations

import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable


JobProgress = Callable[[str, int | None, int | None], None]
JobRunner = Callable[[JobProgress], dict[str, Any]]


_jobs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _copy_job(job: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(job)


def create_job(kind: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "kind": kind,
        "status": "pending",
        "message": "Queued",
        "params": params or {},
        "progress_current": 0,
        "progress_total": None,
        "result": None,
        "error": "",
        "warnings": [],
        "created_at": _utc_now(),
        "started_at": "",
        "finished_at": "",
        "updated_at": _utc_now(),
    }
    with _lock:
        _jobs[job_id] = job
    return _copy_job(job)


def get_job(job_id: str) -> dict[str, Any] | None:
    with _lock:
        job = _jobs.get(job_id)
        return _copy_job(job) if job else None


def has_active_jobs() -> bool:
    with _lock:
        return any(job["status"] in ("pending", "running") for job in _jobs.values())


def update_job(job_id: str, **fields: Any) -> dict[str, Any] | None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        job.update(fields)
        job["updated_at"] = _utc_now()
        return _copy_job(job)


def append_job_warning(job_id: str, message: str) -> dict[str, Any] | None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        warnings = list(job.get("warnings") or [])
        warnings.append(message)
        job["warnings"] = warnings
        job["updated_at"] = _utc_now()
        return _copy_job(job)


def start_job(kind: str, runner: JobRunner, params: dict[str, Any] | None = None) -> dict[str, Any]:
    job = create_job(kind=kind, params=params)
    job_id = job["job_id"]

    def progress(message: str, current: int | None = None, total: int | None = None) -> None:
        payload: dict[str, Any] = {"message": message}
        if current is not None:
            payload["progress_current"] = current
        if total is not None:
            payload["progress_total"] = total
        update_job(job_id, **payload)

    def run_in_thread() -> None:
        update_job(job_id, status="running", started_at=_utc_now(), message="Started")
        try:
            result = runner(progress)
            warnings = result.get("warnings", []) if isinstance(result, dict) else []
            update_job(
                job_id,
                status="succeeded",
                message="Completed",
                result=result,
                warnings=warnings,
                finished_at=_utc_now(),
            )
        except Exception as exc:
            update_job(
                job_id,
                status="failed",
                message="Failed",
                error=str(exc),
                finished_at=_utc_now(),
            )

    threading.Thread(target=run_in_thread, daemon=True).start()
    return get_job(job_id) or job
