"""Bounded continuation of explicitly authorized inventory investigations."""
import json
import logging
import threading

from app import models
from app.services.unified import investigation


def tick(db):
    items = db.query(models.InvestigationRequest).filter_by(status="authorized").order_by(
        models.InvestigationRequest.created_at).all()
    for item in items:
        permission = json.loads(item.result_json or "{}").get("continuation", {})
        if not permission.get("auto_resume"):
            continue
        if permission.get("request_hash") != item.request_hash or permission.get("authorized_by") != item.authorized_by:
            continue
        run = db.get(models.HarnessRun, item.collection_run_id)
        if not run or run.status in {"failed", "interrupted", "cancelled"}:
            item.status = "collection_failed"
            item.result_json = investigation.encode({"continuation": permission,
                "reason": "授权采集未成功；保留人审，不自动重试设备操作"})
            db.commit()
            continue
        if run.status != "completed":
            continue
        try:
            investigation.resume(db, item)
        except Exception as exc:
            db.rollback()
            db.refresh(item)
            # Another worker may own the atomic resume claim. Never overwrite it.
            if str(exc) == "reanalysis_already_claimed" or item.reanalysis_run_id:
                continue
            item.status = "auto_resume_blocked"
            item.result_json = investigation.encode({"continuation": permission,
                "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__})
            db.commit()
        return  # at most one model reassessment per tick


def start_worker(session_factory):
    stop = threading.Event()
    def work():
        while not stop.wait(15):
            try:
                with session_factory() as db:
                    tick(db)
            except Exception:
                logging.getLogger(__name__).exception("Authorized investigation continuation failed")
    thread = threading.Thread(target=work, name="investigation-continuation", daemon=True)
    thread.start()
    return stop, thread
