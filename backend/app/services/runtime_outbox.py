"""Durable evidence outbox. Event + job commit together; workers retry after restart.

No in-memory queue is acknowledged. One in-process lock serializes the local
worker with ingestion; DB uniqueness makes a competing worker rollback safely.
"""
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from app import models

log = logging.getLogger(__name__)


class EvidenceBackpressure(RuntimeError):
    pass


def check_capacity(db, incoming):
    maximum = max(1, int(os.getenv("IOTGUARD_EVIDENCE_MAX_PENDING", "100000")))
    if db.query(models.RuntimeEvidenceJob).count() + incoming > maximum:
        raise EvidenceBackpressure("Evidence backlog at capacity; retry later (events remain in sender WAL)")


def enqueue(db, event):
    job = db.query(models.RuntimeEvidenceJob).filter_by(event_id=event["id"]).first()
    body = dict(event)
    body.pop("duplicate", None)
    if job is None:
        db.add(models.RuntimeEvidenceJob(event_id=event["id"], payload=json.dumps(body, ensure_ascii=False)))
    else:
        job.payload = json.dumps(body, ensure_ascii=False)
    db.flush()
    event["evidence_state"] = "pending"


def drain(factory, limit=25):
    from app.services.ebpf_event_collector import _PERSIST_LOCK
    from app.services.security_evidence import persist_evidence
    completed = 0
    with _PERSIST_LOCK, factory() as db:
        ids = [row[0] for row in db.query(models.RuntimeEvidenceJob.event_id).filter(
            models.RuntimeEvidenceJob.next_attempt_at <= datetime.now(timezone.utc).replace(tzinfo=None)
        ).order_by(models.RuntimeEvidenceJob.event_id).limit(limit).all()]
        for event_id in ids:
            job = db.get(models.RuntimeEvidenceJob, event_id)
            if job is None:
                continue
            try:
                if db.get(models.RuntimeEvent, event_id) is not None:
                    persist_evidence(db, [json.loads(job.payload)], commit=False)
                db.delete(job)
                db.commit()
                completed += 1
            except Exception as exc:
                db.rollback()
                job = db.get(models.RuntimeEvidenceJob, event_id)
                if job is not None:
                    job.attempts += 1
                    job.last_error = type(exc).__name__
                    job.next_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=min(300, 2 ** min(job.attempts, 8)))
                    db.commit()
                log.warning("Runtime evidence job %s retry: %s", event_id, type(exc).__name__)
    return completed


def snapshot(db):
    count, oldest = db.query(func.count(models.RuntimeEvidenceJob.event_id),
                             func.min(models.RuntimeEvidenceJob.created_at)).one()
    failed = db.query(models.RuntimeEvidenceJob).filter(models.RuntimeEvidenceJob.attempts > 0).count()
    return {"pending": count, "retrying": failed, "oldest_pending_at": oldest,
            "ack_scope": "runtime_event_and_durable_evidence_job",
            "evidence_consistency": "eventual"}


def start_worker(factory):
    stop = threading.Event()
    def run():
        while not stop.is_set():
            try:
                n = drain(factory)
            except Exception:
                log.exception("Runtime evidence worker failed; pending jobs retained")
                n = 0
            stop.wait(0.05 if n else 1)
    thread = threading.Thread(target=run, name="runtime-evidence", daemon=True)
    thread.start()
    return stop, thread
