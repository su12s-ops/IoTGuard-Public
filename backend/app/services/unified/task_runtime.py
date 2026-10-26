"""Scoped durable reports and bounded model dispatch for task_graph reviews.

The process-wide semaphore is held by the actual HTTP worker, including a late
response. Reports are immutable receipts within a lease; failed/expired work can
be claimed again. Runtime and applicability reports retain candidate scope until
their schemas support a verified per-CVE projection.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import threading
import time
import uuid

from sqlalchemy.exc import IntegrityError

from app import config, models
from app.services.agent_infra import ModelResponseError, configure_bounded_model_profile
from app.services.unified.agent_base import BudgetExceeded

VERSION = "scoped-task-graph-v6"
_slots = threading.BoundedSemaphore(2)
_claims = threading.RLock()
_task_changed = threading.Condition()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    default=str, separators=(",", ":")).encode()).hexdigest()


def semantic(value):
    """Remove observation receipts, retaining semantic timestamps and freshness."""
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items()
                if k not in {"as_of", "queried_at", "age_seconds", "age_hours"}
                and not k.endswith(("_age_seconds", "_age_hours"))}
    if isinstance(value, list):
        return [semantic(v) for v in value]
    return value


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class BatchRuntime:
    def __init__(self, batch_id, session_factory, client_factory, *, seconds=1800,
                 max_tokens=600_000, max_requests=160, request_seconds=180,
                 output_tokens=16384, task_requests=4, workflow_id=""):
        self.batch_id, self.session_factory = batch_id, session_factory
        self.client_factory = client_factory
        self.deadline = time.monotonic() + max(0, seconds)
        self.max_tokens, self.max_requests = max_tokens, max_requests
        self.request_seconds, self.output_tokens = request_seconds, output_tokens
        self.task_requests = task_requests
        self.owner = uuid.uuid4().hex
        self.lock = threading.RLock()
        self.review_changed = threading.Condition(self.lock)
        self.reviews = {}
        self.admission_stop_reason = ""
        self.reserved = self.consumed = self.requests = self.unknown_usage = 0
        self.task_counts = {}
        self.workflow_id = workflow_id
        self.stop_reason = ""

    def persist_budget(self):
        with self.session_factory() as db:
            row = db.get(models.AnalysisBudget, self.batch_id)
            if row is None:
                row = models.AnalysisBudget(batch_id=self.batch_id, workflow_id=self.workflow_id)
                db.add(row)
            row.charged_tokens = self.consumed
            row.reserved_tokens = self.reserved + sum(r["tokens"] for r in self.reviews.values())
            row.requests, row.unknown_usage_requests = self.requests, self.unknown_usage
            row.updated_at = datetime.now(timezone.utc)
            db.commit()

    def remaining(self):
        return 0 if self.stop_reason else max(0, self.deadline - time.monotonic())

    def acquire_review(self, run_id, *, tokens=200_000, requests=16, seconds=480):
        """Reserve a complete risk's allowance before any role is dispatched."""
        with self.review_changed:
            while True:
                if run_id in self.reviews:
                    return True
                if self.remaining() < seconds or self.remaining() <= 0:
                    self.admission_stop_reason = "analysis_window_exhausted"
                    return False
                held_tokens = sum(r["tokens"] for r in self.reviews.values())
                held_requests = sum(r["requests"] for r in self.reviews.values())
                if (self.consumed + self.reserved + held_tokens + tokens <= self.max_tokens
                        and self.requests + held_requests + requests <= self.max_requests):
                    self.reviews[run_id] = {"tokens": tokens, "requests": requests}
                    try:
                        self.persist_budget()
                    except Exception:
                        del self.reviews[run_id]
                        raise
                    return True
                # Another admitted risk can return unused credit. Wait instead
                # of draining the queue as false failures or premature deferrals.
                if (self.reviews and self.consumed + tokens <= self.max_tokens
                        and self.requests + requests <= self.max_requests):
                    self.review_changed.wait(timeout=min(.5, self.remaining()))
                    continue
                self.admission_stop_reason = "analysis_budget_insufficient_for_review"
                return False

    def release_review(self, run_id):
        with self.review_changed:
            self.reviews.pop(run_id, None)
            try:
                self.persist_budget()
            finally:
                self.review_changed.notify_all()

    def reserve(self, task_id, prompt_tokens, role="", *, review_id=""):
        amount = prompt_tokens + self.output_tokens
        with self.lock:
            if self.remaining() <= 0:
                raise BudgetExceeded("batch_deadline_exhausted")
            if self.task_counts.get(task_id, 0) >= self.task_requests:
                raise BudgetExceeded("task_request_budget_exhausted")
            review = self.reviews.get(review_id)
            held_tokens = sum(r["tokens"] for key, r in self.reviews.items() if key != review_id)
            held_requests = sum(r["requests"] for key, r in self.reviews.items() if key != review_id)
            if review is not None and (review["tokens"] < amount or review["requests"] < 1):
                raise BudgetExceeded("review_model_budget_exhausted")
            if (self.requests + held_requests >= self.max_requests
                    or self.consumed + self.reserved + held_tokens + amount > self.max_tokens):
                if not self.reserved and not self.reviews:
                    self.stop_reason = "batch_model_budget_exhausted"
                raise BudgetExceeded("batch_model_budget_exhausted")
            if review is None and role and role != "decision_planner":
                decision_reserve = min(32768, self.max_tokens // 4)
                if self.consumed + self.reserved + amount > self.max_tokens - decision_reserve:
                    raise BudgetExceeded("batch_budget_reserved_for_decision")
            self.requests += 1
            self.task_counts[task_id] = self.task_counts.get(task_id, 0) + 1
            self.reserved += amount
            if review is not None:
                review["tokens"] -= amount
                review["requests"] -= 1
            try:
                self.persist_budget()
            except Exception:
                self.reserved -= amount
                self.requests -= 1
                self.task_counts[task_id] -= 1
                if review is not None:
                    review["tokens"] += amount
                    review["requests"] += 1
                raise
        return amount

    def settle(self, amount, usage, *, review_id=""):
        with self.lock:
            self.reserved -= amount
            if usage and usage.get("total_tokens") is not None:
                charged = int(usage["total_tokens"])
            else:
                # Retain the reservation as a conservative budget charge, not
                # fabricated observed usage. Transport failures may be billable.
                charged = amount
                self.unknown_usage += 1
            self.consumed += charged
            review = self.reviews.get(review_id)
            if review is not None:
                review["tokens"] = max(0, review["tokens"] + amount - charged)
            self.persist_budget()

    def client(self, task_id, role="", observer=None, *, review_id=""):
        runtime = self
        client = self.client_factory()
        configure_bounded_model_profile(client)
        if hasattr(client, "_max_tokens"):
            client._max_tokens = self.output_tokens
        if hasattr(client, "_output_limit"):
            client._output_limit = self.output_tokens

        class GovernedClient:
            def complete(self, messages, tools=None):
                return self.complete_with_timeout(messages, tools, timeout_s=runtime.request_seconds)

            def complete_with_timeout(self, messages, tools=None, *, timeout_s):
                request_id = uuid.uuid4().hex[:16]
                def observe(kind, **detail):
                    if observer:
                        observer(kind, {"request_id": request_id, **detail})
                # Queueing consumes the caller's role/batch window, not the
                # HTTP request allowance. Otherwise a busy slot can leave a
                # healthy model only a few milliseconds to return a report.
                deadline = time.monotonic() + min(timeout_s, runtime.remaining())
                observe("model_waiting", phase="queue")
                if not _slots.acquire(timeout=max(0, deadline - time.monotonic())):
                    observe("model_failed", phase="failed", reason="global_request_slots_timeout")
                    raise BudgetExceeded("global_request_slots_timeout")
                amount = None
                usage = None
                try:
                    if deadline <= time.monotonic():
                        raise BudgetExceeded("batch_deadline_exhausted")
                    chars = len(json.dumps({"messages": messages, "tools": tools}, ensure_ascii=False))
                    # Includes schema and tool descriptions, unlike context-only
                    # estimates. Reservation is distinct from actual usage.
                    amount = runtime.reserve(task_id, math.ceil(chars / 2), role, review_id=review_id)
                    observe("model_started", phase="model", input_chars=chars,
                            model=getattr(client, "_model", None),
                            thinking=getattr(client, "_thinking", None),
                            reasoning_effort=getattr(client, "_reasoning_effort", None))
                    bounded = getattr(client, "complete_with_timeout", None)
                    request_timeout = min(runtime.request_seconds, deadline - time.monotonic(), runtime.remaining())
                    if request_timeout <= 0:
                        raise BudgetExceeded("batch_deadline_exhausted")
                    response = (bounded(messages, tools=tools, timeout_s=request_timeout)
                                if bounded else client.complete(messages, tools=tools))
                    usage = response.get("usage")
                    observe("model_finished", phase="validating", usage=usage)
                    return response
                except ModelResponseError as exc:
                    usage = exc.usage
                    observe("model_failed", phase="failed", reason=str(exc)[:240])
                    raise
                except Exception as exc:
                    observe("model_failed", phase="failed", reason=type(exc).__name__)
                    raise
                finally:
                    try:
                        if amount is not None:
                            runtime.settle(amount, usage, review_id=review_id)
                    finally:
                        _slots.release()
        return GovernedClient()

    def snapshot(self):
        with self.lock:
            return {"version": VERSION, "batch_id": self.batch_id, "requests": self.requests,
                    "budget_charged_tokens": self.consumed, "reserved_tokens": self.reserved,
                    "review_reserved_tokens": sum(r["tokens"] for r in self.reviews.values()),
                    "admitted_reviews": len(self.reviews),
                    "admission_stop_reason": self.admission_stop_reason,
                    "unknown_usage_requests": self.unknown_usage,
                    "remaining_seconds": round(self.remaining()), "max_tokens": self.max_tokens,
                    "stop_reason": self.stop_reason,
                    "global_request_limit": 2}

    def wait_for_report(self, timeout):
        with _task_changed:
            _task_changed.wait(timeout=max(0, min(.5, timeout)))

    def claim(self, role, asset_id, dependencies, run_id, snapshot_id="", *, lease_owner=None):
        key = digest({"version": VERSION, "role": role, "asset": asset_id,
                      "model": [config.DEEPSEEK_MODEL, config.DEEPSEEK_API_PROTOCOL,
                                config.DEEPSEEK_BASE_URL, config.DEEPSEEK_THINKING],
                      "dependencies": dependencies})
        # Serialize local claims; unique task_key plus transaction handles a
        # colliding insert. A different live owner is never stolen.
        with _claims, self.session_factory() as db:
            row = db.query(models.AnalysisTask).filter_by(task_key=key).first()
            now = datetime.now(timezone.utc)
            if row and row.status == "completed" and utc(row.expires_at) > now:
                return row.id, json.loads(row.report_json), row.origin_run_id, row.origin_snapshot_id
            if row and row.status == "failed" and row.batch_id == self.batch_id:
                return row.id, {"_task_error": row.error or "shared_task_failed"}, row.origin_run_id, row.origin_snapshot_id
            if row and row.status == "running" and utc(row.expires_at) > now:
                return None, None, None, None
            if row is None:
                row = models.AnalysisTask(id="AT-" + uuid.uuid4().hex[:24], task_key=key,
                    asset_id=asset_id, role=role, owner=self.owner, expires_at=now)
                db.add(row)
            else:
                history = json.loads(row.history_json or "[]")
                history.append({"origin_run_id": row.origin_run_id,
                    "origin_snapshot_id": row.origin_snapshot_id, "status": row.status,
                    "report": json.loads(row.report_json or "{}"), "error": row.error,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None})
                row.history_json = json.dumps(history, ensure_ascii=False)
            row.status, row.owner, row.batch_id = "running", lease_owner or self.owner, self.batch_id
            row.origin_run_id, row.report_json, row.error = run_id, "{}", ""
            row.origin_snapshot_id = snapshot_id
            row.dependencies_json = json.dumps(dependencies, ensure_ascii=False, default=str)
            row.updated_at, row.expires_at = now, now + timedelta(seconds=min(480, self.remaining()))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return None, None, None, None
            return row.id, None, run_id, snapshot_id

    def finish(self, task_id, report=None, error="", *, lease_owner=None):
        with self.session_factory() as db:
            now = datetime.now(timezone.utc)
            row = db.get(models.AnalysisTask, task_id)
            if not row:
                return False
            # Fence the write in the database as well as at claim time. A late
            # worker must not finish a replacement lease, even in this batch.
            changed = db.query(models.AnalysisTask).filter(
                models.AnalysisTask.id == task_id,
                models.AnalysisTask.owner == (lease_owner or self.owner),
                models.AnalysisTask.status == "running",
                models.AnalysisTask.expires_at > now,
            ).update({
                "status": "completed" if report is not None else "failed",
                "report_json": json.dumps(deepcopy(report) if report is not None else {}, ensure_ascii=False),
                "error": error[:1000], "updated_at": now,
                "expires_at": now + timedelta(seconds=300 if row.role == "runtime_analyst" else 3600),
            }, synchronize_session=False)
            db.commit()
            if not changed:
                return False
        with _task_changed:
            _task_changed.notify_all()
        return True


def for_review(db, batch_id, session_factory, client_factory):
    """Carry the console's wall deadline and charged budget over batch boundaries."""
    seconds, spent, requests = 1800.0, 0, 0
    flow = db.query(models.ConsoleWorkflow).filter_by(status="running").order_by(
        models.ConsoleWorkflow.created_at.desc()).first()
    if flow:
        seconds -= (datetime.now(timezone.utc) - utc(flow.created_at)).total_seconds()
        batches = {}
        for row in db.query(models.UnifiedAnalysisRun).filter(
                models.UnifiedAnalysisRun.created_at >= flow.created_at).all():
            state = json.loads(row.state_json or "{}")
            budget = state.get("final", {}).get("batch_budget", {})
            name = budget.get("batch_id")
            if name:
                previous = batches.setdefault(name, {})
                for key in ("budget_charged_tokens", "requests"):
                    previous[key] = max(previous.get(key, 0), budget.get(key, 0))
        spent = sum(b.get("budget_charged_tokens", 0) for b in batches.values())
        requests = sum(b.get("requests", 0) for b in batches.values())
        ledger = db.query(models.AnalysisBudget).filter_by(workflow_id=flow.id).all()
        if ledger:
            # In-flight/unknown reservations survive worker loss and count
            # conservatively. A late response settles its original batch row.
            spent = sum(row.charged_tokens + row.reserved_tokens for row in ledger)
            requests = sum(row.requests for row in ledger)
    return BatchRuntime(batch_id, session_factory, client_factory, seconds=max(0, seconds),
                        max_tokens=max(0, 600_000 - spent), max_requests=max(0, 160 - requests),
                        workflow_id=flow.id if flow else "")
