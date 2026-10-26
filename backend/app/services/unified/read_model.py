"""Read-only live role observations; trace never authorizes graph state or usage."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.services.unified.schemas import ALL_AGENT_IDS

_ROLE_EVENTS = ("agent_started", "agent_finished", "agent_failed", "task_waiting")

_ACTIVITY_EVENTS = ("model_waiting", "model_started", "model_finished", "model_failed", "tool_started", "tool_finished", "task_waiting")


def failure_category(error):
    text = (error or "").lower()
    if "context_budget" in text:
        return "context_limit"
    if "reasoning_only_output_budget_exhausted" in text:
        return "reasoning_output_exhausted"
    if "truncat" in text:
        return "output_truncated"
    if "budget" in text or "预算" in text:
        return "budget_limit"
    if "timeout" in text or "时限" in text or "超时" in text:
        return "timeout"
    if any(word in text for word in ("evidence", "finding", "引用", "事实校验")):
        return "evidence_validation"
    if "结构化" in text or "schema" in text:
        return "report_format"
    return "execution_error"


def project_activity(db, row, agents):
    """Durable, bounded observations, separate from authoritative role output."""
    now = datetime.now(timezone.utc)
    end = row.completed_at if row.status != "running" and row.completed_at else now
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    latest, timeline, requests = {}, [], {}
    role_times = {}
    with db.no_autoflush:
        events = db.query(models.TraceEvent).filter(models.TraceEvent.trace_id == row.trace_id,
            models.TraceEvent.actor.in_(ALL_AGENT_IDS), models.TraceEvent.event_type.in_(_ACTIVITY_EVENTS)
        ).order_by(models.TraceEvent.id.desc()).limit(80).all() if row.trace_id else []
    for event in events:
        try:
            detail = json.loads(event.payload_json or "{}")
        except (TypeError, ValueError):
            detail = {}
        if not isinstance(detail, dict):
            detail = {}
        stamp = event.created_at
        if stamp is not None and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        item = {"role": event.actor, "event": event.event_type,
                "phase": detail.get("phase"), "tool": detail.get("tool"),
                "request_id": detail.get("request_id"), "at": stamp.isoformat() if stamp else None,
                "elapsed_seconds": max(0, int((now - stamp).total_seconds())) if stamp else None}
        latest.setdefault(event.actor, item)
        request_id = detail.get("request_id")
        if request_id:
            request = requests.setdefault(request_id, {"role": event.actor})
            request.setdefault(event.event_type, stamp)
        if len(timeline) < 12:
            timeline.append(item)
    tools, tool_seconds = {}, 0.0
    for event in reversed(events):
        if event.event_type not in {"tool_started", "tool_finished"}:
            continue
        try:
            detail = json.loads(event.payload_json or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(detail, dict) or not event.created_at:
            continue
        key = (event.actor, detail.get("tool"))
        stamp = event.created_at.replace(tzinfo=timezone.utc) if event.created_at.tzinfo is None else event.created_at
        if event.event_type == "tool_started":
            tools[key] = stamp
        elif key in tools:
            seconds = max(0, (stamp - tools.pop(key)).total_seconds())
            tool_seconds += seconds
            times = role_times.setdefault(event.actor, {})
            times["tool_seconds"] = times.get("tool_seconds", 0) + seconds
    queue_seconds, model_seconds = 0.0, 0.0
    for request in requests.values():
        waiting, started = request.get("model_waiting"), request.get("model_started")
        ended = request.get("model_finished") or request.get("model_failed")
        queue = max(0, ((started or ended or end) - waiting).total_seconds()) if waiting else 0
        model = max(0, ((ended or end) - started).total_seconds()) if started else 0
        queue_seconds += queue
        model_seconds += model
        times = role_times.setdefault(request["role"], {})
        times["queue_seconds"] = times.get("queue_seconds", 0) + queue
        times["model_seconds"] = times.get("model_seconds", 0) + model
    activity = []
    for role in ALL_AGENT_IDS:
        log = agents.get(role)
        if not log:
            continue
        item = {"role": role, "status": log.get("status"), "error": str(log.get("error") or "")[:400]}
        item["timing"] = {key: round(value, 3) for key, value in role_times.get(role, {}).items()}
        item["timing"]["shared_wait_seconds"] = sum(
            entry.get("shared_wait_ms", 0) for entry in log.get("executions", [log])) / 1000
        item["timing"]["total_seconds"] = log.get("total_latency_ms", log.get("latency_ms", 0)) / 1000
        if item["error"]:
            item["failure_category"] = failure_category(item["error"])
        if row.status == "running" and item["status"] == "running" and role in latest:
            item.update(latest[role])
        activity.append(item)
    created = row.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    totals = {"model_requests": sum("model_started" in request for request in requests.values()),
              "model_responses": sum("model_finished" in request for request in requests.values()),
              "queue_seconds": round(queue_seconds, 3), "model_seconds": round(model_seconds, 3),
              "tool_seconds": round(tool_seconds, 3),
              "wall_seconds": round(max(0, (end - created).total_seconds()), 3) if created else None,
              "observed": bool(requests), "partial": len(events) == 80}
    return {"roles": activity, "timeline": list(reversed(timeline)), "totals": totals,
            "source": "persisted_trace_observations", "updated_at": now.isoformat()}


def project_live_roles(db: Session, row: models.UnifiedAnalysisRun, payload: dict) -> dict:
    """Overlay only observed lifecycle status, not uncommitted specialist output.

    agents_json and usage_json are graph-boundary snapshots. A finished trace is
    not a merged graph result: expose it as `finished`, never synthesize a
    succeeded report. Existing results at least as recent as the event win.
    """
    agents = dict(payload["agents"])
    latest = {}
    # Avoid implicit writes even if a caller supplies an autoflush session.
    with db.no_autoflush:
        if row.trace_id:
            events = db.query(models.TraceEvent).filter(
                models.TraceEvent.trace_id == row.trace_id,
                models.TraceEvent.actor.in_(ALL_AGENT_IDS),
                models.TraceEvent.event_type.in_(_ROLE_EVENTS),
            ).order_by(models.TraceEvent.created_at.desc(),
                       models.TraceEvent.seq.desc(), models.TraceEvent.id.desc())
            for event in events:
                latest.setdefault(event.actor, event)
    projected = []
    for role, event in latest.items():
        if row.status != "running":
            continue
        previous = agents.get(role)
        if previous and (not event.created_at or not row.updated_at
                         or event.created_at <= row.updated_at):
            continue
        # No snapshot entry means a start can predate the latest boundary while
        # the parallel role is still running. It must not disappear in that case.
        status = {"agent_started": "running", "task_waiting": "running", "agent_finished": "finished",
                  "agent_failed": "failed"}[event.event_type]
        try:
            detail = json.loads(event.payload_json or "{}")
        except (TypeError, ValueError):
            detail = {}
        if not isinstance(detail, dict):
            detail = {}
        agents[role] = {
            "status": status, "source": "trace", "trace_status": event.status,
            "trace_event": event.event_type, "trace_event_id": event.id,
            "trace_seq": event.seq, "observed_at": event.created_at,
            "error": str(detail.get("error") or "")[:800],
            "snapshot_pending": True,
        }
        projected.append(role)
    payload["agents"] = agents
    payload["snapshot"] = {
        "updated_at": row.updated_at,
        "source": "graph_boundary",
        "live_roles": sorted(projected),
        "lagging": bool(projected),
        "usage_source": "persisted_usage_meter",
        "usage_may_lag": row.status == "running",
        "note": "角色 trace 仅反映已发生的生命周期事件，不代表图状态已合并或结果授权；"
                "usage 为最近图边界持久化的真实模型计量，运行中可能落后，不以 trace 数估算调用或 token。",
    }
    return payload
