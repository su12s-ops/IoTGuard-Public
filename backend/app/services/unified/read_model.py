"""Read-only live role observations; trace never authorizes graph state or usage."""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app import models
from app.services.unified.schemas import ALL_AGENT_IDS

_ROLE_EVENTS = ("agent_started", "agent_finished", "agent_failed")


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
        status = {"agent_started": "running", "agent_finished": "finished",
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
