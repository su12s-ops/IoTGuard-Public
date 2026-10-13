"""Runtime identity, sensor coverage and bounded evidence timelines.

An observed process is not proof of CVE exploitation. Missing telemetry never
establishes absence of a vulnerability or successful remediation.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from app import models

IDENTITY_FIELDS = ("process_id", "parent_process_id", "process_exec_id", "parent_exec_id",
                   "process_start_time", "boot_id", "sensor_id", "executable", "container_id")


def _int(value):
    if isinstance(value, dict):
        value = value.get("value", 0)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def identity_fields(payload):
    fields = payload.get("output_fields") or {}
    fields = fields if isinstance(fields, dict) else {}
    body = next((payload[key] for key in ("process_exec", "process_kprobe", "process_tracepoint", "process_exit")
                 if isinstance(payload.get(key), dict)), {})
    process = body.get("process") or payload.get("process") or {}
    parent = body.get("parent") or payload.get("parent") or {}
    process = process if isinstance(process, dict) else {}
    parent = parent if isinstance(parent, dict) else {}
    return {
        "process_id": _int(payload.get("process_id") or fields.get("proc.pid") or process.get("pid")),
        "parent_process_id": _int(payload.get("parent_process_id") or fields.get("proc.ppid") or parent.get("pid")),
        "process_exec_id": str(payload.get("process_exec_id") or process.get("exec_id") or "")[:255],
        "parent_exec_id": str(payload.get("parent_exec_id") or parent.get("exec_id") or process.get("parent_exec_id") or "")[:255],
        "process_start_time": str(payload.get("process_start_time") or process.get("start_time") or fields.get("proc.pid.ts") or "")[:64],
        "boot_id": str(payload.get("boot_id") or "")[:64],
        "sensor_id": str(payload.get("sensor_id") or "")[:128],
        "executable": str(payload.get("executable") or process.get("binary") or fields.get("proc.exepath") or "")[:4096],
        "container_id": str(payload.get("container_id") or fields.get("container.id") or process.get("docker") or "")[:128],
    }


def event_time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def coverage(db, asset_id):
    now = datetime.now(timezone.utc)
    sensors = db.query(models.RuntimeSensor).filter_by(asset_id=asset_id).all()
    rows = []
    for sensor in sensors:
        timestamp = sensor.last_heartbeat_at
        timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp
        age = max(0, (now - timestamp).total_seconds())
        status = "stale" if age > 120 else sensor.status
        if status == "running" and sensor.dropped_events:
            status = "degraded"
        rows.append({"sensor_id": sensor.sensor_id, "source": sensor.source, "status": status,
                     "age_seconds": round(age), "dropped_events": sensor.dropped_events,
                     "capabilities": json.loads(sensor.capabilities_json or "{}"), "detail": sensor.detail})
    states = {r["status"] for r in rows}
    status = ("degraded" if "degraded" in states or ("running" in states and len(states) > 1)
              else "running" if "running" in states else "stale" if "stale" in states else "unknown")
    return {"asset_id": asset_id, "status": status, "sensors": rows,
            "basis": "self_reported_collector_heartbeat", "absence_proves_safe": False,
            "note": "心跳仅说明采集器报告的状态；覆盖范围、丢失事件和内核兼容性须分别验证。"}


def timeline(db, asset_id, limit=300):
    rows = db.query(models.RuntimeEvent).filter_by(asset_id=asset_id).order_by(models.RuntimeEvent.id.desc()).limit(limit).all()
    rows.sort(key=lambda row: (event_time(row.occurred_at) or datetime.min.replace(tzinfo=timezone.utc), row.id))
    groups, events = {}, []
    for row in rows:
        if row.process_exec_id:
            key = f"{asset_id}:exec:{row.process_exec_id}"
            basis = "exec_id"
        elif row.boot_id and row.process_id and row.process_start_time:
            key = f"{asset_id}:{row.boot_id}:{row.process_id}:{row.process_start_time}"
            basis = "boot_pid_start_time"
        else:
            key, basis = f"event:{row.id}", "insufficient_process_identity"
        group = groups.setdefault(key, {"id": key, "process_name": row.process_name, "pid": row.process_id,
                                       "executable": row.executable, "basis": basis, "event_ids": []})
        group["event_ids"].append(row.id)
        events.append({"id": row.id, "timestamp": row.occurred_at, "time_valid": event_time(row.occurred_at) is not None,
                       "process_key": key, "parent_exec_id": row.parent_exec_id, "process_name": row.process_name,
                       "pid": row.process_id, "category": row.category, "event_type": row.event_type,
                       "file_path": row.file_path, "destination": row.destination, "port": row.port,
                       "source": row.source, "sensor_id": row.sensor_id, "rule": row.rule,
                       "evidence_level": "runtime_observation"})
    edges, seen = [], set()
    for event in events:
        parent = f"{asset_id}:exec:{event['parent_exec_id']}"
        pair = (parent, event["process_key"])
        if event["parent_exec_id"] and parent in groups and pair[0] != pair[1] and pair not in seen:
            edges.append({"parent": pair[0], "child": pair[1], "basis": "parent_exec_id"})
            seen.add(pair)
    return {"asset_id": asset_id, "coverage": coverage(db, asset_id), "events": events,
            "processes": list(groups.values()), "edges": edges, "limit": limit,
            "exploitation_confirmed": False, "note": "仅关联同一资产的可靠进程标识；不凭重复 PID 拼接行为链。"}


def compare_windows(db, asset_id, checkpoint, window_seconds=300):
    at = event_time(checkpoint)
    if not at:
        raise ValueError("对比时间必须是带日期的 ISO 8601 时间")
    start, end = at - timedelta(seconds=window_seconds), at + timedelta(seconds=window_seconds)
    rows = db.query(models.RuntimeEvent).filter_by(asset_id=asset_id).order_by(models.RuntimeEvent.id.desc()).limit(10000).all()
    before, after = [], []
    unparsed = 0
    for row in rows:
        timestamp = event_time(row.occurred_at)
        if timestamp is None:
            unparsed += 1
        elif start <= timestamp < at:
            before.append(row)
        elif at <= timestamp <= end:
            after.append(row)
    def summary(items):
        return {"count": len(items), "categories": dict(Counter(r.category for r in items)), "event_ids": [r.id for r in items]}
    return {"asset_id": asset_id, "checkpoint": at.isoformat(), "window_seconds": window_seconds,
            "before": summary(before), "after": summary(after), "unparsed_time_count": unparsed,
            "truncated": len(rows) == 10000, "coverage": coverage(db, asset_id),
            "verification_status": "requires_inventory_and_business_checks",
            "note": "事件数量变化或没有事件都不单独证明漏洞已修复。"}
