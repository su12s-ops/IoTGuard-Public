"""Runtime identity, sensor coverage and bounded evidence timelines.

An observed process is not proof of CVE exploitation. Missing telemetry never
establishes absence of a vulnerability or successful remediation.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from app import models
from app.services.event_semantics import semantics

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


EVIDENCE_FRESH_WINDOW_S = 900


def sensor_health(sensor, now=None):
    now = now or datetime.now(timezone.utc)
    timestamp = sensor.last_heartbeat_at
    timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp and timestamp.tzinfo is None else timestamp
    age = round(max(0, (now - timestamp).total_seconds())) if timestamp else None
    try:
        capabilities = json.loads(sensor.capabilities_json or "{}")
    except (ValueError, TypeError):
        capabilities = {}
    if not isinstance(capabilities, dict):
        capabilities = {}
    status = sensor.status
    if status in {"running", "reporting", "stopped"} and capabilities.get("mode") == "pull":
        status = "reporting" if age is not None and age <= 120 else "stale"
    elif status in {"running", "reporting"} and (age is None or age > 120):
        status = "stale"
    if status in {"running", "reporting"} and sensor.dropped_events:
        status = "degraded"
    return status, age, capabilities


def sensor_summary(db):
    order = {"running": 0, "reporting": 0, "degraded": 1, "stale": 2,
             "stopped": 3, "failed": 4, "unknown": 4, "none": 5}
    details = []
    now = datetime.now(timezone.utc)
    for sensor in db.query(models.RuntimeSensor).all():
        status, age, _ = sensor_health(sensor, now)
        details.append({"sensor_id": sensor.sensor_id, "asset_id": sensor.asset_id,
                        "source": sensor.source, "status": status, "heartbeat_age_seconds": age})
    worst = max((item["status"] for item in details), key=lambda s: order.get(s, 9), default="none")
    return {"status": worst, "healthy": sum(item["status"] in {"running", "reporting"} for item in details),
            "total": len(details), "sensors": details}


def evidence_freshness(db, asset_id=None):
    """Whether any real runtime event arrived recently — deliberately separate
    from sensor heartbeat status and from backend liveness."""
    now = datetime.now(timezone.utc)
    query = db.query(func.max(models.RuntimeEvent.occurred_at))
    if asset_id is not None:
        query = query.filter(models.RuntimeEvent.asset_id == asset_id)
    latest = query.scalar()
    age = None
    if latest:
        parsed = event_time(latest) or latest
        age = round(max(0, (now - parsed).total_seconds()))
    return {"fresh": age is not None and age <= EVIDENCE_FRESH_WINDOW_S,
            "latest_event_age_seconds": age, "window_seconds": EVIDENCE_FRESH_WINDOW_S,
            "basis": "latest_persisted_runtime_event_occurred_at"}


def coverage(db, asset_id):
    now = datetime.now(timezone.utc)
    sensors = db.query(models.RuntimeSensor).filter_by(asset_id=asset_id).all()
    rows = []
    for sensor in sensors:
        status, age, capabilities = sensor_health(sensor, now)
        rows.append({"sensor_id": sensor.sensor_id, "source": sensor.source, "status": status,
                     "age_seconds": age, "dropped_events": sensor.dropped_events,
                     "capabilities": capabilities, "detail": sensor.detail})
    states = {r["status"] for r in rows}
    healthy_states = {"running", "reporting"}
    status = ("degraded" if "degraded" in states or (states & healthy_states and states - healthy_states)
              else "running" if "running" in states else "reporting" if "reporting" in states
              else "stale" if "stale" in states else "unknown")
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
                       "evidence_level": "runtime_observation", **semantics(json.loads(row.raw_json or "{}"))})
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


def evidence_sessions(db, asset_id, limit=500):
    """P1-3：按进程会话键聚合 SecurityEvidence（行为链页的证据明细视图）。

    分组语义与 timeline() 一致（键名可互相对照）：
    - process_exec_id 存在 → f"{asset_id}:exec:{exec_id}"（PID 复用可区分）；
    - 缺 exec_id 的存量证据 → 每条独立成组并标注
      insufficient_session_identity（证据表无 boot_id/start_time，
      凭 pid 分组会凭空拼接 PID 复用行为——不虚构）。

    只聚合同一资产内的证据；父会话边仅在 parent_exec_id 恰为本资产
    已知会话时输出。
    """
    rows = db.query(models.SecurityEvidence).filter_by(asset_id=asset_id) \
        .order_by(models.SecurityEvidence.id.desc()).limit(max(1, min(limit, 2000))).all()
    rows.reverse()

    sessions: dict[str, dict] = {}
    for row in rows:
        if row.process_exec_id:
            key, basis = f"{asset_id}:exec:{row.process_exec_id}", "exec_id"
        else:
            key, basis = f"evidence:{row.id}", "insufficient_session_identity"
        session = sessions.get(key)
        if session is None:
            session = sessions[key] = {
                "id": key, "basis": basis, "process_exec_id": row.process_exec_id or "",
                "parent_exec_id": row.parent_exec_id or "",
                "device_id": row.device_id, "process": row.process or "unknown",
                "pid": row.pid, "ppid": row.ppid, "user": row.user,
                "commandline": row.commandline or "",
                "evidence_by_type": {}, "evidence_ids": [],
                "first_timestamp": row.timestamp, "last_timestamp": row.timestamp,
                "max_severity_score": row.severity_score or 0, "max_severity": row.severity,
            }
        session["evidence_by_type"][row.evidence_type] = session["evidence_by_type"].get(row.evidence_type, 0) + 1
        session["evidence_ids"].append(row.evidence_id)
        if row.timestamp:
            if not session["first_timestamp"]:
                session["first_timestamp"] = row.timestamp
            session["last_timestamp"] = row.timestamp
        if (row.severity_score or 0) > session["max_severity_score"]:
            session["max_severity_score"] = row.severity_score
            session["max_severity"] = row.severity
        # exec 会替换映像：同会话内取最后一条证据的最终映像/命令行（ps 语义）
        if row.process:
            session["process"] = row.process
        if row.commandline:
            session["commandline"] = row.commandline
        if row.parent_exec_id and not session["parent_exec_id"]:
            session["parent_exec_id"] = row.parent_exec_id

    edges, seen = [], set()
    for session in sessions.values():
        parent = f"{asset_id}:exec:{session['parent_exec_id']}"
        pair = (parent, session["id"])
        if (session["parent_exec_id"] and session["basis"] == "exec_id"
                and parent in sessions and pair[0] != pair[1] and pair not in seen):
            edges.append({"parent": pair[0], "child": pair[1], "basis": "parent_exec_id"})
            seen.add(pair)

    sessions_list = sorted(sessions.values(),
                           key=lambda s: (s["first_timestamp"] or "", min(s["evidence_ids"])))
    return {
        "asset_id": asset_id,
        "sessions": sessions_list,
        "edges": edges,
        "session_count": len(sessions_list),
        "insufficient_identity_count": sum(1 for s in sessions_list if s["basis"] == "insufficient_session_identity"),
        "note": "按 process_exec_id 聚合同一进程（exec+网络+文件证据）；缺会话身份的存量证据独立成组，不凭 PID 拼接。",
    }


def cve_runtime_evidence(db, cve_id: str, asset_id: int | None = None):
    """P1-4：某 CVE 的相关进程/网络/文件证据下钻（行为链页 → 证据明细）。

    匹配语义与风险评估共用 runtime_evidence.package_match_reasons（直接/
    上下文命中同源判定）；证据按 P1-3 会话键聚合，可跳转会话视图。
    诚实边界：文本/端口匹配属上下文关联，exploitation_confirmed 恒为
    False，无匹配时如实返回 not_observed，不虚构证据。
    """
    from app.services.runtime_evidence import _annotate_event, package_match_reasons
    from app.services.runtime_context import package_related_to_service, service_name
    from app.services.security_evidence import _watch_path_match

    risk_query = db.query(models.RiskAssessment).filter(
        models.RiskAssessment.cve_id == cve_id,
        models.RiskAssessment.active.is_(True))
    if asset_id is not None:
        risk_query = risk_query.filter(models.RiskAssessment.asset_id == asset_id)
    risks = risk_query.all()
    if not risks:
        return None

    category_map = {"process": "process_execution", "network": "network_activity"}

    blocks = []
    for risk in risks:
        asset = db.get(models.LinuxAsset, risk.asset_id)
        if asset is None:
            continue
        services = list(asset.services)
        related = [s for s in services if package_related_to_service(risk.package_name, service_name(s))]
        service_names = {service_name(s).lower() for s in related if service_name(s)}
        service_ports = {s.port for s in related if s.port}
        # 攻击场景 id（lpe/data_leak 等驱动特权上下文判定）与行为链同一来源
        from app.services.agent_intelligence import classify_scenario
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=risk.cve_id).first()
        scenario_id = classify_scenario(vuln, risk.package_name).get("id", "") if vuln else ""

        rows = db.query(models.SecurityEvidence).filter_by(asset_id=asset.id) \
            .order_by(models.SecurityEvidence.id.desc()).limit(2000).all()
        rows.reverse()

        matched = []
        for row in rows:
            file_path = row.file_path or ""
            category = category_map.get(row.evidence_type or "",
                                        "sensitive_file_access" if _watch_path_match(file_path) else "runtime_observation")
            try:
                raw = json.loads(row.raw_data or "{}")
            except ValueError:
                raw = {}
            event = {
                "asset_id": asset.id,
                "timestamp": row.timestamp or "",
                "category": category,
                "process_name": row.process or "",
                "pid": row.pid or 0,
                "commandline": row.commandline or "",
                "parent_process": row.parent_process or "",
                "file_path": file_path,
                "port": row.destination_port or 0,
                "destination": row.destination_ip or "",
                "raw": raw,
                "severity_score": row.severity_score or 0,
            }
            direct_reasons, contextual_reasons = package_match_reasons(
                event, risk.package_name, service_names, service_ports, scenario_id)
            if not direct_reasons and not contextual_reasons:
                continue
            match_type = "direct" if direct_reasons else "contextual"
            reasons = direct_reasons or contextual_reasons
            annotated = _annotate_event(event, match_type, reasons)
            annotated["evidence_id"] = row.evidence_id
            annotated["evidence_type"] = row.evidence_type
            annotated["user"] = row.user
            annotated["session_key"] = f"{asset.id}:exec:{row.process_exec_id}" if row.process_exec_id else ""
            matched.append(annotated)

        matched.sort(key=lambda item: item["evidence_weight"], reverse=True)
        direct_count = sum(1 for item in matched if item["match_type"] == "direct")
        by_type: dict[str, int] = {}
        for item in matched:
            by_type[item["evidence_type"]] = by_type.get(item["evidence_type"], 0) + 1

        # 按 P1-3 会话键聚合（同一进程实例的直接/上下文证据归并展示）
        sessions: dict[str, dict] = {}
        for item in matched:
            key = item["session_key"] or f"evidence:{item['evidence_id']}"
            session = sessions.setdefault(key, {
                "id": key, "basis": "exec_id" if item["session_key"] else "insufficient_session_identity",
                "process": item["process_name"], "pid": item.get("pid") or 0,
                "evidence_ids": [], "max_weight": 0.0,
            })
            session["evidence_ids"].append(item["evidence_id"])
            session["max_weight"] = max(session["max_weight"], item["evidence_weight"])

        runtime_status = "verified" if direct_count else "contextual" if matched else "not_observed"
        blocks.append({
            "cve_id": risk.cve_id,
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "package_name": risk.package_name,
            "runtime_status": runtime_status,
            "signals": {
                "direct_count": direct_count,
                "contextual_count": len(matched) - direct_count,
                "by_type": by_type,
                "max_weight": matched[0]["evidence_weight"] if matched else 0,
                "session_count": len(sessions),
            },
            "evidence": matched[:500],
            "sessions": list(sessions.values()),
            "scenario_id": scenario_id,
            "exploitation_confirmed": False,
            "absence_proves_safe": False,
            "note": "匹配=进程名/命令行/文件路径/原始报文含软件包或别名（直接），或命中关联服务名/端口（上下文）；"
                    "上下文关联不构成漏洞被利用的证明，无匹配时表示“未观察到”，不代表安全。",
        })

    return {"cve_id": cve_id, "assets": blocks, "asset_count": len(blocks)}


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


def reliability_snapshot(db) -> dict:
    """P0 采集可靠性快照：心跳自报指标 × 服务端观测交叉。

    0 与 unknown 的语义边界（验收要点）：
    - dropped_events：仅采集器如实上报时为数值（0=真实零丢失）；
      从未上报（None）→ "unavailable"。
    - stored_events：按 sensor_id 归属的服务端入库计数，0=该传感器名下
      确无归属事件（P0 之前的历史事件可能无 sensor 归属，附注说明）。
    - forwarder 计数器（received/uploaded/duplicates/retries/failed/...）：
      仅在使用 P0 转发器（批量确认协议）时存在，否则 "unknown"。
    """
    sensors = db.query(models.RuntimeSensor).order_by(models.RuntimeSensor.id).all()
    attributed = {(asset_id, sensor_id): count for asset_id, sensor_id, count in
        db.query(models.RuntimeEvent.asset_id, models.RuntimeEvent.sensor_id, func.count(models.RuntimeEvent.id))
        .filter(models.RuntimeEvent.sensor_id != "")
        .group_by(models.RuntimeEvent.asset_id, models.RuntimeEvent.sensor_id).all()}
    times = {}
    for asset_id, sensor_id, first_at, last_at in (
            db.query(models.RuntimeEvent.asset_id, models.RuntimeEvent.sensor_id,
                     func.min(models.RuntimeEvent.occurred_at),
                     func.max(models.RuntimeEvent.occurred_at))
            .filter(models.RuntimeEvent.sensor_id != "")
            .group_by(models.RuntimeEvent.asset_id, models.RuntimeEvent.sensor_id).all()):
        times[(asset_id, sensor_id)] = (first_at, last_at)
    rows = []
    for sensor in sensors:
        try:
            capabilities = json.loads(sensor.capabilities_json or "{}")
        except ValueError:
            capabilities = {}
        status, age, capabilities = sensor_health(sensor)
        metrics = capabilities.get("metrics")
        first_at, last_at = times.get((sensor.asset_id, sensor.sensor_id), (None, None))
        rows.append({
            "asset_id": sensor.asset_id,
            "sensor_id": sensor.sensor_id,
            "source": sensor.source,
            "status": status,
            "reported_status": sensor.status,
            "heartbeat_age_seconds": age,
            "dropped_events": sensor.dropped_events if sensor.dropped_events is not None else "unavailable",
            "self_reported_metrics": metrics if isinstance(metrics, dict) else "unknown",
            "collection_window": _collection_window(sensor, capabilities),
            "server_observed": {
                "stored_events": attributed.get((sensor.asset_id, sensor.sensor_id), 0),
                "first_event_at": first_at or "unknown",
                "last_event_at": last_at or "unknown",
            },
            "detail": (sensor.detail or "")[:400],
        })
    return {
        "sensors": rows,
        "server_totals": {
            "runtime_events": db.query(models.RuntimeEvent).count(),
            "security_evidence": db.query(models.SecurityEvidence).count(),
            "events_without_sensor_attribution": db.query(models.RuntimeEvent)
                .filter(models.RuntimeEvent.sensor_id == "").count(),
        },
        "semantics": {
            "zero_vs_unknown": "0 表示真实为零；unavailable/unknown 表示底层未提供，不虚构为零",
            "dropped_events_source": "仅采集器如实上报（探针 supervisor 健康文件或转发器指标）",
            "note": "P0 之前入库的历史事件可能缺少 sensor_id 归属，计入 events_without_sensor_attribution",
        },
    }


def _collection_window(sensor, capabilities):
    """Expose source-side completeness separately from server ingest counts."""
    if sensor.source != "logread":
        return "not_applicable"
    window = capabilities.get("last_window")
    if not isinstance(window, dict):
        return {"status": "unavailable", "reason": "no_completed_window"}
    total = window.get("lines_total")
    built = window.get("events_built")
    year_missing = window.get("year_missing_lines", 0)
    unparseable = window.get("unparseable_lines", 0)
    parsed = all(isinstance(value, int) and not isinstance(value, bool)
                 for value in (total, built, year_missing, unparseable))
    skipped = year_missing + unparseable if parsed else "unknown"
    return {
        "status": "truncated" if window.get("truncated") else "bounded_window",
        "lines_total": total if parsed else "unknown",
        "events_built": built if parsed else "unknown",
        "skipped_lines": skipped if parsed else "unknown",
        "stored_new": window.get("stored_new", "unknown"),
        "duplicates": window.get("duplicates", "unknown"),
        "ring_loss": "unavailable",
        "window_first": window.get("window_first") or "unknown",
        "window_last": window.get("window_last") or "unknown",
        "boot_id": window.get("boot_id") or "unknown",
    }
