"""统一任务追踪服务（第八阶段）。

唯一的事件写入咽喉：所有子系统（四智能体编排、设备管线、Harness）经
start_trace / emit / finish_trace 记录，保证：
- trace_id 全局唯一，同一任务的事件共享 trace_id；
- seq 在 trace 内单调递增，保留发生顺序；
- 不同资产/并发任务天然隔离（trace_id 不同，事件按 trace_id 归属）；
- payload 服务端脱敏（凭据类键递归剔除）并限长；
- 旧数据不回填：不传 trace 的调用完全无感（零行为变化）。

诚实性约束：LLM 用量/模型信息仅有真实采集依据时记录，否则标 unavailable；
程序步骤 is_llm_step=False，绝不伪装为大模型步骤。
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models

MAX_PAYLOAD_BYTES = 16_000          # payload_json 落库上限（超出截断标记）
# 敏感键判定：按键名分词后整词匹配（api_key/api-key 归一为 apikey），
# 避免 token_usage（LLM 用量）这类复合含义键被误伤。
_SENSITIVE_SEGMENTS = {"password", "passwd", "secret", "token", "credential",
                       "credentials", "apikey", "private"}


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "api_key" in normalized or "apikey" in normalized:
        return True
    segments = re.split(r"[+_\s]", normalized)
    return bool(_SENSITIVE_SEGMENTS & set(segments))


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

TASK_TYPES = {
    "four_agent_analysis", "device_refresh", "device_cve_match",
    "discovery_enrollment", "harness_investigate", "harness_repair", "harness_collect",
    "runtime_log_collection", "unified_four_agent",
}


def new_trace_id() -> str:
    return "TR-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]


def sanitize_payload(value: Any) -> Any:
    """递归剔除敏感键并压缩过长列表/字符串（服务端脱敏，前端不接收原始敏感值）。"""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = sanitize_payload(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        kept = [sanitize_payload(item) for item in list(value)[:50]]
        if len(value) > 50:
            kept.append(f"[+{len(value) - 50} more truncated]")
        return kept
    if isinstance(value, str) and len(value) > 2_000:
        return value[:2_000] + "…[truncated]"
    return value


def _bounded(payload: dict[str, Any] | None) -> str:
    text = json.dumps(sanitize_payload(payload or {}), ensure_ascii=False, default=str)
    if len(text) > MAX_PAYLOAD_BYTES:
        text = text[:MAX_PAYLOAD_BYTES] + '…"}'
    return text


def _refs(evidence_refs: Iterable[str] | None) -> str:
    seen: list[str] = []
    for ref in evidence_refs or []:
        ref = str(ref)[:128]
        if ref and ref not in seen:
            seen.append(ref)
        if len(seen) >= 50:
            break
    return json.dumps(seen, ensure_ascii=False)


def start_trace(db: Session, *, task_type: str, target_type: str = "", target_ref: str = "",
                run_ref_type: str = "", run_ref_id: str = "", harness_run_id: str = "",
                metadata: dict[str, Any] | None = None) -> models.TraceRun:
    """创建追踪根记录并发 task_started 事件。task_type 必须在登记清单内。"""
    if task_type not in TASK_TYPES:
        raise ValueError(f"未登记的任务类型: {task_type}")
    trace = models.TraceRun(trace_id=new_trace_id(), task_type=task_type,
                            target_type=target_type, target_ref=target_ref,
                            run_ref_type=run_ref_type, run_ref_id=run_ref_id,
                            harness_run_id=harness_run_id, status="running")
    db.add(trace)
    db.commit()
    emit(db, trace.trace_id, "task_started", actor="trace", status="running",
         payload={"task_type": task_type, "target_type": target_type, "target_ref": target_ref,
                  "run_ref_type": run_ref_type, "run_ref_id": run_ref_id,
                  "harness_run_id": harness_run_id, **(metadata or {})})
    return trace


def emit(db: Session, trace_id: str, event_type: str, *, actor: str = "", status: str = "",
         is_llm_step: bool = False, payload: dict[str, Any] | None = None,
         evidence_refs: Iterable[str] | None = None,
         started_at: datetime | None = None, finished_at: datetime | None = None,
         duration_ms: int = 0, commit: bool = True) -> models.TraceEvent | None:
    """追加事件（trace_id 为空时静默跳过：旧调用路径零影响）。"""
    if not trace_id:
        return None
    last = (db.query(func.max(models.TraceEvent.seq))
            .filter(models.TraceEvent.trace_id == trace_id).scalar() or 0)
    event = models.TraceEvent(
        trace_id=trace_id, seq=last + 1, event_type=event_type[:48], actor=actor[:64],
        status=status[:32], is_llm_step=bool(is_llm_step), payload_json=_bounded(payload),
        evidence_refs_json=_refs(evidence_refs), started_at=started_at,
        finished_at=finished_at, duration_ms=int(duration_ms))
    db.add(event)
    if commit:
        db.commit()
    return event


def finish_trace(db: Session, trace_id: str, status: str, *,
                 summary: dict[str, Any] | None = None, error: str = "") -> None:
    if not trace_id:
        return
    trace = db.query(models.TraceRun).filter_by(trace_id=trace_id).one_or_none()
    if trace is None:
        return
    trace.status = status[:32]
    trace.error = (error or "")[:4000]
    trace.summary_json = _bounded(summary or {})
    trace.finished_at = models.utcnow()
    db.commit()
    emit(db, trace_id, "task_finished", actor="trace", status=status[:32],
         payload={"summary": summary or {}, "error": (error or "")[:1000]})


# ── 查询侧（Trace API 与前端 AgentOps 消费） ─────────────────────────────────


def serialize_event(row: models.TraceEvent) -> dict[str, Any]:
    try:
        payload = json.loads(row.payload_json or "{}")
    except ValueError:
        payload = {"_parse_error": True}
    try:
        refs = json.loads(row.evidence_refs_json or "[]")
    except ValueError:
        refs = []
    return {"id": row.id, "seq": row.seq, "trace_id": row.trace_id,
            "event_type": row.event_type, "actor": row.actor, "status": row.status,
            "is_llm_step": row.is_llm_step, "payload": payload, "evidence_refs": refs,
            "started_at": row.started_at, "finished_at": row.finished_at,
            "duration_ms": row.duration_ms, "created_at": row.created_at}


def serialize_run(row: models.TraceRun, *, event_count: int | None = None) -> dict[str, Any]:
    data = {
        "trace_id": row.trace_id, "task_type": row.task_type,
        "target_type": row.target_type, "target_ref": row.target_ref,
        "run_ref_type": row.run_ref_type, "run_ref_id": row.run_ref_id,
        "harness_run_id": row.harness_run_id, "status": row.status,
        "summary": json.loads(row.summary_json or "{}"), "error": row.error,
        "started_at": row.started_at, "finished_at": row.finished_at,
        "created_at": row.created_at,
    }
    if event_count is not None:
        data["event_count"] = event_count
    return data


def list_traces(db: Session, *, task_type: str = "", status: str = "",
                page: int = 1, page_size: int = 20) -> tuple[list[dict[str, Any]], int]:
    query = db.query(models.TraceRun)
    if task_type:
        query = query.filter(models.TraceRun.task_type == task_type)
    if status:
        query = query.filter(models.TraceRun.status == status)
    total = query.count()
    rows = (query.order_by(models.TraceRun.id.desc())
            .offset((page - 1) * page_size).limit(page_size).all())
    counts = dict(
        db.query(models.TraceEvent.trace_id, func.count(models.TraceEvent.id))
        .filter(models.TraceEvent.trace_id.in_([r.trace_id for r in rows] or [""]))
        .group_by(models.TraceEvent.trace_id).all()) if rows else {}
    return [serialize_run(row, event_count=counts.get(row.trace_id, 0)) for row in rows], total


def get_trace(db: Session, trace_id: str) -> models.TraceRun | None:
    return db.query(models.TraceRun).filter_by(trace_id=trace_id).one_or_none()


def trace_events(db: Session, trace_id: str, *,
                 event_type: str = "") -> list[dict[str, Any]]:
    query = db.query(models.TraceEvent).filter(models.TraceEvent.trace_id == trace_id)
    if event_type:
        query = query.filter(models.TraceEvent.event_type == event_type)
    rows = query.order_by(models.TraceEvent.seq, models.TraceEvent.id).all()
    return [serialize_event(row) for row in rows]


def summary_stats(db: Session) -> dict[str, Any]:
    """任务总览统计：数量按状态、策略拦截数、平均执行耗时（真实记录聚合）。"""
    total = db.query(models.TraceRun).count()
    by_status = dict(db.query(models.TraceRun.status, func.count(models.TraceRun.id))
                     .group_by(models.TraceRun.status).all())
    blocked = (db.query(func.count(func.distinct(models.TraceEvent.trace_id)))
               .filter(models.TraceEvent.event_type.in_(
                   ["harness_policy_blocked", "policy_blocked"])).scalar() or 0)
    durations = [row for row in db.query(models.TraceRun.started_at, models.TraceRun.finished_at)
                 .filter(models.TraceRun.finished_at.isnot(None)).all() if row[0] and row[1]]
    avg_ms: int | str = "unavailable"
    if durations:
        total_ms = sum((fin - sta).total_seconds() * 1000 for sta, fin in durations)
        avg_ms = int(total_ms / len(durations))
    return {"total_traces": total, "by_status": by_status,
            "policy_blocked_traces": blocked, "avg_duration_ms": avg_ms,
            "task_types": sorted({row[0] for row in db.query(models.TraceRun.task_type).all()
                                  if row[0]})}


def evidence_for_trace(db: Session, trace_id: str) -> dict[str, Any]:
    """解析 trace 事件引用的证据：SecurityEvidence / CVE 各自如实呈现（缺失不伪造）。"""
    events = trace_events(db, trace_id)
    refs: list[str] = []
    for event in events:
        for ref in event["evidence_refs"]:
            if ref not in refs:
                refs.append(ref)
    evidence_ids = [ref for ref in refs if ref.startswith("SE-")]
    cve_ids = [ref for ref in refs if _CVE_RE.match(ref)]
    evidence_rows = []
    if evidence_ids:
        rows = (db.query(models.SecurityEvidence)
                .filter(models.SecurityEvidence.evidence_id.in_(evidence_ids)).all())
        by_key = {row.evidence_id: row for row in rows}
        for ref in evidence_ids:  # 保持引用顺序；不存在的标记 unresolved
            row = by_key.get(ref)
            evidence_rows.append({
                "evidence_id": ref,
                "resolved": row is not None,
                "evidence_type": row.evidence_type if row else "",
                "device_id": row.device_id if row else "",
                "source": row.source if row else "",
                "severity": row.severity if row else "",
                "timestamp": row.timestamp if row else "",
                "description": (row.description or "")[:200] if row else "",
            } if row else {"evidence_id": ref, "resolved": False})
    cve_rows = []
    if cve_ids:
        rows = (db.query(models.VulnerabilityInfo)
                .filter(models.VulnerabilityInfo.cve_id.in_(cve_ids)).all())
        by_key = {row.cve_id: row for row in rows}
        for ref in cve_ids:
            row = by_key.get(ref)
            cve_rows.append({"cve_id": ref, "resolved": row is not None,
                             "cvss_score": row.cvss_score if row else 0,
                             "cvss_severity": row.cvss_severity if row else "",
                             "fixed_version": row.fixed_version if row else ""})
    for ref in refs:
        if ref.startswith("ADV-"):
            record = db.query(models.OfficialCveRecord).filter_by(evidence_id=ref).first()
            evidence_rows.append({"evidence_id": ref, "resolved": bool(record), "evidence_type": "official_advisory",
                "source": record.source_url if record else "", "description": record.evidence_status if record else "",
                "content_sha256": record.content_sha256 if record else ""})
        elif ref.startswith("INV-"):
            record = db.query(models.CollectionEvidence).filter_by(evidence_id=ref).first()
            evidence_rows.append({"evidence_id": ref, "resolved": bool(record), "evidence_type": "inventory",
                "asset_id": record.asset_id if record else None, "source": "fixed_collector",
                "content_sha256": record.content_sha256 if record else ""})
    return {"trace_id": trace_id, "evidence": evidence_rows, "cves": cve_rows,
            "note": "unresolved = 事件引用但库中不存在（如实呈现，不剔除不伪造）"}
