from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
import json
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.services.device_access import require_control
from app.services.runtime_telemetry import (
    compare_windows,
    coverage,
    cve_runtime_evidence,
    evidence_sessions,
    timeline,
)
from app.services import ebpf_lsm
from app.services.security_evidence import (
    FILE_WATCH_PATHS,
    build_process_tree,
    query_evidence,
    serialize_evidence,
    summarize_evidence,
)
from app.services.ebpf_event_collector import (
    append_events,
    clear_events,
    correlate_runtime_events,
    generate_demo_runtime_events,
    load_runtime_events,
    parse_event_lines,
    runtime_status,
    summarize_runtime_events,
)

router = APIRouter(prefix="/runtime", tags=["Runtime eBPF"])


@router.get("/ebpf/events")
def list_ebpf_events(
    limit: int = 200,
    hostname: str | None = None,
    category: str | None = None,
    source: str | None = None,
    severity_min: int | None = None,
    mode: str | None = None,
    db: Session = Depends(get_db),
):
    events = load_runtime_events(
        db=db,
        limit=limit,
        hostname=hostname,
        category=category,
        source=source,
        severity_min=severity_min,
        mode=mode,
    )
    total = len(
        load_runtime_events(
            db=db,
            limit=100000,
            hostname=hostname,
            category=category,
            source=source,
            severity_min=severity_min,
            mode=mode,
        )
    )
    return {"count": total, "events": events}


@router.get("/ebpf/summary")
def ebpf_summary(db: Session = Depends(get_db)):
    return summarize_runtime_events(db)


@router.get("/ebpf/status")
def ebpf_status(request: Request, db: Session = Depends(get_db)):
    api_base = str(request.base_url).rstrip("/") + "/api"
    return runtime_status(db, api_base=api_base)


@router.get("/ebpf/correlations")
def ebpf_correlations(db: Session = Depends(get_db)):
    return correlate_runtime_events(db)


@router.post("/ebpf/events", dependencies=[Depends(require_control)])
async def ingest_ebpf_events(payload: dict[str, Any] | list[dict[str, Any]], db: Session = Depends(get_db)):
    payloads = payload if isinstance(payload, list) else [payload]
    if len(payloads) > 2000:
        raise HTTPException(413, "每批最多接收 2000 条事件")
    try:
        events = append_events(payloads, db=db)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return {
        "message": "eBPF events ingested",
        "count": len(events),
        "events": events,
        "categories": sorted({event["category"] for event in events}),
        "sources": sorted({event["source"] for event in events}),
    }


@router.post("/ebpf/upload", dependencies=[Depends(require_control)])
async def upload_ebpf_events(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read(5_000_001)
    if len(raw) > 5_000_000:
        raise HTTPException(413, "事件文件不能超过 5 MB")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "事件文件须使用 UTF-8 编码") from exc
    payloads = parse_event_lines(content)
    if not payloads:
        raise HTTPException(400, "事件文件中没有可识别的事件")
    if len(payloads) > 2000:
        raise HTTPException(413, "每批最多接收 2000 条事件")
    events = append_events(payloads, db=db)
    return {
        "message": "eBPF event file uploaded",
        "filename": file.filename or "",
        "parsed": len(payloads),
        "count": len(events),
        "categories": sorted({event["category"] for event in events}),
        "sources": sorted({event["source"] for event in events}),
    }


@router.post("/ebpf/demo", dependencies=[Depends(require_control)])
def create_demo_ebpf_events(per_asset: int = 4, clear_existing: bool = False, db: Session = Depends(get_db)):
    if clear_existing:
        clear_events(db=db)
    events = generate_demo_runtime_events(db, per_asset=per_asset)
    return {
        "message": "Runtime demo evidence generated",
        "count": len(events),
        "hosts": sorted({event["hostname"] for event in events if event.get("hostname")}),
        "sources": sorted({event["source"] for event in events}),
    }


@router.delete("/ebpf/events", dependencies=[Depends(require_control)])
def reset_ebpf_events(db: Session = Depends(get_db)):
    result = clear_events(db=db)
    return {"message": "eBPF events cleared", "count": result["runtime_events_cleared"],
            "runtime_events_cleared": result["runtime_events_cleared"],
            "evidence_preserved": result["evidence_preserved"],
            "scope": result["scope"], "note": result["note"]}


@router.post("/ebpf/events/batch", dependencies=[Depends(require_control)])
async def ingest_ebpf_events_batch(payload: dict[str, Any], db: Session = Depends(get_db)):
    """P0 转发器批量确认端点。

    契约：请求 {"events":[...]}（≤500 条）；响应即服务端持久化确认——
    accepted=新入库，duplicates=幂等命中（重试/重放安全），rejected=
    逐条拒绝原因（不影响其余事件）。仅当 HTTP 200 且响应可解析时客户端
    才可视为已确认；"请求已发出"不等于已持久化。
    """
    events_in = payload.get("events")
    if not isinstance(events_in, list) or not events_in:
        raise HTTPException(400, "请求体必须包含非空 events 数组")
    if len(events_in) > 500:
        raise HTTPException(413, "每批最多 500 条事件")
    from app.services.ebpf_event_collector import normalize_event
    accepted_payloads: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, item in enumerate(events_in):
        if not isinstance(item, dict):
            rejected.append({"index": index, "reason": "事件必须是 JSON 对象"})
            continue
        if len(json.dumps(item, ensure_ascii=False, default=str)) > 1_000_000:
            rejected.append({"index": index, "reason": "单条事件超过 1MB 上限"})
            continue
        try:
            accepted_payloads.append(normalize_event(item))
        except ValueError as exc:
            rejected.append({"index": index, "reason": str(exc)[:200]})
    stored: list[dict[str, Any]] = []
    if accepted_payloads:
        try:
            stored = append_events(accepted_payloads, db=db)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(400, str(exc)) from exc
    duplicates = sum(1 for event in stored if event.get("duplicate"))
    return {
        "ack": True,
        "received": len(events_in),
        "accepted": len(stored) - duplicates,
        "duplicates": duplicates,
        "rejected": rejected,
        "stored_event_ids": [event.get("id") for event in stored],
    }


# ── 阶段二：SecurityEvidence 统一证据 API（进程 / 网络 / 文件 / 进程树） ──────


def _evidence_response(db: Session, evidence_type: str | None, device_id: str | None,
                       severity_min: int | None, limit: int, include_raw: bool) -> dict:
    rows = query_evidence(db, evidence_type=evidence_type, device_id=device_id,
                          severity_min=severity_min, limit=limit)
    return {
        "count": len(rows),
        "type": evidence_type or "all",
        "device_id": device_id or "all",
        "events": [serialize_evidence(row, include_raw=include_raw) for row in rows],
    }


@router.get("/evidence")
def list_evidence(
    device_id: str | None = None,
    type: str | None = Query(None, pattern="^(process|network|file)$"),
    severity_min: int | None = Query(None, ge=0, le=100),
    limit: int = Query(200, ge=1, le=1000),
    include_raw: bool = False,
    db: Session = Depends(get_db),
):
    return _evidence_response(db, type, device_id, severity_min, limit, include_raw)


@router.get("/evidence/summary")
def evidence_summary(db: Session = Depends(get_db)):
    summary = summarize_evidence(db)
    summary["lsm"] = ebpf_lsm.lsm_status(db)
    return summary


@router.get("/evidence/process")
def process_events(
    device_id: str | None = None, severity_min: int | None = None,
    limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db),
):
    return _evidence_response(db, "process", device_id, severity_min, limit, False)


@router.get("/evidence/network")
def network_events(
    device_id: str | None = None, severity_min: int | None = None,
    limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db),
):
    return _evidence_response(db, "network", device_id, severity_min, limit, False)


@router.get("/evidence/file")
def file_events(
    device_id: str | None = None, severity_min: int | None = None,
    watched_only: bool = False,
    limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db),
):
    rows = query_evidence(db, evidence_type="file", device_id=device_id,
                          severity_min=severity_min, limit=limit * 4 if watched_only else limit)
    if watched_only:
        rows = [row for row in rows
                if any(row.file_path and (row.file_path.startswith(p) or row.file_path == p)
                       for p in FILE_WATCH_PATHS)][:limit]
    return {"count": len(rows), "type": "file", "watched_only": watched_only,
            "watch_paths": FILE_WATCH_PATHS,
            "events": [serialize_evidence(row) for row in rows]}


@router.get("/evidence/process-tree")
def process_tree(device_id: str | None = None, limit: int = Query(1000, ge=1, le=4000),
                 db: Session = Depends(get_db)):
    return build_process_tree(db, device_id=device_id, limit=limit)


# ── eBPF LSM 实验功能（默认 observe，不默认阻断） ─────────────────────────────


class LsmPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["observe", "enforce"] = "observe"
    watch_paths: list[str] | None = None
    restricted_processes: list[str] | None = None
    enabled: bool = True
    updated_by: str = Field(default="", max_length=128)
    note: str = Field(default="", max_length=2000)
    enforce_ack: bool = False


class LsmCapabilityInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(default="", max_length=128)
    bpf_lsm_supported: bool
    lsm_list: str = Field(default="", max_length=2048)
    detail: str = Field(default="", max_length=4000)


@router.get("/lsm/status")
def lsm_status_endpoint(db: Session = Depends(get_db)):
    return ebpf_lsm.lsm_status(db)


@router.get("/lsm/policies")
def lsm_policies(device_id: str | None = None, db: Session = Depends(get_db)):
    return ebpf_lsm.get_policy(db, device_id or "")


@router.put("/lsm/policies", dependencies=[Depends(require_control)])
def update_lsm_policy(payload: LsmPolicyInput, device_id: str | None = None, db: Session = Depends(get_db)):
    try:
        return ebpf_lsm.update_policy(
            db, device_id or "", mode=payload.mode, watch_paths=payload.watch_paths,
            restricted_processes=payload.restricted_processes, enabled=payload.enabled,
            updated_by=payload.updated_by, note=payload.note, enforce_ack=payload.enforce_ack,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/lsm/capability", dependencies=[Depends(require_control)])
def report_lsm_capability(payload: LsmCapabilityInput, db: Session = Depends(get_db)):
    return ebpf_lsm.record_capability(db, payload.device_id, bpf_lsm_supported=payload.bpf_lsm_supported,
                                      lsm_list=payload.lsm_list, detail=payload.detail)


class SensorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int = Field(gt=0)
    sensor_id: str = Field(min_length=1, max_length=128)
    source: Literal["falco", "tetragon", "bpftrace", "runtime_probe"]
    status: Literal["running", "degraded", "stopped", "unsupported"]
    dropped_events: int | None = Field(default=None, ge=0)
    capabilities: dict = Field(default_factory=dict)
    detail: str = Field(default="", max_length=1000)


@router.get("/ebpf/reliability")
def ebpf_reliability(db: Session = Depends(get_db)):
    """P0 采集可靠性快照：自报指标（心跳）与服务端观测交叉呈现。

    语义约定：数值 0 表示真实为零；底层无法提供的一律 "unavailable"/"unknown"，
    绝不虚构为零（dropped_events 仅在采集器如实上报时为数值）。
    """
    from app.services.runtime_telemetry import reliability_snapshot
    return reliability_snapshot(db)


@router.post("/sensors/heartbeat", dependencies=[Depends(require_control)])
def heartbeat(payload: SensorHeartbeat, db: Session = Depends(get_db)):
    if not db.get(models.LinuxAsset, payload.asset_id):
        raise HTTPException(404, "资产不存在")
    if len(json.dumps(payload.capabilities)) > 10000:
        raise HTTPException(413, "能力信息过大")
    row = db.query(models.RuntimeSensor).filter_by(asset_id=payload.asset_id, sensor_id=payload.sensor_id).one_or_none()
    if row is None:
        row = models.RuntimeSensor(asset_id=payload.asset_id, sensor_id=payload.sensor_id)
        db.add(row)
    row.source, row.status = payload.source, payload.status
    row.dropped_events, row.detail = payload.dropped_events, payload.detail
    row.capabilities_json = json.dumps(payload.capabilities, ensure_ascii=False)
    row.last_heartbeat_at = models.utcnow()
    db.commit()
    return coverage(db, payload.asset_id)


@router.get("/assets/{asset_id}/coverage")
def asset_coverage(asset_id: int, db: Session = Depends(get_db)):
    if not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    return coverage(db, asset_id)


@router.get("/assets/{asset_id}/timeline")
def asset_timeline(asset_id: int, limit: int = Query(300, ge=1, le=2000), db: Session = Depends(get_db)):
    if not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    return timeline(db, asset_id, limit)


@router.get("/assets/{asset_id}/evidence-sessions")
def asset_evidence_sessions(asset_id: int, limit: int = Query(500, ge=1, le=2000), db: Session = Depends(get_db)):
    """P1-3：按进程会话键聚合的证据明细视图（与 timeline 的会话键互相可对照）。"""
    if not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    return evidence_sessions(db, asset_id, limit)


@router.get("/cve-evidence")
def cve_evidence_view(cve_id: str, asset_id: int | None = Query(None), db: Session = Depends(get_db)):
    """P1-4：该 CVE 相关进程/网络/文件证据下钻（行为链详情页消费）。

    匹配语义与风险评估共用同一判定函数；无活跃风险记录 → 404，
    有记录无证据 → not_observed（两者语义不同，不混淆）。
    """
    result = cve_runtime_evidence(db, cve_id, asset_id)
    if result is None:
        raise HTTPException(404, "该 CVE 无活跃风险记录")
    return result


@router.get("/assets/{asset_id}/comparison")
def comparison(asset_id: int, checkpoint: str, window_seconds: int = Query(300, ge=10, le=3600), db: Session = Depends(get_db)):
    if not db.get(models.LinuxAsset, asset_id):
        raise HTTPException(404, "资产不存在")
    try:
        return compare_windows(db, asset_id, checkpoint, window_seconds)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
