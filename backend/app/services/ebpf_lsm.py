"""eBPF LSM 实验功能：策略与内核能力管理。

设计原则：
- 默认只观察（observe），绝不默认阻断；
- enforce 必须显式确认（enforce_ack）且采集端已上报内核支持 BPF LSM；
- 后端只保存策略与能力状态，真正的 LSM 挂载/阻断由 Linux 侧
  collector/ebpf_lsm_monitor.py 执行（需内核以 lsm=...,bpf 启动）。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.services.security_evidence import FILE_WATCH_PATHS

GLOBAL_POLICY_KEY = ""


def _get_or_create(db: Session, device_id: str) -> models.LsmPolicy:
    row = db.query(models.LsmPolicy).filter_by(device_id=device_id).one_or_none()
    if row is None:
        row = models.LsmPolicy(device_id=device_id, mode="observe",
                               watch_paths_json=json.dumps(FILE_WATCH_PATHS),
                               restricted_processes_json=json.dumps([]))
        db.add(row)
        db.commit()
    return row


def get_policy(db: Session, device_id: str) -> dict:
    row = _get_or_create(db, device_id)
    return serialize_policy(row)


def serialize_policy(row: models.LsmPolicy) -> dict:
    return {
        "device_id": row.device_id or "(global)",
        "mode": row.mode,
        "enabled": row.enabled,
        "watch_paths": json.loads(row.watch_paths_json or "[]"),
        "restricted_processes": json.loads(row.restricted_processes_json or "[]"),
        "updated_by": row.updated_by,
        "note": row.note,
        "kernel": {
            "bpf_lsm_supported": bool(row.kernel_bpf_lsm_supported),
            "lsm_list": row.kernel_lsm_list or "",
            "detail": row.capability_detail or "",
            "last_probe_at": row.last_probe_at,
        },
        "updated_at": row.updated_at,
    }


def update_policy(
    db: Session, device_id: str, *, mode: str, watch_paths: list[str] | None,
    restricted_processes: list[str] | None, enabled: bool,
    updated_by: str, note: str, enforce_ack: bool,
) -> dict:
    row = _get_or_create(db, device_id)
    if mode not in ("observe", "enforce"):
        raise ValueError("mode 只允许 observe 或 enforce")
    if mode == "enforce":
        if not enforce_ack:
            raise ValueError("启用 enforce 必须显式确认 enforce_ack=true；默认只观察不阻断")
        if not row.kernel_bpf_lsm_supported:
            raise PermissionError(
                "采集端尚未确认内核支持 BPF LSM（需内核以 lsm=...,bpf 启动并提供 BTF）；"
                "enforce 被拒绝，策略保持 observe"
            )
    row.mode = mode
    row.enabled = enabled
    row.updated_by, row.note = updated_by, note
    if watch_paths is not None:
        if not watch_paths or any(not str(p).startswith("/") for p in watch_paths):
            raise ValueError("监控路径必须是以 / 开头的绝对路径列表")
        row.watch_paths_json = json.dumps([str(p) for p in watch_paths], ensure_ascii=False)
    if restricted_processes is not None:
        row.restricted_processes_json = json.dumps([str(p) for p in restricted_processes], ensure_ascii=False)
    db.commit()
    return serialize_policy(row)


def record_capability(db: Session, device_id: str, *, bpf_lsm_supported: bool,
                      lsm_list: str, detail: str) -> dict:
    """采集端上报内核能力探测结果；enforce 策略依赖此结果。"""
    row = _get_or_create(db, device_id)
    row.kernel_bpf_lsm_supported = bool(bpf_lsm_supported)
    row.kernel_lsm_list = (lsm_list or "")[:2048]
    row.capability_detail = (detail or "")[:4000]
    row.last_probe_at = datetime.now(timezone.utc)
    if not bpf_lsm_supported and row.mode == "enforce":
        row.mode = "observe"
        row.note = (row.note + " [自动降级 observe：内核不支持 BPF LSM]").strip()
    db.commit()
    return serialize_policy(row)


def lsm_status(db: Session) -> dict:
    policies = db.query(models.LsmPolicy).order_by(models.LsmPolicy.device_id).all()
    return {
        "experimental": True,
        "default_mode": "observe",
        "enforce_enabled_any": any(p.mode == "enforce" and p.enabled for p in policies),
        "policies": [serialize_policy(p) for p in policies],
        "note": "eBPF LSM 处于实验阶段：默认只观察不阻断；enforce 需内核支持（lsm=...,bpf）与显式确认。",
    }
