"""阶段五发现闭环：授权网段扫描 → 观察 → 身份识别 → IotDevice 建档 → CVE 匹配。

编排层 only——本模块不重新实现任何扫描器或识别器：

- 网段扫描复用 iot_devices.discover()（白名单、≤128 地址、线程与超时控制全部继承）；
- 协议指纹与设备建档复用 device_inventory.upsert_device()（幂等，业务键为
  vendor|model|mac-or-host 哈希，绝不以 IP 作为永久资产 ID）；
- CVE 匹配复用 device_vulnerability.run_device_matching()（厂商公告精确版本优先，
  NVD 通用路线只产生 potentially_affected 候选，绝不提升为已确认漏洞）。

处理状态（DeviceObservation.review_status）：

- pending              待识别（discover() 写入后的初始态）
- identified           已识别并晋升为 IotDevice（identity_confidence 达标）
- insufficient_evidence 信息不足（探测无可读协议响应，或身份置信度低于阈值；
                       设备以"待确认资产"留存时同样落此态，原始观察证据保留）
- failed               处理失败（探测过程异常；保留原始观察，支持安全重试）

安全边界：本模块只读探测与建档，绝不触发修复、Harness 或任何设备写操作
（LINUXGUARD_ENABLE_DEVICE_REPAIR 等既有开关与本流程无关且不受影响）。
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services import device_inventory, device_vulnerability, iot_devices

# 身份置信度阈值：达到才视为"已识别"；device_identity_endpoint=0.9 达标，
# banner_heuristic=0.35 视为信息不足（设备仍以待确认资产形式留存）。
IDENTIFY_CONFIDENCE_FLOOR = 0.5

REVIEW_PENDING = "pending"
REVIEW_IDENTIFIED = "identified"
REVIEW_INSUFFICIENT = "insufficient_evidence"
REVIEW_FAILED = "failed"
RETRYABLE_STATUSES = (REVIEW_PENDING, REVIEW_INSUFFICIENT, REVIEW_FAILED, "", None)


def _evidence(row: models.DeviceObservation) -> dict[str, Any]:
    try:
        parsed = json.loads(row.evidence_json or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except ValueError:
        return {}


def _save_evidence(db: Session, row: models.DeviceObservation, patch: dict[str, Any]) -> None:
    merged = _evidence(row)
    merged.update(patch)
    row.evidence_json = json.dumps(merged, ensure_ascii=False)


def _mark(db: Session, row: models.DeviceObservation, status: str, note: str,
          device: models.IotDevice | None = None, evidence_patch: dict[str, Any] | None = None) -> None:
    row.review_status = status
    row.review_note = note[:1000]
    row.reviewed_at = models.utcnow()
    if device is not None:
        row.promoted_device_id = device.device_id
    if evidence_patch:
        _save_evidence(db, row, evidence_patch)
    db.commit()


def _versioned_components(device: models.IotDevice) -> int:
    return sum(1 for component in device.components if (component.version or "").strip())


# RTOS 能力边界（如实标记，不伪造支持）：Zephyr 等嵌入式 OS 无 SSH 服务端、
# 无发行版包管理器、无 eBPF 运行时——主机线采集与运行时探针对其不适用。
ZEPHYR_UNSUPPORTED_CAPABILITIES = {
    "ssh_inventory": "unsupported: Zephyr RTOS 固件不提供 SSH 服务端",
    "package_inventory": "unsupported: 无发行版包管理器（apk/opkg/dpkg）",
    "ebpf_runtime": "unsupported: 无 eBPF 运行时与 Falco/Tetragon 生态",
}


def _capability_marks(device: models.IotDevice) -> dict[str, str] | None:
    """对 Zephyr 设备返回能力边界标注；其他设备返回 None（不标注）。"""
    if (device.os or "").startswith("Zephyr"):
        return dict(ZEPHYR_UNSUPPORTED_CAPABILITIES)
    return None


def _correlate_dhcp(db: Session, device: models.IotDevice, host: str) -> int:
    """按 MAC（优先）或 IP 把网关 DHCP 观察与已建档设备关联；不改写租约语义。"""
    try:
        metadata = json.loads(device.metadata_json or "{}")
    except ValueError:
        metadata = {}
    mac = str(metadata.get("mac_address", "")).lower()
    query = db.query(models.DeviceObservation).filter(models.DeviceObservation.source == "dhcp_lease")
    matched = {row.id: row for row in query.all()
               if (mac and row.mac_address == mac) or (row.ip_address == host and not mac)}
    linked = 0
    for row in matched.values():
        if row.promoted_device_id and row.promoted_device_id != device.device_id:
            continue  # 已关联到其他设备，保留首次结论
        basis = "mac" if mac and row.mac_address == mac else "ip"
        _mark(db, row, REVIEW_IDENTIFIED,
              f"DHCP 观察与主动扫描发现关联（依据 {basis}）",
              device=device, evidence_patch={"correlation": {"basis": basis, "device_id": device.device_id,
                                                             "identity_confidence": device.identity_confidence}})
        linked += 1
    return linked


def enroll_observation(db: Session, observation: models.DeviceObservation,
                       probe_timeout: float = 2.0) -> dict[str, Any]:
    """处理单条 tcp_connect 观察：识别 → 建档 → （证据充分时）CVE 匹配。

    幂等：重复处理同一观察只更新既有设备（upsert_device 语义），不产生重复资产。
    """
    host = observation.ip_address or observation.identity_key
    ports = _evidence(observation).get("open_ports") or []
    observation.review_attempts = (observation.review_attempts or 0) + 1
    db.commit()
    if not ports:
        _mark(db, observation, REVIEW_INSUFFICIENT, "观察缺少开放端口证据，等待下轮扫描补充")
        return {"observation_id": observation.id, "ip": host, "status": REVIEW_INSUFFICIENT,
                "device_id": "", "cve": "deferred_no_evidence"}

    try:
        device, report = device_inventory.upsert_device(
            db, host, ports=ports, timeout=probe_timeout,
            banner_fallback=True, scan_scope="cidr_discovery",
        )
    except ValueError as exc:
        # upsert_device 明确拒绝（无可读协议响应）：信息不足，保留原始观察证据。
        _mark(db, observation, REVIEW_INSUFFICIENT, str(exc)[:1000])
        return {"observation_id": observation.id, "ip": host, "status": REVIEW_INSUFFICIENT,
                "device_id": "", "cve": "deferred_no_evidence"}
    except Exception as exc:  # 探测过程异常：处理失败，支持安全重试
        db.rollback()
        fresh = db.get(models.DeviceObservation, observation.id)
        if fresh is None:
            return {"observation_id": observation.id, "ip": host, "status": REVIEW_FAILED,
                    "device_id": "", "cve": "skipped", "error": f"{type(exc).__name__}: {exc}"}
        _mark(db, fresh, REVIEW_FAILED, f"{type(exc).__name__}: {exc}")
        return {"observation_id": fresh.id, "ip": host, "status": REVIEW_FAILED,
                "device_id": "", "cve": "skipped", "error": str(exc)[:500]}

    # 建档成功：按身份置信度区分"已识别 / 待确认资产（信息不足）"。
    status = REVIEW_IDENTIFIED if device.identity_confidence >= IDENTIFY_CONFIDENCE_FLOOR else REVIEW_INSUFFICIENT
    note = (f"已晋升为设备 {device.device_id}（identity_source={device.identity_source}, "
            f"confidence={device.identity_confidence}）" if status == REVIEW_IDENTIFIED else
            f"以待确认资产留存 {device.device_id}（identity_confidence={device.identity_confidence} "
            f"低于 {IDENTIFY_CONFIDENCE_FLOOR}，不推断厂商/型号/固件）")

    # CVE 联动：仅当设备具备带版本的组件或固件证据时调用既有匹配引擎；
    # 证据不足只记录资产并标记待补充信息。绝不修改匹配结论语义。
    versioned = _versioned_components(device)
    cve_summary: dict[str, Any] = {"status": "deferred_no_version_evidence", "affected_count": 0}
    if versioned > 0:
        try:
            result = device_vulnerability.run_device_matching(db, device)
            cve_summary = {"status": "matched", "stats": result.get("stats", {}),
                           "affected_count": int(result.get("affected_count", 0))}
        except Exception as exc:  # 匹配失败不回退已完成的建档
            db.rollback()
            db.refresh(device)
            cve_summary = {"status": "matching_error", "affected_count": 0, "error": str(exc)[:300]}
    else:
        cve_summary["note"] = "组件/固件版本证据不足，仅记录资产，待补充信息后匹配"

    enrollment = {"device_id": device.device_id, "identity_source": device.identity_source,
                  "identity_confidence": device.identity_confidence,
                  "components_with_version": versioned, "cve": cve_summary,
                  "services": report.get("identified", {})}
    capability_marks = _capability_marks(device)
    if capability_marks is not None:
        enrollment["capabilities"] = capability_marks
    _mark(db, observation, status, note, device=device, evidence_patch={"enrollment": enrollment})

    try:
        correlated = _correlate_dhcp(db, device, host)
    except Exception:  # 关联失败不影响建档结果
        db.rollback()
        correlated = 0
    return {"observation_id": observation.id, "ip": host, "status": status,
            "device_id": device.device_id, "cve": cve_summary["status"],
            "affected_count": cve_summary.get("affected_count", 0), "dhcp_correlated": correlated}


def _scope_rows(db: Session, scope: str, include_identified: bool = False) -> list[models.DeviceObservation]:
    """范围内待处理的主动扫描观察。

    include_identified=True（完整闭环扫描）：已识别行也重新处理——
    upsert_device 幂等，仅刷新设备画像与 last_seen，不产生重复资产；
    include_identified=False（安全重试入口）：只处理未完成识别的行。
    """
    rows = db.query(models.DeviceObservation).filter(
        models.DeviceObservation.scope == scope,
        models.DeviceObservation.source == "tcp_connect",
        models.DeviceObservation.presence == "responded",
    ).all()
    if include_identified:
        return rows
    return [row for row in rows if row.review_status in RETRYABLE_STATUSES]


def enroll_scope(db: Session, scope: str, probe_timeout: float = 2.0, limit: int = 128) -> dict[str, Any]:
    """不重新扫描，仅重试某个范围中未完成识别的观察（安全重试入口）。"""
    rows = _scope_rows(db, scope)[:max(1, limit)]
    known = {device.device_id for device in db.query(models.IotDevice).all()}
    return _process_rows(db, rows, known, probe_timeout)


def _process_rows(db: Session, rows: list[models.DeviceObservation], known_device_ids: set[str],
                  probe_timeout: float) -> dict[str, Any]:
    summary: dict[str, Any] = {"processed": 0, "identified": 0, "insufficient_evidence": 0, "failed": 0,
                               "enrolled_new": 0, "enrolled_existing": 0, "cve_matched": 0, "cve_deferred": 0,
                               "dhcp_correlated": 0, "devices": []}
    for row in rows:
        result = enroll_observation(db, row, probe_timeout=probe_timeout)
        summary["processed"] += 1
        summary[result["status"]] = summary.get(result["status"], 0) + 1
        if result.get("device_id"):
            if result["device_id"] in known_device_ids:
                summary["enrolled_existing"] += 1
            else:
                summary["enrolled_new"] += 1
                known_device_ids.add(result["device_id"])
        if result.get("cve") == "matched":
            summary["cve_matched"] += 1
        elif result.get("cve", "").startswith("deferred"):
            summary["cve_deferred"] += 1
        summary["dhcp_correlated"] += int(result.get("dhcp_correlated", 0))
        summary["devices"].append(result)
    return summary


def discover_and_enroll(db: Session, cidr: str, ports: list[int], timeout: float = 0.3,
                        probe_timeout: float = 2.0) -> dict[str, Any]:
    """完整闭环入口：授权网段扫描 → 观察 → 识别 → 建档 → CVE 匹配。

    未授权网段 / 超过 128 地址等边界由 iot_devices.discover() 原样拒绝
    （ValueError 向上传播，且未发生任何扫描或写入）。
    """
    scan = iot_devices.discover(db, cidr, ports, timeout)  # 白名单/范围/线程/超时全部继承
    known = {device.device_id for device in db.query(models.IotDevice).all()}
    rows = _scope_rows(db, scan["scope"], include_identified=True)  # 完整闭环：全量幂等刷新
    summary = _process_rows(db, rows, known, probe_timeout)
    summary.update({"scan": scan, "scope": scan["scope"],
                    "responding_devices": scan.get("responding_devices", 0),
                    "boundaries": ["仅晋升协议指纹可证实的设备身份；未识别协议只保留横幅证据。",
                                   "NVD 通用匹配保持候选（potentially_affected）语义，不确认为漏洞。",
                                   "本流程不触发任何修复或设备写操作。"]})
    return summary
