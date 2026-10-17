"""智能体专属工具集（M5 中立模块）。

工具按职责分组、互不重叠：智能体的能力边界 = 它注册的工具集合。
所有工具只读真实数据库（IoT 设备清单 / CVE 情报 / SecurityEvidence / 修复任务），
不提供任何 shell 执行能力。供唯一正式编排器（services/unified/）注册使用。
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.security_evidence import FILE_WATCH_PATHS, build_process_tree
from app.utils.version_compare import is_version_less

# ───────────────────────── Agent 1：设备情报专属工具 ─────────────────────────


def _device_brief(device: models.IotDevice) -> dict[str, Any]:
    return {
        "device_id": device.device_id, "device_name": device.device_name,
        "device_type": device.device_type, "vendor": device.vendor, "model": device.model,
        "firmware_version": device.firmware_version, "os": device.os, "ip": device.ip,
        "status": device.status, "identity_source": device.identity_source,
        "open_ports": sorted(service.port for service in device.services if service.status == "open"),
    }


def tool_query_device_profile(db: Session, device_id: str = "", host: str = "") -> dict[str, Any]:
    """按 device_id 或 IP/主机名查询设备画像（含服务与组件）。"""
    device = None
    if device_id:
        device = db.query(models.IotDevice).filter_by(device_id=device_id).one_or_none()
    if device is None and host:
        device = db.query(models.IotDevice).filter(
            (models.IotDevice.ip == host) | (models.IotDevice.device_id == host)
        ).first()
    if device is None:
        # 兼容主机型资产：LinuxAsset 同样是真实项目数据
        key = host or device_id
        asset = db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == key) | (models.LinuxAsset.ip_address == key)
        ).first() if key else None
        if asset is None:
            return {"found": False, "note": "未找到匹配设备，请在 data_gaps 中说明"}
        return {
            "found": True, "asset_kind": "linux_host",
            "device_id": asset.hostname, "device_name": asset.hostname,
            "device_type": asset.device_type, "vendor": asset.distribution,
            "model": asset.device_model, "firmware_version": asset.firmware_version,
            "os": f"{asset.os_name} {asset.os_version}".strip(),
            "ip": asset.ip_address, "status": "registered",
            "inventory_complete": asset.inventory_complete,
            "component_count": len(asset.packages),
            "components_truncated": len(asset.packages) > 200,
            "services": [{"port": s.port, "service_type": s.service_name or s.process_name,
                          "product": s.process_name} for s in asset.services],
            "components": [{"name": p.package_name, "version": p.package_version,
                            "type": "package"} for p in asset.packages[:200]],
            "open_ports": [s.port for s in asset.services],
        }
    return {
        "found": True, "asset_kind": "iot_device", **_device_brief(device),
        "services": [{
            "port": s.port, "service_type": s.service_type, "product": s.product,
            "version": s.version, "auth_state": s.auth_state, "status": s.status,
        } for s in sorted(device.services, key=lambda item: item.port)],
        "components": [{
            "name": c.component_name, "version": c.version,
            "type": c.component_type, "cpe": c.cpe, "source": c.source,
        } for c in device.components],
    }


def tool_list_devices(db: Session) -> dict[str, Any]:
    """列出已登记的全部智能设备（简要）。"""
    devices = db.query(models.IotDevice).order_by(models.IotDevice.last_seen_at.desc()).limit(50).all()
    hosts = db.query(models.LinuxAsset).order_by(models.LinuxAsset.id).limit(50).all()
    return {
        "iot_devices": [_device_brief(device) for device in devices],
        "linux_hosts": [{"device_id": a.hostname, "device_name": a.hostname,
                         "ip": a.ip_address, "os": a.distribution} for a in hosts],
    }


def tool_query_network_surface(db: Session, device_id: str = "", host: str = "") -> dict[str, Any]:
    """查询设备网络暴露面：开放端口、协议、认证状态与暴露等级。"""
    device = None
    if device_id:
        device = db.query(models.IotDevice).filter_by(device_id=device_id).one_or_none()
    if device is None and host:
        device = db.query(models.IotDevice).filter(models.IotDevice.ip == host).first()
    if device is None:
        key = host or device_id
        asset = db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == key) | (models.LinuxAsset.ip_address == key)).first() if key else None
        if asset is None:
            return {"found": False}
        return {"found": True, "asset_kind": "linux_host", "device_id": asset.hostname,
            "ip": asset.ip_address, "exposure_level": asset.exposure_level,
            "open_services": [{"port": s.port, "service_type": s.service_name or s.process_name,
                "product": s.process_name, "listen_address": s.listen_address,
                "public": bool(s.is_public_exposed), "auth_state": "unknown"} for s in asset.services],
            "anonymous_services": [], "note": "清单中的监听事实；不代表主动公网可达性或认证验证"}
    open_services = [s for s in device.services if s.status == "open"]
    risky = [s for s in open_services if s.auth_state == "anonymous_accepted"]
    return {
        "found": True, "device_id": device.device_id, "ip": device.ip,
        "open_services": [{"port": s.port, "service_type": s.service_type,
                           "product": s.product, "auth_state": s.auth_state} for s in open_services],
        "anonymous_services": [s.service_type for s in risky],
        "risk_baseline": device.risk_score, "risk_basis": device.risk_score_basis,
    }


# ─────────────────── Agent 2：漏洞情报专属工具 ───────────────────────────────


def tool_query_cve_intelligence(db: Session, cve_id: str = "", package_name: str = "",
                                limit: int = 10) -> dict[str, Any]:
    """查询 CVE 情报：CVSS、CISA KEV、EPSS、多源情报状态。"""
    query = db.query(models.VulnerabilityInfo)
    if cve_id:
        query = query.filter(models.VulnerabilityInfo.cve_id == cve_id)
    if package_name:
        query = query.filter(models.VulnerabilityInfo.affected_package == package_name)
    vulnerabilities = query.order_by(models.VulnerabilityInfo.cvss_score.desc()).limit(max(1, limit)).all()
    findings = []
    for vuln in vulnerabilities:
        intel = db.query(models.ThreatIntelSource).filter_by(cve_id=vuln.cve_id).one_or_none()
        sources = db.query(models.VulnerabilityIntelligenceSource).filter_by(cve_id=vuln.cve_id).all()
        findings.append({
            "cve_id": vuln.cve_id, "title": vuln.title, "cvss_score": vuln.cvss_score,
            "cvss_severity": vuln.cvss_severity, "affected_package": vuln.affected_package,
            "fixed_version": vuln.fixed_version, "source": vuln.source,
            "kev": bool(intel and intel.is_kev), "kev_due_date": intel.kev_due_date if intel else "",
            "epss_score": intel.epss_score if intel else 0.0,
            "epss_percentile": intel.epss_percentile if intel else 0.0,
            "intelligence_sources": {s.source: s.fetch_status for s in sources},
        })
    return {"count": len(findings), "vulnerabilities": findings}


def tool_query_version_impact(db: Session, cve_id: str, installed_version: str,
                              fixed_version: str = "") -> dict[str, Any]:
    """版本影响判断：装机版本与修复版本的真实比较。"""
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).one_or_none()
    resolved_fixed = fixed_version or (vuln.fixed_version if vuln else "")
    if not installed_version or not resolved_fixed:
        return {"cve_id": cve_id, "version_impact": "unknown",
                "reason": "缺少装机版本或修复版本，不能下结论"}
    affected = is_version_less(installed_version, resolved_fixed)
    return {
        "cve_id": cve_id, "installed_version": installed_version,
        "fixed_version": resolved_fixed,
        "version_impact": "affected" if affected else "fixed",
        "comparison": f"{installed_version} < {resolved_fixed} = {affected}",
        "advisory_source": vuln.source if vuln else "",
    }


def tool_query_matched_vulnerabilities(db: Session, host: str = "",
                                       cve_id: str = "", device_id: str = "") -> dict[str, Any]:
    """查询已入库的版本命中记录（主机 VulnerabilityMatch + 设备 DeviceVulnerabilityMatch）。"""
    from app.services.device_vulnerability import device_matches, resolve_device
    query = db.query(models.VulnerabilityMatch)
    if cve_id:
        query = query.filter((models.VulnerabilityMatch.cve_id == cve_id) |
            (models.VulnerabilityMatch.cve_id.startswith(cve_id + ":", autoescape=True) if ":" not in cve_id else False))
    key = host or device_id
    if key:
        asset_ids = db.query(models.LinuxAsset.id).filter(
            (models.LinuxAsset.hostname == key) | (models.LinuxAsset.ip_address == key))
        query = query.filter(models.VulnerabilityMatch.asset_id.in_(asset_ids))
    matches = query.order_by(models.VulnerabilityMatch.id.desc()).limit(30).all()
    rows = []
    for match in matches:
        asset = db.get(models.LinuxAsset, match.asset_id)
        if host and asset and asset.hostname != host and asset.ip_address != host:
            continue
        rows.append({
            "host": asset.hostname if asset else "",
            "cve_id": match.cve_id, "package_name": match.package_name,
            "installed_version": match.installed_version, "fixed_version": match.fixed_version,
            "match_status": match.match_status, "confidence": match.confidence,
            "active": match.active,
        })
    # 阶段六：设备组件 × CVE 命中（按 device_id/IP/名称解析设备）
    device_rows = []
    key = device_id or host
    if key:
        device = resolve_device(db, key)
        if device:
            device_rows = device_matches(db, device)
    return {"count": len(rows), "matches": rows,
            "device_count": len(device_rows), "device_matches": device_rows}


# ─────────────────── Agent 3：运行时行为专属工具（SecurityEvidence） ─────────


def _evidence_keys(db: Session, device_id: str) -> list[str]:
    """把 device_id/IP/主机名解析成证据表可能使用的全部标识键。

    SecurityEvidence.device_id 记录的是采集端上报的 hostname 或 IP；
    智能设备分析时用 device_id 查询，需要同时匹配设备 IP 与名称。
    设备线与主机线是同一台物理机的两条档案（IP 相同）：设备键还要传递到
    同 IP 主机线资产的自报主机名——SSH/logread 采集锚定的正是该主机名
    （如 OpenWrt 设备线 DEV-* ↔ 主机线 OpenWrt-<hash>），否则设备面研判
    会因证据键失配而错误地得到"无运行时证据"。
    """
    keys = {device_id}
    device = db.query(models.IotDevice).filter(
        (models.IotDevice.device_id == device_id) | (models.IotDevice.ip == device_id)
    ).first()
    if device:
        keys.update({device.device_id, device.ip, device.device_name})
        if device.ip:
            asset_by_ip = db.query(models.LinuxAsset).filter(
                models.LinuxAsset.ip_address == device.ip).first()
            if asset_by_ip is None:
                # 主机线资产可能没有 IP 字段（操作员上传清单不含管理地址）；
                # 指纹钉扎的 DeviceConnection（host↔asset_id）是平台自身的
                # 权威同机绑定，经它解析到主机线资产的自报主机名。
                connection = db.query(models.DeviceConnection).filter(
                    models.DeviceConnection.host == device.ip).first()
                if connection is not None and connection.asset_id:
                    asset_by_ip = db.get(models.LinuxAsset, connection.asset_id)
            if asset_by_ip is not None:
                keys.update({asset_by_ip.hostname, asset_by_ip.ip_address})
    asset = db.query(models.LinuxAsset).filter(
        (models.LinuxAsset.hostname == device_id) | (models.LinuxAsset.ip_address == device_id)
    ).first()
    if asset:
        keys.update({asset.hostname, asset.ip_address})
        if asset.ip_address:
            device_by_ip = db.query(models.IotDevice).filter(
                models.IotDevice.ip == asset.ip_address).first()
            if device_by_ip:
                keys.update({device_by_ip.device_id, device_by_ip.device_name})
    return sorted(key for key in keys if key)


def _evidence_rows(db: Session, evidence_type: str, device_id: str, limit: int) -> list[dict[str, Any]]:
    keys = _evidence_keys(db, device_id)
    query = db.query(models.SecurityEvidence).filter(
        models.SecurityEvidence.evidence_type == evidence_type,
        models.SecurityEvidence.device_id.in_(keys),
    ).order_by(models.SecurityEvidence.id.desc()).limit(max(1, min(limit, 200)))
    return [{
        "evidence_id": row.evidence_id, "process": row.process, "pid": row.pid,
        "ppid": row.ppid, "user": row.user, "commandline": row.commandline,
        "process_exec_id": row.process_exec_id or "",
        "operation": row.operation, "destination_ip": row.destination_ip,
        "destination_port": row.destination_port, "file_path": row.file_path,
        "severity": row.severity, "timestamp": row.timestamp, "source": row.source,
    } for row in reversed(query.all())]


def tool_query_process_evidence(db: Session, device_id: str, limit: int = 50) -> dict[str, Any]:
    """查询进程类 eBPF 证据（带 evidence_id）。"""
    rows = _evidence_rows(db, "process", device_id, limit)
    return {"count": len(rows), "events": rows}


def tool_query_network_evidence(db: Session, device_id: str, limit: int = 50) -> dict[str, Any]:
    """查询网络连接类 eBPF 证据（带 evidence_id）。"""
    rows = _evidence_rows(db, "network", device_id, limit)
    return {"count": len(rows), "events": rows}


def tool_query_file_evidence(db: Session, device_id: str, limit: int = 50,
                             watched_only: bool = True) -> dict[str, Any]:
    """查询文件访问类 eBPF 证据；watched_only 限定受控路径。"""
    rows = _evidence_rows(db, "file", device_id, limit)
    if watched_only:
        rows = [row for row in rows
                if any(row.get("file_path", "").startswith(path) or row.get("file_path") == path
                       for path in FILE_WATCH_PATHS)]
    return {"count": len(rows), "watch_paths": FILE_WATCH_PATHS, "events": rows}


def tool_query_runtime_data_quality(db: Session, device_id: str) -> dict[str, Any]:
    """P2-3：查询设备的运行时数据质量——采集覆盖、真实丢失、证据新鲜度、数据缺口。

    语义边界（与 reliability_snapshot 一致）：
    - dropped_events：采集器如实上报时为数值（0=真实零丢失）；未上报 →
      "unavailable"，绝不虚构为零；
    - 无心跳传感器 ≠ 覆盖良好；freshness 按证据时间分桶，无证据如实说明；
    - data_gaps 明确列出缺口供智能体在 data_gaps 字段中如实声明。
    """
    from datetime import datetime, timezone

    from app.services.runtime_telemetry import coverage, event_time

    keys = _evidence_keys(db, device_id)
    if not keys:
        return {"device_id": device_id, "found": False, "data_gaps": ["未找到匹配设备或资产标识"]}
    # 标识未匹配任何设备/资产/证据时如实返回 found=False（不凭空生成质量报告）
    known = (
        db.query(models.IotDevice).filter(
            (models.IotDevice.device_id == device_id) | (models.IotDevice.ip == device_id)).first()
        is not None
        or db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == device_id) | (models.LinuxAsset.ip_address == device_id)).first()
        is not None
        or db.query(models.SecurityEvidence).filter(models.SecurityEvidence.device_id.in_(keys)).first()
        is not None
    )
    if not known:
        return {"device_id": device_id, "found": False,
                "data_gaps": ["该标识未匹配任何设备、资产或运行时证据"]}

    asset = db.query(models.LinuxAsset).filter(
        (models.LinuxAsset.hostname == device_id) | (models.LinuxAsset.ip_address == device_id)
    ).first()
    gaps: list[str] = []
    sensor_rows = []
    if asset is None:
        gaps.append("该标识未登记为 Linux 资产，无法查询采集器心跳覆盖")
        coverage_view = {"status": "unknown", "sensors": []}
    else:
        coverage_view = coverage(db, asset.id)
        if not coverage_view["sensors"]:
            gaps.append("该资产没有任何采集器心跳记录（覆盖未知，不代表安全）")
        if asset.distribution == "openwrt" and not any(
                sensor["source"] == "logread" for sensor in coverage_view["sensors"]):
            gaps.append("OpenWrt 资产尚无 logread 运行时日志采集记录（运行时覆盖缺口，不代表安全）")
    for sensor in coverage_view.get("sensors", []):
        sensor_rows.append({
            "sensor_id": sensor["sensor_id"], "source": sensor["source"], "status": sensor["status"],
            "age_seconds": sensor["age_seconds"], "dropped_events": sensor["dropped_events"],
            "self_reported_metrics": sensor["capabilities"].get("metrics", "unknown"),
        })
        if sensor["dropped_events"] == "unavailable" or sensor["dropped_events"] is None:
            gaps.append(f"传感器 {sensor['sensor_id']} 未上报丢失计数（unavailable，非零丢失）")
        elif sensor["dropped_events"]:
            gaps.append(f"传感器 {sensor['sensor_id']} 报告丢失 {sensor['dropped_events']} 条事件")
        if sensor["status"] == "stale":
            gaps.append(f"传感器 {sensor['sensor_id']} 心跳已过期（{sensor['age_seconds']}s 未更新）")
        if sensor["source"] == "logread":
            gaps.append(f"传感器 {sensor['sensor_id']} 为 logread 拉取式降级采集（设备原生日志，"
                        "非 eBPF 内核级观测；ring 覆盖窗口外的历史不可知）")

    now = datetime.now(timezone.utc)
    freshness = {}
    stale_hours = {"process": 24, "network": 24, "file": 168}
    for evidence_type in ("process", "network", "file"):
        query = db.query(models.SecurityEvidence).filter(
            models.SecurityEvidence.evidence_type == evidence_type,
            models.SecurityEvidence.device_id.in_(keys),
        ).order_by(models.SecurityEvidence.id.desc()).limit(500)
        rows = query.all()
        latest = max((event_time(row.timestamp) for row in rows), default=None)
        latest = latest.astimezone(timezone.utc) if latest and latest.tzinfo is None else latest
        age_hours = round((now - latest).total_seconds() / 3600, 2) if latest else None
        entry = {"count_recent": len(rows), "latest_timestamp": latest.isoformat() if latest else None,
                 "age_hours": age_hours}
        if latest is None:
            entry["freshness"] = "no_evidence"
            gaps.append(f"无 {evidence_type} 类证据（该类型覆盖为零）")
        else:
            entry["freshness"] = "fresh" if age_hours <= stale_hours[evidence_type] else "stale"
            if entry["freshness"] == "stale":
                gaps.append(f"{evidence_type} 类证据已过期（最近 {age_hours}h 前）")
        freshness[evidence_type] = entry

    sessionless = 0
    if asset is not None:
        sessionless = db.query(models.SecurityEvidence).filter(
            models.SecurityEvidence.asset_id == asset.id,
            models.SecurityEvidence.process_exec_id == "",
        ).count()
        if sessionless:
            gaps.append(f"{sessionless} 条证据缺进程会话身份（P1-3 升级前的存量数据，无法参与行为链聚合）")

    return {
        "device_id": device_id, "found": True,
        "keys_queried": keys,
        "coverage": {"status": coverage_view.get("status", "unknown"), "sensors": sensor_rows},
        "dropped_events": {row["sensor_id"]: ("unavailable" if row["dropped_events"] is None
                                              else row["dropped_events"]) for row in sensor_rows},
        "freshness": freshness,
        "data_gaps": gaps,
        "note": "缺口如实列出；覆盖缺失或证据过期时，未观察到行为不得解释为未发生。",
    }


def tool_query_process_tree(db: Session, device_id: str) -> dict[str, Any]:
    """查询设备进程树与「服务→shell→下载器」链（按设备多标识键合并）。"""
    merged: dict[str, Any] = {}
    for key in _evidence_keys(db, device_id):
        tree = build_process_tree(db, device_id=key, limit=1000)
        for name, part in tree.get("devices", {}).items():
            if part.get("process_count"):
                merged[name] = part
    if not merged:
        return {"note": "该设备暂无进程证据", "queried_keys": _evidence_keys(db, device_id)}
    combined_roots = []
    chains = []
    for part in merged.values():
        combined_roots.extend(part.get("roots", []))
        chains.extend(part.get("service_shell_chains", []))
    return {"roots": combined_roots, "service_shell_chains": chains,
            "process_count": sum(part.get("process_count", 0) for part in merged.values()),
            "max_depth": max((part.get("max_depth", 0) for part in merged.values()), default=0)}


# ─────────────────── Agent 4：修复与验证专属工具 ─────────────────────────────

REMEDIATION_ACTION_WHITELIST = [
    "change_config", "restart_service", "disable_service", "enable_authentication",
    "update_package", "backup_file", "restore_file",
]


def tool_query_remediation_targets(db: Session, host: str = "", cve_id: str = "",
                                   device_id: str = "") -> dict[str, Any]:
    """查询已获授权、可进入修复流程的风险事件与现有修复任务（含设备 CVE 命中）。"""
    from app.services.remediation_engine import _authorized
    from app.services.device_vulnerability import device_matches, resolve_device
    query = db.query(models.RiskAssessment).filter(models.RiskAssessment.active.is_(True))
    if cve_id:
        query = query.filter(models.RiskAssessment.cve_id == cve_id)
    targets, unauthorized = [], 0
    for risk in query.order_by(models.RiskAssessment.priority_rank).limit(50).all():
        asset = db.get(models.LinuxAsset, risk.asset_id)
        if host and asset and asset.hostname != host and asset.ip_address != host:
            continue
        entry = {
            "risk_id": risk.id, "host": asset.hostname if asset else "",
            "cve_id": risk.cve_id, "package_name": risk.package_name,
            "risk_level": risk.risk_level, "review_status": risk.review_status,
            "authorized": _authorized(risk),
        }
        task = db.query(models.RemediationTask).filter_by(risk_id=risk.id).first()
        if task:
            entry["existing_task"] = {"id": task.id, "status": task.status}
        if entry["authorized"]:
            targets.append(entry)
        else:
            unauthorized += 1
    # 阶段六：设备 CVE 命中作为修复目标（authorized=False——设备修复必须走设备任务 Harness 审批）
    device_targets = []
    key = device_id or host
    if key:
        device = resolve_device(db, key)
        if device:
            for match in device_matches(db, device):
                if not match["affected"]:
                    continue
                device_targets.append({
                    "device": device.device_name, "device_id": device.device_id,
                    "cve_id": match["cve_id"], "component_name": match["component_name"],
                    "installed_version": match["installed_version"],
                    "fixed_version": match["fixed_version"],
                    "match_status": match["match_status"],
                    "applicability_source": match["applicability_source"],
                    "authorized": False,
                    "note": "设备修复必须经设备任务 Harness（审批 + 登记产物 + 回退）执行，LLM 无执行权。",
                })
    return {"authorized_targets": targets, "unauthorized_count": unauthorized,
            "device_targets": device_targets}


def tool_query_remediation_options(db: Session, cve_id: str, package_name: str = "",
                                   host: str = "") -> dict[str, Any]:
    """查询允许的修复动作白名单与包管理器命令模板（只读参考，不执行）。"""
    from app.services.remediation_engine import _package_command
    asset = db.query(models.LinuxAsset).filter(
        (models.LinuxAsset.hostname == host) | (models.LinuxAsset.ip_address == host)
    ).first() if host else None
    distribution = asset.distribution if asset else ""
    return {
        "action_whitelist": REMEDIATION_ACTION_WHITELIST,
        "package_command_template": _package_command(distribution, package_name or cve_id) if asset else "",
        "distribution": distribution,
        "openwrt_note": "OpenWrt 设备修复必须走设备任务 Harness（审批+登记产物），不生成直接命令",
        "execution_rule": "修复动作由平台白名单执行器执行；LLM 只能提出动作与参数，不能执行 shell。",
    }


def tool_query_verification_status(db: Session, cve_id: str = "", host: str = "") -> dict[str, Any]:
    """查询修复任务当前状态与可用的验证手段。"""
    query = db.query(models.RemediationTask)
    if cve_id:
        query = query.filter(models.RemediationTask.cve_id == cve_id)
    tasks = query.order_by(models.RemediationTask.id.desc()).limit(20).all()
    rows = []
    for task in tasks:
        asset = db.get(models.LinuxAsset, task.asset_id)
        if host and asset and asset.hostname != host:
            continue
        rows.append({
            "task_id": task.id, "cve_id": task.cve_id, "status": task.status,
            "current_version": task.current_version, "target_version": task.target_version,
            "verification_command": task.verification_command,
        })
    return {"count": len(rows), "tasks": rows,
            "verification_means": ["重新探测设备服务与组件", "复查 eBPF 运行时证据窗口", "修复任务状态流转"]}
