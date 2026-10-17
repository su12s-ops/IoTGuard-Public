"""逐风险事件证据包构建（确定性，无 LLM）。

从旧 System B 迁出的通用证据组装能力：聚合资产、漏洞 advisory、多源情报、
网络可达性、传感器覆盖、eBPF 统一证据与运行时事件，形成带 evidence_id 的
只读证据包。消费方：统一编排器证据准备节点、设备 Harness inspect_evidence。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import models
from app.services.ebpf_event_collector import load_runtime_events
from app.services.reachability import analyze_reachability
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.vulnerability_intelligence.service import get_source_bundle


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceItem(StrictModel):
    evidence_id: str
    evidence_type: str
    source: str
    timestamp: str
    reliability: Literal["direct", "derived", "contextual", "unknown"]
    content: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class EvidencePacket(StrictModel):
    object_id: str
    risk_id: int
    match_id: int
    asset: dict[str, Any]
    vulnerability: dict[str, Any]
    package_match: dict[str, Any]
    service_context: dict[str, Any]
    network_exposure: dict[str, Any]
    runtime_evidence: list[EvidenceItem]
    threat_intelligence: dict[str, Any]
    intelligence_sources: dict[str, Any] = Field(default_factory=dict)
    data_quality: dict[str, Any]
    baseline: dict[str, Any]
    evidence_items: list[EvidenceItem]

    @property
    def evidence_ids(self) -> set[str]:
        return {item.evidence_id for item in self.evidence_items}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_evidence_packet(db: Session, risk: models.RiskAssessment) -> EvidencePacket:
    asset = db.get(models.LinuxAsset, risk.asset_id)
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    vulnerability = db.query(models.VulnerabilityInfo).filter_by(cve_id=risk.cve_id).one_or_none()
    intel = db.query(models.ThreatIntelSource).filter_by(cve_id=risk.cve_id).one_or_none()
    if not asset or not match or not vulnerability:
        raise ValueError("risk event is missing exact asset, match, or vulnerability data")

    now = _utc_now()
    services = list(asset.services)
    reachability = analyze_reachability(asset, match.package_name, services)
    runtime = evaluate_runtime_evidence(
        asset, match.package_name, services, load_runtime_events(db=db, limit=5000)
    )
    items: list[EvidenceItem] = []

    def add(
        suffix: str,
        evidence_type: str,
        source: str,
        reliability: str,
        content: dict,
        summary: str = "",
        timestamp: str | None = None,
    ):
        item = EvidenceItem(
            evidence_id=f"EV-{risk.id}-{suffix}",
            evidence_type=evidence_type,
            source=source,
            timestamp=timestamp or now,
            reliability=reliability,
            content=content,
            summary=summary,
        )
        items.append(item)
        return item

    add(
        "PKG", "package_version", "asset_collector", "direct",
        {
            "package_name": match.package_name,
            "installed_version": match.installed_version,
            "fixed_version": match.fixed_version,
            "match_status": match.match_status,
            "reason_code": match.reason_code,
        },
        match.match_reason,
    )
    add(
        "VULN", "vulnerability_advisory", vulnerability.source or "unknown", "contextual",
        {
            "cve_id": vulnerability.cve_id,
            "cvss_score": vulnerability.cvss_score,
            "status": match.match_status,
            "last_modified_date": vulnerability.last_modified_date,
        },
        vulnerability.title,
    )
    parts = vulnerability.cve_id.split(":")
    release = parts[1] if len(parts) > 1 else ""
    source_bundle = get_source_bundle(
        db,
        vulnerability.cve_id,
        release=release,
        package_name=match.package_name,
    )
    source_labels = {
        "canonical": "Canonical Ubuntu applicability",
        "nvd": "NVD technical severity",
        "cisa_kev": "CISA known exploitation",
        "epss": "FIRST exploitation probability",
        "kylin": "Kylin OS package applicability",
    }
    for source_name, source_data in source_bundle.items():
        add(
            f"SRC-{source_name.upper()}",
            "vulnerability_intelligence_source",
            source_name,
            "direct" if source_name == "canonical" else "contextual",
            {
                "status": source_data.get("status", "unavailable"),
                "value": source_data.get("value", {}),
                "source_updated_at": source_data.get("source_updated_at", ""),
                "fetched_at": source_data.get("fetched_at", ""),
                "error_message": source_data.get("error_message", ""),
            },
            source_labels[source_name],
            source_data.get("source_updated_at") or source_data.get("fetched_at") or now,
        )
    add(
        "NET", "network_exposure", "asset_collector", "derived",
        reachability,
        reachability.get("reason") or reachability.get("conclusion", ""),
    )
    from app.services.runtime_telemetry import coverage
    sensor_coverage = coverage(db, asset.id)
    add("COVERAGE", "sensor_coverage", "collector_heartbeat", "contextual", sensor_coverage,
        "心跳和采集范围不等同于漏洞不存在；运行时关联不等同于已利用。")
    if asset.distribution == "openwrt":
        advisory = db.query(models.OpenWrtAdvisory).filter_by(
            cve_id=vulnerability.cve_id, package_name=match.package_name, release=asset.os_version
        ).one_or_none()
        add("OPENWRT", "vendor_applicability", "operator_supplied_openwrt_advisory", "contextual",
            {"source_url": advisory.source_url if advisory else "", "release": asset.os_version,
             "affected_versions": json.loads(advisory.affected_versions_json) if advisory else [],
             "fixed_versions": json.loads(advisory.fixed_versions_json) if advisory else [],
             "content_verified_automatically": False}, "记录由操作人员依据官方公告整理，需结合原文核对。")
    # SecurityEvidence 统一证据（eBPF 进程/网络/文件三类监控）进入智能体证据包。
    from app.services.security_evidence import build_process_tree, query_evidence
    device_evidence = query_evidence(db, device_id=asset.hostname, limit=200)
    if device_evidence:
        type_counts = {"process": 0, "network": 0, "file": 0}
        for row in device_evidence:
            type_counts[row.evidence_type] = type_counts.get(row.evidence_type, 0) + 1
        tree = build_process_tree(db, device_id=asset.hostname)
        device_tree = tree.get("devices", {}).get(asset.hostname, {})
        add(
            "SE-RUN", "security_evidence", "ebpf_security_evidence", "direct",
            {
                "type_counts": type_counts,
                "process_tree_max_depth": device_tree.get("max_depth", 0),
                "service_shell_chains": device_tree.get("service_shell_chains", []),
                "recent_process_events": [
                    {"process": row.process, "pid": row.pid, "ppid": row.ppid,
                     "commandline": row.commandline, "timestamp": row.timestamp}
                    for row in device_evidence if row.evidence_type == "process"
                ][:10],
                "recent_network_events": [
                    {"process": row.process, "destination": f"{row.destination_ip}:{row.destination_port}",
                     "timestamp": row.timestamp}
                    for row in device_evidence if row.evidence_type == "network"
                ][:10],
                "watched_file_events": [
                    {"process": row.process, "operation": row.operation, "file_path": row.file_path,
                     "severity": row.severity, "timestamp": row.timestamp}
                    for row in device_evidence if row.evidence_type == "file"
                ][:10],
                "evidence_note": "eBPF 统一证据为真实内核事件归一化结果；证据存在不等于漏洞被利用。",
            },
            f"eBPF 统一证据：进程 {type_counts.get('process', 0)} / 网络 {type_counts.get('network', 0)} / 文件 {type_counts.get('file', 0)} 条",
        )
    runtime_items: list[EvidenceItem] = []
    for index, event in enumerate(runtime.get("matched_events", [])[:20], 1):
        runtime_items.append(add(
            f"RT-{index}", "runtime_event", event.get("source", "runtime_probe"), "contextual",
            {
                "event_id": event.get("id"),
                "process_name": event.get("process_name", ""),
                "commandline": event.get("commandline", ""),
                "category": event.get("category", ""),
                "severity": event.get("severity", ""),
                "occurred_at": event.get("timestamp", ""),
                "process_id": event.get("process_id", 0),
                "process_exec_id": event.get("process_exec_id", ""),
                "parent_exec_id": event.get("parent_exec_id", ""),
                "sensor_id": event.get("sensor_id", ""),
                "exploitation_confirmed": False,
            },
            event.get("risk_signal", ""),
        ))

    data_quality = {
        "installed_version_present": bool(match.installed_version),
        "fixed_version_present": bool(match.fixed_version),
        "match_status": match.match_status,
        "reason_code": match.reason_code,
        "inventory_complete": bool(asset.inventory_complete),
        "runtime_coverage": sensor_coverage["status"],
    }
    return EvidencePacket(
        object_id=f"risk-{risk.id}",
        risk_id=risk.id,
        match_id=match.id,
        asset={
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "distribution": asset.distribution,
            "os_version": asset.os_version,
            "exposure_level": asset.exposure_level,
            "business_level": asset.business_level,
            "updated_at": str(asset.updated_at or ""),
            "device_type": asset.device_type,
            "device_model": asset.device_model,
            "firmware_version": asset.firmware_version,
            "identity_source": asset.identity_source,
            "capabilities": json.loads(asset.capabilities_json or "{}"),
        },
        vulnerability={
            "cve_id": vulnerability.cve_id,
            "title": vulnerability.title,
            "description": vulnerability.description,
            "cvss_score": vulnerability.cvss_score,
            "vendor_severity": vulnerability.cvss_severity,
            "published_date": vulnerability.published_date,
            "last_modified_date": vulnerability.last_modified_date,
            "source": vulnerability.source,
        },
        package_match={
            "match_id": match.id,
            "package_name": match.package_name,
            "installed_version": match.installed_version,
            "fixed_version": match.fixed_version,
            "match_status": match.match_status,
            "affected": match.affected,
            "reason_code": match.reason_code,
            "reason": match.match_reason,
            "confidence": match.confidence,
        },
        service_context={
            "services": [
                {
                    "service_name": service.service_name,
                    "port": service.port,
                    "protocol": service.protocol,
                    "listen_address": service.listen_address,
                    "process_name": service.process_name,
                    "public": bool(service.is_public_exposed),
                }
                for service in services
            ]
        },
        network_exposure=reachability,
        runtime_evidence=runtime_items,
        threat_intelligence={
            "is_kev": bool(intel and intel.is_kev),
            "epss_score": float(intel.epss_score if intel else 0),
            "exploit_status": intel.exploit_status if intel else "unknown",
            "sources": source_bundle,
        },
        intelligence_sources=source_bundle,
        data_quality=data_quality,
        baseline={
            "preliminary_score": risk.preliminary_score,
            "preliminary_level": risk.preliminary_level,
            "preliminary_decision": risk.preliminary_decision,
            "preliminary_reason": risk.preliminary_reason,
        },
        evidence_items=items,
    )
