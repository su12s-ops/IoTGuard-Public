"""统一的只读证据查询模块。

原单角色 DeepSeek 工具调用机制中的查询能力迁移至此，供 AutoGen 四智能体
协同复核系统复用。本模块只做只读查询，绝不执行 Shell 命令、不修改任何数据。

提供的查询能力：
  - 资产清单（get_asset_inventory）
  - 漏洞上下文（get_vulnerability_context）
  - 运行时证据（get_runtime_evidence）
  - 修复任务上下文（get_remediation_context）
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.ebpf_event_collector import load_runtime_events


# ── 工具定义（供 LLM 声明工具 schema 使用，保持与旧机制一致的名称）──────

EVIDENCE_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_asset_inventory",
            "description": "读取纳管资产及已采集的软件包、服务数量。",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_vulnerability_context",
            "description": "按主机名或 CVE 查询版本命中、风险和漏洞情报。至少提供 hostname 或 cve_id 之一。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "cve_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_runtime_evidence",
            "description": "按主机名和可选软件包查询经过脱敏的运行时 eBPF/探针证据。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "package_name": {"type": "string"},
                },
                "required": ["hostname"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_remediation_context",
            "description": "按主机名或 CVE 查询修复任务、状态、前置条件和验证命令。",
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "cve_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
    },
]


# ── 只读查询实现 ──────────────────────────────────────────────────────────


def get_asset_inventory(db: Session) -> dict[str, Any]:
    assets = db.query(models.LinuxAsset).order_by(models.LinuxAsset.id).all()
    return {
        "assets": [
            {
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "os": f"{asset.os_name} {asset.os_version}".strip(),
                "distribution": asset.distribution,
                "exposure_level": asset.exposure_level,
                "business_level": asset.business_level,
                "package_count": len(asset.packages),
                "service_count": len(asset.services),
            }
            for asset in assets[:20]
        ]
    }


def get_vulnerability_context(db: Session, hostname: str = "", cve_id: str = "") -> dict[str, Any]:
    rows = []
    for match in db.query(models.VulnerabilityMatch).filter_by(affected=True).all():
        asset = db.get(models.LinuxAsset, match.asset_id)
        if not asset or (hostname and asset.hostname != hostname) or (cve_id and match.cve_id != cve_id):
            continue
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=match.cve_id).first()
        risk = db.query(models.RiskAssessment).filter_by(match_id=match.id).one_or_none()
        rows.append(
            {
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "cve_id": match.cve_id,
                "package_name": match.package_name,
                "installed_version": match.installed_version,
                "fixed_version": match.fixed_version,
                "match_reason": match.match_reason,
                "cvss_score": vuln.cvss_score if vuln else 0,
                "risk_score": (risk.final_score if risk else 0) or (risk.preliminary_score if risk else 0),
                "risk_level": risk.risk_level if risk else "",
                "decision": risk.decision if risk else "",
            }
        )
    return {"matches": rows[:20]}


def get_runtime_evidence(db: Session, hostname: str, package_name: str = "") -> dict[str, Any]:
    events = load_runtime_events(db=db, limit=500, hostname=hostname)
    if package_name:
        package = package_name.lower()
        events = [
            event
            for event in events
            if package in " ".join([event.get("process_name", ""), event.get("commandline", ""), event.get("rule", "")]).lower()
        ]
    # 阶段二：同步返回 SecurityEvidence 统一证据（进程/网络/文件三类）与进程树链。
    from app.services.security_evidence import build_process_tree, query_evidence, serialize_evidence

    evidence_rows = query_evidence(db, device_id=hostname, limit=60)
    if package_name:
        keyword = package_name.lower()
        evidence_rows = [row for row in evidence_rows
                         if keyword in f"{row.process} {row.commandline}".lower()]
    typed = {"process": [], "network": [], "file": []}
    for row in evidence_rows:
        typed.setdefault(row.evidence_type, []).append(serialize_evidence(row))
    tree = build_process_tree(db, device_id=hostname)
    return {
        "hostname": hostname,
        "event_count": len(events),
        "events": [
            {
                "event_id": event.get("id"),
                "source": event.get("source"),
                "category": event.get("category"),
                "severity": event.get("severity"),
                "rule": event.get("rule"),
                "process_name": event.get("process_name"),
                "commandline": event.get("commandline"),
                "timestamp": event.get("timestamp"),
            }
            for event in events[:30]
        ],
        "security_evidence": {
            "type_counts": {key: len(value) for key, value in typed.items()},
            "process_events": typed.get("process", [])[:10],
            "network_events": typed.get("network", [])[:10],
            "file_events": typed.get("file", [])[:10],
            "process_tree": tree.get("devices", {}).get(hostname, {}),
        },
    }


def get_remediation_context(db: Session, hostname: str = "", cve_id: str = "") -> dict[str, Any]:
    tasks = []
    for task in db.query(models.RemediationTask).order_by(models.RemediationTask.id).all():
        asset = db.get(models.LinuxAsset, task.asset_id)
        if not asset or (hostname and asset.hostname != hostname) or (cve_id and task.cve_id != cve_id):
            continue
        tasks.append(
            {
                "task_id": task.id,
                "hostname": asset.hostname,
                "cve_id": task.cve_id,
                "package_name": task.package_name,
                "status": task.status,
                "current_version": task.current_version,
                "target_version": task.target_version,
                "remediation_command": task.remediation_command,
                "verification_command": task.verification_command,
                "mitigation": task.mitigation,
            }
        )
    return {"tasks": tasks[:20]}


def run_evidence_tool(db: Session, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """按工具名分发到对应只读查询。未识别的工具直接抛错（拒绝执行）。"""
    if name == "get_asset_inventory":
        return get_asset_inventory(db)
    if name == "get_vulnerability_context":
        return get_vulnerability_context(db, **arguments)
    if name == "get_runtime_evidence":
        return get_runtime_evidence(db, **arguments)
    if name == "get_remediation_context":
        return get_remediation_context(db, **arguments)
    raise ValueError(f"Unsupported evidence tool requested: {name}")
