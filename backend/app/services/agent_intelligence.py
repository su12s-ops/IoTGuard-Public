from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.ebpf_event_collector import load_runtime_events
from app.services.reachability import analyze_reachability
from app.services.runtime_context import SERVICE_DEPENDENCIES, package_related_to_service, service_is_exposed, service_name
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.vulnerability_intelligence.service import get_source_bundle

SCENARIO_TEMPLATES = [
    {
        "id": "rce",
        "name": "远程代码执行",
        "keywords": ["remote code execution", "rce", "execute code", "command injection", "buffer overflow"],
        "weight": 24,
        "trigger": "网络暴露服务命中 RCE 类 CVE 时，优先级上调。",
    },
    {
        "id": "lpe",
        "name": "本地提权",
        "keywords": ["privilege escalation", "local user", "sudo", "setuid", "root privileges"],
        "weight": 16,
        "trigger": "需要本地交互或低权限账号时，结合 eBPF 执行行为验证。",
    },
    {
        "id": "data_leak",
        "name": "数据泄露",
        "keywords": ["information disclosure", "data leak", "sensitive", "exposure", "read arbitrary"],
        "weight": 18,
        "trigger": "影响 Web、数据库或加密组件时，关注真实访问路径。",
    },
    {
        "id": "availability",
        "name": "拒绝服务",
        "keywords": ["denial of service", "dos", "crash", "resource exhaustion"],
        "weight": 10,
        "trigger": "服务正在运行且承载业务时，优先级中等上调。",
    },
    {
        "id": "crypto",
        "name": "加密组件风险",
        "keywords": ["openssl", "certificate", "tls", "ssl", "cryptographic"],
        "weight": 12,
        "trigger": "底层加密库被上层网络服务调用时，形成跨软件影响链。",
    },
]


@dataclass
class RuntimeEvidence:
    status: str
    matched_events: list[dict[str, Any]]
    conclusion: str
    score: int
    confidence: float = 0
    strength: float = 0
    signals: dict[str, Any] | None = None


def _installed_packages(asset: models.LinuxAsset) -> dict[str, models.AssetPackage]:
    return {package.package_name: package for package in asset.packages}


def classify_scenario(vuln: models.VulnerabilityInfo, package_name: str) -> dict[str, Any]:
    text = " ".join(
        [
            vuln.title or "",
            vuln.description or "",
            vuln.cwe_id or "",
            package_name or "",
        ]
    ).lower()
    best = None
    for template in SCENARIO_TEMPLATES:
        hits = [keyword for keyword in template["keywords"] if keyword in text]
        if hits and (not best or len(hits) > len(best["matched_keywords"])):
            best = {**template, "matched_keywords": hits}
    if best:
        return best
    return {
        "id": "package_vulnerability",
        "name": "软件包漏洞",
        "matched_keywords": [package_name],
        "weight": 8,
        "trigger": "当前能确认包级版本命中，继续结合运行时证据判断真实可利用性。",
    }


def build_dependency_topology(db: Session) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(node_id: str, label: str, node_type: str, **extra: Any) -> None:
        nodes[node_id] = {"id": node_id, "label": label, "type": node_type, **extra}

    for asset in db.query(models.LinuxAsset).all():
        asset_id = f"asset:{asset.id}"
        add_node(asset_id, asset.hostname, "asset", ip_address=asset.ip_address)
        packages = _installed_packages(asset)

        for service in asset.services:
            service_name_value = service_name(service)
            service_id = f"service:{asset.id}:{service.port}:{service_name_value}"
            add_node(
                service_id,
                service_name_value,
                "service",
                port=service.port,
                protocol=service.protocol,
                exposed=service_is_exposed(service),
            )
            edges.append({"source": asset_id, "target": service_id, "relation": "runs"})

            candidate_packages = [service_name_value, *SERVICE_DEPENDENCIES.get(service_name_value, [])]
            for package_name in candidate_packages:
                if package_name in packages:
                    package_id = f"package:{asset.id}:{package_name}"
                    add_node(package_id, package_name, "package", version=packages[package_name].package_version)
                    edges.append({"source": service_id, "target": package_id, "relation": "uses"})

        affected_matches = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id, affected=True).all()
        for match in affected_matches:
            package_id = f"package:{asset.id}:{match.package_name}"
            add_node(package_id, match.package_name, "package", version=match.installed_version)
            cve_id = f"cve:{match.cve_id}"
            add_node(cve_id, match.cve_id, "cve", fixed_version=match.fixed_version)
            edges.append({"source": asset_id, "target": package_id, "relation": "has_package"})
            edges.append({"source": package_id, "target": cve_id, "relation": "affected_by"})

    return {"nodes": list(nodes.values()), "edges": edges}


def _runtime_matches(
    asset: models.LinuxAsset,
    package_name: str,
    services: list[models.AssetService],
    events: list[dict[str, Any]],
    scenario: dict[str, Any],
) -> RuntimeEvidence:
    related_services = [
        service
        for service in services
        if package_related_to_service(package_name, service_name(service))
    ]
    runtime = evaluate_runtime_evidence(asset, package_name, related_services, events, scenario_id=scenario.get("id", ""))
    return RuntimeEvidence(
        status=runtime["status"],
        matched_events=runtime["matched_events"],
        conclusion=runtime["conclusion"],
        score=int(runtime["adjustment_score"]),
        confidence=float(runtime["confidence"]),
        strength=float(runtime["strength_score"]),
        signals=runtime["signals"],
    )
    related_services = [
        service
        for service in services
        if _package_related_to_service(package_name, _service_name(service))
    ]
    service_names = {_service_name(service) for service in related_services}
    ports = {service.port for service in related_services if service.port}
    related_processes = {package_name}
    related_processes.update(service_names)
    for dependency_service_name in service_names:
        related_processes.update(SERVICE_DEPENDENCIES.get(dependency_service_name, []))

    direct_matched = []
    contextual_matched = []
    for event in events:
        event_host = (event.get("hostname") or "").lower()
        if event_host and event_host not in {asset.hostname.lower(), asset.ip_address.lower()}:
            continue
        process = (event.get("process_name") or "").lower()
        commandline = (event.get("commandline") or "").lower()
        parent_process = (event.get("parent_process") or "").lower()
        category = (event.get("category") or "").lower()
        raw_text = str(event.get("raw") or "").lower()
        event_port = int(event.get("port") or 0)
        privileged_context = (
            category in {"sensitive_file_access", "privilege_activity"}
            and (
                scenario.get("id") in {"lpe", "data_leak"}
                or package_name in {"sudo", "bash", "openssh-server", "ssh", "pam", "passwd", "shadow"}
            )
        )
        direct_package_match = (
            package_name.lower() in process
            or package_name.lower() in commandline
            or package_name.lower() in parent_process
            or package_name.lower() in raw_text
            or privileged_context
        )
        context_match = (
            any(name and name.lower() in process for name in service_names)
            or any(name and name.lower() in commandline for name in service_names)
            or any(name and name.lower() in parent_process for name in service_names)
            or any(name and name.lower() in raw_text for name in service_names)
            or event_port in ports
        )
        if direct_package_match:
            direct_matched.append(event)
        elif context_match:
            contextual_matched.append(event)

    if direct_matched:
        categories = Counter(event.get("category", "runtime_observation") for event in direct_matched)
        return RuntimeEvidence(
            status="verified",
            matched_events=direct_matched[:5],
            conclusion=f"eBPF 直接观察到 {len(direct_matched)} 条与该软件包或攻击场景相关的运行时证据，主要类型为 {dict(categories)}。",
            score=20,
        )
    if contextual_matched:
        categories = Counter(event.get("category", "runtime_observation") for event in contextual_matched)
        return RuntimeEvidence(
            status="contextual",
            matched_events=contextual_matched[:5],
            conclusion=f"eBPF 未直接命中该软件包，但观察到 {len(contextual_matched)} 条关联服务上下文证据，主要类型为 {dict(categories)}。",
            score=8,
        )
    if events:
        return RuntimeEvidence(
            status="not_observed",
            matched_events=[],
            conclusion="已接入 eBPF 事件，但暂未观察到该软件包或关联服务的实时行为。",
            score=-8,
        )
    return RuntimeEvidence(
        status="waiting",
        matched_events=[],
        conclusion="尚未上传 Falco/Tetragon eBPF 事件，当前仅使用资产、服务和依赖图谱进行静态推演。",
        score=0,
    )


def _dependency_path(asset: models.LinuxAsset, package_name: str, services: list[models.AssetService]) -> dict[str, Any]:
    return analyze_reachability(asset, package_name, services)
    exposed_services = []
    related_paths = []
    for service in services:
        service_name_value = service_name(service)
        if not package_related_to_service(package_name, service_name_value):
            continue
        path = [asset.hostname, f"{service_name_value}:{service.port}/{service.protocol}"]
        if service_name_value != package_name:
            path.append(package_name)
        path.append("CVE")
        related_paths.append(path)
        if service_is_exposed(service):
            exposed_services.append(
                {
                    "service_name": service_name_value,
                    "port": service.port,
                    "protocol": service.protocol,
                    "listen_address": service.listen_address,
                }
            )

    if related_paths:
        return {
            "status": "linked",
            "paths": related_paths,
            "exposed_services": exposed_services,
            "conclusion": "该漏洞包可通过上层服务或依赖关系追溯到实际运行组件。",
        }
    return {
        "status": "package_only",
        "paths": [[asset.hostname, package_name, "CVE"]],
        "exposed_services": [],
        "conclusion": "当前未发现明确上层服务调用链，暂按包级命中处理。",
    }


def build_behavior_chains(db: Session) -> list[dict[str, Any]]:
    events = load_runtime_events(db=db, limit=2000)
    risks = db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all()
    chains = []
    for risk in risks:
        asset = db.get(models.LinuxAsset, risk.asset_id)
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=risk.cve_id).first()
        intel = db.query(models.ThreatIntelSource).filter_by(cve_id=risk.cve_id).first()
        task = db.query(models.RemediationTask).filter_by(risk_id=risk.id).one_or_none()
        if not asset or not match or not vuln:
            continue

        services = list(asset.services)
        scenario = classify_scenario(vuln, match.package_name)
        topology = _dependency_path(asset, match.package_name, services)
        runtime = _runtime_matches(asset, match.package_name, services, events, scenario)
        exposure_bonus = 18 if topology["exposed_services"] else 0
        graph_bonus = 10 if topology["status"] == "linked" else 0
        dynamic_score = min(
            100,
            round(
                (risk.final_score if risk.final_score and risk.final_score > 0 else (risk.preliminary_score or 0))
                + scenario["weight"]
                + exposure_bonus
                + graph_bonus
                + runtime.score,
                2,
            ),
        )
        if dynamic_score >= 85:
            dynamic_level = "Critical"
        elif dynamic_score >= 70:
            dynamic_level = "High"
        elif dynamic_score >= 50:
            dynamic_level = "Medium"
        else:
            dynamic_level = "Low"

        cve_parts = risk.cve_id.split(":")
        source_bundle = get_source_bundle(
            db,
            risk.cve_id,
            release=cve_parts[1] if len(cve_parts) > 1 else "",
            package_name=match.package_name,
        )

        chains.append(
            {
                "chain_id": f"{asset.id}-{risk.cve_id}",
                "priority_rank": risk.priority_rank,
                "asset": {
                    "id": asset.id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "os": f"{asset.os_name} {asset.os_version}".strip(),
                    "distribution": asset.distribution,
                    "exposure_level": asset.exposure_level,
                    "business_level": asset.business_level,
                },
                "service_context": [
                    {
                        "service_name": service_name(service),
                        "port": service.port,
                        "protocol": service.protocol,
                        "listen_address": service.listen_address,
                        "is_public_exposed": service_is_exposed(service),
                    }
                    for service in services[:8]
                ],
                "package": {
                    "name": match.package_name,
                    "installed_version": match.installed_version,
                    "fixed_version": match.fixed_version,
                },
                "intelligence": {
                    "cve_id": risk.cve_id,
                    "source": vuln.source,
                    "cvss_score": vuln.cvss_score,
                    "epss_score": intel.epss_score if intel else 0,
                    "is_kev": bool(intel and intel.is_kev),
                    "references": vuln.references,
                    "sources": source_bundle,
                },
                "matching": {
                    "affected": match.affected,
                    "confidence": match.confidence,
                    "reason": match.match_reason,
                },
                "attack_scenario": scenario,
                "dependency_graph": topology,
                "runtime_verification": {
                    "status": runtime.status,
                    "conclusion": runtime.conclusion,
                    "confidence": runtime.confidence,
                    "strength": runtime.strength,
                    "signals": runtime.signals or {},
                    "matched_events": runtime.matched_events,
                },
                "risk": {
                    "base_score": risk.final_score if risk.final_score and risk.final_score > 0 else (risk.preliminary_score or 0),
                    "base_level": risk.risk_level if risk.final_score and risk.final_score > 0 else (risk.preliminary_level or "Low"),
                    "dynamic_score": dynamic_score,
                    "dynamic_level": dynamic_level,
                    "reason": risk.reason,
                    "decision": risk.decision if risk.final_score and risk.final_score > 0 else (risk.preliminary_decision or "monitor"),
                    "decision_reason": risk.decision_reason,
                    "explanation": {
                        "applicability_source": risk.applicability_source,
                        "ubuntu_priority": risk.ubuntu_priority,
                        "technical_severity": risk.technical_severity,
                        "likelihood_level": risk.likelihood_level,
                        "known_exploited": bool(risk.known_exploited),
                    },
                    "status": {
                        "affected": risk.affected_status,
                        "reachable": risk.reachable_status,
                        "runtime": risk.runtime_status,
                        "exploitability": risk.exploitability_status,
                    },
                    "adjustment": {
                        "scenario": scenario["weight"],
                        "dependency_graph": graph_bonus,
                        "exposure": exposure_bonus,
                        "runtime": runtime.score,
                    },
                },
                "remediation": {
                    "command": task.remediation_command if task else "",
                    "verification": task.verification_command if task else "",
                    "status": task.status if task else "pending",
                },
            }
        )
    chains.sort(key=lambda item: item["risk"]["dynamic_score"], reverse=True)
    for index, chain in enumerate(chains, 1):
        chain["priority_rank"] = index
    return chains


def build_four_agent_workflow(db: Session) -> dict[str, Any]:
    """总览大屏数据：拓扑、行为链 + 真实四智能体协同复核状态（非静态卡片）。"""
    import json

    events = load_runtime_events(db=db, limit=2000)
    metrics = {
        "assets": db.query(models.LinuxAsset).count(),
        "packages": db.query(models.AssetPackage).count(),
        "services": db.query(models.AssetService).count(),
        "vulnerabilities": db.query(models.VulnerabilityInfo).count(),
        "matches": db.query(models.VulnerabilityMatch).count(),
        "affected_matches": db.query(models.VulnerabilityMatch).filter_by(affected=True).count(),
        "risks": db.query(models.RiskAssessment).count(),
        "tasks": db.query(models.RemediationTask).count(),
        "ebpf_events": len(events),
    }
    topology = build_dependency_topology(db)
    chains = build_behavior_chains(db)

    # ── 真实复核状态：从最近一次 AnalysisReport 读取 ──
    latest_report = (
        db.query(models.AnalysisReport)
        .order_by(models.AnalysisReport.id.desc())
        .first()
    )
    review_payload = _review_agent_status(latest_report)

    agents = [
        {
            "id": "evidence_audit_agent",
            "name": "Evidence Audit Agent",
            "goal": "审核数据覆盖完整性与质量，输出数据盲区与补采要求。",
            "status": review_payload["agents"]["evidence_audit"]["status"],
            "confidence": review_payload["agents"]["evidence_audit"]["confidence"],
            "output": review_payload["agents"]["evidence_audit"]["output"],
        },
        {
            "id": "impact_assessment_agent",
            "name": "漏洞影响研判智能体",
            "goal": "评估漏洞实际影响与优先级，给出确认/升级/降级意见。",
            "status": review_payload["agents"]["impact_assessment"]["status"],
            "confidence": review_payload["agents"]["impact_assessment"]["confidence"],
            "output": review_payload["agents"]["impact_assessment"]["output"],
        },
        {
            "id": "exposure_runtime_agent",
            "name": "Exposure & Runtime Agent",
            "goal": "验证运行时证据关联强度，识别矛盾证据。",
            "status": review_payload["agents"]["exposure_runtime"]["status"],
            "confidence": review_payload["agents"]["exposure_runtime"]["confidence"],
            "output": review_payload["agents"]["exposure_runtime"]["output"],
        },
        {
            "id": "decision_coordinator_agent",
            "name": "处置决策协调智能体",
            "goal": "综合意见输出唯一结构化裁定（确认/升级/降级/证据不足）。",
            "status": review_payload["agents"]["decision_coordinator"]["status"],
            "confidence": review_payload["agents"]["decision_coordinator"]["confidence"],
            "output": review_payload["agents"]["decision_coordinator"]["output"],
        },
    ]
    return {
        "metrics": metrics,
        "agents": agents,
        "workflow_edges": [
            {"from": "evidence_audit_agent", "to": "decision_coordinator_agent"},
            {"from": "impact_assessment_agent", "to": "decision_coordinator_agent"},
            {"from": "exposure_runtime_agent", "to": "decision_coordinator_agent"},
        ],
        "topology": topology,
        "top_chains": chains[:5],
        "review": review_payload["summary"],
        "api_sequence": [
            "数据质量审核智能体：审核资产/情报/运行时数据覆盖，输出盲区与补采要求。",
            "漏洞影响研判智能体：评估漏洞实际影响与优先级，给出确认/升级/降级意见。",
            "运行时归因验证智能体：验证 eBPF/探针证据关联强度与矛盾证据。",
            "处置决策协调智能体：综合意见输出唯一结构化裁定，驱动最终风险与修复任务。",
        ],
    }


def _review_agent_status(report) -> dict[str, Any]:
    """从复核报告解析各智能体状态与最终裁定摘要（v2：agent_executions_json 为主）。"""
    import json

    agents = {
        "evidence_audit": {"status": "pending", "confidence": 0, "output": "", "error": "", "duration_ms": 0},
        "impact_assessment": {"status": "pending", "confidence": 0, "output": "", "error": "", "duration_ms": 0},
        "exposure_runtime": {"status": "pending", "confidence": 0, "output": "", "error": "", "duration_ms": 0},
        "decision_coordinator": {"status": "pending", "confidence": 0, "output": "", "error": "", "duration_ms": 0},
    }
    summary = {"status": "none", "verdict": "", "confidence": 0, "human_review_required": False, "error": ""}

    if report is None:
        return {"agents": agents, "summary": summary}

    summary["status"] = report.status
    summary["error"] = report.error or ""
    summary["human_review_required"] = bool(getattr(report, "human_review_object_count", 0))
    try:
        verdict = json.loads(report.verdict_json or "{}")
    except json.JSONDecodeError:
        verdict = {}

    # v2: 读取 object_verdicts 统计
    object_verdicts = verdict.get("object_verdicts", [])
    if object_verdicts and isinstance(object_verdicts, list):
        confidences = [v.get("confidence", 0) for v in object_verdicts if isinstance(v, dict)]
        summary["confidence"] = round(sum(confidences) / len(confidences) * 100) if confidences else 0
        summary["human_review_required"] = any(v.get("human_review_required") for v in object_verdicts)
        summary["verdict"] = verdict.get("overall_summary", "")[:200]
    elif verdict:
        # 旧版 single-verdict 格式
        summary["verdict"] = verdict.get("verdict", "")
        summary["confidence"] = verdict.get("confidence", 0)
        summary["human_review_required"] = bool(verdict.get("human_review_required", False))

    try:
        opinions = json.loads(report.opinions_json or "{}")
    except json.JSONDecodeError:
        opinions = {}

    try:
        agent_execs = json.loads(report.agent_executions_json or "{}")
    except json.JSONDecodeError:
        agent_execs = {}

    agent_id_map = [
        ("evidence_audit", "evidence_audit_agent", "evidence_audit"),
        ("impact_assessment", "impact_assessment_agent", "impact_assessment"),
        ("exposure_runtime", "exposure_runtime_agent", "exposure_runtime"),
        ("decision_coordinator", "decision_coordinator_agent", "coordinator"),
    ]

    for key, agent_id, event_field in agent_id_map:
        exec_info = agent_execs.get(agent_id, {})
        exec_status = exec_info.get("status", "pending")
        outputs: list[dict[str, Any]] = []
        if isinstance(exec_info.get("event_results"), list):
            outputs.extend(item for item in exec_info["event_results"] if isinstance(item, dict))
        if isinstance(opinions, list):
            outputs.extend(
                item[event_field]
                for item in opinions
                if isinstance(item, dict) and isinstance(item.get(event_field), dict)
            )
        legacy_output = opinions.get(agent_id, "") if isinstance(opinions, dict) else ""
        unique_outputs: list[dict[str, Any]] = []
        seen_outputs: set[str] = set()
        for item in outputs:
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            if marker not in seen_outputs:
                seen_outputs.add(marker)
                unique_outputs.append(item)

        summary_lines: list[str] = []
        for item in unique_outputs[:3]:
            object_id = item.get("object_id", "事件")
            result_status = (
                item.get("evidence_quality")
                or item.get("impact_status")
                or item.get("risk_direction")
                or "/".join(filter(None, [item.get("exposure_status"), item.get("runtime_status")]))
            )
            reason = str(item.get("reason") or "").strip()
            summary_lines.append(f"{object_id} [{result_status or '已完成'}] {reason}".strip())
        output = "\n".join(summary_lines) or str(legacy_output or "")
        confidences = [float(item.get("confidence", 0) or 0) for item in unique_outputs]
        output_confidence = round(sum(confidences) / len(confidences) * 100) if confidences else 0

        if exec_status == "completed":
            agents[key]["status"] = "completed"
            agents[key]["confidence"] = output_confidence or 85
            agents[key]["output"] = output[:600]
        elif exec_status == "failed":
            agents[key]["status"] = "failed"
            agents[key]["confidence"] = output_confidence or 20
            agents[key]["output"] = output[:600]
            agents[key]["error"] = exec_info.get("error", "")
        elif exec_status == "running":
            agents[key]["status"] = "running"
            agents[key]["confidence"] = 50
        else:
            # pending — 回退检查 opinions
            has_output = bool(output.strip()) and output.strip() != "{}"
            if has_output:
                agents[key]["status"] = "completed"
                agents[key]["confidence"] = 75
            else:
                agents[key]["status"] = "pending"
                agents[key]["confidence"] = 10
            agents[key]["output"] = output[:600] if has_output else ""

        agents[key]["duration_ms"] = exec_info.get("duration_ms", 0)
        agents[key]["error"] = agents[key].get("error", "") or exec_info.get("error", "")

    # 全局失败/跳过覆盖
    if report.status == "running":
        for key in agents:
            if agents[key]["status"] == "pending":
                agents[key]["status"] = "running"
    elif report.status == "failed":
        for key in agents:
            if agents[key]["status"] in ("pending", "running"):
                agents[key]["status"] = "failed"
    elif report.status == "skipped":
        for key in agents:
            agents[key]["status"] = "skipped"

    return {"agents": agents, "summary": summary}


def build_business_reconstruction(db: Session) -> dict[str, Any]:
    chains = build_behavior_chains(db)
    grouped: dict[str, list[str]] = defaultdict(list)
    for chain in chains:
        hostname = chain["asset"]["hostname"]
        package_name = chain["package"]["name"]
        command = chain["remediation"]["command"]
        actions = [
            f"优先处理 {package_name} 对应的 {chain['attack_scenario']['name']} 场景，动态风险为 {chain['risk']['dynamic_level']}。",
            chain["dependency_graph"]["conclusion"],
            chain["runtime_verification"]["conclusion"],
        ]
        if command:
            actions.append(f"执行修复命令：{command}")
        for action in actions:
            if action not in grouped[hostname]:
                grouped[hostname].append(action)
    risk_dist = Counter(chain["risk"]["dynamic_level"] for chain in chains)
    return {
        "summary": {
            "affected_assets": len(grouped),
            "behavior_chains": len(chains),
            "risk_distribution": dict(risk_dist),
        },
        "assets": [{"hostname": hostname, "actions": actions} for hostname, actions in grouped.items()],
    }
