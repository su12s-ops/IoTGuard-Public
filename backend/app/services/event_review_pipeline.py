"""Per-risk, typed, fail-safe expert review pipeline used for final delivery."""

from __future__ import annotations

import asyncio
import json
import re
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from app import models
from app.config import DATA_DIR, DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
from app.services.ebpf_event_collector import load_runtime_events
from app.services.reachability import analyze_reachability
from app.services.risk_engine import risk_level
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.vulnerability_intelligence.service import get_source_bundle


BATCH_SIZE = 5
MAX_RETRIES = 1
PIPELINE_VERSION = "per-risk-expert-audit-v3"
ANALYSIS_RUN_DIR = DATA_DIR / "analysis_runs"

AGENT_EVIDENCE = "evidence_audit_agent"
AGENT_IMPACT = "impact_assessment_agent"
AGENT_RUNTIME = "exposure_runtime_agent"
AGENT_COORDINATOR = "decision_coordinator_agent"
AGENT_DATA_QUALITY = AGENT_EVIDENCE  # legacy import compatibility
SPECIALIST_AGENTS = [AGENT_EVIDENCE, AGENT_IMPACT, AGENT_RUNTIME]
ALL_AGENTS = SPECIALIST_AGENTS + [AGENT_COORDINATOR]

DIRECTION_ADJUSTMENTS = {
    "maintain": 0,
    "upgrade_minor": 10,
    "upgrade_major": 20,
    "downgrade_minor": -10,
    "downgrade_major": -20,
}

REVIEWABLE_STATUSES = {"candidate", "reanalysis_required"}

_STAGE_RANK = {
    "candidate_preflight": 0,
    "evidence_preparing": 1,
    "agent_reviewing": 2,
    "conflict_review": 3,
    "coordinator_review": 4,
    "audit_policy": 5,
}


class _RunProgressTracker:
    """Aggregate concurrent per-event agent work into monotonic run progress."""

    def __init__(self, total_events: int, callback=None):
        self.total_events = max(1, total_events)
        self.callback = callback
        self.event_states: dict[tuple[str, str], dict[str, Any]] = {}
        self.processed_events = 0
        self.stage_rank = 0
        self.percent = 0

    def _agent_summary(self) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for agent_name in ALL_AGENTS:
            states = [
                self.event_states.get((object_id, agent_name))
                for object_id in {key[0] for key in self.event_states}
            ]
            states = [state for state in states if state]
            terminal = [state for state in states if state.get("status") in {"completed", "failed", "skipped"}]
            if any(state.get("status") == "running" for state in states):
                status = "running"
            elif len(terminal) >= self.total_events:
                status = "failed" if any(state.get("status") in {"failed", "skipped"} for state in terminal) else "completed"
            elif terminal:
                status = "running"
            else:
                status = "pending"
            errors = [str(state.get("error")) for state in terminal if state.get("error")]
            summary[agent_name] = {
                "status": status,
                "attempts": sum(int(state.get("attempts") or 0) for state in terminal),
                "duration_ms": sum(int(state.get("duration_ms") or 0) for state in terminal),
                "output_valid": len(terminal) >= self.total_events and all(state.get("output_valid") for state in terminal),
                "opinion_count": sum(bool(state.get("output_valid")) for state in terminal),
                "processed_event_count": len(terminal),
                "total_event_count": self.total_events,
                "error": "; ".join(errors),
            }
        return summary

    def emit(
        self,
        stage: str,
        *,
        object_id: str = "",
        message: str = "",
        percent: int = 0,
        agent_name: str = "",
        agent_status: str = "",
        execution: dict[str, Any] | None = None,
        processed_events: int | None = None,
    ) -> None:
        if agent_name and object_id:
            state = {"status": agent_status or "running"}
            if execution:
                state.update({
                    key: execution.get(key)
                    for key in ("status", "attempts", "duration_ms", "output_valid", "error")
                })
            self.event_states[(object_id, agent_name)] = state
        if processed_events is not None:
            self.processed_events = max(self.processed_events, processed_events)
        rank = _STAGE_RANK.get(stage, self.stage_rank)
        if rank >= self.stage_rank:
            self.stage_rank = rank
            current_stage = stage
        else:
            current_stage = next(
                (name for name, value in _STAGE_RANK.items() if value == self.stage_rank),
                stage,
            )
        terminal_actions = sum(
            state.get("status") in {"completed", "failed", "skipped"}
            for state in self.event_states.values()
        )
        action_percent = 15 + round(70 * terminal_actions / max(1, self.total_events * len(ALL_AGENTS)))
        self.percent = max(self.percent, min(99, max(percent, action_percent)))
        if self.callback:
            self.callback(
                current_stage=current_stage,
                agent_executions=self._agent_summary(),
                processed_object_count=self.processed_events,
                current_object_id=object_id,
                progress_message=message,
                progress_percent=self.percent,
            )


def _batches(items: list[Any], size: int = BATCH_SIZE):
    for offset in range(0, len(items), size):
        yield items[offset: offset + size]


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


class EvidenceAuditResult(StrictModel):
    object_id: str
    evidence_quality: Literal["sufficient", "partial", "insufficient", "conflicting"]
    confidence: float = Field(ge=0, le=1)
    valid_evidence_ids: list[str] = Field(default_factory=list)
    conflicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str


class ImpactAssessmentResult(StrictModel):
    object_id: str
    impact_status: Literal[
        "confirmed_affected", "potentially_affected", "not_affected", "insufficient_evidence"
    ]
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    counter_evidence_ids: list[str] = Field(default_factory=list)
    required_conditions: list[str] = Field(default_factory=list)
    conditions_met: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str


class ExposureRuntimeResult(StrictModel):
    object_id: str
    exposure_status: Literal[
        "internet_reachable", "internal_reachable", "local_only", "unreachable", "unknown"
    ]
    runtime_status: Literal["verified", "contextual", "not_observed", "waiting"]
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str


class ConflictItem(StrictModel):
    code: str
    description: str
    involved_agents: list[str]


class ConflictResult(StrictModel):
    has_major_conflict: bool = False
    conflicts: list[ConflictItem] = Field(default_factory=list)
    rereview_count: int = Field(default=0, ge=0, le=1)
    unresolved: bool = False


class CoordinatorResult(StrictModel):
    object_id: str
    impact_status: Literal[
        "confirmed_affected", "potentially_affected", "not_affected", "insufficient_evidence"
    ]
    risk_direction: Literal[
        "maintain", "upgrade_minor", "upgrade_major", "downgrade_minor", "downgrade_major"
    ]
    recommended_priority: Literal["critical", "high", "medium", "low"]
    recommended_action: Literal[
        "immediate_fix", "scheduled_fix", "mitigate", "monitor", "collect_more_evidence", "defer"
    ]
    confidence: float = Field(ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    requested_tools: list[Literal["collect_inventory", "inspect_runtime", "inspect_evidence", "manual_review"]] = Field(default_factory=list, max_length=4)
    reason: str


class AuditPolicyDecision(StrictModel):
    status: Literal["auto_confirmed", "pending_human_review"]
    reasons: list[str]
    adjustment: int
    final_score: float | None
    final_level: str | None


RESULT_SCHEMAS = {
    AGENT_EVIDENCE: EvidenceAuditResult,
    AGENT_IMPACT: ImpactAssessmentResult,
    AGENT_RUNTIME: ExposureRuntimeResult,
    AGENT_COORDINATOR: CoordinatorResult,
}


EVIDENCE_PROMPT = """你是 Evidence Audit Agent。只审核这一条风险事件的证据质量，不评分。
输出必须严格匹配给定 JSON schema。引用 evidence_id；识别完整性、时效性、可靠性、反证和缺失事实。"""

IMPACT_PROMPT = """你是 Impact Assessment Agent。只判断这一条资产/软件包/CVE 是否处于影响范围。
输入故意不包含 preliminary_score/preliminary_decision，不能被规则分数锚定。严格输出 JSON schema。"""

RUNTIME_PROMPT = """你是 Exposure & Runtime Agent。只判断业务、网络和运行时路径。
not_observed 不代表漏洞不存在；runtime event 也不代表已证明 CVE 被成功利用。运行时证据只影响紧迫度、优先级和证据强度。严格输出 JSON schema。"""

COORDINATOR_PROMPT = """你是 Decision Coordinator Agent。读取一条事件的规则 baseline、三个专家结构化结果和冲突结果。
你只给出离散 risk_direction 与处置建议，不能给自由数值、不能决定是否自动确认、不能授予修复权限。
证据不足时可在 requested_tools 中选择补采清单、查看运行时、重建证据包或人工复核；不得生成 shell 命令。
OpenWrt 必须依据对应固件的厂商适用性记录，不能套用 Ubuntu 修复版本。严格输出 JSON schema。"""


T = TypeVar("T", bound=StrictModel)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _object_id(risk: models.RiskAssessment) -> str:
    return f"risk-{risk.id}"


def _legacy_object_id(risk: models.RiskAssessment) -> str:
    return f"asset-{risk.asset_id}-{risk.cve_id}"


def _configured() -> bool:
    return bool(DEEPSEEK_API_KEY)


def _create_model_client():
    from autogen_core.models import ModelInfo
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    return OpenAIChatCompletionClient(
        model=DEEPSEEK_MODEL,
        api_key=DEEPSEEK_API_KEY,
        base_url=DEEPSEEK_BASE_URL.rstrip("/"),
        temperature=0.1,
        model_info=ModelInfo(
            vision=False,
            function_calling=True,
            json_output=True,
            structured_output=True,
            family="deepseek",
        ),
    )


def _extract_json(text: str) -> dict[str, Any] | None:
    if not text or not text.strip():
        return None
    value = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    for candidate in (value, re.sub(r",(\s*[}\]])", r"\1", value)):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{.*\}", value, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _write_run_snapshot(run_id: str, payload: dict[str, Any]) -> Path:
    ANALYSIS_RUN_DIR.mkdir(parents=True, exist_ok=True)
    target = ANALYSIS_RUN_DIR / f"{run_id}.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps({"run_id": run_id, "updated_at": _utc_now(), **payload}, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def _validate_evidence_ids(result: StrictModel, packet: EvidencePacket) -> None:
    payload = result.model_dump()
    ids: list[str] = []
    for field in (
        "valid_evidence_ids", "conflicting_evidence_ids", "supporting_evidence_ids", "counter_evidence_ids"
    ):
        ids.extend(payload.get(field, []))
    unknown = sorted(set(ids) - packet.evidence_ids)
    if unknown:
        raise ValueError(f"unknown evidence_id: {unknown}")


async def _call_model_json(prompt: str, context: dict[str, Any], model_client, agent_name: str) -> tuple[dict | None, str]:
    from autogen_core.models import UserMessage

    full_prompt = (
        f"{prompt}\n\nJSON Schema:\n{json.dumps(RESULT_SCHEMAS[agent_name].model_json_schema(), ensure_ascii=False)}"
        f"\n\nEvent input:\n{json.dumps(context, ensure_ascii=False, default=str)}"
    )
    try:
        response = await model_client.create(
            messages=[UserMessage(content=full_prompt, source=agent_name)], json_output=True
        )
        raw = response.content if hasattr(response, "content") else str(response)
        text = str(raw or "").strip()
        return _extract_json(text), text
    except Exception as exc:
        return None, f"LLM API error: {exc}"


async def _run_typed_agent(
    agent_name: str,
    prompt: str,
    context: dict[str, Any],
    packet: EvidencePacket,
    model_client,
) -> tuple[StrictModel | None, dict[str, Any]]:
    schema = RESULT_SCHEMAS[agent_name]
    started = time.perf_counter()
    last_raw = ""
    last_error = ""
    for attempt in range(MAX_RETRIES + 1):
        parsed, raw = await _call_model_json(prompt, context, model_client, agent_name)
        last_raw = raw
        try:
            if parsed is None:
                raise ValueError("response is not a JSON object")
            result = schema.model_validate(parsed)
            if result.object_id != packet.object_id:
                raise ValueError(f"object_id mismatch: {result.object_id}")
            _validate_evidence_ids(result, packet)
            return result, {
                "agent_name": agent_name,
                "status": "completed",
                "parse_status": "valid",
                "attempts": attempt + 1,
                "retry_count": attempt,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "output_valid": True,
                "output": result.model_dump(),
                "raw_text": raw,
                "error": "",
            }
        except (ValidationError, ValueError) as exc:
            last_error = str(exc)
            context = {**context, "retry_instruction": f"Previous output invalid: {last_error}"}
    return None, {
        "agent_name": agent_name,
        "status": "failed",
        "parse_status": "invalid",
        "attempts": MAX_RETRIES + 1,
        "retry_count": MAX_RETRIES,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "output_valid": False,
        "output": None,
        "raw_text": last_raw,
        "error": last_error or last_raw or "unknown agent failure",
    }


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
    # 阶段二：SecurityEvidence 统一证据（eBPF 进程/网络/文件三类监控）进入智能体证据包。
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
        object_id=_object_id(risk),
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


def detect_conflicts(
    packet: EvidencePacket,
    evidence: EvidenceAuditResult,
    impact: ImpactAssessmentResult,
    runtime: ExposureRuntimeResult,
    rereview_count: int = 0,
) -> ConflictResult:
    conflicts: list[ConflictItem] = []
    if evidence.evidence_quality in {"conflicting", "insufficient"} and impact.impact_status == "confirmed_affected" and impact.confidence >= 0.8:
        conflicts.append(ConflictItem(
            code="evidence_quality_vs_impact_confidence",
            description="证据质量不足或冲突，但影响智能体仍给出高置信度确认。",
            involved_agents=[AGENT_EVIDENCE, AGENT_IMPACT],
        ))
    if packet.package_match.get("match_status") == "potentially_affected" and impact.impact_status == "not_affected":
        conflicts.append(ConflictItem(
            code="deterministic_match_vs_not_affected",
            description="确定性版本规则仍命中，但影响智能体判断不受影响。",
            involved_agents=[AGENT_IMPACT],
        ))
    public_service = any(
        service.get("public") or service.get("listen_address") in {"0.0.0.0", "::"}
        for service in packet.service_context.get("services", [])
    )
    if public_service and runtime.exposure_status == "unreachable":
        conflicts.append(ConflictItem(
            code="public_listener_vs_unreachable",
            description="资产证据存在公网监听或映射，但暴露智能体判断不可达。",
            involved_agents=[AGENT_RUNTIME],
        ))
    # confirmed impact + runtime not_observed is intentionally not a conflict.
    return ConflictResult(
        has_major_conflict=bool(conflicts),
        conflicts=conflicts,
        rereview_count=rereview_count,
        unresolved=bool(conflicts) and rereview_count >= 1,
    )


def apply_audit_policy(
    packet: EvidencePacket,
    evidence: EvidenceAuditResult | None,
    impact: ImpactAssessmentResult | None,
    runtime: ExposureRuntimeResult | None,
    coordinator: CoordinatorResult | None,
    conflict: ConflictResult,
    failed_agents: list[str] | None = None,
) -> AuditPolicyDecision:
    reasons: list[str] = []
    failed_agents = failed_agents or []
    if failed_agents:
        reasons.append("agent_or_schema_failure:" + ",".join(failed_agents))
    if not all([evidence, impact, runtime, coordinator]):
        reasons.append("structured_result_incomplete")
    results = [item for item in (evidence, impact, runtime, coordinator) if item is not None]
    if any(float(item.confidence) < 0.70 for item in results):
        reasons.append("confidence_below_0.70")
    if evidence and evidence.evidence_quality != "sufficient":
        reasons.append("evidence_" + evidence.evidence_quality)
    if conflict.unresolved:
        reasons.append("unresolved_major_conflict")
    if not packet.package_match.get("installed_version"):
        reasons.append("installed_version_missing")
    if not packet.package_match.get("fixed_version") or packet.package_match.get("match_status") in {"unknown", "data_error", "insufficient_data"}:
        reasons.append("fixed_version_or_vulnerability_status_unreliable")
    if coordinator:
        if coordinator.recommended_action == "collect_more_evidence":
            reasons.append("coordinator_collect_more_evidence")
        if coordinator.recommended_priority in {"high", "critical"}:
            reasons.append("high_or_critical_priority")
            if packet.asset.get("business_level") == "core":
                reasons.append("high_or_critical_core_asset")
        if coordinator.recommended_action == "immediate_fix":
            reasons.append("high_impact_operation_requires_human")
    if impact and packet.package_match.get("match_status") == "potentially_affected" and impact.impact_status == "not_affected":
        reasons.append("major_baseline_contradiction")

    direction = coordinator.risk_direction if coordinator else "maintain"
    adjustment = DIRECTION_ADJUSTMENTS[direction]
    baseline = float(packet.baseline.get("preliminary_score") or 0)
    score = round(max(0.0, min(100.0, baseline + adjustment)), 2)
    score_level = risk_level(score)
    if score_level in {"High", "Critical"}:
        reasons.append("high_or_critical_final_score")
    if reasons:
        return AuditPolicyDecision(
            status="pending_human_review",
            reasons=list(dict.fromkeys(reasons)),
            adjustment=adjustment,
            final_score=None,
            final_level=None,
        )
    return AuditPolicyDecision(
        status="auto_confirmed",
        reasons=[],
        adjustment=adjustment,
        final_score=score,
        final_level=score_level,
    )


async def _process_event(packet: EvidencePacket, model_client, progress: _RunProgressTracker | None = None) -> dict[str, Any]:
    packet_payload = packet.model_dump()
    specialist_contexts = {
        AGENT_EVIDENCE: packet_payload,
        AGENT_IMPACT: {key: value for key, value in packet_payload.items() if key != "baseline"},
        AGENT_RUNTIME: packet_payload,
    }
    prompts = {
        AGENT_EVIDENCE: EVIDENCE_PROMPT,
        AGENT_IMPACT: IMPACT_PROMPT,
        AGENT_RUNTIME: RUNTIME_PROMPT,
    }
    async def run_specialist(name: str):
        if progress:
            progress.emit(
                "agent_reviewing", object_id=packet.object_id, agent_name=name,
                agent_status="running", percent=25,
                message=f"{name} is reviewing {packet.object_id}",
            )
        result, execution = await _run_typed_agent(
            name, prompts[name], specialist_contexts[name], packet, model_client
        )
        if progress:
            progress.emit(
                "agent_reviewing", object_id=packet.object_id, agent_name=name,
                agent_status=execution["status"], execution=execution, percent=55,
                message=f"{name} finished {packet.object_id}",
            )
        return result, execution

    specialist_calls = await asyncio.gather(*[run_specialist(name) for name in SPECIALIST_AGENTS])
    results = {name: result for name, (result, _) in zip(SPECIALIST_AGENTS, specialist_calls)}
    executions = {name: execution for name, (_, execution) in zip(SPECIALIST_AGENTS, specialist_calls)}
    audit_trail = list(executions.values())
    failed = [name for name, result in results.items() if result is None]

    if failed:
        skipped = {
            "agent_name": AGENT_COORDINATOR,
            "status": "skipped",
            "attempts": 0,
            "duration_ms": 0,
            "output_valid": False,
            "error": "specialist failure",
        }
        executions[AGENT_COORDINATOR] = skipped
        audit_trail.append(skipped)
        if progress:
            progress.emit(
                "coordinator_review", object_id=packet.object_id,
                agent_name=AGENT_COORDINATOR, agent_status="skipped", execution=skipped,
                percent=85, message=f"Coordinator skipped for fail-safe event {packet.object_id}",
            )
        conflict = ConflictResult()
        policy = apply_audit_policy(packet, results.get(AGENT_EVIDENCE), results.get(AGENT_IMPACT), results.get(AGENT_RUNTIME), None, conflict, failed)
        return {"packet": packet, "results": results, "executions": executions, "audit_trail": audit_trail, "conflict": conflict, "coordinator": None, "policy": policy}

    evidence = results[AGENT_EVIDENCE]
    impact = results[AGENT_IMPACT]
    runtime = results[AGENT_RUNTIME]
    conflict = detect_conflicts(packet, evidence, impact, runtime)
    if progress:
        progress.emit(
            "conflict_review", object_id=packet.object_id, percent=65,
            message=f"Checking evidence conflicts for {packet.object_id}",
        )

    if conflict.has_major_conflict:
        involved = sorted({agent for item in conflict.conflicts for agent in item.involved_agents})
        descriptions = [item.description for item in conflict.conflicts]
        for name in involved:
            context = {
                **specialist_contexts[name],
                "directed_rereview": descriptions,
                "instruction": "仅针对列出的冲突复议一次并输出完整结构化结果。",
            }
            if progress:
                progress.emit(
                    "conflict_review", object_id=packet.object_id, agent_name=name,
                    agent_status="running", percent=68,
                    message=f"Directed rereview by {name} for {packet.object_id}",
                )
            result, execution = await _run_typed_agent(name, prompts[name], context, packet, model_client)
            execution["rereview"] = True
            if progress:
                progress.emit(
                    "conflict_review", object_id=packet.object_id, agent_name=name,
                    agent_status=execution["status"], execution=execution, percent=72,
                    message=f"Directed rereview finished for {packet.object_id}",
                )
            executions[name] = execution
            audit_trail.append(execution)
            results[name] = result
            if result is None:
                failed.append(name)
        if not failed:
            evidence = results[AGENT_EVIDENCE]
            impact = results[AGENT_IMPACT]
            runtime = results[AGENT_RUNTIME]
            conflict = detect_conflicts(packet, evidence, impact, runtime, rereview_count=1)
        else:
            conflict = ConflictResult(
                has_major_conflict=True,
                conflicts=conflict.conflicts,
                rereview_count=1,
                unresolved=True,
            )

    coordinator = None
    if not failed:
        coord_context = {
            "object_id": packet.object_id,
            "baseline": packet.baseline,
            "evidence_audit": evidence.model_dump(),
            "impact_assessment": impact.model_dump(),
            "exposure_runtime": runtime.model_dump(),
            "conflict_result": conflict.model_dump(),
        }
        if progress:
            progress.emit(
                "coordinator_review", object_id=packet.object_id,
                agent_name=AGENT_COORDINATOR, agent_status="running", percent=75,
                message=f"Coordinator is deciding {packet.object_id}",
            )
        coordinator, coord_execution = await _run_typed_agent(
            AGENT_COORDINATOR, COORDINATOR_PROMPT, coord_context, packet, model_client
        )
        if progress:
            progress.emit(
                "coordinator_review", object_id=packet.object_id,
                agent_name=AGENT_COORDINATOR, agent_status=coord_execution["status"],
                execution=coord_execution, percent=85,
                message=f"Coordinator finished {packet.object_id}",
            )
        executions[AGENT_COORDINATOR] = coord_execution
        audit_trail.append(coord_execution)
        if coordinator is None:
            failed.append(AGENT_COORDINATOR)
    else:
        executions[AGENT_COORDINATOR] = {
            "agent_name": AGENT_COORDINATOR,
            "status": "skipped",
            "parse_status": "not_run",
            "attempts": 0,
            "retry_count": 0,
            "duration_ms": 0,
            "output_valid": False,
            "output": None,
            "raw_text": "",
            "error": "specialist failure",
        }
        audit_trail.append(executions[AGENT_COORDINATOR])
        if progress:
            progress.emit(
                "coordinator_review", object_id=packet.object_id,
                agent_name=AGENT_COORDINATOR, agent_status="skipped",
                execution=executions[AGENT_COORDINATOR], percent=85,
                message=f"Coordinator skipped for fail-safe event {packet.object_id}",
            )

    policy = apply_audit_policy(packet, evidence, impact, runtime, coordinator, conflict, failed)
    return {
        "packet": packet,
        "results": results,
        "executions": executions,
        "audit_trail": audit_trail,
        "conflict": conflict,
        "coordinator": coordinator,
        "policy": policy,
    }


async def _safe_process_event(packet: EvidencePacket, model_client, progress: _RunProgressTracker | None = None) -> dict[str, Any]:
    """Contain unexpected failures to the current event only."""
    try:
        return await _process_event(packet, model_client, progress)
    except Exception as exc:
        execution = {
            "agent_name": "pipeline",
            "status": "failed",
            "parse_status": "error",
            "attempts": 1,
            "retry_count": 0,
            "duration_ms": 0,
            "output_valid": False,
            "output": None,
            "raw_text": "",
            "error": str(exc),
        }
        conflict = ConflictResult()
        policy = apply_audit_policy(packet, None, None, None, None, conflict, ["pipeline"])
        if progress:
            for agent_name in ALL_AGENTS:
                failed_execution = {**execution, "agent_name": agent_name}
                progress.emit(
                    "audit_policy", object_id=packet.object_id,
                    agent_name=agent_name, agent_status="failed", execution=failed_execution,
                    percent=90, message=f"Fail-safe review required for {packet.object_id}",
                )
        return {
            "packet": packet,
            "results": {},
            "executions": {"pipeline": execution},
            "audit_trail": [execution],
            "conflict": conflict,
            "coordinator": None,
            "policy": policy,
        }


def _persist_event_result(db: Session, run_id: str, outcome: dict[str, Any]) -> None:
    """Persist only while System B owns the formal entry."""
    from app import config
    if config.UNIFIED_PIPELINE_MODE == "on":
        raise ValueError("system_b_formal_writer_disabled")
    packet: EvidencePacket = outcome["packet"]
    risk = db.get(models.RiskAssessment, packet.risk_id)
    if risk is None:
        return
    results = {
        name: value.model_dump() if value is not None else None
        for name, value in outcome["results"].items()
    }
    coordinator = outcome["coordinator"]
    if coordinator is not None:
        results[AGENT_COORDINATOR] = coordinator.model_dump()
    policy: AuditPolicyDecision = outcome["policy"]
    conflict: ConflictResult = outcome["conflict"]

    risk.evidence_packet_json = packet.model_dump_json()
    risk.agent_results_json = json.dumps(results, ensure_ascii=False)
    risk.conflict_result_json = conflict.model_dump_json()
    risk.audit_policy_reasons = json.dumps(policy.reasons, ensure_ascii=False)
    risk.review_status = policy.status
    risk.human_review_required = policy.status == "pending_human_review"
    risk.review_adjustment = policy.adjustment
    risk.review_completed_at = datetime.now(timezone.utc)
    risk.review_failed_agents = json.dumps(
        [name for name, execution in outcome["executions"].items() if execution["status"] == "failed"],
        ensure_ascii=False,
    )
    risk.review_conflicts = json.dumps(
        [item.description for item in conflict.conflicts], ensure_ascii=False
    )
    missing: list[str] = []
    for result in outcome["results"].values():
        if result is not None:
            missing.extend(getattr(result, "missing_evidence", []))
    if coordinator is not None:
        missing.extend(coordinator.missing_evidence)
        risk.review_confidence = coordinator.confidence
        risk.review_verdict = coordinator.impact_status
        risk.review_evidence_ids = json.dumps(coordinator.supporting_evidence_ids, ensure_ascii=False)
        risk.review_reason = coordinator.reason
        risk.recommended_priority = coordinator.recommended_priority
        risk.recommended_action = coordinator.recommended_action
        risk.risk_direction = coordinator.risk_direction
    else:
        risk.review_confidence = 0
        risk.review_verdict = "insufficient_evidence"
        risk.review_evidence_ids = "[]"
        risk.review_reason = "; ".join(policy.reasons)
        risk.recommended_action = "collect_more_evidence"
        risk.risk_direction = "maintain"
    risk.review_missing_evidence = json.dumps(list(dict.fromkeys(missing)), ensure_ascii=False)

    if policy.status == "auto_confirmed":
        risk.final_score = policy.final_score
        risk.risk_level = policy.final_level
        risk.decision = risk.recommended_action
        risk.reason = risk.review_reason
    else:
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
        risk.reason = risk.review_reason or "后端审计策略要求人工审核"

    for execution in outcome.get("audit_trail", outcome["executions"].values()):
        name = execution.get("agent_name", "unknown")
        output = execution.get("output") or {}
        evidence_ids: list[str] = []
        for field in ("valid_evidence_ids", "conflicting_evidence_ids", "supporting_evidence_ids", "counter_evidence_ids"):
            evidence_ids.extend(output.get(field, []))
        db.add(models.AgentAuditRecord(
            run_id=run_id,
            risk_id=risk.id,
            object_id=packet.object_id,
            agent_name=name,
            model=DEEPSEEK_MODEL,
            evidence_ids_json=json.dumps(sorted(set(evidence_ids)), ensure_ascii=False),
            structured_output_json=json.dumps(output, ensure_ascii=False),
            raw_response=execution.get("raw_text", ""),
            parse_status=execution.get("parse_status", "unknown"),
            retry_count=execution.get("retry_count", 0),
            latency_ms=execution.get("duration_ms", 0),
            error=execution.get("error", ""),
        ))


def _selection(db: Session) -> dict[str, Any]:
    risks = db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all()
    selected: list[models.RiskAssessment] = []
    skipped: list[dict[str, Any]] = []
    for risk in risks:
        oid = _object_id(risk)
        reason = ""
        if not risk.active:
            reason = "inactive"
        elif risk.review_status not in REVIEWABLE_STATUSES:
            reason = "status_not_reviewable"
        elif not risk.match_id:
            matches = db.query(models.VulnerabilityMatch).filter_by(
                asset_id=risk.asset_id, cve_id=risk.cve_id, active=True
            ).all()
            if len(matches) == 1:
                risk.match_id = matches[0].id
                risk.package_name = matches[0].package_name
            else:
                reason = "exact_match_missing" if not matches else "exact_match_ambiguous"
        elif db.get(models.VulnerabilityMatch, risk.match_id) is None:
            reason = "match_not_found"
        if reason:
            skipped.append({"object_id": oid, "reason": reason, "detail": risk.review_status})
        else:
            selected.append(risk)
    db.flush()
    return {
        "total_risks_in_db": len(risks),
        "candidate_count": sum(r.review_status in REVIEWABLE_STATUSES for r in risks),
        "selected_object_count": len(selected),
        "selected_object_ids": [_object_id(risk) for risk in selected],
        "unselected_count": len(skipped),
        "skipped_objects": skipped,
        "_selected_risks": selected,
    }


def _explain_candidate_selection(db: Session) -> dict[str, Any]:
    return _selection(db)


def preflight_check(db: Session) -> dict[str, Any]:
    selection = _selection(db)
    result = {
        "asset_count": db.query(models.LinuxAsset).count(),
        "package_count": db.query(models.AssetPackage).count(),
        "vulnerability_count": db.query(models.VulnerabilityInfo).count(),
        "match_count": db.query(models.VulnerabilityMatch).filter_by(active=True).count(),
        "affected_match_count": db.query(models.VulnerabilityMatch).filter_by(active=True, affected=True).count(),
        "risk_assessment_count": selection["total_risks_in_db"],
        **{key: value for key, value in selection.items() if key != "_selected_risks"},
        "pipeline_version": PIPELINE_VERSION,
    }
    if not selection["selected_object_count"]:
        result.update(status="no_candidates", model_called=False, message="当前没有可进入智能研判的候选对象")
    else:
        result["status"] = "ready"
    return result


async def _run_pipeline(
    db: Session,
    run_id: str,
    selected: list[models.RiskAssessment],
    progress_callback=None,
) -> dict[str, Any]:
    progress = _RunProgressTracker(len(selected), progress_callback)
    packets: list[EvidencePacket] = []
    immediate_failures: list[tuple[models.RiskAssessment, str]] = []
    for index, risk in enumerate(selected, start=1):
        risk.review_status = "evidence_preparing"
        progress.emit(
            "evidence_preparing", object_id=_object_id(risk),
            percent=5 + round(10 * index / max(1, len(selected))),
            message=f"Building evidence packet {index}/{len(selected)}",
        )
        try:
            packet = build_evidence_packet(db, risk)
            risk.evidence_packet_json = packet.model_dump_json()
            packets.append(packet)
        except Exception as exc:
            immediate_failures.append((risk, str(exc)))
    for risk, error in immediate_failures:
        risk.review_status = "pending_human_review"
        risk.human_review_required = True
        risk.review_reason = f"evidence_packet_failed: {error}"
        risk.audit_policy_reasons = json.dumps(["evidence_packet_failed"], ensure_ascii=False)
        risk.final_score = None
    db.commit()

    if not packets:
        progress.emit(
            "audit_policy", percent=99, processed_events=len(selected),
            message="Evidence packet creation failed; events require human review",
        )
        return {
            "status": "human_review", "valid_verdicts": [], "event_results": [],
            "candidate_count": len(selected), "selected_object_count": len(selected),
            "completed_object_count": 0, "human_review_object_count": len(selected),
            "agent_executions": {}, "answer": "证据包构建失败，全部进入人工审核。",
            "termination_reason": "evidence_packet_failed", "current_stage": "audit_policy",
        }

    model_client = _create_model_client()
    outcomes: list[dict[str, Any]] = []
    try:
        processed_offset = 0
        for batch in _batches(packets):
            for packet in batch:
                risk = db.get(models.RiskAssessment, packet.risk_id)
                risk.review_status = "agent_reviewing"
            db.commit()
            outcomes.extend(await asyncio.gather(*[
                _safe_process_event(packet, model_client, progress) for packet in batch
            ]))
            for outcome in outcomes[processed_offset: processed_offset + len(batch)]:
                _persist_event_result(db, run_id, outcome)
                progress.emit(
                    "audit_policy", object_id=outcome["packet"].object_id,
                    processed_events=processed_offset + 1,
                    percent=90 + round(8 * (processed_offset + 1) / max(1, len(selected))),
                    message=f"Backend audit policy applied to {outcome['packet'].object_id}",
                )
                processed_offset += 1
            db.commit()
    finally:
        try:
            await model_client.close()
        except Exception:
            pass

    completed = sum(outcome["policy"].status == "auto_confirmed" for outcome in outcomes)
    human = len(selected) - completed
    status = "completed" if human == 0 else ("partial" if completed else "human_review")
    aggregate: dict[str, dict[str, Any]] = {}
    for name in ALL_AGENTS:
        executions = [outcome["executions"].get(name) for outcome in outcomes if outcome["executions"].get(name)]
        aggregate[name] = {
            "status": "failed" if any(item["status"] == "failed" for item in executions) else "completed",
            "attempts": sum(item.get("attempts", 0) for item in executions),
            "duration_ms": sum(item.get("duration_ms", 0) for item in executions),
            "output_valid": all(item.get("output_valid", False) for item in executions),
            "opinion_count": sum(item.get("output_valid", False) for item in executions),
            "error": "; ".join(item.get("error", "") for item in executions if item.get("error")),
            "event_results": [item.get("output") for item in executions],
        }
    event_results = [{
        "object_id": outcome["packet"].object_id,
        "risk_id": outcome["packet"].risk_id,
        "evidence_packet": outcome["packet"].model_dump(),
        "evidence_audit": outcome["results"].get(AGENT_EVIDENCE).model_dump() if outcome["results"].get(AGENT_EVIDENCE) else None,
        "impact_assessment": outcome["results"].get(AGENT_IMPACT).model_dump() if outcome["results"].get(AGENT_IMPACT) else None,
        "exposure_runtime": outcome["results"].get(AGENT_RUNTIME).model_dump() if outcome["results"].get(AGENT_RUNTIME) else None,
        "conflict": outcome["conflict"].model_dump(),
        "coordinator": outcome["coordinator"].model_dump() if outcome["coordinator"] else None,
        "audit_policy": outcome["policy"].model_dump(),
    } for outcome in outcomes]
    return {
        "status": status,
        "valid_verdicts": [event["coordinator"] for event in event_results if event["coordinator"]],
        "event_results": event_results,
        "candidate_count": len(selected),
        "selected_object_count": len(selected),
        "completed_object_count": completed,
        "human_review_object_count": human,
        "agent_executions": aggregate,
        "answer": f"逐事件处理 {len(selected)} 条：自动确认 {completed} 条，人工审核 {human} 条。",
        "termination_reason": "pipeline_completed" if human == 0 else "audit_policy_human_review",
        "current_stage": "audit_policy",
    }


def _fail_selected(db: Session, selected: list[models.RiskAssessment], reason: str) -> None:
    for risk in selected:
        risk.review_status = "pending_human_review"
        risk.human_review_required = True
        risk.review_reason = reason
        risk.audit_policy_reasons = json.dumps([reason], ensure_ascii=False)
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
        risk.review_completed_at = datetime.now(timezone.utc)
    db.commit()


def run_review_analysis(db: Session, run_id: str | None = None, selected_risks=None, selection_result=None, progress_callback=None) -> dict[str, Any]:
    from app import config
    if config.UNIFIED_PIPELINE_MODE == "on":
        raise ValueError("system_b_formal_writer_disabled")
    del selection_result
    selected = list(selected_risks or _selection(db)["_selected_risks"])
    run_id = run_id or uuid.uuid4().hex[:12]
    if not selected:
        return {"status": "no_candidates", "review_run_id": run_id, "model_called": False}
    if not _configured():
        _fail_selected(db, selected, "deepseek_api_not_configured")
        return {
            "status": "human_review", "review_run_id": run_id,
            "candidate_count": len(selected), "selected_object_count": len(selected),
            "completed_object_count": 0, "human_review_object_count": len(selected),
            "valid_verdicts": [], "event_results": [], "agent_executions": {},
            "answer": "DeepSeek API 未配置；每条事件均已 fail-safe 进入人工审核。",
            "termination_reason": "deepseek_api_not_configured", "current_stage": "audit_policy",
        }
    try:
        result = asyncio.run(_run_pipeline(db, run_id, selected, progress_callback))
    except Exception as exc:
        traceback.print_exc()
        _fail_selected(db, selected, f"pipeline_failure:{exc}")
        result = {
            "status": "human_review", "candidate_count": len(selected),
            "selected_object_count": len(selected), "completed_object_count": 0,
            "human_review_object_count": len(selected), "valid_verdicts": [],
            "event_results": [], "agent_executions": {}, "answer": str(exc),
            "termination_reason": "pipeline_failure", "current_stage": "audit_policy",
        }
    result["review_run_id"] = run_id
    result["pipeline_version"] = PIPELINE_VERSION
    return result


def _persist_report(db: Session, report: models.AnalysisReport, result: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any]:
    report.status = result["status"]
    report.answer = result.get("answer", "")
    report.verdict_json = json.dumps({
        "pipeline_version": PIPELINE_VERSION,
        "event_results": result.get("event_results", []),
        "object_verdicts": result.get("valid_verdicts", []),
        "overall_summary": result.get("answer", ""),
    }, ensure_ascii=False, default=str)
    report.opinions_json = json.dumps(result.get("event_results", []), ensure_ascii=False, default=str)
    report.agent_executions_json = json.dumps(result.get("agent_executions", {}), ensure_ascii=False)
    report.termination_reason = result.get("termination_reason", "")
    report.current_stage = result.get("current_stage", "audit_policy")
    report.processed_object_count = result.get("selected_object_count", 0)
    report.completed_object_count = result.get("completed_object_count", 0)
    report.human_review_object_count = result.get("human_review_object_count", 0)
    report.object_verdict_count = len(result.get("valid_verdicts", []))
    report.progress_percent = 100
    report.current_object_id = ""
    report.progress_message = "Review completed"
    report.progress_sequence = int(report.progress_sequence or 0) + 1
    report.progress_updated_at = datetime.now(timezone.utc)
    report.completed_at = datetime.now(timezone.utc)
    db.commit()
    response = {
        "run_id": report.review_run_id,
        "report_id": report.id,
        "model": report.model,
        "status": report.status,
        "pipeline_version": PIPELINE_VERSION,
        "current_stage": report.current_stage,
        "candidate_count": report.candidate_count,
        "selected_object_count": report.selected_object_count,
        "processed_object_count": report.processed_object_count,
        "completed_object_count": report.completed_object_count,
        "human_review_object_count": report.human_review_object_count,
        "object_verdict_count": report.object_verdict_count,
        "progress_percent": report.progress_percent,
        "current_object_id": report.current_object_id,
        "progress_message": report.progress_message,
        "progress_sequence": report.progress_sequence,
        "progress_updated_at": report.progress_updated_at.isoformat() if report.progress_updated_at else "",
        "selected_object_ids": selection["selected_object_ids"],
        "skipped_objects": selection["skipped_objects"],
        "agent_executions": result.get("agent_executions", {}),
        "verdict": json.loads(report.verdict_json),
        "answer": report.answer,
        "error": report.error,
        "termination_reason": report.termination_reason,
        "created_at": report.created_at.isoformat() if report.created_at else "",
        "completed_at": report.completed_at.isoformat() if report.completed_at else "",
    }
    _write_run_snapshot(report.review_run_id, response)
    return response


def generate_and_save_report(db: Session, run_id: str | None = None, background: bool = False) -> dict[str, Any]:
    from app import config
    if config.UNIFIED_PIPELINE_MODE == "on":
        raise ValueError("system_b_formal_writer_disabled")
    selection = _selection(db)
    selected = selection["_selected_risks"]
    run_id = run_id or uuid.uuid4().hex[:12]
    if not selected:
        return {
            "run_id": "", "status": "no_candidates", "candidate_count": selection["candidate_count"],
            "selected_object_count": 0, "total_risks_in_db": selection["total_risks_in_db"],
            "skipped_objects": selection["skipped_objects"], "selected_object_ids": [],
            "pipeline_version": PIPELINE_VERSION, "model_called": False,
            "message": "当前没有可进入智能研判的候选对象",
        }
    report = models.AnalysisReport(
        model=DEEPSEEK_MODEL,
        status="running",
        review_run_id=run_id,
        pipeline_version=PIPELINE_VERSION,
        current_stage="evidence_preparing",
        candidate_count=selection["candidate_count"],
        selected_object_count=len(selected),
        selected_object_ids_json=json.dumps(selection["selected_object_ids"], ensure_ascii=False),
        skipped_objects_json=json.dumps(selection["skipped_objects"], ensure_ascii=False),
        progress_percent=5,
        progress_message="Preparing evidence packets",
        progress_sequence=1,
        progress_updated_at=datetime.now(timezone.utc),
    )
    db.add(report)
    for risk in selected:
        risk.review_status = "evidence_preparing"
    db.commit()
    db.refresh(report)
    risk_ids = [risk.id for risk in selected]

    if background:
        import threading
        from app.database import SessionLocal

        def worker():
            worker_db = SessionLocal()
            try:
                worker_report = worker_db.query(models.AnalysisReport).filter_by(review_run_id=run_id).one()
                worker_selected = worker_db.query(models.RiskAssessment).filter(models.RiskAssessment.id.in_(risk_ids)).all()
                result = run_review_analysis(
                    worker_db,
                    run_id,
                    worker_selected,
                    progress_callback=lambda **payload: _persist_run_progress(run_id, **payload),
                )
                _persist_report(worker_db, worker_report, result, selection)
            except Exception as exc:
                traceback.print_exc()
                worker_selected = worker_db.query(models.RiskAssessment).filter(models.RiskAssessment.id.in_(risk_ids)).all()
                _fail_selected(worker_db, worker_selected, f"background_failure:{exc}")
                worker_report = worker_db.query(models.AnalysisReport).filter_by(review_run_id=run_id).one_or_none()
                if worker_report:
                    worker_report.status = "human_review"
                    worker_report.error = str(exc)
                    worker_report.progress_percent = 100
                    worker_report.progress_message = "Background review failed; human review required"
                    worker_report.progress_sequence = int(worker_report.progress_sequence or 0) + 1
                    worker_report.progress_updated_at = datetime.now(timezone.utc)
                    worker_report.completed_at = datetime.now(timezone.utc)
                    worker_db.commit()
            finally:
                worker_db.close()

        threading.Thread(target=worker, daemon=True).start()
        return {
            "run_id": run_id, "report_id": report.id, "model": report.model,
            "status": "running", "candidate_count": selection["candidate_count"],
            "selected_object_count": len(selected), "total_risks_in_db": selection["total_risks_in_db"],
            "skipped_objects": selection["skipped_objects"], "selected_object_ids": selection["selected_object_ids"],
            "pipeline_version": PIPELINE_VERSION, "current_stage": "evidence_preparing",
            "progress_percent": report.progress_percent,
            "current_object_id": report.current_object_id,
            "progress_message": report.progress_message,
            "progress_sequence": report.progress_sequence,
            "model_called": _configured(), "created_at": report.created_at.isoformat() if report.created_at else "",
        }

    result = run_review_analysis(db, run_id, selected)
    return _persist_report(db, report, result, selection)


def latest_analysis(db: Session) -> dict[str, Any] | None:
    report = db.query(models.AnalysisReport).order_by(models.AnalysisReport.id.desc()).first()
    if report is None:
        return None
    return {
        "id": report.id,
        "run_id": report.review_run_id or str(report.id),
        "review_run_id": report.review_run_id or str(report.id),
        "model": report.model,
        "status": report.status,
        "pipeline_version": report.pipeline_version or "legacy",
        "current_stage": report.current_stage or "",
        "candidate_count": report.candidate_count or 0,
        "selected_object_count": report.selected_object_count or 0,
        "processed_object_count": report.processed_object_count or 0,
        "completed_object_count": report.completed_object_count or 0,
        "human_review_object_count": report.human_review_object_count or 0,
        "object_verdict_count": report.object_verdict_count or 0,
        "progress_percent": report.progress_percent or 0,
        "current_object_id": report.current_object_id or "",
        "progress_message": report.progress_message or "",
        "progress_sequence": report.progress_sequence or 0,
        "progress_updated_at": report.progress_updated_at.isoformat() if report.progress_updated_at else "",
        "selected_object_ids": json.loads(report.selected_object_ids_json or "[]"),
        "skipped_objects": json.loads(report.skipped_objects_json or "[]"),
        "agent_executions": json.loads(report.agent_executions_json or "{}"),
        "verdict": json.loads(report.verdict_json or "{}"),
        "opinions": json.loads(report.opinions_json or "[]"),
        "answer": report.answer,
        "error": report.error,
        "termination_reason": report.termination_reason or "",
        "created_at": report.created_at.isoformat() if report.created_at else "",
        "completed_at": report.completed_at.isoformat() if report.completed_at else "",
        "is_legacy": not bool(report.pipeline_version),
    }


def review_status() -> dict[str, Any]:
    return {
        "configured": _configured(),
        "model": DEEPSEEK_MODEL,
        "mode": "per-risk-fixed-expert-audit",
        "pipeline_version": PIPELINE_VERSION,
        "pipeline": [
            {"step": 1, "name": "candidate", "description": "规则候选"},
            {"step": 2, "name": "evidence_preparing", "description": "逐事件证据包"},
            {"step": 3, "name": "agent_reviewing", "description": "三专家独立研判"},
            {"step": 4, "name": "conflict_review", "description": "冲突检测与一次定向复议"},
            {"step": 5, "name": "coordinator_review", "description": "逐事件协调建议"},
            {"step": 6, "name": "audit_policy", "description": "后端自动确认或人工审核"},
        ],
        "agents": [
            {"id": AGENT_EVIDENCE, "role": "Evidence Audit Agent"},
            {"id": AGENT_IMPACT, "role": "Impact Assessment Agent"},
            {"id": AGENT_RUNTIME, "role": "Exposure & Runtime Agent"},
            {"id": AGENT_COORDINATOR, "role": "Decision Coordinator Agent"},
        ],
        "batch_size": BATCH_SIZE,
        "max_retries": MAX_RETRIES,
        "risk_direction_adjustments": DIRECTION_ADJUSTMENTS,
    }


def _persist_run_progress(
    run_id: str,
    current_stage: str,
    agent_executions: dict[str, Any],
    processed_object_count: int = 0,
    current_object_id: str = "",
    progress_message: str = "",
    progress_percent: int = 0,
) -> None:
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        report = db.query(models.AnalysisReport).filter_by(review_run_id=run_id).one_or_none()
        if report:
            report.current_stage = current_stage
            report.agent_executions_json = json.dumps(agent_executions, ensure_ascii=False)
            report.processed_object_count = processed_object_count
            report.current_object_id = current_object_id
            report.progress_message = progress_message
            report.progress_percent = max(int(report.progress_percent or 0), int(progress_percent or 0))
            report.progress_sequence = int(report.progress_sequence or 0) + 1
            report.progress_updated_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def apply_human_review(db: Session, risk_id: int, decision: str, reason: str) -> models.RiskAssessment:
    risk = db.get(models.RiskAssessment, risk_id)
    if risk is None:
        raise ValueError("risk event not found")
    if risk.review_status not in {"pending_human_review", "human_reviewing"}:
        raise ValueError(f"risk event status {risk.review_status} is not awaiting human review")
    if decision == "reject":
        risk.review_status = "rejected"
        risk.human_review_required = False
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
    elif decision == "confirm":
        adjustment = DIRECTION_ADJUSTMENTS.get(risk.risk_direction or "maintain", 0)
        final = max(0.0, min(100.0, float(risk.preliminary_score or 0) + adjustment))
        risk.review_status = "human_confirmed"
        risk.human_review_required = False
        risk.final_score = round(final, 2)
        risk.risk_level = risk_level(final)
        risk.decision = risk.recommended_action or risk.preliminary_decision
    else:
        raise ValueError("decision must be confirm or reject")
    risk.review_reason = f"{risk.review_reason}\n[human_review] {reason}".strip()
    risk.review_completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(risk)
    return risk
