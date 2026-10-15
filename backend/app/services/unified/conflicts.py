"""确定性冲突检测（继承 System B 三规则 + 跨智能体交叉扩展）。

全部为纯程序规则（无 LLM）；命中即触发定向复议（≤1 次），复议后仍未消解
则由审计门禁强制人工复核。新增交叉规则直接回应审计 §7-7（动态证据引入后
偶尔导致错误风险升级）：运行时告警与「不受影响/已修复」结论冲突时，一律
转人工，不允许任何一侧自动压过另一侧。
"""
from __future__ import annotations

from typing import Any

from app.services.unified.schemas import (
    AGENT_RUNTIME,
    AGENT_VULNERABILITY,
    ConflictItemRecord,
    ConflictResultRecord,
)


def detect_conflicts(state_like: dict[str, Any]) -> ConflictResultRecord:
    """从状态快照检测冲突。state_like 需含 baseline/vulnerability/runtime 键。"""
    conflicts: list[ConflictItemRecord] = []
    baseline = state_like.get("baseline") or {}
    vulnerability = state_like.get("vulnerability") or {}
    runtime = state_like.get("runtime") or {}
    investigation = state_like.get("investigation") or {}

    match_status = str(baseline.get("match_status") or "")
    findings = vulnerability.get("findings") or []
    not_affected = [f for f in findings
                    if isinstance(f, dict) and f.get("applicability") == "not_affected"]
    fixed = [f for f in findings
             if isinstance(f, dict) and f.get("version_impact") == "fixed"]
    # 「已消解」= 语义判定不受影响，或真实版本比较证明已修复/不适用
    resolved = [
        f for f in findings
        if isinstance(f, dict)
        and (f.get("applicability") == "not_affected"
             or f.get("version_impact") in {"fixed", "not_affected"})
    ]

    # 规则 1（System B）：确定性版本规则仍命中，但影响分析判不受影响。
    if match_status in {"potentially_affected", "affected"} and not_affected:
        conflicts.append(ConflictItemRecord(
            code="deterministic_match_vs_not_affected",
            description="确定性版本规则仍命中，但漏洞分析师判断不受影响。",
            involved_agents=[AGENT_VULNERABILITY]))

    # 规则 2（System B）：证据质量不足/冲突，但影响分析高置信确认。
    evidence_quality = str(investigation.get("evidence_quality") or "")
    top_confidence = max((float(f.get("confidence") or 0) for f in findings
                          if isinstance(f, dict)), default=0)
    if evidence_quality in {"conflicting", "insufficient"} and findings and top_confidence >= 0.8:
        conflicts.append(ConflictItemRecord(
            code="evidence_quality_vs_impact_confidence",
            description="证据质量不足或冲突，但漏洞分析师仍给出高置信度结论。",
            involved_agents=[AGENT_VULNERABILITY]))

    # 规则 3（System B）：公网监听 vs 不可达。
    services = (investigation.get("services") or [])
    public_listener = any(
        (isinstance(s, dict) and (s.get("public") or s.get("auth_state") == "anonymous_accepted"))
        for s in services) or bool(baseline.get("public_listener"))
    if public_listener and runtime.get("exposure_status") == "unreachable":
        conflicts.append(ConflictItemRecord(
            code="public_listener_vs_unreachable",
            description="资产存在公网监听/匿名服务，但运行时分析师判断不可达。",
            involved_agents=[AGENT_RUNTIME]))

    # 规则 4（新增，§7-7）：运行时告警与「不受影响/已修复」交叉冲突。
    behavior_level = str(runtime.get("behavior_level") or "NORMAL")
    if behavior_level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and resolved:
        conflicts.append(ConflictItemRecord(
            code="runtime_alert_vs_not_affected",
            description="运行时行为告警与漏洞分析师的不受影响/已修复结论冲突；"
                        "不得互相自动压过，转人工核实。",
            involved_agents=[AGENT_VULNERABILITY, AGENT_RUNTIME]))

    # 规则 5（新增，F5 配套）：规则基线高危，但命中 CVE 均已修复/不受影响。
    preliminary_level = str(baseline.get("preliminary_level") or "")
    if preliminary_level in {"High", "Critical"} and findings and len(resolved) == len(findings):
        conflicts.append(ConflictItemRecord(
            code="baseline_high_vs_all_findings_resolved",
            description="规则基线为高危，但漏洞分析师认定全部命中已修复/不受影响（F5 校验）。",
            involved_agents=[AGENT_VULNERABILITY]))

    # 规则 6（新增，F6 配套）：过期证据支撑的告警。
    freshness = str(runtime.get("evidence_freshness") or "none")
    if behavior_level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and freshness == "stale":
        conflicts.append(ConflictItemRecord(
            code="stale_evidence_active_behavior",
            description="行为告警仅由过期证据支撑（freshness=stale）；紧迫度结论需要新鲜证据。",
            involved_agents=[AGENT_RUNTIME]))

    # 规则 7（新增）：多源情报矛盾「未被分析师消解」时才升级为冲突——
    # 分析师已给出明确适用性结论（confirmed/potentially/not_affected）视为已消解；
    # 只有结论仍为 insufficient_evidence（或没有任何结论）时才强制转人工。
    # （实验教训：无条件触发会在多源数据常态差异上空转，制造无意义复议。）
    intel_conflicts = vulnerability.get("intelligence_conflicts") or []
    if intel_conflicts:
        unresolved_by_analyst = (
            not findings
            or all(isinstance(f, dict) and f.get("applicability") in
                   {"insufficient_evidence", None, ""} for f in findings)
        )
        if unresolved_by_analyst:
            conflicts.append(ConflictItemRecord(
                code="intelligence_source_conflict",
                description="漏洞情报来源之间存在矛盾且分析师未能消解"
                            "（如厂商 under_investigation vs NVD affected）。",
                involved_agents=[AGENT_VULNERABILITY]))

    return ConflictResultRecord(
        has_major_conflict=bool(conflicts),
        conflicts=conflicts,
        rereview_count=0,
        unresolved=bool(conflicts),
    )


def merge_rereview(previous: ConflictResultRecord,
                   state_like: dict[str, Any]) -> ConflictResultRecord:
    """定向复议后重跑检测：仍未消解 → unresolved=True（门禁转人工）。"""
    refreshed = detect_conflicts(state_like)
    return ConflictResultRecord(
        has_major_conflict=refreshed.has_major_conflict,
        conflicts=refreshed.conflicts,
        rereview_count=1,
        unresolved=refreshed.has_major_conflict,
    )
