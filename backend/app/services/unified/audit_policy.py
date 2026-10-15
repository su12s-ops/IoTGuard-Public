"""确定性审计门禁（继承 System B apply_audit_policy 全部语义 + 统一链扩展）。

原则不变：LLM 只产生离散裁定与建议；最终分数 = 规则基线 + 有界方向映射；
门禁命中任一理由 → pending_human_review（fail-closed，绝不虚降风险）。

统一链扩展：
- 任一角色降级/失败 → agent_degraded:<role>（部分失败不再全丢——其余角色
  意见保留，但结论必须人工复核，R7）；
- runtime_status=stale_verified → stale_runtime_evidence（F6：过期证据不得
  走「已验证」激进路径）；
- 简单分层的规则直通结论显式标注 rule_tier_simple（可审计，非 auto_confirm）。
"""
from __future__ import annotations

from typing import Any

from app.services.unified.schemas import AGENT_DECISION, AuditPolicyDecisionRecord

# 有界方向映射（继承 System B，LLM 不可越权的唯一分数通道）
DIRECTION_ADJUSTMENTS = {
    "maintain": 0,
    "upgrade_minor": 10,
    "upgrade_major": 20,
    "downgrade_minor": -10,
    "downgrade_major": -20,
}


def risk_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def apply_unified_audit_policy(state_like: dict[str, Any]) -> AuditPolicyDecisionRecord:
    """对单事件计算审计门禁结论。state_like 需含 baseline/degraded_roles/
    conflict_result/runtime/decision 键（状态快照或其子集）。"""
    baseline = state_like.get("baseline") or {}
    decision = state_like.get("decision") or {}
    runtime = state_like.get("runtime") or state_like.get("runtime_program_fallback") or {}
    conflict = state_like.get("conflict_result") or {}
    degraded_roles = state_like.get("degraded_roles") or []

    reasons: list[str] = []

    # 角色完整性：任一角色失败/降级 → 人工复核（意见保留，权威不给）
    for role in degraded_roles:
        reasons.append(f"agent_degraded:{role}")
    verdicts = decision.get("verdicts") or []
    if not verdicts:
        reasons.append("structured_result_incomplete")

    # 置信度门禁（继承 System B：任一裁置信度 <0.70 → 人工）
    for verdict in verdicts:
        try:
            confidence = float(verdict.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0
        if confidence < 0.70:
            reasons.append("confidence_below_0.70")
            break

    # 证据质量门禁（继承）
    investigation = state_like.get("investigation") or {}
    evidence_quality = investigation.get("evidence_quality")
    if evidence_quality and evidence_quality != "sufficient":
        reasons.append(f"evidence_{evidence_quality}")

    # 冲突门禁（继承）
    if conflict.get("unresolved"):
        reasons.append("unresolved_major_conflict")

    # 基础数据门禁（继承）
    if not baseline.get("installed_version"):
        reasons.append("installed_version_missing")
    if not baseline.get("fixed_version") or baseline.get("match_status") in {
            "unknown", "data_error", "insufficient_data"}:
        reasons.append("fixed_version_or_vulnerability_status_unreliable")

    # F6：过期运行时证据不得自动确认
    if runtime.get("runtime_status") == "stale_verified":
        reasons.append("stale_runtime_evidence")
    if runtime.get("runtime_status") == "unavailable" and runtime.get("capability_limited"):
        reasons.append("runtime_capability_unavailable")

    # 裁定内容门禁（继承 System B 语义）
    for verdict in verdicts:
        action = verdict.get("recommended_action")
        priority = verdict.get("recommended_priority")
        if action == "collect_more_evidence":
            reasons.append("coordinator_collect_more_evidence")
        if priority in {"high", "critical"}:
            reasons.append("high_or_critical_priority")
            if (baseline.get("business_level") or "").lower() == "core":
                reasons.append("high_or_critical_core_asset")
        if action == "immediate_fix":
            reasons.append("high_impact_operation_requires_human")
        break   # 单事件语义：取第一个 verdict

    # 基线矛盾门禁（继承：规则命中 vs 不受影响）
    verdict = verdicts[0] if verdicts else {}
    if (baseline.get("match_status") in {"potentially_affected", "affected"}
            and verdict.get("impact_status") == "not_affected"):
        reasons.append("major_baseline_contradiction")

    # 有界方向映射 + 分数计算（LLM 永不直写分数）
    direction = verdict.get("risk_direction", "maintain") if verdict else "maintain"
    adjustment = DIRECTION_ADJUSTMENTS.get(direction, 0)
    score = round(max(0.0, min(100.0, float(baseline.get("preliminary_score") or 0) + adjustment)), 2)
    score_level = risk_level(score)
    if score_level in {"High", "Critical"}:
        reasons.append("high_or_critical_final_score")

    if AGENT_DECISION in degraded_roles:
        reasons.append("decision_planner_failed_fallback")

    if reasons:
        return AuditPolicyDecisionRecord(
            status="pending_human_review",
            reasons=list(dict.fromkeys(reasons)),
            adjustment=adjustment,
            final_score=None,
            final_level=None,
        )
    return AuditPolicyDecisionRecord(
        status="auto_confirmed",
        reasons=[],
        adjustment=adjustment,
        final_score=score,
        final_level=score_level,
    )
