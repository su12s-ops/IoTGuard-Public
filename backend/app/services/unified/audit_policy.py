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


def _deterministic_contradiction_reasons(state_like: dict[str, Any], verdicts: list,
                                         runtime: dict) -> list[str]:
    """模型裁定与程序确定性核验的矛盾检查（M4.1 校准 + M4.2 深化，通用安全语义规则）。

    - branch_exclusion_contradiction：可信分支排除证据 vs confirmed/potentially
      受影响（M4.2 扩展：potentially 同样纳入——E3a 残余方差整改）；
    - deterministic_fixed_overridden：确定性已修复判定被推翻为受影响；
    - fixed_disposal_contradiction：已修复判定下仍给出修复类处置（X2 加固）；
    - vendor_not_affected_overridden：厂商精确公告 not_affected（含 backport）
      被通用候选推翻（Y1/Y2/E3 家族）；
    - vendor_conflict_unresolved_disposal：厂商适用性冲突未消解却确认受影响
      或直接进入修复处置（「组件已安装」≠「CVE 适用已确认」）；
    - urgency_claim_without_fresh_runtime：宣称新鲜运行时证据支撑紧迫但证据
      并不新鲜（stale_verified 不是活跃利用的充分依据）；
    - urgency_basis_undeclared：immediate_fix 未声明紧迫依据；
    - static_urgency_without_amplifier：静态证据独立支撑 immediate_fix 但无
      确定性放大因子（KEV 或 受影响组件公网监听×CVSS≥9.0）——E2 整改；
    - static_evidence_urgency_requires_human：静态证据独立支撑的紧急修复
      不被一刀切禁止，但必须人工复核（不做武断禁止）；
    - applicability_conflated_with_stale_runtime：把「运行时证据过期」直接
      推导成「适用性不足」的口径混用（适用性与证据有效性必须分离）。
    """
    verdict = verdicts[0] if verdicts else {}
    if not isinstance(verdict, dict) or verdict.get("program_fallback"):
        return []
    impact = verdict.get("impact_status")
    action = verdict.get("recommended_action")
    prep = state_like.get("evidence_prep") or {}
    candidates = prep.get("candidates") or []
    first = candidates[0] if candidates else {}
    branch = first.get("branch_check") or {}
    compare = first.get("version_compare") or {}
    conflict = first.get("vendor_conflict") or {}
    vendor_patch = first.get("vendor_patch") or {}
    amplifiers = first.get("urgency_amplifiers") or {}

    freshness = str(runtime.get("evidence_freshness") or "")
    if not freshness:
        packet_runtime = prep.get("runtime_facts") or {}
        buckets = {view.get("freshness") for view in
                   (packet_runtime.get("freshness") or {}).values() if isinstance(view, dict)}
        freshness = "fresh" if "fresh" in buckets else ("stale" if buckets else "")

    reasons: list[str] = []
    if candidates:   # 仅当预取包携带候选确定性事实时才做矛盾核查
        branch_excluded = branch.get("result") in {
            "branch_excluded", "below_stated_affected_range"}
        if branch_excluded and impact in {"confirmed_affected", "potentially_affected"}:
            reasons.append("branch_exclusion_contradiction")
        if compare.get("result") == "fixed" and impact in {"confirmed_affected", "potentially_affected"}:
            reasons.append("deterministic_fixed_overridden")
        if compare.get("result") == "fixed" and action in {"immediate_fix", "scheduled_fix"}:
            reasons.append("fixed_disposal_contradiction")
        if (vendor_patch.get("release_status") == "not_affected"
                and impact in {"confirmed_affected", "potentially_affected"}):
            reasons.append("vendor_not_affected_overridden")
        if conflict.get("unresolved") and (impact == "confirmed_affected"
                                           or action in {"scheduled_fix", "immediate_fix"}):
            reasons.append("vendor_conflict_unresolved_disposal")
    if action == "immediate_fix":
        basis = verdict.get("urgency_basis") or "unknown"
        if basis == "fresh_runtime_evidence" and freshness != "fresh":
            reasons.append("urgency_claim_without_fresh_runtime")
        elif basis == "unknown" and freshness != "fresh":
            reasons.append("urgency_basis_undeclared")
        elif basis == "static_evidence_only":
            if candidates and impact in {"confirmed_affected", "potentially_affected"} \
                    and not amplifiers.get("any_present"):
                reasons.append("static_urgency_without_amplifier")
            reasons.append("static_evidence_urgency_requires_human")
    if impact == "insufficient_evidence" and compare.get("result") == "affected" \
            and freshness == "stale":
        reasons.append("applicability_conflated_with_stale_runtime")
    return reasons


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

    # ── M4.1 校准：确定性安全语义矛盾 → fail-closed（与 decide 节点校验同语义）。
    # 模型输出经反馈重试后若仍与程序确定性核验矛盾，门禁兜底强制人工，
    # 绝不自动采纳任何一侧。全部为通用规则（无案例编号）。 ──
    reasons.extend(_deterministic_contradiction_reasons(
        state_like, verdicts, runtime))

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
