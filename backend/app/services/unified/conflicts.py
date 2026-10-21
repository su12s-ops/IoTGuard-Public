"""Deterministic, evidence-scoped disagreement classification for four roles.

Different professional dimensions do not require another investigation. Only
fresh CVE-specific runtime evidence can contradict static applicability; a
generic alert and absence of observed exploitation cannot do so.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.unified.schemas import (
    AGENT_ASSET, AGENT_DECISION, AGENT_RUNTIME, AGENT_VULNERABILITY,
    ConflictItemRecord, ConflictResultRecord,
)

_AFFECTED = {"confirmed_affected", "potentially_affected"}
_SPECIFIC = {"cve_related_evidence", "confirmed_exploitation"}


def _refs(value):
    if isinstance(value, dict):
        ids = {str(v) for k in ("evidence_ids", "supporting_evidence_ids")
               for v in value.get(k) or [] if isinstance(v, str)}
        if value.get("evidence_id"):
            ids.add(str(value["evidence_id"]))
        for item in value.values():
            if isinstance(item, (dict, list)):
                ids.update(_refs(item))
        return ids
    if isinstance(value, list):
        return set().union(*(_refs(item) for item in value)) if value else set()
    return set()


def _cve(value):
    return str(value or "").split(":")[0]


def _matching(candidate, finding, single=False):
    left, right = _cve(candidate.get("cve_id")), _cve(finding.get("cve_id"))
    if left and right and left != right:
        return False
    package_left, package_right = candidate.get("package_name"), finding.get("package_name")
    if package_left and package_right and package_left != package_right:
        return False
    return bool(left and right or single)


def _excludes(candidate):
    return ((candidate.get("branch_check") or {}).get("result") in
        {"branch_excluded", "below_stated_affected_range"}
        or (candidate.get("version_compare") or {}).get("result") in {"fixed", "not_affected"}
        or (candidate.get("vendor_patch") or {}).get("release_status") == "not_affected")


def _date(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _fresh_related(runtime_finding, static_finding, state, single):
    runtime = state.get("runtime") or {}
    if runtime_finding.get("relation") not in _SPECIFIC or runtime.get("evidence_freshness") != "fresh":
        return False
    evidence_id = runtime_finding.get("evidence_id")
    if not evidence_id:
        return False
    snapshot = state.get("evidence_snapshot") or {}
    registry = snapshot.get("evidence_registry")
    metadata = (registry or {}).get(evidence_id) or {}
    if isinstance(registry, dict) and evidence_id not in registry:
        return False
    if isinstance(registry, dict) and metadata.get("kind") != "runtime":
        return False
    # A report-level relation cannot bind one alert to every candidate CVE.
    linked = {_cve(v) for v in (runtime_finding.get("cve_ids") or metadata.get("cve_ids") or [])}
    linked.update({_cve(runtime_finding.get("cve_id")), _cve(metadata.get("cve_id"))})
    linked.discard("")
    if linked and _cve(static_finding.get("cve_id")) not in linked:
        return False
    if not linked and not single:
        return False
    freshness = ((state.get("evidence_prep") or {}).get("runtime_facts") or {}).get("freshness") or {}
    aspect = runtime_finding.get("aspect")
    if isinstance(freshness.get(aspect), dict) and freshness[aspect].get("freshness") != "fresh":
        return False
    if isinstance(registry, dict):
        observed = _date(metadata.get("timestamp") or metadata.get("observed_at") or metadata.get("as_of"))
        reference = _date(snapshot.get("created_at")) or datetime.now(timezone.utc)
        if not observed or not 0 <= (reference - observed).total_seconds() <= (168 if aspect == "file" else 24) * 3600:
            return False
    return True


def detect_conflicts(state_like: dict[str, Any]) -> ConflictResultRecord:
    """Classify per candidate; advisory information is retained without a replay."""
    state = state_like.model_dump() if hasattr(state_like, "model_dump") else state_like
    baseline = state.get("baseline") or {}
    vulnerability = state.get("vulnerability") or {}
    runtime = state.get("runtime") or {}
    investigation = state.get("investigation") or {}
    findings = [f for f in vulnerability.get("findings") or [] if isinstance(f, dict)]
    candidates = [c for c in (state.get("evidence_prep") or {}).get("candidates") or [] if isinstance(c, dict)]
    registry = (state.get("evidence_snapshot") or {}).get("evidence_registry")
    conflicts = []

    def add(code, description, agents, category="substantive_judgment", evidence=()):
        ids = set(evidence)
        if isinstance(registry, dict):
            ids.intersection_update(registry)
        item = ConflictItemRecord(code=code, description=description, involved_agents=agents,
            category=category, evidence_ids=sorted(ids))
        if item not in conflicts:
            conflicts.append(item)

    def candidates_for(finding):
        return [c for c in candidates if _matching(c, finding, len(candidates) == len(findings) == 1)]

    def proven_excluded(finding):
        return any(_excludes(c) and not (c.get("vendor_conflict") or {}).get("unresolved")
                   for c in candidates_for(finding))

    resolved = [f for f in findings if f.get("applicability") == "not_affected"
                or f.get("version_impact") in {"fixed", "not_affected"}]
    affected = [f for f in findings if f.get("applicability") in _AFFECTED]
    for finding in findings:
        refs = _refs(finding)
        subject = str(finding.get("cve_id") or "当前候选")
        same_baseline = _matching(baseline, finding, len(findings) == 1)
        if (same_baseline and baseline.get("match_status") in {"potentially_affected", "affected"}
                and finding.get("applicability") == "not_affected" and not proven_excluded(finding)):
            add("deterministic_match_vs_not_affected", f"{subject} 的确定性候选仍命中，但分析师判不受影响，需核对当前证据。",
                [AGENT_VULNERABILITY], evidence=refs)
        if (investigation.get("evidence_quality") in {"conflicting", "insufficient"}
                and float(finding.get("confidence") or 0) >= 0.8
                and finding.get("applicability") != "insufficient_evidence"):
            add("evidence_quality_vs_impact_confidence", f"{subject} 的证据不足或冲突，但仍给出高置信确定结论。",
                [AGENT_VULNERABILITY], evidence=refs)
        for candidate in candidates_for(finding):
            if _excludes(candidate) and finding.get("applicability") in _AFFECTED:
                add("deterministic_fact_vs_analyst_conclusion",
                    f"{subject} 的当前分支、修复版本或厂商排除事实与受影响结论矛盾。",
                    [AGENT_VULNERABILITY], evidence=refs | _refs(candidate))
            if (candidate.get("installed_version") and finding.get("installed_version")
                    and candidate["installed_version"] != finding["installed_version"]):
                add("inventory_version_mismatch", f"{subject} 引用了不同于当前快照的安装版本，定向更新漏洞结论。",
                    [AGENT_VULNERABILITY], "fact_version", refs | _refs(candidate))

    public_listener = any(isinstance(s, dict) and (s.get("public") or
        s.get("auth_state") == "anonymous_accepted") for s in investigation.get("services") or [])
    if (public_listener or baseline.get("public_listener")) and runtime.get("exposure_status") == "unreachable":
        add("public_listener_vs_unreachable", "公网监听与网络可达性是不同事实；需说明实际路径或隔离证据。",
            [AGENT_RUNTIME], evidence=_refs(runtime) | _refs(investigation))
    if affected and runtime.get("exploitation_relation", "not_observed") in {"not_observed", "monitoring_unavailable", "monitoring_missing"}:
        add("static_affected_without_observed_exploitation", "静态受影响与未观察到利用属于不同专业维度，不触发重研。",
            [], "dimension_difference", _refs(affected) | _refs(runtime))
    behavior = runtime.get("behavior_level")
    if behavior in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and resolved:
        specific_conflict = False
        for finding in resolved:
            supporting = [f for f in runtime.get("findings") or [] if isinstance(f, dict)
                          and _fresh_related(f, finding, state, len(findings) == 1)]
            if supporting:
                specific_conflict = True
                add("runtime_alert_vs_not_affected", f"{finding.get('cve_id', '当前候选')} 的新鲜漏洞特异运行时证据与不受影响/已修复结论矛盾。",
                    [AGENT_VULNERABILITY, AGENT_RUNTIME], evidence=_refs(finding) | _refs(supporting))
        if not specific_conflict:
            add("generic_runtime_alert_vs_static_resolution", "泛化、过期或未绑定当前 CVE 的运行时异常不推翻静态修复结论。",
                [], "dimension_difference", _refs(runtime) | _refs(resolved))
    if (baseline.get("preliminary_level") in {"High", "Critical"} and findings
            and len(resolved) == len(findings) and not all(proven_excluded(f) for f in resolved)):
        add("baseline_high_vs_all_findings_resolved", "高危基线与全部候选已修复/不受影响存在待核验的证据差异。",
            [AGENT_VULNERABILITY], evidence=_refs(resolved))
    if behavior in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and runtime.get("evidence_freshness") == "stale":
        add("stale_evidence_active_behavior", "历史告警只能说明历史行为；当前紧迫度需要新鲜证据。",
            [AGENT_RUNTIME], "fact_version", _refs(runtime))

    # A confident model answer cannot resolve incompatible official records.
    # Source disagreement must disappear from new deterministic evidence.
    for candidate in candidates:
        if (candidate.get("vendor_conflict") or {}).get("unresolved"):
            add("intelligence_source_conflict", f"{candidate.get('cve_id', '当前候选')} 的官方来源冲突仍由当前证据确认；明确结论不能代替新证据。",
                [AGENT_VULNERABILITY], evidence=_refs(candidate))
    for conflict in vulnerability.get("intelligence_conflicts") or []:
        add("intelligence_source_conflict", "漏洞分析记录了未解决的情报冲突，必须核对来源和作用范围。",
            [AGENT_VULNERABILITY], evidence=_refs(conflict))

    current_snapshot = state.get("evidence_snapshot_id") or (state.get("evidence_snapshot") or {}).get("snapshot_id")
    for role, provenance in (state.get("role_provenance") or {}).items():
        bound = provenance.get("valid_for_snapshot_id") or provenance.get("snapshot_id")
        if current_snapshot and bound and bound != current_snapshot and role in {AGENT_ASSET, AGENT_VULNERABILITY, AGENT_RUNTIME}:
            add("role_snapshot_version_mismatch", f"{role} 的结论绑定历史证据快照，需验证依赖是否失效。",
                [role], "fact_version", _refs(provenance))

    harness = state.get("harness_feedback") or {}
    if isinstance(harness, dict):
        for row in harness.get("feedback") or []:
            if row.get("terminal") or row.get("status") == "policy_denied":
                add("harness_safety_block", "Harness 安全策略拒绝候选意图；停止修复规划，不能通过反复提示绕过。",
                    [AGENT_DECISION], "safety_block", _refs(row))
            elif row.get("technical_status") in {"missing_artifact", "incompatible_version", "missing_recovery_point", "insufficient_evidence"}:
                add("harness_plan_infeasible", "Harness 发现修复产物、兼容性、恢复或依赖条件未满足，仅调整处置方案。",
                    [AGENT_DECISION], "plan_feasibility", _refs(row))
    major = any(item.category != "dimension_difference" for item in conflicts)
    return ConflictResultRecord(has_major_conflict=major, conflicts=conflicts,
                                rereview_count=0, unresolved=major)


def merge_rereview(previous: ConflictResultRecord, state_like: dict[str, Any]) -> ConflictResultRecord:
    """Re-evaluate evidence after bounded replay; agreement alone is not proof."""
    refreshed = detect_conflicts(state_like)
    return ConflictResultRecord(has_major_conflict=refreshed.has_major_conflict,
        conflicts=refreshed.conflicts, rereview_count=previous.rereview_count + 1,
        unresolved=refreshed.has_major_conflict)
