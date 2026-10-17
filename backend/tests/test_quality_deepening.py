"""Stage 9B M4.2 研判深化专项回归。

覆盖（任务书第二/三/四/五/六部分）：
- Schema 深化：资产证据分级（verified/unverified/conflicting）、漏洞适用性
  专业维度（版本区间/分支/backport/公告特异性）、运行时证据关联语义
  （exploitation_relation 与逐条 relation）、决策四维分层（DimensionAssessment）；
- evidence_prep 深化：厂商补丁 backport 检测、紧迫度放大因子
  （KEV / 公网监听×CVSS≥9.0）、低于受影响区间下界检测、源立场矛盾扩展；
- 决策语义约束（E2/E3a 整改 + X2 加固 + 厂商 not_affected 优先）与
  审计门禁同语义 fail-closed 理由；
- 冲突规则 8：确定性核验事实与分析师结论矛盾 → 定向复议；
- 路由：证据不足候选与源立场矛盾候选不得 simple 直通；
- 语义消融钩子：ablation_mask 隐藏角色报告（决策输入侧，非失败路径）；
- Y1–Y10 独立测试集：Fixture 隔离性（一案例一事件）与真值表先验不变量、
  关键确定性事实（backport/区间/放大因子）落包。

全部使用假 LLM 客户端与隔离 SQLite，不触网、不触碰真实库。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Y 案例集位于 scripts/（实验脚本目录），确保可导入
_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from app import models
from app.services.unified import audit_policy, conflicts as conflicts_mod
from app.services.unified.agent_base import UsageMeter
from app.services.unified.evidence_prep import (
    build_evidence_prep_packet,
    check_branch_applicability,
    collect_stances,
    compute_urgency_amplifiers,
    detect_vendor_conflict,
    detect_vendor_patch_semantics,
)
from app.services.unified.graph import RunContext, build_graph, _decision_semantic_errors
from app.services.unified.routing import (
    _candidates_evidence_insufficient,
    decide_routing,
)
from app.services.unified.schemas import (
    AssetEvidenceReport,
    DecisionResponseReport,
    RuntimeAnalysisReport,
    VerdictItem,
)
from app.services.unified.state import TASK_RISK_REVIEW, UnifiedAnalysisState, empty_state

from tests.test_unified_pipeline import (  # 复用既有测试基建
    GOOD_ASSET,
    GOOD_DECISION,
    GOOD_RUNTIME,
    GOOD_VULN,
    ScriptedClient,
    base_state,
    json_response,
    make_asset,
    make_evidence,
)


class FullRecorderClient:
    """记录完整 messages 的假客户端；按角色返回响应序列。"""

    def __init__(self, response_by_role: dict[str, dict | list[dict]]):
        self.response_by_role = response_by_role
        self.sent: list[str] = []

    def complete(self, messages, tools=None):
        system = messages[0]["content"]
        self.sent.append(system + "\n||\n" + "\n".join(
            str(message.get("content") or "") for message in messages[1:]))
        for role, payload in self.response_by_role.items():
            if role in system:
                responses = payload if isinstance(payload, list) else [payload]
                chosen = responses.pop(0) if len(responses) > 1 else responses[0]
                return {"content": json.dumps(chosen, ensure_ascii=False), "tool_calls": []}
        return {"content": "{}", "tool_calls": []}


def run_graph(db_factory, state, client, trace_id="", risk=None, ablation_mask=frozenset()):
    ctx = RunContext(db_factory=db_factory, trace_id=trace_id,
                     meter=UsageMeter(), client_factory=lambda: client, risk=risk,
                     ablation_mask=frozenset(ablation_mask))
    result = build_graph(ctx).invoke(state)
    if isinstance(result, dict):
        result = UnifiedAnalysisState.model_validate(result)
    return result, ctx


# ── Schema 深化 ───────────────────────────────────────────────────────────────


class TestSchemaDeepening:
    def test_asset_evidence_grading_fields(self):
        report = AssetEvidenceReport.model_validate({
            "device_id": "edge-01",
            "verified_facts": [{"fact": "sshd 监听 22", "source": "query_network_surface"}],
            "unverified_observations": [{"item": "包清单可能不完整", "reason": "single_source"}],
            "conflicting_facts": [{"description": "两条情报源对适用性矛盾", "sources": ["nvd", "canonical"]}],
        })
        assert report.verified_facts[0].fact == "sshd 监听 22"
        assert report.unverified_observations[0].reason == "single_source"
        assert report.conflicting_facts[0].sources == ["nvd", "canonical"]

    def test_vulnerability_finding_professional_dimensions(self):
        from app.services.unified.schemas import VulnerabilityFinding
        finding = VulnerabilityFinding.model_validate({
            "cve_id": "CVE-2026-81010", "version_range_relation": "below_affected_range",
            "branch_relation": "vendor_branch_matches_advisory",
            "patch_semantics": "vendor_backport_applied",
            "advisory_specificity": "vendor_precise_match"})
        assert finding.version_range_relation == "below_affected_range"
        assert finding.patch_semantics == "vendor_backport_applied"

    def test_exploitation_relation_requires_supporting_findings(self):
        with pytest.raises(Exception, match="confirmed_exploitation"):
            RuntimeAnalysisReport.model_validate({
                "behavior_level": "NORMAL", "runtime_status": "contextual",
                "evidence_ids": ["SE-1"],
                "findings": [{"aspect": "process", "evidence_id": "SE-1",
                              "description": "仅组件存在", "relation": "component_present"}],
                "exploitation_relation": "confirmed_exploitation"})

    def test_exploitation_relation_supported_passes(self):
        report = RuntimeAnalysisReport.model_validate({
            "behavior_level": "SUSPICIOUS", "runtime_status": "verified",
            "evidence_freshness": "fresh", "evidence_ids": ["SE-1"],
            "findings": [{"aspect": "process", "evidence_id": "SE-1",
                          "description": "攻击链与候选模式一致",
                          "relation": "confirmed_exploitation", "observed_at": "2026-10-15T00:00:00Z",
                          "source_quality": "sensor_verified"}],
            "exploitation_relation": "confirmed_exploitation"})
        assert report.findings[0].relation == "confirmed_exploitation"
        assert report.findings[0].observed_at

    def test_verdict_dimension_assessments_independent(self):
        verdict = VerdictItem.model_validate({
            "object_id": "risk-1",
            "applicability_dimension": {"status": "established", "conclusion": "版本命中",
                                        "confidence": 0.9, "gaps": []},
            "runtime_dimension": {"status": "insufficient_evidence",
                                  "conclusion": "监控缺失", "gaps": ["无 eBPF 源"]},
            "exposure_dimension": {"status": "partial", "conclusion": "仅内网可达"},
            "unsatisfied_conditions": ["补丁尚未发布"]})
        assert verdict.applicability_dimension.status == "established"
        assert verdict.runtime_dimension.status == "insufficient_evidence"
        assert verdict.exposure_dimension.conclusion == "仅内网可达"
        assert verdict.unsatisfied_conditions == ["补丁尚未发布"]

    def test_follow_up_request_expected_effect(self):
        report = DecisionResponseReport.model_validate({
            "follow_up_requests": [{
                "target_agent": "runtime_analyst", "question": "是否观察到利用链？",
                "expected_effect": "确认后 urgency_basis 可取 fresh_runtime_evidence"}]})
        assert report.follow_up_requests[0].expected_effect

    def test_conflict_resolution_declarations(self):
        report = DecisionResponseReport.model_validate({
            "resolved_conflicts": ["分支排除与候选命中：以厂商公告为准"],
            "unresolved_conflicts": ["kylin 与 canonical 立场矛盾"]})
        assert report.resolved_conflicts and report.unresolved_conflicts


# ── evidence_prep 深化 ────────────────────────────────────────────────────────


class TestVendorPatchSemantics:
    def test_backport_detection(self):
        semantics = detect_vendor_patch_semantics({
            "canonical": {"records": [{"release": "jammy", "status": "not_affected",
                                       "note": "Fix was backported to 3.7.3-4ubuntu1.4 in jammy."}]},
        }, "3.7.3-4ubuntu1.4")
        assert semantics["release_status"] == "not_affected"
        assert semantics["backport"] is True

    def test_plain_not_affected_without_backport(self):
        semantics = detect_vendor_patch_semantics({
            "canonical": {"records": [{"release": "jammy", "status": "not_affected",
                                       "note": "jammy ships 2.6.8, predates 2.7.x line."}]},
        }, "2.6.8-1")
        assert semantics["release_status"] == "not_affected"
        assert semantics["backport"] is False

    def test_missing_advisory_is_explicit(self):
        semantics = detect_vendor_patch_semantics({}, "1.0")
        assert semantics["release_status"] == ""
        assert "不得据此下确定性结论" in semantics["note"]


class TestUrgencyAmplifiers:
    def test_kev_alone_is_amplifier(self):
        result = compute_urgency_amplifiers(
            {"kev": True, "cvss_score": 7.5}, public_services=[], package_name="nginx")
        assert result["kev"] is True and result["any_present"] is True

    def test_critical_public_component_matching_package(self):
        result = compute_urgency_amplifiers(
            {"kev": False, "cvss_score": 9.8},
            public_services=[{"port": 443, "service_name": "caddy",
                              "process_name": "caddy", "listen_address": "0.0.0.0"}],
            package_name="caddy")
        assert result["critical_public_component"] is True
        assert result["any_present"] is True

    def test_critical_public_nonmatching_package_not_amplifier(self):
        """客户端库（无监听服务）不算组件公网暴露——保守匹配规则。"""
        result = compute_urgency_amplifiers(
            {"kev": False, "cvss_score": 9.8},
            public_services=[{"port": 22, "service_name": "ssh",
                              "process_name": "sshd", "listen_address": "0.0.0.0"}],
            package_name="curl")
        assert result["critical_public_component"] is False
        assert result["any_present"] is False

    def test_high_cvss_public_below_threshold(self):
        result = compute_urgency_amplifiers(
            {"kev": False, "cvss_score": 8.8},
            public_services=[{"port": 22, "service_name": "dropbear",
                              "process_name": "dropbear", "listen_address": "0.0.0.0"}],
            package_name="dropbear")
        assert result["critical_public_component"] is False

    def test_no_amplifier_plain_static(self):
        result = compute_urgency_amplifiers(
            {"kev": False, "cvss_score": 8.1}, public_services=[], package_name="curl")
        assert result["any_present"] is False


class TestBranchBelowRange:
    def test_below_stated_range_detected(self):
        result = check_branch_applicability(
            [{"source": "nvd",
              "text": "Affected versions: 2.7.0 before 2.7.3 only."}], "2.6.8-1")
        assert result["result"] == "below_stated_affected_range"
        assert result["below_range_statements"]

    def test_in_range_still_works(self):
        result = check_branch_applicability(
            [{"source": "nvd",
              "text": "Affected versions: 2.7.0 before 2.7.3 only."}], "2.7.2-1")
        assert result["result"] == "in_stated_affected_range"


class TestStanceConflicts:
    def test_affected_vs_not_affected_is_conflict(self):
        conflict = detect_vendor_conflict({
            "canonical": {"records": [{"release": "jammy", "status": "affected"}]},
            "kylin": {"cpe_status": "not_affected"},
        })
        assert conflict["unresolved"] is True
        assert "not_affected" in conflict["description"]

    def test_collect_stances_reads_kylin(self):
        stances = collect_stances({
            "canonical": {"records": [{"status": "affected"}]},
            "nvd": {"cpe_status": "affected"},
            "kylin": {"cpe_status": "not_affected"},
        })
        assert stances == {"canonical": "affected", "nvd": "affected", "kylin": "not_affected"}


# ── 决策语义约束（E2/E3a 整改 + X2 加固 + 厂商优先） ──────────────────────────


def _facts(**overrides):
    facts = {
        "available": True,
        "version_compare": {"result": "affected"},
        "branch_check": {"result": "undetermined"},
        "vendor_conflict": {"unresolved": False},
        "vendor_patch": {"release_status": "", "backport": False},
        "urgency_amplifiers": {"any_present": False, "kev": False,
                               "critical_public_component": False},
    }
    facts.update(overrides)
    return facts


class TestDecisionSemanticConstraintsM42:
    def test_static_urgency_without_amplifier_rejected(self):
        """E2 整改：厂商 affected+高 CVSS+装机受影响的静态组合不得 immediate_fix。"""
        errors = _decision_semantic_errors(
            {"impact_status": "confirmed_affected", "recommended_action": "immediate_fix",
             "urgency_basis": "static_evidence_only"},
            _facts(), freshness="none")
        assert any("缺乏确定性放大因子" in error for error in errors)

    def test_static_urgency_with_amplifier_accepted(self):
        """Y6 语义：KEV 存在时静态紧迫性合法（不触发反馈重试）。"""
        errors = _decision_semantic_errors(
            {"impact_status": "confirmed_affected", "recommended_action": "immediate_fix",
             "urgency_basis": "static_evidence_only"},
            _facts(urgency_amplifiers={"any_present": True, "kev": True}), freshness="none")
        assert not any("放大因子" in error for error in errors)

    def test_static_urgency_constraint_only_for_applicable_impact(self):
        errors = _decision_semantic_errors(
            {"impact_status": "not_affected", "recommended_action": "immediate_fix",
             "urgency_basis": "static_evidence_only"},
            _facts(), freshness="none")
        assert not any("放大因子" in error for error in errors)

    def test_branch_exclusion_now_blocks_potentially(self):
        """E3a 整改：branch_excluded 与 potentially_affected 也算矛盾（不再只拦 confirmed）。"""
        errors = _decision_semantic_errors(
            {"impact_status": "potentially_affected", "recommended_action": "monitor"},
            _facts(branch_check={"result": "branch_excluded"}), freshness="none")
        assert any("potentially_affected 矛盾" in error for error in errors)

    def test_below_range_also_blocks(self):
        errors = _decision_semantic_errors(
            {"impact_status": "confirmed_affected", "recommended_action": "monitor"},
            _facts(branch_check={"result": "below_stated_affected_range"}), freshness="none")
        assert any("低于" in error or "排除" in error for error in errors)

    def test_fixed_disposal_contradiction(self):
        """X2 加固：已修复判定下不得给修复类处置。"""
        errors = _decision_semantic_errors(
            {"impact_status": "not_affected", "recommended_action": "scheduled_fix"},
            _facts(version_compare={"result": "fixed"}), freshness="none")
        assert any("修复类处置" in error for error in errors)

    def test_vendor_not_affected_overridden(self):
        errors = _decision_semantic_errors(
            {"impact_status": "potentially_affected", "recommended_action": "monitor"},
            _facts(vendor_patch={"release_status": "not_affected", "backport": True}),
            freshness="none")
        assert any("厂商精确公告" in error and "backport" in error for error in errors)


class TestAuditPolicyNewReasons:
    def _state(self, verdict, **candidate):
        prep_candidate = {
            "cve_id": "CVE-2026-83001", "branch_check": {"result": "undetermined"},
            "version_compare": {"result": "affected"},
            "vendor_conflict": {"unresolved": False},
            "vendor_patch": {"release_status": "", "backport": False},
            "urgency_amplifiers": {"any_present": False}}
        prep_candidate.update(candidate)
        return {
            "baseline": {"preliminary_score": 80, "installed_version": "1.0",
                         "fixed_version": "1.1", "match_status": "potentially_affected"},
            "degraded_roles": [], "conflict_result": {},
            "runtime": {"runtime_status": "not_observed", "evidence_freshness": "none"},
            "decision": {"verdicts": [verdict]},
            "evidence_prep": {"candidates": [prep_candidate]},
        }

    def test_static_urgency_without_amplifier_gates_human(self):
        state = self._state({"impact_status": "confirmed_affected",
                             "recommended_action": "immediate_fix",
                             "urgency_basis": "static_evidence_only", "confidence": 0.9})
        policy = audit_policy.apply_unified_audit_policy(state)
        assert "static_urgency_without_amplifier" in policy.reasons
        assert policy.status == "pending_human_review"

    def test_fixed_disposal_reason(self):
        state = self._state({"impact_status": "not_affected",
                             "recommended_action": "scheduled_fix",
                             "urgency_basis": "no_urgency_evidence", "confidence": 0.9},
                            version_compare={"result": "fixed"})
        policy = audit_policy.apply_unified_audit_policy(state)
        assert "fixed_disposal_contradiction" in policy.reasons

    def test_vendor_not_affected_override_reason(self):
        state = self._state({"impact_status": "potentially_affected",
                             "recommended_action": "monitor",
                             "urgency_basis": "no_urgency_evidence", "confidence": 0.9},
                            vendor_patch={"release_status": "not_affected", "backport": True})
        policy = audit_policy.apply_unified_audit_policy(state)
        assert "vendor_not_affected_overridden" in policy.reasons

    def test_branch_exclusion_covers_potentially(self):
        state = self._state({"impact_status": "potentially_affected",
                             "recommended_action": "monitor",
                             "urgency_basis": "no_urgency_evidence", "confidence": 0.9},
                            branch_check={"result": "branch_excluded"})
        policy = audit_policy.apply_unified_audit_policy(state)
        assert "branch_exclusion_contradiction" in policy.reasons


# ── 冲突规则 8：确定性事实 vs 分析师结论 ──────────────────────────────────────


class TestDeterministicFactConflict:
    def test_branch_exclusion_vs_analyst_conclusion_triggers_rereview(self):
        conflict = conflicts_mod.detect_conflicts({
            "baseline": {"match_status": "potentially_affected"},
            "vulnerability": {"findings": [{"cve_id": "CVE-1",
                                            "applicability": "potentially_affected",
                                            "confidence": 0.8}]},
            "evidence_prep": {"candidates": [
                {"branch_check": {"result": "branch_excluded"},
                 "version_compare": {"result": "affected"},
                 "vendor_patch": {"release_status": ""}}]},
        })
        codes = [item.code for item in conflict.conflicts]
        assert "deterministic_fact_vs_analyst_conclusion" in codes
        item = next(item for item in conflict.conflicts
                    if item.code == "deterministic_fact_vs_analyst_conclusion")
        assert "vulnerability_analyst" in item.involved_agents

    def test_agreeing_analyst_no_conflict(self):
        conflict = conflicts_mod.detect_conflicts({
            "baseline": {"match_status": "potentially_affected"},
            "vulnerability": {"findings": [{"cve_id": "CVE-1",
                                            "applicability": "not_affected"}]},
            "evidence_prep": {"candidates": [
                {"branch_check": {"result": "branch_excluded"},
                 "version_compare": {"result": "unknown"},
                 "vendor_patch": {"release_status": ""}}]},
        })
        codes = [item.code for item in conflict.conflicts]
        assert "deterministic_fact_vs_analyst_conclusion" not in codes


# ── 路由：证据不足与立场矛盾候选不得 simple 直通 ─────────────────────────────


class TestRoutingHardCases:
    def test_evidence_insufficient_candidates(self):
        assert _candidates_evidence_insufficient([
            {"match_status": "unknown", "installed_version": ""}]) is True
        assert _candidates_evidence_insufficient([
            {"match_status": "insufficient_data", "installed_version": "1.0"}]) is True
        assert _candidates_evidence_insufficient([
            {"match_status": "potentially_affected", "installed_version": "1.0"}]) is False

    def test_unconfirmed_component_routes_standard(self, session_factory):
        db = session_factory()
        asset = make_asset(db, inventory=False)
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81013",
                                     package_name="gnupg", preliminary_score=59,
                                     preliminary_level="Medium", active=True)
        db.add(risk)
        db.commit()
        routing = decide_routing(db, TASK_RISK_REVIEW, asset.hostname, "linux_host",
                                 risk=risk, candidates=[{
                                     "cve_id": "CVE-2026-81013", "package_name": "gnupg",
                                     "installed_version": "", "fixed_version": "1.1",
                                     "match_status": "unknown"}])
        assert routing.tier == "standard"
        db.close()

    def test_stance_conflict_routes_standard(self, session_factory):
        from app.services.vulnerability_intelligence.service import upsert_source_record
        db = session_factory()
        asset = make_asset(db)
        upsert_source_record(db, "CVE-2026-83002", "canonical",
                             {"records": [{"release": "jammy", "package": "nginx",
                                           "status": "not_affected"}]},
                             source_updated_at="2026-10-01T00:00:00Z")
        upsert_source_record(db, "CVE-2026-83002", "nvd",
                             {"cpe_status": "affected", "description": "x"},
                             source_updated_at="2026-10-01T00:00:00Z")
        db.commit()
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-83002:jammy",
                                     package_name="nginx", preliminary_score=55,
                                     preliminary_level="Medium", active=True)
        db.add(risk)
        db.commit()
        routing = decide_routing(db, TASK_RISK_REVIEW, asset.hostname, "linux_host",
                                 risk=risk, candidates=[{
                                     "cve_id": "CVE-2026-83002:jammy",
                                     "package_name": "nginx", "installed_version": "1.0",
                                     "fixed_version": "1.1",
                                     "match_status": "potentially_affected"}])
        assert routing.tier == "standard"
        db.close()


# ── 语义消融钩子 ──────────────────────────────────────────────────────────────


class TestSemanticAblationHook:
    def test_ablated_report_hidden_from_decision_input(self, session_factory):
        """隐藏运行时报告：决策上下文 runtime_report=None + 显式标注（非降级路径）。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        decision = json.loads(json.dumps(GOOD_DECISION))
        decision["verdicts"][0]["supporting_evidence_ids"] = []
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": GOOD_RUNTIME,
            "研判与处置规划师": decision,
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client,
                               ablation_mask=frozenset({"runtime_analyst"}))
        # 角色照常执行（不是失败/降级）
        assert "runtime_analyst" not in (final.degraded_roles or [])
        assert final.runtime is not None
        sent = "\n".join(client.sent)
        assert '"runtime_report": null' in sent
        assert '"semantic_ablation_masked"' in sent   # 决策上下文显式标注
        # 决策仍然完成（信息缺失下的研判），门禁兜底不因消融本身触发
        assert final.stage_status.get("decide") == "succeeded"

    def test_no_mask_by_default(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": GOOD_RUNTIME,
            "研判与处置规划师": GOOD_DECISION,
        })
        final, _ctx = run_graph(session_factory, base_state(), client)
        sent = "\n".join(client.sent)
        assert '"semantic_ablation_masked"' not in sent   # 上下文无消融标注
        assert '"runtime_report": null' not in sent
        assert final.stage_status.get("decide") == "succeeded"


# ── 决策上下文的分层提示与维度引用校验 ────────────────────────────────────────


class TestDecisionPromptAndValidation:
    def test_layered_model_prompt_present(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": GOOD_RUNTIME,
            "研判与处置规划师": GOOD_DECISION,
        })
        run_graph(session_factory, base_state(), client)
        sent = "\n".join(client.sent)
        assert "分层研判模型" in sent
        assert "applicability_dimension" in sent
        assert "不得因『分数已高不能再升』" in sent      # E1 方向语义
        assert "返回更多信息本身不构成提高置信度的依据" in sent   # 补查纪律

    def test_dimension_citation_hallucination_checked(self, session_factory):
        """维度支撑引用不存在 ID → 防幻觉反馈重试。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0]["applicability_dimension"] = {
            "status": "established", "supporting_evidence_ids": ["SE-FAKE-9"]}
        good = json.loads(json.dumps(GOOD_DECISION))
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": GOOD_RUNTIME,
            "研判与处置规划师": [bad, good],
        })
        final, _ctx = run_graph(session_factory, base_state(), client)
        sent = "\n".join(client.sent)
        assert "防幻觉校验失败" in sent
        assert final.stage_status.get("decide") == "succeeded"


# ── Y1–Y10 独立测试集：真值不变量 + Fixture 隔离性 + 关键事实 ────────────────


class TestYQualityCases:
    @pytest.fixture(scope="class")
    def y_db(self, tmp_path_factory):
        from tests.closure_fixture import build_fixture, fresh_session_factory
        from stage9b_quality_cases import extend_fixture_for_y_cases
        root = tmp_path_factory.mktemp("y-fixture")
        factory, engine = fresh_session_factory(root / "db")
        db = factory()
        build_fixture(db, with_runtime=True)
        extend_fixture_for_y_cases(db)
        yield db
        db.close()
        engine.dispose()

    def test_truth_table_invariants(self):
        from stage9b_quality_cases import Y_CASE_ORDER, Y_TRUTH
        assert set(Y_TRUTH.keys()) == set(Y_CASE_ORDER)
        for case, truth in Y_TRUTH.items():
            assert truth["impact"], case
            assert truth["actions"], case
            assert truth["directions"], case
            assert truth.get("label") and truth.get("acceptance"), case

    def test_each_case_exactly_one_active_risk(self, y_db):
        from stage9b_quality_cases import Y_CASE_ORDER
        for case in Y_CASE_ORDER:
            rows = y_db.query(models.RiskAssessment).filter(
                models.RiskAssessment.cve_id.like(f"{case}%"),
                models.RiskAssessment.active).all()
            assert len(rows) == 1, f"{case} 应恰有 1 条 active 风险（实际 {len(rows)}）"

    def test_all_y_cases_route_standard(self, y_db):
        from stage9b_quality_cases import Y_CASE_ORDER
        from app.services.unified import routing
        for case in Y_CASE_ORDER:
            risk = y_db.query(models.RiskAssessment).filter(
                models.RiskAssessment.cve_id.like(f"{case}%")).one()
            asset = y_db.get(models.LinuxAsset, risk.asset_id)
            match = y_db.get(models.VulnerabilityMatch, risk.match_id)
            decision = routing.decide_routing(
                y_db, TASK_RISK_REVIEW, asset.hostname, "linux_host", risk=risk,
                candidates=[{"cve_id": risk.cve_id, "package_name": risk.package_name,
                             "installed_version": match.installed_version,
                             "fixed_version": match.fixed_version,
                             "match_status": match.match_status}])
            assert decision.tier == "standard", f"{case} 应走全量评审层"

    def test_y1_backport_facts_flow_into_prep(self, y_db):
        packet = build_evidence_prep_packet(y_db, "edge-10", "linux_host", [{
            "cve_id": "CVE-2026-81010:jammy", "package_name": "gnutls28",
            "installed_version": "3.7.3-4ubuntu1.4", "fixed_version": "3.8.9",
            "match_status": "potentially_affected"}])
        candidate = packet.candidates[0]
        assert candidate.version_compare["result"] == "not_affected"
        assert candidate.version_compare["legacy_candidate_fixed_version"] == "3.8.9"
        assert candidate.fixed_version == ""
        assert candidate.vendor_patch["release_status"] == "not_affected"
        assert candidate.vendor_patch["backport"] is True

    def test_y2_below_range_excluded(self, y_db):
        packet = build_evidence_prep_packet(y_db, "edge-11", "linux_host", [{
            "cve_id": "CVE-2026-81011:jammy", "package_name": "haproxy",
            "installed_version": "2.6.8-1", "fixed_version": "2.7.3-1",
            "match_status": "potentially_affected"}])
        assert packet.candidates[0].branch_check["result"] in {
            "below_stated_affected_range", "branch_excluded"}
        assert packet.candidates[0].vendor_patch["release_status"] == "not_affected"

    def test_y6_amplifiers_present(self, y_db):
        packet = build_evidence_prep_packet(y_db, "edge-15", "linux_host", [{
            "cve_id": "CVE-2026-81015:jammy", "package_name": "caddy",
            "installed_version": "2.6.4-1", "fixed_version": "2.6.4-2",
            "match_status": "affected"}])
        amplifiers = packet.candidates[0].urgency_amplifiers
        assert amplifiers["kev"] is True
        assert amplifiers["critical_public_component"] is True
        assert amplifiers["any_present"] is True

    def test_y10_mitigated_has_no_amplifier(self, y_db):
        packet = build_evidence_prep_packet(y_db, "edge-19", "linux_host", [{
            "cve_id": "CVE-2026-81019:jammy", "package_name": "memcached",
            "installed_version": "1.6.14-1", "fixed_version": "1.6.15-1",
            "match_status": "affected"}])
        assert packet.candidates[0].urgency_amplifiers["any_present"] is False

    def test_e2_style_static_has_no_amplifier(self, y_db):
        """E2 复核：edge-01 curl 客户端包无放大因子（immediate+static 将被拦）。"""
        packet = build_evidence_prep_packet(y_db, "edge-01", "linux_host", [{
            "cve_id": "CVE-2026-81002:jammy", "package_name": "curl",
            "installed_version": "7.81.0-1ubuntu1.10", "fixed_version": "7.81.0-1ubuntu1.16",
            "match_status": "potentially_affected"}])
        assert packet.candidates[0].urgency_amplifiers["any_present"] is False

    def test_counterfactual_build_removes_kev(self, tmp_path_factory):
        from tests.closure_fixture import build_fixture, fresh_session_factory
        from stage9b_quality_cases import extend_fixture_for_y_cases
        root = tmp_path_factory.mktemp("y-cf")
        factory, engine = fresh_session_factory(root / "db")
        db = factory()
        build_fixture(db, with_runtime=True)
        extend_fixture_for_y_cases(db, y6_kev=False)
        packet = build_evidence_prep_packet(db, "edge-15", "linux_host", [{
            "cve_id": "CVE-2026-81015:jammy", "package_name": "caddy",
            "installed_version": "2.6.4-1", "fixed_version": "2.6.4-2",
            "match_status": "affected"}])
        amplifiers = packet.candidates[0].urgency_amplifiers
        assert amplifiers["kev"] is False
        # 公网+CVSS 9.8 仍在（Critical 公网组件独立成立）
        assert amplifiers["critical_public_component"] is True
        db.close()
        engine.dispose()
