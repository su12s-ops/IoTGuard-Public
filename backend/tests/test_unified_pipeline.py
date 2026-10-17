"""统一四智能体（Stage 9B）专项回归。

覆盖：输出 Schema 语义（F6 新鲜度）、字段预分拣（CF6 根因修复）、
带反馈重试（F3）、预算控制、路由分层（R8）、冲突检测（含跨 Agent 交叉）、
确定性门禁（fail-closed）、F5 聚合修复、图拓扑（并行/复议/补查有界）、
降级路径（F7 部分失败不全丢）、影子隔离（shadow 不触碰正式字段）、
run_unified_sync 全链路、统一 API、报告 F1 修复。

全部使用假 LLM 客户端与隔离 SQLite，不触网、不触碰真实库。
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import models
from app.services.unified import audit_policy, conflicts as conflicts_mod
from app.services.unified import aggregator, routing as routing_mod
from app.services.unified.agent_base import (
    BudgetExceeded,
    UnifiedToolLoopAgent,
    UsageMeter,
    triage_extra_fields,
    validation_error_summary,
)
from app.services.unified.agents_def import (
    ASSET_INVESTIGATOR_SPEC,
    DECISION_PLANNER_SPEC,
    RUNTIME_ANALYST_SPEC,
    VULNERABILITY_ANALYST_SPEC,
)
from app.services.unified.graph import STAGE_TOPOLOGY, RunContext, build_graph
from app.services.unified.schemas import (
    AssetEvidenceReport,
    DecisionResponseReport,
    RuntimeAnalysisReport,
    VulnerabilityAnalysisReport,
)
from app.services.unified.state import (
    TASK_RISK_REVIEW,
    UnifiedAnalysisState,
    empty_state,
)


# ── 测试基建 ─────────────────────────────────────────────────────────────────


def make_asset(db, hostname="edge-01", ip="192.0.2.10", distribution="ubuntu",
               exposure="public", business="core", inventory=True):
    asset = models.LinuxAsset(hostname=hostname, ip_address=ip, distribution=distribution,
                              os_version="22.04", exposure_level=exposure,
                              business_level=business, inventory_complete=inventory)
    db.add(asset)
    db.commit()
    return asset


def make_evidence(db, evidence_id="SE-1", device_id="edge-01", evidence_type="process",
                  process="sh", timestamp="2026-10-15T00:00:00Z", asset_id=None):
    row = models.SecurityEvidence(evidence_id=evidence_id, device_id=device_id,
                                  evidence_type=evidence_type, process=process,
                                  timestamp=timestamp, asset_id=asset_id)
    db.add(row)
    db.commit()
    return row


def base_state(**overrides):
    state = empty_state("UA-test", TASK_RISK_REVIEW, "edge-01", "linux_host", "shadow")
    state.candidate_context = [{
        "cve_id": "CVE-2026-81001", "package_name": "nginx",
        "installed_version": "1.18.0", "fixed_version": "1.18.1",
        "match_status": "potentially_affected"}]
    for key, value in overrides.items():
        setattr(state, key, value)
    return state


def run_graph(db_factory, state, client, trace_id="", risk=None):
    ctx = RunContext(db_factory=db_factory, trace_id=trace_id,
                     meter=UsageMeter(), client_factory=lambda: client, risk=risk)
    result = build_graph(ctx).invoke(state)
    if isinstance(result, dict):
        result = UnifiedAnalysisState.model_validate(result)
    return result, ctx


class ScriptedClient:
    """按角色脚本返回响应的假客户端；线程安全（并行节点共享）。"""

    def __init__(self, script: dict[str, list]):
        import threading
        self.script = script
        self.sent: list[str] = []
        self._lock = threading.Lock()

    def complete(self, messages, tools=None):
        system = messages[0]["content"]
        user = messages[-1]["content"]
        with self._lock:
            self.sent.append(system[:80] + "||" + user[:200])
            for key, responses in self.script.items():
                if key in system:
                    if not responses:
                        return {"content": "{}", "tool_calls": []}
                    response = responses.pop(0)
                    break
            else:
                return {"content": "{}", "tool_calls": []}
        if callable(response):
            response = response(messages)
        return response


def json_response(payload):
    return {"content": json.dumps(payload, ensure_ascii=False), "tool_calls": []}


GOOD_ASSET = {
    "device_id": "edge-01", "device_type": "server", "os": "Ubuntu 22.04",
    "services": [{"port": 443, "service_type": "nginx", "product": "nginx"}],
    "evidence_inventory": {"runtime_evidence_present": True, "evidence_freshness": "fresh"},
    "evidence_quality": "partial", "confidence": 0.7,
}

GOOD_VULN = {
    "findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8, "kev": True,
                  "version_impact": "affected", "applicability": "confirmed_affected",
                  "confidence": 0.8}],
    "max_observed_severity": "critical", "confidence": 0.75,
}

GOOD_RUNTIME = {
    "behavior_level": "ACTIVE", "runtime_status": "verified",
    "evidence_freshness": "fresh", "exposure_status": "internet_reachable",
    "evidence_ids": ["SE-1"],
    "findings": [{"aspect": "process", "evidence_id": "SE-1", "description": "nginx→sh"}],
    "confidence": 0.8,
}

GOOD_DECISION = {
    "verdicts": [{"object_id": "risk-1", "impact_status": "confirmed_affected",
                  "risk_direction": "upgrade_minor", "recommended_action": "immediate_fix",
                  "recommended_priority": "high", "confidence": 0.85,
                  "supporting_evidence_ids": ["SE-1"], "reason": "KEV+运行时证据"}],
    "key_evidence_checks": [{"evidence_id": "SE-1", "check": "存在性", "passed": True}],
    "response_plan": {"risk_ref": "CVE-2026-81001",
                      "actions": [{"action": "update_package", "target": "nginx",
                                   "rationale": "kev 受控利用"}],
                      "rollback_plan": ["restore_file 还原备份"]},
    "confidence": 0.8, "reason": "证据充分",
}


# ── Schema 语义 ──────────────────────────────────────────────────────────────


class TestSchemas:
    def test_field_triage_moves_unknown_keys_to_notes(self):
        parsed = {"device_id": "edge-01", "confidence": 0.6, "note": "Zephyr 无 eBPF 说明"}
        cleaned, moved = triage_extra_fields(parsed, AssetEvidenceReport)
        assert "note" not in cleaned
        assert any("note" in item for item in moved)
        assert any("note" in item for item in cleaned["notes"])
        report = AssetEvidenceReport.model_validate(cleaned)
        assert report.device_id == "edge-01"

    def test_runtime_stale_evidence_cannot_support_alert(self):
        # F6：过期证据不得支撑 ACTIVE 告警
        with pytest.raises(Exception, match="过期"):
            RuntimeAnalysisReport.model_validate({
                "behavior_level": "ACTIVE", "runtime_status": "stale_verified",
                "evidence_freshness": "stale", "evidence_ids": ["SE-1"],
                "findings": [{"aspect": "process", "evidence_id": "SE-1", "description": "x"}]})

    def test_runtime_verified_requires_fresh(self):
        with pytest.raises(Exception, match="verified"):
            RuntimeAnalysisReport.model_validate({
                "behavior_level": "NORMAL", "runtime_status": "verified",
                "evidence_freshness": "stale", "evidence_ids": ["SE-1"],
                "findings": [{"aspect": "process", "evidence_id": "SE-1", "description": "x"}]})

    def test_runtime_stale_verified_is_valid_path(self):
        report = RuntimeAnalysisReport.model_validate({
            "behavior_level": "NORMAL", "runtime_status": "stale_verified",
            "evidence_freshness": "stale", "evidence_ids": ["SE-1"],
            "findings": [{"aspect": "process", "evidence_id": "SE-1", "description": "x"}]})
        assert report.runtime_status == "stale_verified"

    def test_runtime_alert_requires_evidence(self):
        with pytest.raises(Exception, match="evidence_id"):
            RuntimeAnalysisReport.model_validate({"behavior_level": "ACTIVE"})

    def test_vulnerability_severity_cannot_exaggerate(self):
        with pytest.raises(Exception, match="夸大"):
            VulnerabilityAnalysisReport.model_validate({
                "findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 5.0}],
                "max_observed_severity": "critical"})

    def test_decision_follow_up_target_enum(self):
        with pytest.raises(Exception):
            DecisionResponseReport.model_validate({
                "follow_up_requests": [{"target_agent": "decision_planner", "question": "x"}]})

    def test_decision_response_plan_allows_whitelist_actions_only(self):
        with pytest.raises(Exception):
            DecisionResponseReport.model_validate({
                "response_plan": {"actions": [{"action": "run_shell", "target": "x",
                                               "rationale": "y"}]}})

    def test_decision_response_plan_bans_shell_params(self):
        with pytest.raises(Exception):
            DecisionResponseReport.model_validate({
                "response_plan": {"actions": [{"action": "update_package", "target": "nginx",
                                               "rationale": "x",
                                               "params": {"command": "rm -rf /"}}]}})

    def test_validation_error_summary_is_injective(self):
        try:
            RuntimeAnalysisReport.model_validate({"behavior_level": "ACTIVE"})
        except Exception as exc:
            summary = validation_error_summary(exc)
            assert "behavior_level" in summary
            assert len(summary) < 500


# ── 执行基座（F3 / 预算） ─────────────────────────────────────────────────────


class TestAgentBase:
    def _db(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        return db

    def test_retry_with_validation_feedback(self, session_factory):
        """F3：第一次输出非法（ACTIVE 无证据），错误摘要必须出现在第二次上下文。"""
        db = self._db(session_factory)
        calls = []

        def second_attempt_ok(messages):
            calls.append(messages[-1]["content"])
            return json_response(GOOD_RUNTIME)

        client = ScriptedClient({
            "运行时分析师": [json_response({"behavior_level": "ACTIVE", "evidence_ids": []}),
                             second_attempt_ok]})
        agent = UnifiedToolLoopAgent(RUNTIME_ANALYST_SPEC, client)
        result = agent.run(db, context="测试", deadline_s=30)
        db.close()
        assert result.status == "succeeded"
        assert result.attempts >= 1
        assert any("结构化校验" in text or "错误" in text for text in calls)

    def test_budget_exceeded_degrades(self, session_factory):
        db = self._db(session_factory)
        meter = UsageMeter(max_llm_calls=1)
        meter.register_call({"total_tokens": 1})
        meter.register_call({"total_tokens": 1})   # 超过上限 → 预算耗尽
        client = ScriptedClient({"运行时分析师": [json_response(GOOD_RUNTIME)]})
        agent = UnifiedToolLoopAgent(RUNTIME_ANALYST_SPEC, client, meter=meter)
        result = agent.run(db, context="测试", deadline_s=30)
        db.close()
        assert result.status == "degraded"
        assert "预算" in result.error

    def test_client_exception_degrades_not_crashes(self, session_factory):
        """实验修复 #1：客户端/解析异常必须走重试→降级，绝不击穿调用方（图节点）。"""
        db = self._db(session_factory)

        class ExplodingClient:
            def __init__(self):
                self.calls = 0

            def complete(self, messages, tools=None):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("simulated API outage")
                return json_response(GOOD_RUNTIME)

        agent = UnifiedToolLoopAgent(RUNTIME_ANALYST_SPEC, ExplodingClient())
        result = agent.run(db, context="测试", deadline_s=60)
        db.close()
        assert result.status == "succeeded"   # 异常消耗重试后恢复

        class AlwaysExploding:
            def complete(self, messages, tools=None):
                raise RuntimeError("simulated API outage")

        agent = UnifiedToolLoopAgent(RUNTIME_ANALYST_SPEC, AlwaysExploding())
        result = agent.run(db, context="测试", deadline_s=60)
        db.close()
        assert result.status == "failed"
        assert "RuntimeError" in result.error

    def test_tool_rejection_for_unregistered_tool(self, session_factory):
        db = self._db(session_factory)

        def respond_with_foreign_tool(messages):
            return {"content": "", "tool_calls": [
                {"id": "t1", "name": "query_cve_intelligence", "arguments": {}}]}

        client = ScriptedClient({
            "资产与证据调查员": [respond_with_foreign_tool, json_response(GOOD_ASSET)]})
        agent = UnifiedToolLoopAgent(ASSET_INVESTIGATOR_SPEC, client)
        result = agent.run(db, context="测试", deadline_s=30)
        db.close()
        assert result.status == "succeeded"
        assert result.tool_calls[0]["ok"] is False
        assert "未注册" in result.tool_calls[0]["error"]


# ── 路由分层 ─────────────────────────────────────────────────────────────────


class TestRouting:
    def test_simple_tier_skips_all_agents(self, session_factory):
        db = session_factory()
        asset = make_asset(db)
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81001",
                                     package_name="nginx", preliminary_score=45,
                                     preliminary_level="Medium", active=True)
        db.add(risk)
        db.commit()
        routing = routing_mod.decide_routing(db, TASK_RISK_REVIEW, "edge-01", "linux_host",
                                             risk=risk)
        db.close()
        assert routing.tier == "simple"
        assert routing.active_agents() == []

    def test_high_level_goes_full_review(self, session_factory):
        db = session_factory()
        asset = make_asset(db)
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81001",
                                     package_name="nginx", preliminary_score=75,
                                     preliminary_level="High", active=True)
        db.add(risk)
        db.commit()
        make_evidence(db)
        routing = routing_mod.decide_routing(db, TASK_RISK_REVIEW, "edge-01", "linux_host",
                                             risk=risk,
                                             candidates=[{"cve_id": "CVE-2026-81001"}])
        db.close()
        assert routing.tier == "standard"
        assert set(routing.active_agents()) == {
            "asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"}

    def test_capability_unsupported_skips_runtime(self, session_factory):
        db = session_factory()
        make_asset(db)
        routing = routing_mod.decide_routing(
            db, TASK_RISK_REVIEW, "zephyr-01", "device", risk=None,
            capability_marks={"unsupported": {"ebpf": True}},
            candidates=[{"cve_id": "CVE-2026-81001"}])
        db.close()
        assert routing.include_runtime is False
        assert "runtime_analyst" in routing.skipped_agents

    def test_no_runtime_evidence_skips_runtime(self, session_factory):
        db = session_factory()
        make_asset(db)
        routing = routing_mod.decide_routing(
            db, TASK_RISK_REVIEW, "edge-01", "linux_host", risk=None,
            candidates=[{"cve_id": "CVE-2026-81001"}])
        db.close()
        assert routing.include_runtime is False


# ── 冲突检测 ─────────────────────────────────────────────────────────────────


class TestConflicts:
    def test_match_vs_not_affected(self):
        result = conflicts_mod.detect_conflicts({
            "baseline": {"match_status": "potentially_affected"},
            "vulnerability": {"findings": [{"applicability": "not_affected"}]}})
        codes = [item.code for item in result.conflicts]
        assert "deterministic_match_vs_not_affected" in codes
        assert result.unresolved

    def test_runtime_alert_vs_not_affected_cross_conflict(self):
        # §7-7：运行时告警 vs 不受影响——必须冲突转人工，不允许自动压过
        result = conflicts_mod.detect_conflicts({
            "baseline": {},
            "runtime": {"behavior_level": "ACTIVE", "evidence_freshness": "fresh"},
            "vulnerability": {"findings": [{"applicability": "not_affected"}]}})
        codes = [item.code for item in result.conflicts]
        assert "runtime_alert_vs_not_affected" in codes

    def test_baseline_high_vs_all_resolved(self):
        result = conflicts_mod.detect_conflicts({
            "baseline": {"preliminary_level": "High"},
            "vulnerability": {"findings": [{"version_impact": "fixed"},
                                           {"version_impact": "not_affected"}]}})
        codes = [item.code for item in result.conflicts]
        assert "baseline_high_vs_all_findings_resolved" in codes

    def test_stale_evidence_alert(self):
        result = conflicts_mod.detect_conflicts({
            "baseline": {},
            "runtime": {"behavior_level": "ACTIVE", "evidence_freshness": "stale"}})
        codes = [item.code for item in result.conflicts]
        assert "stale_evidence_active_behavior" in codes

    def test_intelligence_conflict(self):
        result = conflicts_mod.detect_conflicts({
            "baseline": {},
            "vulnerability": {"findings": [],
                              "intelligence_conflicts": [{"sources": ["nvd", "canonical"],
                                                          "description": "矛盾"}]}})
        codes = [item.code for item in result.conflicts]
        assert "intelligence_source_conflict" in codes

    def test_no_conflict_on_aligned_state(self):
        result = conflicts_mod.detect_conflicts({
            "baseline": {"match_status": "potentially_affected"},
            "investigation": {"evidence_quality": "sufficient"},
            "vulnerability": {"findings": [{"applicability": "confirmed_affected",
                                            "confidence": 0.9}]},
            "runtime": {"behavior_level": "NORMAL", "evidence_freshness": "fresh"}})
        assert not result.has_major_conflict


# ── 审计门禁 ─────────────────────────────────────────────────────────────────


class TestAuditPolicy:
    def _baseline(self):
        return {"preliminary_score": 70.0, "preliminary_level": "High",
                "match_status": "potentially_affected", "installed_version": "1.18.0",
                "fixed_version": "1.18.1", "business_level": "normal"}

    def test_degraded_role_forces_human_review(self):
        decision = audit_policy.apply_unified_audit_policy({
            "baseline": self._baseline(),
            "degraded_roles": ["runtime_analyst"],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {},
            "conflict_result": {},
            "decision": {"verdicts": [{"risk_direction": "maintain",
                                       "recommended_action": "monitor",
                                       "recommended_priority": "medium",
                                       "impact_status": "potentially_affected",
                                       "confidence": 0.9}]}})
        assert decision.status == "pending_human_review"
        assert "agent_degraded:runtime_analyst" in decision.reasons

    def test_stale_verified_gates_auto_confirm(self):
        decision = audit_policy.apply_unified_audit_policy({
            "baseline": self._baseline(),
            "degraded_roles": [],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {"runtime_status": "stale_verified"},
            "conflict_result": {},
            "decision": {"verdicts": [{"risk_direction": "maintain",
                                       "recommended_action": "monitor",
                                       "recommended_priority": "low",
                                       "impact_status": "potentially_affected",
                                       "confidence": 0.9}]}})
        assert decision.status == "pending_human_review"
        assert "stale_runtime_evidence" in decision.reasons

    def test_bounded_direction_mapping_only(self):
        decision = audit_policy.apply_unified_audit_policy({
            "baseline": {**self._baseline(), "preliminary_score": 30.0,
                         "preliminary_level": "Medium"},
            "degraded_roles": [],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {"runtime_status": "not_observed"},
            "conflict_result": {},
            "decision": {"verdicts": [{"risk_direction": "upgrade_major", "risk_change_basis": "new relevant exposure compared to input.baseline",
                                       "recommended_action": "monitor",
                                       "recommended_priority": "low",
                                       "impact_status": "potentially_affected",
                                       "confidence": 0.95}]}})
        assert decision.adjustment == 20   # 有界映射
        assert decision.final_score == 50.0
        assert decision.final_level == "Medium"

    def test_low_confidence_gates(self):
        decision = audit_policy.apply_unified_audit_policy({
            "baseline": {**self._baseline(), "preliminary_level": "Medium",
                         "preliminary_score": 45},
            "degraded_roles": [],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {"runtime_status": "not_observed"},
            "conflict_result": {},
            "decision": {"verdicts": [{"risk_direction": "maintain",
                                       "recommended_action": "monitor",
                                       "recommended_priority": "low",
                                       "impact_status": "potentially_affected",
                                       "confidence": 0.4}]}})
        assert "confidence_below_0.70" in decision.reasons

    def test_unresolved_conflict_gates(self):
        decision = audit_policy.apply_unified_audit_policy({
            "baseline": self._baseline(),
            "degraded_roles": [],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {"runtime_status": "not_observed"},
            "conflict_result": {"unresolved": True},
            "decision": {"verdicts": [{"risk_direction": "maintain",
                                       "recommended_action": "monitor",
                                       "recommended_priority": "low",
                                       "impact_status": "potentially_affected",
                                       "confidence": 0.95}]}})
        assert "unresolved_major_conflict" in decision.reasons


# ── F5 聚合修复 ──────────────────────────────────────────────────────────────


class TestAggregator:
    def test_fixed_findings_excluded_from_baseline(self):
        result = aggregator.aggregate_device_risk(
            {"services": [{"port": 443}]},
            {"findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8,
                           "version_impact": "fixed"}]},
            {"behavior_level": "NORMAL"})
        # 已修复组件不得按 CVSS 9.8 计 40 分基线
        assert result["severity"] == "none"
        assert result["findings_excluded_f5"] == ["CVE-2026-81001"]
        assert "剔除" in result["rationale"]
        assert result["risk_score"] <= 10 + 2   # 暴露面单项

    def test_active_finding_and_kev_counted(self):
        result = aggregator.aggregate_device_risk(
            {"services": [{"port": 443}]},
            {"findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8, "kev": True,
                           "version_impact": "affected"}]},
            {"behavior_level": "ACTIVE", "runtime_status": "verified"})
        assert result["severity"] == "critical"
        assert result["kev"] is True
        assert result["risk_score"] == 40 + 10 + 8 + 2
        assert result["priority"] == "high"   # 60 分 ≥60 → high（critical 需 ≥80）

    def test_not_affected_excluded_but_affected_counted(self):
        result = aggregator.aggregate_device_risk(
            {"services": []},
            {"findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8,
                           "version_impact": "not_affected"},
                          {"cve_id": "CVE-2026-81002", "cvss_score": 7.5,
                           "version_impact": "affected"}]},
            {"behavior_level": "NORMAL"})
        assert result["severity"] == "high"   # 只计 affected 的 7.5
        assert result["findings_counted"] == 1


# ── 图拓扑 ───────────────────────────────────────────────────────────────────


class TestGraphTopology:
    def test_stage_topology_shape(self):
        assert STAGE_TOPOLOGY["investigate_asset"] == ["analyze_vulnerability", "analyze_runtime"]
        assert STAGE_TOPOLOGY["analyze_vulnerability"] == ["detect_conflicts"]
        assert STAGE_TOPOLOGY["analyze_runtime"] == ["detect_conflicts"]

    def test_parallel_error_writes_merge_not_crash(self, session_factory):
        """最终验收实验修复：并行节点并发写 error 必须 merge，不得 InvalidUpdateError。

        实验实测（E3 网络中断窗口）：state.py 中 error 字段被定义两次，
        普通注解覆盖了 Annotated reducer，A2∥A3 并发记录错误时整图崩溃
        （InvalidUpdateError: Can receive only one value per step）。
        """
        def reducer_of(field_name):
            metadata = UnifiedAnalysisState.model_fields[field_name].metadata
            callables = [item for item in metadata if callable(item)]
            assert callables, f"{field_name} 注解丢失 Annotated reducer（重复定义回归）"
            return callables[0]

        merge_error = reducer_of("error")
        assert merge_error("APIConnectionError: node A2", "APIConnectionError: node A3") == \
            "APIConnectionError: node A2; APIConnectionError: node A3"
        reducer_of("degraded_roles")    # merge_unique
        reducer_of("stage_status")      # merge_dict

    def test_decision_empty_verdicts_get_feedback_retry(self, session_factory):
        """最终验收实验修复：空 verdicts 不得静默计为成功（完备性反馈重试）。

        实验实测：规划师一次运行输出 verdicts=[]，旧路径通过校验，只能靠
        门禁 structured_result_incomplete 兜底转人工；现在必须先反馈重试。
        """
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [
                json_response({"verdicts": [], "confidence": 0.5,
                               "reason": "未给出裁定"}),
                json_response(GOOD_DECISION),   # 反馈重试后给出合法裁定
            ],
        })
        state = base_state()
        final, _ctx = run_graph(session_factory, state, client)
        assert final.decision and final.decision.get("verdicts")
        assert final.stage_status["decide"] == "succeeded"

    def test_decision_persistent_empty_verdicts_falls_back(self, session_factory):
        """持续输出空 verdicts → 程序兜底裁定 + 决策降级 + 门禁转人工。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [
                json_response({"verdicts": [], "confidence": 0.5}),
                json_response({"verdicts": [], "confidence": 0.5}),
            ],
        })
        state = base_state()
        final, _ctx = run_graph(session_factory, state, client)
        fallback_verdicts = (final.decision or {}).get("verdicts") or []
        assert fallback_verdicts, "程序兜底必须给出保底裁定"
        assert fallback_verdicts[0]["recommended_action"] == "collect_more_evidence"
        assert final.stage_status["decide"] == "failed"
        assert final.final["policy"]["status"] == "pending_human_review"

    def test_happy_path_parallel_and_followup(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        decision_calls = {"n": 0}

        def decide_first(messages):
            decision_calls["n"] += 1
            return json_response({
                "verdicts": [{"object_id": "edge-01", "impact_status": "confirmed_affected",
                              "risk_direction": "maintain", "recommended_action": "monitor",
                              "recommended_priority": "medium", "confidence": 0.5}],
                "follow_up_requests": [{"target_agent": "runtime_analyst",
                                        "question": "SE-1 的父进程是什么？"}],
                "confidence": 0.5, "reason": "需要补查"})

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME), json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [decide_first, json_response(GOOD_DECISION)],
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client)
        assert final.stage_status["analyze_vulnerability"] == "succeeded"
        assert final.stage_status["analyze_runtime"] == "succeeded"
        assert final.follow_ups_used == 1
        decide_calls = len([s for s in client.sent if s.startswith("你是研判与处置规划师")])
        assert decide_calls == 2                 # decide 恰好两轮（补查后复读）
        assert (final.decision or {}).get("key_evidence_checks")   # 第二轮产出为最终结果
        assert final.final["policy"]["status"] == "pending_human_review"
        assert final.final["plan"]["requires_approval"] is True

    def test_conflict_triggers_single_directed_rereview(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        vuln_calls = {"n": 0}

        def vuln_rereview(messages):
            vuln_calls["n"] += 1
            assert "定向复议" in messages[-1]["content"]
            # 维持「不受影响」原结论 → 冲突仍未消解 → 门禁转人工
            return json_response({
                "findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8, "kev": True,
                              "version_impact": "not_affected",
                              "applicability": "not_affected", "confidence": 0.8}],
                "max_observed_severity": "critical", "confidence": 0.75})

        def vuln_not_affected(messages):
            vuln_calls["n"] += 1
            return json_response({
                "findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8, "kev": True,
                              "version_impact": "not_affected",
                              "applicability": "not_affected", "confidence": 0.8}],
                "max_observed_severity": "critical", "confidence": 0.75})

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [vuln_not_affected, vuln_rereview],
            # 运行时分析师同为被牵连角色：主分析 + 复议（复议维持 ACTIVE 结论）
            "运行时分析师": [json_response(GOOD_RUNTIME), json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        state = base_state()
        state.baseline = {"match_status": "potentially_affected", "preliminary_level": "High",
                          "preliminary_score": 70, "installed_version": "1.18.0",
                          "fixed_version": "1.18.1", "packet_evidence_ids": ["SE-1"]}
        final, ctx = run_graph(session_factory, state, client)
        assert final.conflict_result.rereview_count == 1
        assert final.rereview_used == 1
        assert vuln_calls["n"] == 2             # 定向复议恰好一次
        assert final.final["policy"]["status"] == "pending_human_review"
        assert "unresolved_major_conflict" in final.final["policy"]["reasons"]

    def test_agent_failure_degrades_without_losing_others(self, session_factory):
        """F7：运行时分析师失败 → 保留其余角色意见 + 门禁强制人工。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()

        def invalid_runtime(seed):
            return json_response({"behavior_level": "ACTIVE", "evidence_ids": [],
                                  "data_gaps": [f"invalid-{seed}"]})

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            # 持续输出非法（告警却无证据；含 data_gaps 避免被判空默认）：
            # 主尝试×2 + 整体重试×2 全部非法 → 角色降级
            "运行时分析师": [invalid_runtime(1), invalid_runtime(2),
                             invalid_runtime(3), invalid_runtime(4)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client)
        assert "runtime_analyst" in final.degraded_roles
        assert final.vulnerability is not None            # 意见保留
        assert final.investigation is not None
        assert final.runtime_program_fallback["behavior_level"] == "NORMAL"
        assert final.final["policy"]["status"] == "pending_human_review"
        assert "agent_degraded:runtime_analyst" in final.final["policy"]["reasons"]

    def test_runtime_fabricated_evidence_degrades(self, session_factory):
        """防幻觉：两次均引用伪造 evidence_id → 剔除后不足以支撑告警 → 角色降级，
        程序按无证据处理（NORMAL，不虚增风险）。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db, evidence_id="SE-1")
        db.close()

        def fabricated(seed):
            return json_response({
                "behavior_level": "ACTIVE", "runtime_status": "verified",
                "evidence_freshness": "fresh",
                "evidence_ids": [f"SE-FAKE-{seed}"],
                "findings": [{"aspect": "process", "evidence_id": f"SE-FAKE-{seed}",
                              "description": "不存在的事件"}],
                "confidence": 0.8})

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [fabricated(1), fabricated(2)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client)
        assert "runtime_analyst" in final.degraded_roles
        assert final.runtime_program_fallback["behavior_level"] == "NORMAL"
        assert final.final["policy"]["status"] == "pending_human_review"

    def test_follow_up_failure_marks_degraded_but_finishes(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            # call1=主分析成功；call2=补查、call3=补查的反馈重试 → 均非法 → 补查失败
            "运行时分析师": [json_response(GOOD_RUNTIME),
                             json_response({"behavior_level": "ACTIVE"}),
                             json_response({"behavior_level": "BLOCKED", "findings": []})],
            "研判与处置规划师": [
                json_response({
                    "verdicts": [{"object_id": "edge-01", "impact_status": "confirmed_affected",
                                  "risk_direction": "maintain", "recommended_action": "monitor",
                                  "recommended_priority": "medium", "confidence": 0.5}],
                    "follow_up_requests": [{"target_agent": "runtime_analyst",
                                            "question": "补查"}],
                    "confidence": 0.5}),
                json_response(GOOD_DECISION),
            ],
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client)
        assert final.follow_ups_used == 1
        assert final.follow_up_results[0].get("error")
        assert "runtime_analyst" in final.degraded_roles

    def test_no_infinite_followup_loop(self, session_factory):
        db = session_factory()
        make_asset(db)
        db.close()
        decision_calls = {"n": 0}

        def always_request_followup(messages):
            decision_calls["n"] += 1
            return json_response({
                "verdicts": [{"object_id": "edge-01", "impact_status": "insufficient_evidence",
                              "risk_direction": "maintain",
                              "recommended_action": "collect_more_evidence",
                              "recommended_priority": "low", "confidence": 0.3}],
                "follow_up_requests": [{"target_agent": "asset_investigator",
                                        "question": "再查一次"}],
                "confidence": 0.3})

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [always_request_followup],
        })
        state = base_state()
        final, ctx = run_graph(session_factory, state, client)
        # 预算 1 轮补查后必须收敛：只允许一轮补查，且图正常走到 finalize
        assert final.follow_ups_used == 1
        assert final.stage_status["finalize"] == "succeeded"
        assert final.follow_up_results   # 补查确实执行过


# ── 全链路 runner（影子隔离 / 简单分层 / 落库） ───────────────────────────────


class TestRunner:
    def _make_risk_event(self, session_factory, level="High", score=70.0):
        db = session_factory()
        asset = make_asset(db)
        make_evidence(db, asset_id=asset.id)
        vuln = models.VulnerabilityInfo(cve_id="CVE-2026-81001", title="t",
                                        cvss_score=9.8, cvss_severity="Critical",
                                        affected_package="nginx", fixed_version="1.18.1",
                                        source="test", published_date="2026-01-01",
                                        last_modified_date="2026-01-02", description="d")
        db.add(vuln)
        match = models.VulnerabilityMatch(asset_id=asset.id, cve_id="CVE-2026-81001",
                                          package_name="nginx", installed_version="1.18.0",
                                          fixed_version="1.18.1", match_status="potentially_affected",
                                          affected=True, active=True, confidence=1.0)
        db.add(match)
        db.commit()
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81001",
                                     package_name="nginx", match_id=match.id,
                                     preliminary_score=score, preliminary_level=level,
                                     preliminary_decision="scheduled_fix", active=True,
                                     final_score=None, risk_level=None, decision=None)
        db.add(risk)
        db.commit()
        run_row = models.UnifiedAnalysisRun(
            run_id="UA-t1", task_type="risk_review", target_type="linux_host",
            target_ref="edge-01", mode="shadow", risk_id=risk.id)
        db.add(run_row)
        db.commit()
        row_pk = run_row.id
        db.close()
        return row_pk

    def test_shadow_run_persists_and_never_touches_formal_fields(self, session_factory, monkeypatch):
        import app.services.unified.runner as runner_mod
        monkeypatch.setattr(runner_mod, "SessionLocal", session_factory)
        row_id = self._make_risk_event(session_factory)
        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        db = session_factory()
        row = db.get(models.UnifiedAnalysisRun, row_id)
        # 影子隔离基线：运行前快照正式字段的全部当前值
        risk_before = db.get(models.RiskAssessment, row.risk_id)
        before = {key: getattr(risk_before, key) for key in
                  ("final_score", "risk_level", "decision", "review_status",
                   "review_reason", "human_review_required", "audit_policy_reasons",
                   "agent_results_json", "recommended_action", "risk_direction")}
        runner_mod.run_unified_sync(db, row, client_factory=lambda: client)
        db.refresh(row)
        assert row.status == "completed"
        assert row.pipeline_version == "unified-four-agent-v1"
        state = json.loads(row.state_json)
        policy = state["final"]["policy"]
        assert policy["status"] == "pending_human_review"   # High+immediate_fix 门禁
        # 影子隔离：正式字段逐项与运行前完全一致（未被影子运行触碰）
        risk = db.get(models.RiskAssessment, row.risk_id)
        for key, value in before.items():
            assert getattr(risk, key) == value, f"影子运行改动了正式字段 {key}"
        db.close()

    def test_simple_tier_zero_llm(self, session_factory, monkeypatch):
        import app.services.unified.runner as runner_mod
        monkeypatch.setattr(runner_mod, "SessionLocal", session_factory)
        db = session_factory()
        asset = make_asset(db)
        # M4.2：simple 层要求证据充分——无 match 行（装机版本未知）的候选按
        # 证据不足升全量评审，因此本测试必须带生产形态的 match 行
        match = models.VulnerabilityMatch(
            asset_id=asset.id, cve_id="CVE-2026-81099", package_name="curl",
            installed_version="7.81.0", fixed_version="7.81.1", affected=True,
            match_status="potentially_affected")
        db.add(match)
        db.flush()
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81099",
                                     package_name="curl", preliminary_score=45,
                                     preliminary_level="Medium", active=True,
                                     match_id=match.id)
        db.add(risk)
        db.commit()
        run_row = models.UnifiedAnalysisRun(
            run_id="UA-simple", task_type="risk_review", target_type="linux_host",
            target_ref="edge-01", mode="shadow", risk_id=risk.id)
        db.add(run_row)
        db.commit()
        row_pk = run_row.id
        db.close()

        def exploding_factory():
            raise AssertionError("simple 分层不允许任何 LLM 调用")

        db = session_factory()
        row = db.get(models.UnifiedAnalysisRun, row_pk)
        runner_mod.run_unified_sync(db, row, client_factory=exploding_factory)
        db.refresh(row)
        assert row.status == "completed"
        final = json.loads(row.state_json)["final"]
        assert final["rule_tier_simple"] is True
        assert final["usage"]["llm_calls"] == 0
        db.close()


# ── 统一 API ─────────────────────────────────────────────────────────────────


class TestUnifiedApi:
    def test_specs_endpoint(self, client):
        response = client.get("/api/unified/specs")
        assert response.status_code == 200
        payload = response.json()
        assert payload["pipeline_version"] == "unified-four-agent-v1"
        names = [agent["name"] for agent in payload["agents"]]
        assert names == ["asset_investigator", "vulnerability_analyst",
                         "runtime_analyst", "decision_planner"]
        tools = {agent["name"]: set(agent["tools"]) for agent in payload["agents"]}
        assert tools["decision_planner"] == set()   # 决策者无独立取证工具
        assert not tools["asset_investigator"] & tools["vulnerability_analyst"]

    def test_analyze_disabled_returns_503(self, client, monkeypatch):
        from app import config
        monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "off")
        response = client.post("/api/unified/analyze", json={"hostname": "edge-01"})
        assert response.status_code == 503

    def test_analyze_requires_known_target(self, client, monkeypatch, control_headers):
        from app import config
        monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "shadow")
        response = client.post("/api/unified/analyze",
                               json={"hostname": "missing-host", "task_type": "device_surface"})
        assert response.status_code in {401, 503}   # write-capable entry requires the control token
        response = client.post("/api/unified/analyze", headers=control_headers,
                               json={"hostname": "missing-host", "task_type": "device_surface"})
        assert response.status_code == 404

    def test_runs_listing(self, client):
        response = client.get("/api/unified/runs")
        assert response.status_code == 200
        assert response.json() == []

    def test_runs_listing_filters_by_risk_and_target(self, client, session_factory):
        """M4.3：风险详情/资产页按 risk_id、target_ref 关联影子运行（只读过滤）。"""
        db = session_factory()
        asset = make_asset(db, hostname="edge-filter")
        match = models.VulnerabilityMatch(
            asset_id=asset.id, cve_id="CVE-2026-81097", package_name="curl",
            installed_version="7.81.0", fixed_version="7.81.1", affected=True,
            match_status="potentially_affected")
        db.add(match)
        db.flush()
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-81097",
                                     package_name="curl", preliminary_score=45,
                                     preliminary_level="Medium", active=True,
                                     match_id=match.id)
        db.add(risk)
        db.commit()
        db.add(models.UnifiedAnalysisRun(
            run_id="UA-flt-1", task_type="risk_review", target_type="linux_host",
            target_ref="edge-filter", mode="shadow", risk_id=risk.id))
        db.add(models.UnifiedAnalysisRun(
            run_id="UA-flt-2", task_type="device_surface", target_type="device",
            target_ref="wrt-device", mode="shadow"))
        db.commit()
        risk_pk = risk.id
        db.close()

        listed = client.get("/api/unified/runs").json()
        assert {row["run_id"] for row in listed} >= {"UA-flt-1", "UA-flt-2"}

        by_risk = client.get("/api/unified/runs", params={"risk_id": risk_pk}).json()
        assert [row["run_id"] for row in by_risk] == ["UA-flt-1"]

        by_target = client.get("/api/unified/runs", params={"target_ref": "wrt-device"}).json()
        assert [row["run_id"] for row in by_target] == ["UA-flt-2"]

        by_mode = client.get("/api/unified/runs", params={"mode": "formal"}).json()
        assert by_mode == []

        combined = client.get("/api/unified/runs",
                              params={"risk_id": risk_pk, "mode": "shadow"}).json()
        assert [row["run_id"] for row in combined] == ["UA-flt-1"]


# ── F1 报告修复 ──────────────────────────────────────────────────────────────


class TestReportF1Fix:
    def test_markdown_report_survives_v3_list_opinions(self, session_factory):
        """F1（P0）：v3 管线存在时 markdown_report 不再崩溃。"""
        from app.services.report_service import markdown_report
        db = session_factory()
        make_asset(db)
        report = models.AnalysisReport(model="test", status="human_review",
                                       pipeline_version="per-risk-expert-audit-v3",
                                       verdict_json=json.dumps({"verdict": ""}),
                                       opinions_json=json.dumps([
                                           {"object_id": "risk-1",
                                            "coordinator": {"recommended_action": "monitor",
                                                            "confidence": 0.6},
                                            "audit_policy": {"status": "pending_human_review"}}]),
                                       review_run_id="r1")
        db.add(report)
        db.commit()
        text = markdown_report(db)
        db.close()
        assert "risk-1" in text
        assert "pending_human_review" in text

    def test_markdown_report_dict_opinions_still_renders(self, session_factory):
        from app.services.report_service import markdown_report
        db = session_factory()
        make_asset(db)
        report = models.AnalysisReport(model="test", status="completed",
                                       verdict_json="{}",
                                       opinions_json=json.dumps(
                                           {"impact_assessment_agent": "意见内容"}),
                                       review_run_id="r2")
        db.add(report)
        db.commit()
        text = markdown_report(db)
        db.close()
        assert "意见内容" in text


# ── Stage 10 效率优化回归（真实合同语义，不伪造指标） ──────────────────────────


def test_request_scoped_tool_cache_hits_within_run_and_resets_across_runs(session_factory, monkeypatch):
    """确定性工具在同意图内命中缓存；新运行必须重新查询（不跨运行泄漏）。"""
    db = session_factory()
    make_asset(db)
    make_evidence(db)
    db.close()
    target = next(t for t in VULNERABILITY_ANALYST_SPEC.tools if t.name == "query_version_impact")
    original_invoke = target.invoke
    calls = {"n": 0}
    vuln_llm_calls = {"n": 0}

    def counting(db_arg, arguments):
        calls["n"] += 1
        return original_invoke(db_arg, arguments)

    monkeypatch.setattr(target, "invoke", counting)

    def vuln_repeat_tool(messages):
        vuln_llm_calls["n"] += 1
        if vuln_llm_calls["n"] <= 2:   # 前两次 LLM 轮次发出完全相同的工具调用
            return {"content": "", "tool_calls": [
                {"id": "t1", "name": "query_version_impact",
                 "arguments": {"cve_id": "CVE-2026-81001",
                               "installed_version": "1.18.0", "fixed_version": "1.18.1"}}]}
        return json_response(GOOD_VULN)

    client = ScriptedClient({
        "资产与证据调查员": [json_response(GOOD_ASSET)],
        "漏洞分析师": [vuln_repeat_tool],
        "运行时分析师": [json_response(GOOD_RUNTIME)],
        "研判与处置规划师": [json_response(GOOD_DECISION)],
    })
    state = base_state()
    final, _ctx = run_graph(session_factory, state, client)
    assert final.stage_status["decide"] == "succeeded"
    assert calls["n"] == 1, "同一运行内相同参数的确定性工具必须命中缓存（handler 只执行一次）"

    # 新运行 = 新 RunContext：缓存不得跨运行泄漏，handler 重新执行
    second_run_llm = {"n": 0}

    def vuln_tool_once(messages):
        second_run_llm["n"] += 1
        if second_run_llm["n"] == 1:
            return {"content": "", "tool_calls": [
                {"id": "t2", "name": "query_version_impact",
                 "arguments": {"cve_id": "CVE-2026-81001",
                               "installed_version": "1.18.0", "fixed_version": "1.18.1"}}]}
        return json_response(GOOD_VULN)

    client2 = ScriptedClient({
        "资产与证据调查员": [json_response(GOOD_ASSET)],
        "漏洞分析师": [vuln_tool_once],
        "运行时分析师": [json_response(GOOD_RUNTIME)],
        "研判与处置规划师": [json_response(GOOD_DECISION)],
    })
    run_graph(session_factory, base_state(), client2)
    assert calls["n"] == 2, "新运行必须重新查询（缓存不跨运行泄漏）"


def test_runtime_tools_are_never_cached():
    """运行时证据事实可能运行中途到达新事件：时间敏感工具不得进入缓存。"""
    from app.services.unified.agent_base import CACHEABLE_TOOLS
    runtime_tool_names = {t.name for t in RUNTIME_ANALYST_SPEC.tools}
    assert runtime_tool_names.isdisjoint(CACHEABLE_TOOLS)


def test_inventory_only_followups_skip_rereading_decision(session_factory):
    """全部补查申请均为 inventory（操作员门控、本轮必然无新证据）时：
    不再执行补查与完整决策重跑；申请仍随 finalize 登记。"""
    db = session_factory()
    make_asset(db)
    make_evidence(db)
    db.close()
    decide_calls = {"n": 0}

    def decide_with_inventory_request(messages):
        decide_calls["n"] += 1
        return json_response({
            "verdicts": [{"object_id": "edge-01", "impact_status": "potentially_affected",
                          "risk_direction": "maintain", "recommended_action": "monitor",
                          "recommended_priority": "medium", "confidence": 0.5}],
            "follow_up_requests": [{"target_agent": "vulnerability_analyst",
                                    "collection_capability": "inventory",
                                    "question": "补充包依赖链接数据",
                                    "expected_effect": "明确 libcurl 依赖来源"}],
            "confidence": 0.5, "reason": "待操作员授权采集"})

    client = ScriptedClient({
        "资产与证据调查员": [json_response(GOOD_ASSET)],
        "漏洞分析师": [json_response(GOOD_VULN)],
        "运行时分析师": [json_response(GOOD_RUNTIME)],
        "研判与处置规划师": [decide_with_inventory_request],
    })
    final, _ctx = run_graph(session_factory, base_state(), client)
    assert decide_calls["n"] == 1, "inventory-only 补查不得触发第二次完整决策"
    assert final.follow_ups_used == 0
    assert "execute_follow_ups" not in final.stage_status
    assert final.decision.get("follow_up_requests"), "申请本身必须保留在决策结果中"


def test_targeted_evidence_followup_still_runs_full_loop(session_factory):
    """针对既有证据的定向复查（target_agent）保留原路径：补查 + 第二次决策。"""
    db = session_factory()
    make_asset(db)
    make_evidence(db)
    db.close()
    decide_calls = {"n": 0}

    def decide_first(messages):
        decide_calls["n"] += 1
        return json_response({
            "verdicts": [{"object_id": "edge-01", "impact_status": "potentially_affected",
                          "risk_direction": "maintain", "recommended_action": "monitor",
                          "recommended_priority": "medium", "confidence": 0.5}],
            "follow_up_requests": [{"target_agent": "runtime_analyst",
                                    "question": "SE-1 的父进程是什么？"}],
            "confidence": 0.5, "reason": "需要补查"})

    client = ScriptedClient({
        "资产与证据调查员": [json_response(GOOD_ASSET)],
        "漏洞分析师": [json_response(GOOD_VULN)],
        "运行时分析师": [json_response(GOOD_RUNTIME), json_response(GOOD_RUNTIME)],
        "研判与处置规划师": [decide_first, json_response(GOOD_DECISION)],
    })
    final, _ctx = run_graph(session_factory, base_state(), client)
    decide_llm_calls = len([s for s in client.sent if s.startswith("你是研判与处置规划师")])
    assert decide_llm_calls == 2
    assert final.follow_ups_used == 1


def test_rereview_inherits_full_context_and_failure_keeps_original(session_factory):
    """定向复议必须继承角色首次运行上下文；复议失败时保留原结论且不降级该角色。"""
    db = session_factory()
    make_asset(db)
    make_evidence(db)
    db.close()
    seen_contexts = {"original": "", "rereview": ""}

    def vuln_not_affected(messages):
        seen_contexts["original"] = messages[-1]["content"]
        return json_response({
            "findings": [{"cve_id": "CVE-2026-81001", "cvss_score": 9.8, "kev": True,
                          "version_impact": "not_affected",
                          "applicability": "not_affected", "confidence": 0.8}],
            "max_observed_severity": "critical", "confidence": 0.75})

    def vuln_rereview_fails(messages):
        seen_contexts["rereview"] = messages[-1]["content"]
        return {"content": "not json at all", "tool_calls": []}

    client = ScriptedClient({
        "资产与证据调查员": [json_response(GOOD_ASSET)],
        "漏洞分析师": [vuln_not_affected, vuln_rereview_fails],
        "运行时分析师": [json_response(GOOD_RUNTIME)],
        "研判与处置规划师": [json_response(GOOD_DECISION)],
    })
    state = base_state()
    state.baseline = {"match_status": "potentially_affected", "preliminary_level": "High",
                      "preliminary_score": 70, "installed_version": "1.18.0",
                      "fixed_version": "1.18.1", "packet_evidence_ids": ["SE-1"]}
    final, ctx = run_graph(session_factory, state, client)
    # 复议上下文继承首次运行上下文（不是从零开始的裸冲突描述）
    assert "定向复议" in seen_contexts["rereview"]
    assert seen_contexts["original"] and seen_contexts["original"] in seen_contexts["rereview"]
    # 复议失败：保留原结论，原角色不被追加降级
    assert "vulnerability_analyst" not in (final.degraded_roles or [])
    assert final.vulnerability and final.vulnerability.get("findings")
    assert final.conflict_result.rereview_count == 1
    assert final.conflict_result.unresolved, "未消解冲突仍走人工复核"
