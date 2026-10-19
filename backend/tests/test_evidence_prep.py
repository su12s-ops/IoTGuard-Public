"""Stage 9B M4.1 校准专项回归：确定性证据预取 + 决策语义约束 + 兜底口径分离。

覆盖（校准任务书第二/三/四部分）：
- 分支适用性声明提取与装机分支比对（E3 语义，通用规则）；
- 确定性版本比较语义（X2：已修复不得被推翻）；
- 厂商适用性冲突预检（E4：装机/KEV 存在 ≠ 冲突消失）；
- EvidencePrepPacket 构建（有界、as_of、运行内复用语义）；
- 图集成：prepare_evidence 节点成功/失败降级、决策上下文携带预取事实；
- 决策校验的确定性语义约束（反馈重试不合规输出）；
- 审计门禁新增 fail-closed 理由（与 decide 校验同语义兜底）；
- 程序兜底裁定显式 program_fallback 标记（统计口径不得混入 LLM 准确率）。

全部使用假 LLM 客户端与隔离 SQLite，不触网、不触碰真实库。
"""
from __future__ import annotations

import json

import pytest

from app import models
from app.services.unified import audit_policy
from app.services.unified.evidence_prep import (
    build_evidence_prep_packet,
    check_branch_applicability,
    detect_vendor_conflict,
    extract_branch_statements,
)
from app.services.unified.graph import STAGE_TOPOLOGY, RunContext, build_graph
from app.services.unified.agent_base import UsageMeter
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
    """记录完整 messages 的假客户端；按角色返回响应序列（耗尽后重复最后一个）。"""

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


# ── 分支声明提取（E3 语义） ───────────────────────────────────────────────────


class TestBranchStatements:
    NVD_E3_STYLE = ("ASN.1 buffer overread. Affected branch: 3.1.0 before 3.1.7 only. "
                    "The 3.0.x LTS branch (including 3.0.2-0ubuntu1.x) is NOT affected.")

    def test_negative_statement_matching_installed_branch(self):
        statements = extract_branch_statements(self.NVD_E3_STYLE, "3.0.2-0ubuntu1.10")
        assert statements["negative_exclusions"], "装机分支 3.0.x 被显式排除必须被提取"
        assert any("NOT affected" in item for item in statements["negative_exclusions"])

    def test_negative_statement_other_branch_ignored(self):
        statements = extract_branch_statements(self.NVD_E3_STYLE, "3.1.5-1")
        assert not statements["negative_exclusions"]

    def test_branch_check_excluded(self):
        result = check_branch_applicability(
            [{"source": "nvd", "text": self.NVD_E3_STYLE}], "3.0.2-0ubuntu1.10")
        assert result["result"] == "branch_excluded"
        assert result["excluded_branch_statements"][0]["source"] == "nvd"

    def test_branch_check_in_range(self):
        result = check_branch_applicability(
            [{"source": "nvd",
              "text": "Affected branch: 3.1.0 before 3.1.7 only."}], "3.1.5-1")
        assert result["result"] == "in_stated_affected_range"

    def test_branch_check_undetermined_without_statements(self):
        result = check_branch_applicability(
            [{"source": "nvd", "text": "Buffer overread in ASN.1 parsing."}], "3.0.2")
        assert result["result"] == "undetermined"

    def test_version_branch_prefix_semantics(self):
        from app.services.unified.evidence_prep import _branch_matches
        assert _branch_matches("3.0.x", "3.0.2-0ubuntu1.10")
        assert _branch_matches("3.0.2", "3.0.2-0ubuntu1.10")
        assert not _branch_matches("3.1", "3.0.2-0ubuntu1.10")
        assert not _branch_matches("3.0", "3.1.0")


# ── 厂商适用性冲突预检（E4 语义） ─────────────────────────────────────────────


class TestVendorConflict:
    def test_under_investigation_vs_affected_is_unresolved(self):
        conflict = detect_vendor_conflict({
            "canonical": {"records": [{"release": "jammy", "status": "under_investigation"}]},
            "nvd": {"cpe_status": "affected"},
        })
        assert conflict["unresolved"] is True
        assert "canonical" in conflict["stances"]

    def test_aligned_affected_is_not_conflict(self):
        conflict = detect_vendor_conflict({
            "canonical": {"records": [{"release": "jammy", "status": "affected"}]},
            "nvd": {"cpe_status": "affected"},
        })
        assert conflict["unresolved"] is False

    def test_no_sources_no_conflict(self):
        assert detect_vendor_conflict({})["unresolved"] is False

    def test_release_scoped_single_record_detected(self):
        """实验实测缺陷回归：get_source_bundle 的 release 作用域 value 是单条
        选中记录（非 records 列表）——E4 的 under_investigation 曾因此漏检。"""
        bundle = {
            "canonical": {"source": "canonical", "status": "available",
                          "value": {"release": "jammy", "package": "openssl",
                                    "status": "under_investigation"},
                          "evidence": {"records": [{"release": "jammy",
                                                    "package": "openssl",
                                                    "status": "under_investigation"}]}},
            "nvd": {"source": "nvd", "status": "available",
                    "value": {"cpe_status": "affected"}, "evidence": {"cpe_status": "affected"}},
        }
        conflict = detect_vendor_conflict(bundle)
        assert conflict["unresolved"] is True
        assert conflict["stances"] == {"canonical": "under_investigation", "nvd": "affected"}


# ── 预取包构建 ────────────────────────────────────────────────────────────────


class TestPrepPacket:
    def _seed(self, db):
        asset = make_asset(db)
        # These tests assert distro-version facts, so supply a release-scoped
        # vendor record instead of accidentally treating 'unavailable' as proof.
        from app.services.vulnerability_intelligence.service import upsert_source_record
        upsert_source_record(db, "CVE-2026-83001", "canonical", {
            "records": [{"release": "jammy", "package": "nginx", "status": "released",
                         "fixed_version": "1.18.1"}]})
        make_evidence(db, evidence_id="SE-9", asset_id=asset.id)
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2026-83001:jammy", title="t", cvss_score=7.5,
            cvss_severity="High", affected_package="nginx",
            fixed_version="1.18.1", source="test", published_date="2026-01-01",
            last_modified_date="2026-01-02", description="d"))
        db.commit()
        return asset

    def test_packet_builds_with_deterministic_facts(self, session_factory):
        db = session_factory()
        self._seed(db)
        packet = build_evidence_prep_packet(db, "edge-01", "linux_host", [{
            "cve_id": "CVE-2026-83001:jammy", "package_name": "nginx",
            "installed_version": "1.18.0", "fixed_version": "1.18.1",
            "match_status": "potentially_affected"}])
        assert packet.as_of
        assert packet.reuse_note
        assert packet.candidates[0].version_compare["result"] == "affected"
        assert packet.candidates[0].branch_check["result"] == "undetermined"
        assert packet.runtime_facts.get("evidence_ids") == ["SE-9"]
        facts = packet.deterministic_facts()
        assert facts["available"] is True
        assert facts["version_compare"]["result"] == "affected"
        db.close()

    def test_fixed_version_semantics(self, session_factory):
        db = session_factory()
        self._seed(db)
        packet = build_evidence_prep_packet(db, "edge-01", "linux_host", [{
            "cve_id": "CVE-2026-83001:jammy", "package_name": "nginx",
            "installed_version": "1.18.2", "fixed_version": "1.18.1"}])
        assert packet.candidates[0].version_compare["result"] == "fixed"
        db.close()

    def test_branch_exclusion_flows_into_packet(self, session_factory):
        from app.services.vulnerability_intelligence.service import upsert_source_record
        db = session_factory()
        self._seed(db)
        upsert_source_record(db, "CVE-2026-83001", "nvd", {
            "cvss": {"score": 7.5, "severity": "High", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
            "description": ("Affected branch: 3.1.0 before 3.1.7 only. The 1.18.0.x branch "
                            "(including 1.18.0-0ubuntu1.x) is NOT affected."),
            "cpe_status": "affected"}, source_updated_at="2026-10-01T00:00:00Z")
        db.commit()
        packet = build_evidence_prep_packet(db, "edge-01", "linux_host", [{
            "cve_id": "CVE-2026-83001:jammy", "package_name": "nginx",
            "installed_version": "1.18.0-0ubuntu1.4", "fixed_version": "1.18.1"}])
        assert packet.candidates[0].branch_check["result"] == "branch_excluded"
        db.close()

    def test_packet_bounded_and_fail_open(self, session_factory):
        db = session_factory()
        self._seed(db)
        packet = build_evidence_prep_packet(db, "missing-host", "linux_host", [])
        assert packet.candidates == []
        assert packet.asset_facts == {} or not packet.asset_facts.get("profile")
        facts = packet.deterministic_facts()
        assert facts["version_compare"] == {"result": "unknown"}
        db.close()


# ── 图集成：prepare_evidence 节点 ─────────────────────────────────────────────


def run_graph(db_factory, state, client, trace_id="", risk=None):
    ctx = RunContext(db_factory=db_factory, trace_id=trace_id,
                     meter=UsageMeter(), client_factory=lambda: client, risk=risk)
    result = build_graph(ctx).invoke(state)
    if isinstance(result, dict):
        result = UnifiedAnalysisState.model_validate(result)
    return result, ctx


class TestPrepareEvidenceNode:
    def test_topology_has_prepare_evidence(self):
        assert STAGE_TOPOLOGY["prepare"] == ["prepare_evidence"]
        assert STAGE_TOPOLOGY["prepare_evidence"] == ["investigate_asset"]

    def test_node_populates_packet_and_stage(self, session_factory):
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        state = base_state()
        final, _ctx = run_graph(session_factory, state, client)
        assert final.stage_status.get("prepare_evidence") == "succeeded"
        assert final.evidence_prep and final.evidence_prep.get("as_of")
        assert final.stage_status["finalize"] == "succeeded"

    def test_agent_contexts_carry_prep_facts(self, session_factory):
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
        state = base_state()
        final, _ctx = run_graph(session_factory, state, client)
        assert final.evidence_prep  # 预取事实进入状态并供上下文引用
        sent_text = "\n".join(client.sent)
        assert "确定性预取事实" in sent_text          # 资产/漏洞/运行时上下文
        assert "deterministic_facts" in sent_text     # 决策上下文携带确定性事实
        assert "version_compare" in sent_text
        assert "不要重复查询已提供的基础事实" in sent_text

    def test_prep_failure_degrades_to_autonomous_tools(self, session_factory, monkeypatch):
        """预取节点失败不得击穿图：置空证据包并退回各角色自主工具查询。"""
        import app.services.unified.evidence_prep as prep_mod
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        monkeypatch.setattr(prep_mod, "build_evidence_prep_packet",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db hiccup")))
        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [json_response(GOOD_DECISION)],
        })
        state = base_state()
        final, _ctx = run_graph(session_factory, state, client)
        assert final.stage_status.get("prepare_evidence") == "failed"
        assert final.evidence_prep is None
        assert final.stage_status["finalize"] == "succeeded"


# ── 决策语义约束（通用安全语义，无案例编号） ──────────────────────────────────


def prep_packet_with(candidate_overrides: dict) -> dict:
    candidate = {
        "cve_id": "CVE-2026-83001", "package_name": "nginx",
        "installed_version": "1.18.0", "fixed_version": "1.18.1",
        "version_compare": {"result": "affected"},
        "branch_check": {"result": "undetermined"},
        "vendor_conflict": {"unresolved": False, "stances": {}},
        "intel_summary": {}, "matched_rows": 1,
    }
    candidate.update(candidate_overrides)
    return {"as_of": "2026-10-15T00:00:00Z", "target_ref": "edge-01",
            "target_type": "linux_host", "asset_facts": {}, "runtime_facts": {},
            "candidates": [candidate], "reuse_note": ["test"]}


class TestDecisionSemanticConstraints:
    STALE_EVIDENCE_TS = "2026-10-12T00:00:00Z"   # 3 天前 → 预取包新鲜度=stale

    def _seed_intel(self, db, *, branch_text=None, canonical_status=None):
        """按需写入多源情报记录（预取包将从 DB 构建这些确定性事实）。"""
        from app.services.vulnerability_intelligence.service import upsert_source_record
        if branch_text:
            upsert_source_record(db, "CVE-2026-81001", "nvd",
                                 {"description": branch_text, "cpe_status": "affected",
                                  "cvss": {"score": 9.8, "severity": "Critical"}},
                                 source_updated_at="2026-10-01T00:00:00Z")
        if canonical_status:
            upsert_source_record(db, "CVE-2026-81001", "canonical",
                                 {"records": [{"release": "jammy", "package": "nginx",
                                               "status": canonical_status,
                                               "fixed_version": "1.18.1"}]},
                                 source_updated_at="2026-10-01T00:00:00Z")
        db.commit()

    def _run_decide(self, session_factory, first_decision, second_decision=None,
                    installed="1.18.0", fixed="1.18.1", runtime=None,
                    seed=None):
        """全图运行：prepare_evidence 从 DB 构建预取包，决策违规必须收到语义反馈。

        DB 证据为过期时间戳（预取包 freshness=stale）；runtime 默认给
        schema 合法的 stale_verified 报告（NORMAL 行为，不触发 F6 拒绝）。
        """
        stale_runtime = {
            "behavior_level": "NORMAL", "runtime_status": "stale_verified",
            "evidence_freshness": "stale", "evidence_ids": ["SE-1"],
            "findings": [{"aspect": "process", "evidence_id": "SE-1",
                          "description": "三天前的进程观察"}],
            "confidence": 0.6}
        db = session_factory()
        make_asset(db)
        make_evidence(db, evidence_id="SE-1", timestamp=self.STALE_EVIDENCE_TS)
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2026-81001", title="t", cvss_score=9.8, cvss_severity="Critical",
            affected_package="nginx", fixed_version=fixed, source="test",
            published_date="2026-01-01", last_modified_date="2026-01-02", description="d"))
        db.commit()
        if seed:
            self._seed_intel(db, **seed)
        else:
            self._seed_intel(db, canonical_status="released")
        db.close()
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": runtime or stale_runtime,
            "研判与处置规划师": [first_decision, second_decision or GOOD_DECISION],
        })
        state = base_state()
        state.candidate_context = [{
            "cve_id": "CVE-2026-81001", "package_name": "nginx",
            "installed_version": installed, "fixed_version": fixed,
            "match_status": "potentially_affected"}]
        final, _ctx = run_graph(session_factory, state, client)
        return final, client

    def test_fixed_version_cannot_be_overridden(self, session_factory):
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0]["impact_status"] = "confirmed_affected"
        bad["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        good = json.loads(json.dumps(GOOD_DECISION))
        good["verdicts"][0]["impact_status"] = "not_affected"
        good["verdicts"][0]["recommended_action"] = "monitor"
        good["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        final, client = self._run_decide(
            session_factory, bad, second_decision=good,
            installed="1.18.2", fixed="1.18.1")   # 装机高于修复 → 确定性 fixed
        assert "不改变已修复事实" in "\n".join(client.sent)
        verdict = (final.decision or {}).get("verdicts")[0]
        assert verdict["impact_status"] == "not_affected"

    def test_branch_exclusion_blocks_confirmation(self, session_factory):
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        good = json.loads(json.dumps(GOOD_DECISION))
        good["verdicts"][0]["impact_status"] = "insufficient_evidence"
        good["verdicts"][0]["recommended_action"] = "collect_more_evidence"
        good["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        final, client = self._run_decide(
            session_factory, bad, second_decision=good,
            seed={"branch_text": ("Affected branch: 3.1.0 before 3.1.7 only. "
                                  "The 1.18.0.x branch (including 1.18.0-0ubuntu1.x) "
                                  "is NOT affected.")})
        assert "不得仅凭通用 NVD 候选匹配确认受影响" in "\n".join(client.sent)

    def test_unresolved_vendor_conflict_blocks_fix_action(self, session_factory):
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0]["recommended_action"] = "scheduled_fix"
        bad["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        good = json.loads(json.dumps(GOOD_DECISION))
        good["verdicts"][0]["recommended_action"] = "collect_more_evidence"
        good["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        final, client = self._run_decide(
            session_factory, bad, second_decision=good,
            seed={"canonical_status": "under_investigation",
                  "branch_text": "DoS via crafted X.509 certificate chain. Affected."})
        assert "不得直接进入修复处置" in "\n".join(client.sent)

    def test_stale_runtime_cannot_claim_fresh_urgency(self, session_factory):
        stale_report = {
            "behavior_level": "NORMAL", "runtime_status": "stale_verified",
            "evidence_freshness": "stale", "evidence_ids": ["SE-1"],
            "findings": [{"aspect": "process", "evidence_id": "SE-1", "description": "x"}],
            "confidence": 0.6}
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0]["urgency_basis"] = "fresh_runtime_evidence"
        good = json.loads(json.dumps(GOOD_DECISION))
        # M4.2（E2 整改）语义演进：本场景无确定性放大因子（无 KEV、无公网暴露×
        # CVSS≥9.0 组合），静态证据独立支撑的 immediate_fix 不再被接受——正确
        # 修正是降级为 scheduled_fix（原「static_evidence_only 维持 immediate_fix」
        # 为 M4.1 遗留整改项，已被 urgency_amplifiers 约束取代）
        good["verdicts"][0]["recommended_action"] = "scheduled_fix"
        good["verdicts"][0]["urgency_basis"] = "no_urgency_evidence"
        good["verdicts"][0]["reason"] = "运行时证据过期且无紧迫放大因子，降级排期处置"
        final, client = self._run_decide(session_factory, bad,
                                         runtime=stale_report, second_decision=good)
        assert "并非新鲜" in "\n".join(client.sent)
        verdict = (final.decision or {}).get("verdicts")[0]
        assert verdict["recommended_action"] == "scheduled_fix"

    def test_immediate_fix_requires_declared_urgency_basis(self, session_factory):
        bad = json.loads(json.dumps(GOOD_DECISION))
        bad["verdicts"][0].pop("urgency_basis", None)
        good = json.loads(json.dumps(GOOD_DECISION))
        good["verdicts"][0]["urgency_basis"] = "static_evidence_only"
        final, client = self._run_decide(session_factory, bad, second_decision=good)
        assert "必须显式声明 urgency_basis" in "\n".join(client.sent)

    def test_stale_runtime_does_not_imply_insufficient_applicability(self, session_factory):
        bad = {
            "verdicts": [{"object_id": "risk-1", "impact_status": "insufficient_evidence",
                          "risk_direction": "maintain", "recommended_action": "monitor",
                          "recommended_priority": "medium", "confidence": 0.6,
                          "reason": "运行时证据已过期，无法判断适用性"}],
            "confidence": 0.6}
        good = {
            "verdicts": [{"object_id": "risk-1", "impact_status": "potentially_affected",
                          "risk_direction": "maintain", "recommended_action": "monitor",
                          "recommended_priority": "medium", "confidence": 0.7,
                          "runtime_evidence_validity": "stale_verified",
                          "urgency_basis": "no_urgency_evidence",
                          "reason": "静态版本证据支持适用；运行时证据过期仅影响紧迫度"}],
            "confidence": 0.7}
        final, client = self._run_decide(session_factory, bad, second_decision=good)
        assert "不得直接推导为漏洞适用性不足" in "\n".join(client.sent)
        assert (final.decision or {}).get("verdicts")[0]["impact_status"] == "potentially_affected"

    def test_fresh_runtime_auto_normalizes_urgency_basis(self, session_factory):
        """运行时证据新鲜且模型未声明 urgency_basis → 程序归一（不反馈重试）。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()
        decision = json.loads(json.dumps(GOOD_DECISION))
        decision["verdicts"][0].pop("urgency_basis", None)
        client = FullRecorderClient({
            "资产与证据调查员": GOOD_ASSET,
            "漏洞分析师": GOOD_VULN,
            "运行时分析师": GOOD_RUNTIME,
            "研判与处置规划师": decision,
        })
        state = base_state()
        state.evidence_prep = prep_packet_with({})
        final, _ctx = run_graph(session_factory, state, client)
        assert final.stage_status["decide"] == "succeeded"
        verdict = (final.decision or {}).get("verdicts")[0]
        assert verdict["urgency_basis"] == "fresh_runtime_evidence"
        assert any("urgency_basis 由程序归一" in note
                   for note in (final.decision or {}).get("notes") or [])


# ── 审计门禁：确定性矛盾 fail-closed ─────────────────────────────────────────


class TestAuditPolicyContradictions:
    def _state(self, verdict_overrides: dict, prep_packet: dict | None,
               runtime_freshness="stale"):
        verdict = {"impact_status": "confirmed_affected", "risk_direction": "maintain",
                   "recommended_action": "immediate_fix", "recommended_priority": "high",
                   "confidence": 0.9, "urgency_basis": "fresh_runtime_evidence"}
        verdict.update(verdict_overrides)
        return {
            "baseline": {"preliminary_score": 70.0, "preliminary_level": "High",
                         "match_status": "potentially_affected", "installed_version": "1.18.0",
                         "fixed_version": "1.18.1", "business_level": "normal"},
            "degraded_roles": [],
            "investigation": {"evidence_quality": "sufficient"},
            "runtime": {"runtime_status": "not_observed", "evidence_freshness": runtime_freshness},
            "conflict_result": {},
            "decision": {"verdicts": [verdict]},
            "evidence_prep": prep_packet,
        }

    def test_branch_exclusion_contradiction_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {}, prep_packet_with({"branch_check": {"result": "branch_excluded"}}),
            runtime_freshness="fresh"))
        assert "branch_exclusion_contradiction" in decision.reasons
        assert decision.status == "pending_human_review"

    def test_fixed_override_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {}, prep_packet_with({"version_compare": {"result": "fixed"}}),
            runtime_freshness="fresh"))
        assert "deterministic_fixed_overridden" in decision.reasons

    def test_vendor_conflict_disposal_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {"recommended_action": "scheduled_fix", "urgency_basis": "static_evidence_only"},
            prep_packet_with({"vendor_conflict": {"unresolved": True, "stances": {}}}),
            runtime_freshness="fresh"))
        assert "vendor_conflict_unresolved_disposal" in decision.reasons

    def test_urgency_without_fresh_runtime_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {}, prep_packet_with({}), runtime_freshness="stale"))
        assert "urgency_claim_without_fresh_runtime" in decision.reasons

    def test_undeclared_urgency_basis_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {"urgency_basis": "unknown"}, prep_packet_with({}), runtime_freshness="stale"))
        assert "urgency_basis_undeclared" in decision.reasons

    def test_static_evidence_urgency_requires_human_not_banned(self):
        """静态证据独立支撑的紧急建议不被一刀切禁止，但必须人工复核。"""
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {"urgency_basis": "static_evidence_only"}, prep_packet_with({}),
            runtime_freshness="stale"))
        assert decision.status == "pending_human_review"
        assert "static_evidence_urgency_requires_human" in decision.reasons
        assert "urgency_claim_without_fresh_runtime" not in decision.reasons

    def test_stale_runtime_conflated_with_insufficient_gates(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {"impact_status": "insufficient_evidence", "recommended_action": "monitor",
             "urgency_basis": "no_urgency_evidence"},
            prep_packet_with({"version_compare": {"result": "affected"}}),
            runtime_freshness="stale"))
        assert "applicability_conflated_with_stale_runtime" in decision.reasons

    def test_compliant_verdict_adds_no_contradiction_reasons(self):
        decision = audit_policy.apply_unified_audit_policy(self._state(
            {"impact_status": "potentially_affected", "recommended_action": "monitor",
             "urgency_basis": "no_urgency_evidence"},
            prep_packet_with({}), runtime_freshness="stale"))
        for reason in ("branch_exclusion_contradiction", "deterministic_fixed_overridden",
                       "vendor_conflict_unresolved_disposal", "urgency_claim_without_fresh_runtime",
                       "urgency_basis_undeclared", "applicability_conflated_with_stale_runtime"):
            assert reason not in decision.reasons

    def test_program_fallback_verdict_skips_contradiction_checks(self):
        verdict = {"impact_status": "insufficient_evidence", "risk_direction": "maintain",
                   "recommended_action": "collect_more_evidence", "recommended_priority": "medium",
                   "confidence": 0, "program_fallback": True}
        state = self._state({}, prep_packet_with({"version_compare": {"result": "fixed"}}))
        state["decision"]["verdicts"] = [verdict]
        decision = audit_policy.apply_unified_audit_policy(state)
        assert "deterministic_fixed_overridden" not in decision.reasons


# ── 兜底口径分离（实验统计不得混入 LLM 准确率） ────────────────────────────────


class TestProgramFallbackMarker:
    def test_fallback_verdicts_carry_program_fallback_flag(self, session_factory):
        """决策持续失败 → 程序兜底裁定必须显式携带 program_fallback 标记。"""
        db = session_factory()
        make_asset(db)
        make_evidence(db)
        db.close()

        def always_invalid(messages):
            return {"verdicts": [], "confidence": 0.5}

        client = ScriptedClient({
            "资产与证据调查员": [json_response(GOOD_ASSET)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [always_invalid, always_invalid],
        })
        state = base_state()
        state.evidence_prep = prep_packet_with({})
        final, _ctx = run_graph(session_factory, state, client)
        verdicts = (final.decision or {}).get("verdicts") or []
        assert verdicts and verdicts[0].get("program_fallback") is True
        assert final.stage_status["decide"] == "failed"
