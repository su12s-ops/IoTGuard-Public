"""统一编排器兼容适配层测试（Stage 9B M4）。

覆盖：formal_sink 正式落库（fail-closed 语义与 System B 一致）、
auto_confirmed 可达路径、逐智能体审计记录、device_context_json 对账写回（F2/R1）、
run_review_analysis_unified 批量响应契约、/api/analysis 入口按开关切换。
"""
from __future__ import annotations

import copy
import json

from app import config, models
from app.services.unified.adapter import (
    UNIFIED_ADAPTER_VERSION,
    formal_sink,
    generate_and_save_report_unified,
    run_review_analysis_unified,
)
from app.services.unified.graph import RunContext, build_graph
from app.services.unified.agent_base import UsageMeter
from app.services.unified.state import empty_state
from tests.test_unified_pipeline import (
    GOOD_ASSET,
    GOOD_DECISION,
    GOOD_RUNTIME,
    GOOD_VULN,
    ScriptedClient,
    base_state,
    json_response,
    make_asset,
    make_evidence,
    run_graph,
)


def _setup_risk(session_factory, level="High", score=70.0, cve_id="CVE-2026-81001",
                package="nginx", installed="1.18.0", fixed="1.18.1"):
    db = session_factory()
    asset = db.query(models.LinuxAsset).filter_by(hostname="edge-01").one_or_none()
    if asset is None:
        asset = make_asset(db)
    if not db.query(models.SecurityEvidence).filter_by(evidence_id="SE-1").one_or_none():
        make_evidence(db, asset_id=asset.id)
    if db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).one_or_none() is None:
        vuln = models.VulnerabilityInfo(cve_id=cve_id, title="t", cvss_score=9.8,
                                        cvss_severity="Critical", affected_package=package,
                                        fixed_version=fixed, source="test",
                                        published_date="2026-01-01",
                                        last_modified_date="2026-01-02", description="d")
        db.add(vuln)
    match = db.query(models.VulnerabilityMatch).filter_by(
        asset_id=asset.id, cve_id=cve_id, package_name=package).one_or_none()
    if match is None:
        match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=cve_id,
                                          package_name=package, installed_version=installed,
                                          fixed_version=fixed,
                                          match_status="potentially_affected",
                                          affected=True, active=True, confidence=1.0)
        db.add(match)
        db.commit()
    risk = models.RiskAssessment(asset_id=asset.id, cve_id=cve_id,
                                 package_name=package, match_id=match.id,
                                 preliminary_score=score, preliminary_level=level,
                                 preliminary_decision="scheduled_fix", active=True,
                                 final_score=None, risk_level=None, decision=None,
                                 review_status="candidate")
    db.add(risk)
    db.commit()
    risk_id = risk.id
    db.close()
    return risk_id


def _make_run_row(session_factory, risk_id, run_id="UA-f1"):
    db = session_factory()
    row = models.UnifiedAnalysisRun(run_id=run_id, task_type="risk_review",
                                    target_type="linux_host", target_ref="edge-01",
                                    mode="formal", status="running", risk_id=risk_id)
    db.add(row)
    db.commit()
    row_pk = row.id
    db.close()
    return row_pk


FULL_SCRIPT = {
    "资产与证据调查员": [json_response(GOOD_ASSET)],
    "漏洞分析师": [json_response(GOOD_VULN)],
    "运行时分析师": [json_response(GOOD_RUNTIME)],
    "研判与处置规划师": [json_response(GOOD_DECISION)],
}


class TestFormalSink:
    def test_pending_review_written_fail_closed(self, session_factory, monkeypatch):
        import app.services.unified.runner as runner_mod
        monkeypatch.setattr(runner_mod, "SessionLocal", session_factory)
        risk_id = _setup_risk(session_factory)
        row_pk = _make_run_row(session_factory, risk_id)

        db = session_factory()
        row = db.get(models.UnifiedAnalysisRun, row_pk)
        runner_mod.run_unified_sync(db, row, client_factory=lambda: ScriptedClient(copy.deepcopy(FULL_SCRIPT)),
                                    sink=formal_sink)
        risk = db.get(models.RiskAssessment, risk_id)
        # High + immediate_fix + high priority → 门禁强制人工（与 System B 同语义）
        assert risk.review_status == "pending_human_review"
        assert risk.human_review_required is True
        assert risk.final_score is None
        assert risk.risk_level is None
        assert risk.decision is None
        assert risk.recommended_action == "immediate_fix"
        assert risk.risk_direction == "upgrade_minor"
        reasons = json.loads(risk.audit_policy_reasons)
        assert "high_or_critical_priority" in reasons
        assert "high_impact_operation_requires_human" in reasons
        # F2/R1 对账：设备级结论只读附加
        context = json.loads(risk.device_context_json)
        assert context["runtime_status"] == "verified"
        assert context["behavior_level"] == "ACTIVE"
        assert "SE-1" in context["evidence_ids"]
        # 逐智能体审计记录
        records = db.query(models.AgentAuditRecord).filter_by(risk_id=risk_id).all()
        assert {record.agent_name for record in records} == {
            "asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"}
        db.close()

    def test_auto_confirmed_reachable(self, session_factory, monkeypatch):
        """门禁全过时 auto_confirmed 仍可达（低危 + 高置信 + 证据充分）。"""
        import app.services.unified.runner as runner_mod
        monkeypatch.setattr(runner_mod, "SessionLocal", session_factory)
        risk_id = _setup_risk(session_factory, level="Medium", score=30.0)
        row_pk = _make_run_row(session_factory, risk_id, run_id="UA-f2")

        sufficient_asset = dict(GOOD_ASSET)
        sufficient_asset["evidence_quality"] = "sufficient"
        calm_decision = {
            "verdicts": [{"object_id": "risk-1", "impact_status": "potentially_affected",
                          "risk_direction": "maintain", "recommended_action": "monitor",
                          "recommended_priority": "low", "confidence": 0.95,
                          "supporting_evidence_ids": [], "reason": "证据充分，保持观察"}],
            "key_evidence_checks": [],
            "response_plan": {"risk_ref": "CVE-2026-81001", "rollback_plan": ["restore"]},
            "confidence": 0.9, "reason": "ok"}
        client = ScriptedClient({
            "资产与证据调查员": [json_response(sufficient_asset)],
            "漏洞分析师": [json_response(GOOD_VULN)],
            "运行时分析师": [json_response(GOOD_RUNTIME)],
            "研判与处置规划师": [json_response(calm_decision)],
        })
        db = session_factory()
        row = db.get(models.UnifiedAnalysisRun, row_pk)
        runner_mod.run_unified_sync(db, row, client_factory=lambda: client, sink=formal_sink)
        risk = db.get(models.RiskAssessment, risk_id)
        # 注意：GOOD_VULN 为 confirmed_affected + 0.8 置信，方向 maintain → 30 分；
        # simple 分层直通：decision 取规则基线的 preliminary_decision
        assert risk.review_status == "auto_confirmed"
        assert risk.final_score == 30.0
        assert risk.risk_level == "Medium"
        assert risk.decision == "scheduled_fix"
        db.close()


class TestBatchAdapter:
    def test_run_review_analysis_unified_shape_and_effects(self, session_factory, monkeypatch):
        import app.services.unified.runner as runner_mod
        monkeypatch.setattr(runner_mod, "SessionLocal", session_factory)
        risk_a = _setup_risk(session_factory, level="High", score=70.0)
        risk_b = _setup_risk(session_factory, level="Medium", score=45.0,
                             cve_id="CVE-2026-81002", package="curl",
                             installed="7.81.0", fixed="7.81.1")
        db = session_factory()
        risks = [db.get(models.RiskAssessment, risk_a), db.get(models.RiskAssessment, risk_b)]
        result = run_review_analysis_unified(db, "batch1", risks,
                                             client_factory=lambda: ScriptedClient(copy.deepcopy(FULL_SCRIPT)))
        db.close()
        # High（困难候选全量评审→人工门禁）+ Medium（simple 分层 0-LLM 直通）
        assert result["status"] == "partial"
        assert result["completed_object_count"] == 1
        assert result["human_review_object_count"] == 1
        assert result["selected_object_count"] == 2
        assert len(result["event_results"]) == 2
        assert all(event["pipeline_version"] == "unified-four-agent-v1"
                   for event in result["event_results"])
        assert len(result["unified_run_ids"]) == 2
        db = session_factory()
        risk_high = db.get(models.RiskAssessment, risk_a)
        risk_medium = db.get(models.RiskAssessment, risk_b)
        assert risk_high.review_status == "pending_human_review"
        assert risk_high.recommended_action == "immediate_fix"
        # Medium 简单分层：规则直通 auto_confirmed，结论来源显式标注
        assert risk_medium.review_status == "auto_confirmed"
        assert "rule_tier_simple" in json.loads(risk_medium.audit_policy_reasons)
        assert json.loads(risk_medium.device_context_json)["pipeline_version"] == "unified-four-agent-v1"
        db.close()

    def test_analysis_router_switches_by_flag(self, client, monkeypatch, session_factory):
        """flag=on 时 /api/analysis/runs 走统一适配层；off 时走原链路。"""
        from app import main
        monkeypatch.setattr(main, "SessionLocal", session_factory)
        monkeypatch.setattr(main, "init_db", lambda: None)
        monkeypatch.setattr("app.database.SessionLocal", session_factory)

        called = {"unified": 0, "legacy": 0}

        import app.routers.analysis as analysis_mod
        import app.services.unified.adapter as adapter_mod

        def fake_unified(db, run_id=None, background=True):
            called["unified"] += 1
            return {"run_id": run_id, "status": "no_candidates",
                    "pipeline_version": UNIFIED_ADAPTER_VERSION}

        monkeypatch.setattr(adapter_mod, "generate_and_save_report_unified", fake_unified)
        # 种一个候选，保证走到 _review_entrypoint（无候选时在入口前提前返回）
        risk_id = _setup_risk(session_factory, level="High", score=70.0)
        monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
        response = client.post("/api/analysis/runs")
        assert response.status_code == 200
        payload = response.json()
        assert payload["pipeline_version"] == UNIFIED_ADAPTER_VERSION
        assert called["unified"] == 1

        monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "off")
        response = client.post("/api/analysis/runs")
        assert response.status_code == 200
        assert called["unified"] == 1   # 未再增长（走了原链路）
