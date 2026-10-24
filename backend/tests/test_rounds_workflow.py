"""分析轮次（rounds）回归：一键发起（匹配→风险→研判）与工作台状态。

归档/重置语义由 test_experiment_lifecycle.py 覆盖；本文件只验证
/api/rounds/{current,start} 的契约：确定性执行、如实披露、唯一正式入口。
"""
from __future__ import annotations

from app import models


def _seed_round_data(session_factory):
    """一台 Ubuntu 资产 + 情报 + 受影响匹配 + 候选风险 + 已完成统一运行。"""
    db = session_factory()
    try:
        vuln = models.VulnerabilityInfo(
            cve_id="CVE-2099-0001", title="Sample", description="d",
            cvss_score=8.5, cvss_severity="High", affected_package="openssl",
            fixed_version="3.0.2-0ubuntu1.18", source="Ubuntu Security API",
        )
        asset = models.LinuxAsset(
            hostname="round-vm-01", distribution="ubuntu", os_version="24.04",
            exposure_level="public", business_level="core", inventory_complete=True,
        )
        db.add_all([vuln, asset])
        db.flush()
        db.add(models.AssetPackage(asset_id=asset.id, package_name="openssl",
                                   package_version="3.0.2-0ubuntu1.10"))
        match = models.VulnerabilityMatch(
            asset_id=asset.id, cve_id=vuln.cve_id, package_name="openssl",
            installed_version="3.0.2-0ubuntu1.10", fixed_version=vuln.fixed_version,
            affected=True, match_status="potentially_affected", active=True,
        )
        db.add(match)
        db.flush()
        risk = models.RiskAssessment(
            asset_id=asset.id, match_id=match.id, cve_id=vuln.cve_id,
            review_status="candidate", active=True, preliminary_score=70.0,
            preliminary_level="High", priority_rank=1,
        )
        db.add(risk)
        db.flush()
        run = models.UnifiedAnalysisRun(
            run_id="UA-TEST-round-0001", task_type="risk_review",
            target_ref=asset.hostname, mode="formal", status="completed",
            risk_id=risk.id, trace_id="tr-1",
        )
        db.add(run)
        db.commit()
        return {"asset_id": asset.id, "risk_id": risk.id, "run_id": run.run_id}
    finally:
        db.close()


def test_current_round_reports_devices_and_counts(client, session_factory):
    _seed_round_data(session_factory)
    current = client.get("/api/rounds/current").json()
    assert current["device_count"] == 1
    device = current["devices"][0]
    assert device["hostname"] == "round-vm-01"
    assert device["distribution"] == "ubuntu"
    assert device["package_count"] == 1
    assert device["active_matches"] == 1 and device["active_risks"] == 1
    assert current["active"]["unified_runs"] == 1
    assert current["active"]["candidates"] == 1
    assert current["active"]["running"] is False
    assert current["intel"]["vulnerability_count"] == 1
    assert "mode" in current["pipeline"] and "model_configured" in current["pipeline"]


def test_start_round_runs_matching_and_risk_engine(client, session_factory, control_headers, monkeypatch):
    ids = _seed_round_data(session_factory)
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "off")

    started = client.post("/api/rounds/start", headers=control_headers,
                          json={"asset_id": ids["asset_id"]})
    assert started.status_code == 200
    body = started.json()
    assert body["match_count"] >= 1 and body["risk_count"] == 1
    assert body["vulnerability_count"] == 1
    # 编排器关闭时如实披露，不静默
    assert body["review"] is None
    assert "formal_unified_mode_required" in (body["review_unavailable_reason"] or "")


def test_start_round_delegates_to_formal_entry(client, session_factory, control_headers, monkeypatch):
    ids = _seed_round_data(session_factory)
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    # The round now blocks before starting a doomed formal batch when the
    # deployment has no model credential. This test exercises delegation.
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")

    captured = {}

    def fake_create_run(retry_failed, risk_id, batch_size, post_repair, investigation_goal, db, asset_id):
        captured.update(batch_size=batch_size, risk_id=risk_id, post_repair=post_repair, asset_id=asset_id)
        return {"run_id": "UA-NEW-round-0001", "status": "running"}

    from app.routers import analysis as analysis_router
    monkeypatch.setattr(analysis_router, "create_run", fake_create_run)

    started = client.post("/api/rounds/start", headers=control_headers,
                          json={"asset_id": ids["asset_id"], "batch_size": 2})
    assert started.status_code == 200
    body = started.json()
    assert body["review"]["run_id"] == "UA-NEW-round-0001"
    assert body["review_unavailable_reason"] is None
    assert captured == {"batch_size": 2, "risk_id": 0, "post_repair": False, "asset_id": ids["asset_id"]}


def test_start_round_unknown_asset_rejected(client, session_factory, control_headers):
    _seed_round_data(session_factory)
    started = client.post("/api/rounds/start", headers=control_headers,
                          json={"asset_id": 9999})
    assert started.status_code == 404


def test_start_round_requires_control_token(client, session_factory):
    _seed_round_data(session_factory)
    response = client.post("/api/rounds/start", json={})
    assert response.status_code in (401, 503)
