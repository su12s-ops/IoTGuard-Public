import json
import pytest
from pathlib import Path

from app import models

from app.services import result_archive


def _seed(db):
    asset = models.LinuxAsset(hostname="lifecycle-host", distribution="ubuntu", os_version="24.04")
    db.add(asset)
    db.flush()
    db.add(models.AssetPackage(asset_id=asset.id, package_name="nginx", package_version="1.0"))
    db.add(models.AssetService(asset_id=asset.id, service_name="nginx", port=80))
    db.add(models.IotDevice(device_id="cam-1", device_name="Camera-1", ip="192.0.2.10", risk_score=80, security_status="risk"))
    db.add(models.VulnerabilityInfo(cve_id="CVE-2099-0001", title="Test advisory", affected_package="nginx"))
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id="CVE-2099-0001", package_name="nginx")
    db.add(match)
    db.flush()
    risk = models.RiskAssessment(
        match_id=match.id, asset_id=asset.id, cve_id="CVE-2099-0001", package_name="nginx",
        preliminary_score=80, preliminary_level="High",
    )
    db.add(risk)
    db.flush()
    db.add(models.RemediationTask(
        risk_id=risk.id, asset_id=asset.id, cve_id="CVE-2099-0001", package_name="nginx", status="pending"
    ))
    db.add(models.AnalysisReport(review_run_id="run-lifecycle", status="completed"))
    db.add(models.AgentAuditRecord(
        run_id="run-lifecycle", risk_id=risk.id, object_id=f"risk-{risk.id}",
        agent_name="evidence_audit_agent", parse_status="valid",
    ))
    db.add(models.RuntimeEvent(asset_id=asset.id, hostname=asset.hostname, event_type="process", category="process_execution"))
    db.add(models.UnifiedAnalysisRun(run_id="UA-LIFECYCLE", target_ref="lifecycle-host", status="completed"))
    db.add(models.HarnessRun(id="harness-lifecycle-0000000000000001", asset_id=asset.id, status="verified"))
    db.add(models.ScanTarget(name="lab", ip_address="192.0.2.10", authorization_basis="test"))
    db.flush()
    scan_target = db.query(models.ScanTarget).first()
    db.add(models.ScanRun(run_id="scan-lifecycle", target_id=scan_target.id, status="completed"))
    db.add(models.TraceRun(trace_id="TR-LIFECYCLE", task_type="test"))
    db.commit()
    return asset


def test_state_lists_kept_and_derived_counts(client, session_factory):
    db = session_factory()
    _seed(db)
    db.close()

    response = client.get("/api/experiment/state")
    assert response.status_code == 200
    body = response.json()
    assert body["kept"]["linux_asset"] == 1
    assert body["kept"]["iot_device"] == 1
    assert body["derived"]["risk_assessment"] == 1
    assert body["derived"]["runtime_event"] == 1
    assert body["summary"]["assets"] == 1
    assert body["summary"]["high_risks"] == 1


def test_archive_keeps_results_but_not_raw_runtime_events(client, session_factory, control_headers):
    db = session_factory()
    _seed(db)
    db.close()

    response = client.post("/api/experiment/archive", json={"label": "单元测试结果"}, headers=control_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    archive_path = result_archive.archive_dir() / body["filename"]
    assert archive_path.is_file()
    payload = json.loads(archive_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["label"] == "单元测试结果"
    assert len(payload["risks"]) == 1
    assert payload["summary"]["high_risks"] == 1
    assert "runtime_event" not in payload
    assert payload["runtime"]["event_count"] == 1
    assert (archive_path.parent / f"{archive_path.stem}.meta.json").is_file()


@pytest.mark.parametrize("console_refresh", [False, True, "proxy"])
def test_reset_archives_then_clears_derived_data_and_keeps_devices(client, session_factory, control_headers, console_refresh):
    db = session_factory()
    _seed(db)
    db.close()

    response = client.post(
        "/api/experiment/refresh" if console_refresh else "/api/experiment/reset",
        json={"label": "新一轮", "archive": False} if console_refresh else {"label": "新一轮"},
        headers={"X-Experiment-Action": "refresh",
                 "Host": "127.0.0.1:18080" if console_refresh == "proxy" else "testserver",
                 "Origin": "http://127.0.0.1:18080" if console_refresh == "proxy" else "http://testserver"}
        if console_refresh else control_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if not console_refresh:
        assert body["archive"]["filename"].startswith("exp-")
    else:
        assert "archive" not in body
    assert body["kept"]["assets"] == 1
    assert body["kept"]["iot_devices"] == 1

    db = session_factory()
    try:
        assert db.query(models.LinuxAsset).count() == 1
        assert db.query(models.AssetPackage).count() == 1
        assert db.query(models.IotDevice).count() == 1
        device = db.query(models.IotDevice).one()
        assert device.risk_score == 0
        assert device.security_status == "unassessed"
        assert db.query(models.ScanTarget).count() == 1
        assert db.query(models.ScanTarget).one().last_run_id is None
        assert db.query(models.VulnerabilityInfo).count() == 0
        assert db.query(models.VulnerabilityMatch).count() == 0
        assert db.query(models.RiskAssessment).count() == 0
        assert db.query(models.RemediationTask).count() == 0
        assert db.query(models.UnifiedAnalysisRun).count() == 0
        assert db.query(models.HarnessRun).count() == 0
        assert db.query(models.RuntimeEvent).count() == 0
        assert db.query(models.TraceRun).count() == 0
        assert db.query(models.ScanRun).count() == 0
    finally:
        db.close()


def test_reset_requires_control_token(client, session_factory):
    db = session_factory()
    _seed(db)
    db.close()

    response = client.post("/api/experiment/reset", json={"label": "无令牌"})
    assert response.status_code == 503
    db = session_factory()
    try:
        assert db.query(models.RiskAssessment).count() == 1
    finally:
        db.close()


@pytest.mark.parametrize("console_refresh", [False, True])
def test_reset_refuses_while_unified_run_active(client, session_factory, control_headers, console_refresh):
    db = session_factory()
    _seed(db)
    db.add(models.UnifiedAnalysisRun(run_id="UA-RUNNING", target_ref="lifecycle-host", status="running"))
    db.commit()
    db.close()

    response = client.post(
        "/api/experiment/refresh" if console_refresh else "/api/experiment/reset",
        json={"label": "运行中"},
        headers={"X-Experiment-Action": "refresh"} if console_refresh else control_headers,
    )
    assert response.status_code == 409
    db = session_factory()
    try:
        assert db.query(models.RiskAssessment).count() == 1
        assert db.query(models.UnifiedAnalysisRun).filter_by(status="running").count() == 1
    finally:
        db.close()


@pytest.mark.parametrize("headers", [{}, {"X-Experiment-Action": "refresh", "Origin": "https://other.example"}])
def test_console_refresh_rejects_unintended_requests(client, headers):
    assert client.post("/api/experiment/refresh", headers=headers).status_code == 403


def test_legacy_reset_preserves_data_when_archive_fails(client, session_factory, monkeypatch, control_headers):
    db = session_factory()
    _seed(db)
    db.close()

    def fail_archive(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(result_archive, "write_result_archive", fail_archive)
    response = client.post("/api/experiment/reset", json={}, headers=control_headers)
    assert response.status_code == 507
    db = session_factory()
    try:
        assert db.query(models.RiskAssessment).count() == 1
        assert db.query(models.LinuxAsset).count() == 1
    finally:
        db.close()


def test_console_refresh_deletes_intelligence_rounds_and_archives(client, session_factory):
    db = session_factory()
    _seed(db)
    db.add(models.VulnerabilityIntelligenceSource(cve_id="CVE-2099-1", source="nvd"))
    db.add(models.AnalysisRound(round_id="RND-OLD", status="completed"))
    db.add(models.ConsoleWorkflow(id="FLOW-OLD", status="completed"))
    db.commit()
    archive = result_archive.write_result_archive(db)
    db.close()
    response = client.post("/api/experiment/refresh", headers={"X-Experiment-Action": "refresh"})
    assert response.status_code == 200
    assert not (result_archive.archive_dir() / archive["filename"]).exists()
    with session_factory() as db:
        assert db.query(models.VulnerabilityIntelligenceSource).count() == 0
        assert db.query(models.AnalysisRound).count() == 0
        assert db.query(models.ConsoleWorkflow).count() == 0
        assert db.query(models.LinuxAsset).count() == 1
        assert db.query(models.AssetPackage).count() == 1
