"""Asset-detail analysis round: scope isolation, all-eligible batches, resume.

These tests use two synthetic assets. They never call a model: the formal
adapter's worker thread is deferred, and the only queued objects are inspected
from the durable AnalysisReport/AnalysisRound rows.
"""
from __future__ import annotations

import json

import pytest

from app import models
from app.services.unified import adapter


def _seed_asset(db, hostname: str, count: int, *, cve_prefix: str,
                risk_status: str = "candidate", packages: bool = True):
    asset = models.LinuxAsset(
        hostname=hostname, distribution="ubuntu", os_version="24.04",
        exposure_level="internal", business_level="normal", inventory_complete=True,
    )
    db.add(asset)
    db.flush()
    risks = []
    for index in range(count):
        cve_id = f"{cve_prefix}-{index + 1:04d}"
        # Package names must not collide across the two synthetic assets,
        # otherwise the global intelligence rows legitimately match both.
        package = f"{cve_prefix.lower()}-pkg{index + 1}"
        vuln = models.VulnerabilityInfo(
            cve_id=cve_id, title=f"scope {index}", description="scope test",
            affected_package=package, fixed_version="2.0.0", cvss_score=7.5,
            cvss_severity="High", source="test",
        )
        db.add(vuln)
        db.flush()
        if packages:
            db.add(models.AssetPackage(asset_id=asset.id, package_name=package,
                                       package_version="1.0.0"))
        match = models.VulnerabilityMatch(
            asset_id=asset.id, cve_id=cve_id, package_name=package,
            installed_version="1.0.0", fixed_version="2.0.0", affected=True,
            match_status="potentially_affected", active=True,
        )
        db.add(match)
        db.flush()
        risk = models.RiskAssessment(
            asset_id=asset.id, match_id=match.id, cve_id=cve_id, package_name=package,
            active=True, review_status=risk_status, preliminary_score=50 + index,
            preliminary_level="Medium", priority_rank=index + 1,
        )
        db.add(risk)
        risks.append(risk)
    db.commit()
    return asset, risks


def _snapshot(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


@pytest.fixture()
def deferred_workers(monkeypatch):
    pending = []

    class DeferredThread:
        def __init__(self, target, daemon):
            pending.append(target)

        def start(self):
            pass

    monkeypatch.setattr(adapter.threading, "Thread", DeferredThread)
    return pending


def test_asset_round_is_scoped_and_resumable(client, session_factory, control_headers,
                                             monkeypatch, deferred_workers):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    with session_factory() as db:
        target, target_risks = _seed_asset(db, "round-target", 2, cve_prefix="CVE-2099-1000")
        other, other_risks = _seed_asset(db, "round-other", 1, cve_prefix="CVE-2099-2000")
        target_id, other_id = target.id, other.id
        other_risk_id = other_risks[0].id
        other_snapshot = _snapshot(other_risks[0])
        target_ids = {risk.id for risk in target_risks}

    started = client.post("/api/rounds/start", headers=control_headers,
                          json={"asset_id": target_id, "batch_size": 0})
    assert started.status_code == 200
    body = started.json()
    round_payload = body["round"]
    assert body["reused"] is False
    assert round_payload["scope"] == "asset"
    assert round_payload["asset_id"] == target_id
    assert round_payload["selection_mode"] == "all_eligible"
    assert round_payload["counts"]["candidates"] == 2
    assert round_payload["counts"]["eligible"] == 2
    assert round_payload["counts"]["selected"] == 2
    assert round_payload["counts"]["remaining"] == 2  # none processed yet
    selected_ids = {item["risk_id"] for item in round_payload["objects"]}
    assert selected_ids == target_ids
    assert len(deferred_workers) == 1

    with session_factory() as db:
        report = db.query(models.AnalysisReport).one()
        assert json.loads(report.selected_object_ids_json) == [
            f"risk-{risk_id}" for risk_id in sorted(target_ids)]
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == other_snapshot
        assert db.query(models.AnalysisRound).count() == 1

    # A refresh/duplicate click must return the same round, not create another
    # report and not re-run matching/risk over a running batch.
    again = client.post("/api/rounds/start", headers=control_headers,
                        json={"asset_id": target_id, "batch_size": 0})
    assert again.status_code == 200
    second = again.json()
    assert second["reused"] is True
    assert second["round_id"] == round_payload["round_id"]
    with session_factory() as db:
        assert db.query(models.AnalysisReport).count() == 1
        assert db.query(models.AnalysisRound).count() == 1
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == other_snapshot
        assert db.get(models.RiskAssessment, other_risk_id).review_status == "candidate"

    recovered = client.get(f"/api/rounds/{round_payload['round_id']}")
    assert recovered.status_code == 200
    assert recovered.json()["round_id"] == round_payload["round_id"]
    current = client.get(f"/api/rounds/current?asset_id={target_id}")
    assert current.status_code == 200
    assert current.json()["round"]["round_id"] == round_payload["round_id"]


def test_background_review_preserves_priority_order(session_factory):
    """IN queries do not promise order; the worker must use the chosen order."""
    with session_factory() as db:
        _, risks = _seed_asset(db, "ordering", 3, cve_prefix="CVE-2099-1100")
        chosen = [risks[2].id, risks[0].id, risks[1].id]
        ordered = adapter._ordered_selected_risks(db, chosen)
        assert [risk.id for risk in ordered] == chosen
        assert adapter._ordered_selected_risks(db, []) == []


def test_round_zero_candidates_does_not_touch_other_asset(client, session_factory,
                                                         control_headers, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    with session_factory() as db:
        # Target has a historically reviewed risk with no exact active match;
        # it is not eligible for a new formal batch.
        target, target_risks = _seed_asset(db, "zero-target", 1, cve_prefix="CVE-2099-3000",
                                           risk_status="pending_human_review", packages=False)
        target_risks[0].match_id = None
        other, other_risks = _seed_asset(db, "zero-other", 1, cve_prefix="CVE-2099-4000")
        target_id = target.id
        other_risk_id = other_risks[0].id
        other_snapshot = _snapshot(other_risks[0])
        db.commit()

    started = client.post("/api/rounds/start", headers=control_headers,
                          json={"asset_id": target_id, "batch_size": 0})
    assert started.status_code == 200
    body = started.json()
    assert body["round"]["status"] == "no_candidates"
    assert body["round"]["counts"]["candidates"] == 0
    assert body["round"]["counts"]["selected"] == 0
    assert body["review"] is None
    with session_factory() as db:
        assert db.query(models.AnalysisReport).count() == 0
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == other_snapshot


def test_round_rejects_foreign_risk_id(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        target, _ = _seed_asset(db, "foreign-target", 1, cve_prefix="CVE-2099-5000")
        other, other_risks = _seed_asset(db, "foreign-other", 1, cve_prefix="CVE-2099-6000")
        target_id, foreign_risk_id = target.id, other_risks[0].id
    response = client.post("/api/rounds/start", headers=control_headers,
                           json={"asset_id": target_id, "risk_id": foreign_risk_id,
                                 "batch_size": 0})
    assert response.status_code == 409
    assert response.json()["detail"] == "risk_not_in_asset_scope"


def test_single_risk_round_selects_only_requested_risk(client, session_factory,
                                                      control_headers, monkeypatch,
                                                      deferred_workers):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    with session_factory() as db:
        target, risks = _seed_asset(db, "single-target", 2, cve_prefix="CVE-2099-7000")
        target_id, requested_risk_id = target.id, risks[0].id
        unrequested_id = risks[1].id
    response = client.post("/api/rounds/start", headers=control_headers,
                           json={"asset_id": target_id, "risk_id": requested_risk_id,
                                 "batch_size": 0})
    assert response.status_code == 200
    payload = response.json()["round"]
    assert payload["selection_mode"] == "single_risk"
    assert payload["requested_risk_id"] == requested_risk_id
    assert payload["selected_object_ids"] == [f"risk-{requested_risk_id}"]
    assert payload["counts"]["eligible"] == 2
    assert payload["counts"]["selected"] == 1
    with session_factory() as db:
        assert db.get(models.RiskAssessment, unrequested_id).review_status in (
            "candidate", "reanalysis_required")


def test_analysis_runs_batch_zero_selects_all_asset_risks(client, session_factory,
                                                         control_headers, monkeypatch,
                                                         deferred_workers):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        target, risks = _seed_asset(db, "batch-target", 3, cve_prefix="CVE-2099-8000")
        other, other_risks = _seed_asset(db, "batch-other", 2, cve_prefix="CVE-2099-9000")
        target_id = target.id
        target_ids = {risk.id for risk in risks}
        other_risk_id = other_risks[0].id
        other_snapshot = _snapshot(other_risks[0])
    response = client.post(f"/api/analysis/runs?asset_id={target_id}&batch_size=0",
                           headers=control_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "running"
    assert body["selection_mode"] == "all_eligible"
    assert body["eligible_object_count"] == 3
    assert body["selected_object_count"] == 3
    assert body["remaining_object_count"] == 0
    assert {int(item.split("-")[1]) for item in body["selected_object_ids"]} == target_ids
    with session_factory() as db:
        assert db.query(models.AnalysisReport).count() == 1
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == other_snapshot


def test_risk_calculation_and_ranking_are_asset_scoped(client, session_factory,
                                                       control_headers):
    with session_factory() as db:
        target, target_risks = _seed_asset(db, "risk-target", 2, cve_prefix="CVE-2099-A000")
        other, other_risks = _seed_asset(db, "risk-other", 2, cve_prefix="CVE-2099-B000")
        target_id = target.id
        other_id = other.id
        other_risk_id = other_risks[0].id
        other_snapshot = _snapshot(other_risks[0])
        other_ranks = {risk.id: risk.priority_rank for risk in other_risks}
    response = client.post(f"/api/risk/calculate?asset_id={target_id}", headers=control_headers)
    assert response.status_code == 200
    assert response.json()["asset_id"] == target_id
    with session_factory() as db:
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == other_snapshot
        assert {risk.id: risk.priority_rank for risk in db.query(models.RiskAssessment)
                .filter_by(asset_id=other_id).all()} == other_ranks
        target_ranks = [risk.priority_rank for risk in db.query(models.RiskAssessment)
                        .filter_by(asset_id=target_id).all()]
        assert sorted(target_ranks) == list(range(1, len(target_ranks) + 1))
    ranking = client.get(f"/api/risk/ranking?asset_id={target_id}").json()
    assert {row["asset_id"] for row in ranking} == {target_id}


def test_round_blocks_when_model_not_configured(client, session_factory, control_headers,
                                                monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "")
    with session_factory() as db:
        target, _ = _seed_asset(db, "blocked-target", 1, cve_prefix="CVE-2099-C000")
        target_id = target.id
    response = client.post("/api/rounds/start", headers=control_headers,
                           json={"asset_id": target_id, "batch_size": 0})
    assert response.status_code == 200
    body = response.json()
    assert body["round"]["status"] == "blocked"
    assert "model_not_configured" in body["round"]["blocked_reason"]
    assert body["review"] is None
    with session_factory() as db:
        assert db.query(models.AnalysisReport).count() == 0


def test_intel_basis_includes_openwrt_advisory_timestamp(session_factory):
    from datetime import datetime, timezone

    from app.routers.rounds import _intel_timestamp

    fetched = datetime(2026, 10, 23, 1, 53, 29, tzinfo=timezone.utc)
    with session_factory() as db:
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2099-D001", title="OpenWrt", description="d",
            affected_package="cgi-io", source="openwrt_official_ghsa"))
        db.add(models.OpenWrtAdvisory(
            cve_id="CVE-2099-D001", package_name="cgi-io", release="25.12",
            source_url="https://example.invalid/advisory", updated_at=fetched))
        db.commit()
        value, scope = _intel_timestamp(db, ["CVE-2099-D001"])
        assert value.replace(tzinfo=timezone.utc) == fetched
        assert "openwrt_advisory" in scope
        assert scope.startswith("selected_cves:")


def test_analysis_status_reports_protocol_without_secret(client, monkeypatch):
    monkeypatch.setattr("app.config.DEEPSEEK_MODEL", "scope-model")
    monkeypatch.setattr("app.config.DEEPSEEK_API_PROTOCOL", "anthropic")
    monkeypatch.setattr("app.config.DEEPSEEK_BASE_URL", "https://example.invalid/api/anthropic")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "must-not-leak")
    response = client.get("/api/analysis/status")
    assert response.status_code == 200
    body = response.json()
    assert body["api_protocol"] == "anthropic"
    assert body["endpoint_host"] == "example.invalid"
    assert body["batch_size"] == 0 and body["batch_cap"] >= 1
    text = json.dumps(body)
    assert "must-not-leak" not in text
    assert "DEEPSEEK_API_KEY" not in text


def _report_row(db, risk_ids, *, status):
    report = models.AnalysisReport(
        model="test", status=status, review_run_id="recover-test-run",
        pipeline_version="unified-four-agent-v1", current_stage="agent_reviewing",
        candidate_count=len(risk_ids), selected_object_count=len(risk_ids),
        selected_object_ids_json=json.dumps([f"risk-{item}" for item in risk_ids]),
        termination_reason="legacy_interrupted",
    )
    db.add(report)
    db.commit()
    return report


def test_recover_interrupted_resets_orphaned_in_progress_risks(client, session_factory,
                                                               control_headers, monkeypatch,
                                                               deferred_workers):
    """Container-stop orphans block every new batch until explicit recovery."""
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    with session_factory() as db:
        target, risks = _seed_asset(db, "recover-target", 2, cve_prefix="CVE-2099-E000")
        target_id = target.id
        risk_ids = [risk.id for risk in risks]
        for risk in risks:
            risk.review_status = "agent_reviewing"
        _report_row(db, risk_ids, status="interrupted")
        for risk_id in risk_ids:
            db.add(models.UnifiedAnalysisRun(
                run_id=f"UA-recover-test-run-{risk_id}", task_type="risk_review",
                target_type="linux_host", target_ref="recover-target",
                mode="formal", status="running", risk_id=risk_id))
        db.commit()

    blocked = client.post(f"/api/analysis/runs?asset_id={target_id}&batch_size=0",
                          headers=control_headers)
    assert blocked.status_code == 409

    recovered = client.post("/api/analysis/recover-interrupted", headers=control_headers)
    assert recovered.status_code == 200
    body = recovered.json()
    assert body["recovered"] == 2
    assert set(body["reset_object_ids"]) == {f"risk-{item}" for item in risk_ids}
    assert sorted(body["interrupted_run_ids"]) == sorted(
        f"UA-recover-test-run-{item}" for item in risk_ids)
    assert body["running_report_count"] == 0

    with session_factory() as db:
        for risk_id in risk_ids:
            risk = db.get(models.RiskAssessment, risk_id)
            assert risk.review_status == "reanalysis_required"
            assert "[interrupted_run_recovered]" in risk.review_reason
        # The interrupted report is evidence; recovery must not rewrite it.
        assert db.query(models.AnalysisReport).filter_by(status="interrupted").count() == 1
        orphans = db.query(models.UnifiedAnalysisRun).filter(
            models.UnifiedAnalysisRun.run_id.like("UA-recover-test-run-%")).all()
        assert {row.status for row in orphans} == {"interrupted"}

    restarted = client.post(f"/api/analysis/runs?asset_id={target_id}&batch_size=0",
                            headers=control_headers)
    assert restarted.status_code == 200
    assert restarted.json()["status"] == "running"


def test_recover_interrupted_never_resets_live_running_report_objects(client, session_factory,
                                                                      control_headers):
    with session_factory() as db:
        target, risks = _seed_asset(db, "live-target", 1, cve_prefix="CVE-2099-F000")
        risk = risks[0]
        risk.review_status = "agent_reviewing"
        _report_row(db, [risk.id], status="running")
        db.add(models.UnifiedAnalysisRun(
            run_id=f"UA-recover-test-run-{risk.id}", task_type="risk_review",
            target_type="linux_host", target_ref="live-target",
            mode="formal", status="running", risk_id=risk.id))
        db.commit()
        risk_id = risk.id

    recovered = client.post("/api/analysis/recover-interrupted", headers=control_headers)
    assert recovered.status_code == 200
    body = recovered.json()
    assert body["recovered"] == 0
    assert body["running_report_count"] == 1
    assert body["interrupted_run_ids"] == []
    assert body["skipped"] and body["skipped"][0]["reason"] == "referenced_by_running_report"
    with session_factory() as db:
        assert db.get(models.RiskAssessment, risk_id).review_status == "agent_reviewing"
        live_run = db.query(models.UnifiedAnalysisRun).filter_by(
            run_id=f"UA-recover-test-run-{risk_id}").one()
        assert live_run.status == "running"
