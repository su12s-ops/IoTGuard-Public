"""Asset-scoped rounds must never mutate or admit another asset's risks."""
import json

import pytest

from app import models
from app.services.risk_engine import calculate_risk
from app.services.unified import adapter


def _seed(db):
    vuln = models.VulnerabilityInfo(cve_id="CVE-2099-0901", title="Scope", description="scope",
        affected_package="openssl", fixed_version="3.0.2-0ubuntu1.18", cvss_score=8.0)
    assets = [models.LinuxAsset(hostname=name, distribution="ubuntu", os_version="24.04",
        inventory_complete=True) for name in ("scope-target", "scope-other")]
    db.add_all([vuln, *assets]); db.flush()
    risks = []
    for asset in assets:
        db.add(models.AssetPackage(asset_id=asset.id, package_name="openssl",
            package_version="3.0.2-0ubuntu1.10"))
        match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=vuln.cve_id,
            package_name="openssl", installed_version="3.0.2-0ubuntu1.10",
            fixed_version=vuln.fixed_version, affected=True, active=True,
            match_status="potentially_affected")
        db.add(match); db.flush()
        risk = models.RiskAssessment(asset_id=asset.id, match_id=match.id, cve_id=vuln.cve_id,
            package_name="openssl", active=True, review_status="candidate",
            preliminary_score=99 if asset == assets[1] else 10,
            priority_rank=1 if asset == assets[1] else 2)
        db.add(risk); risks.append(risk)
    db.commit()
    return assets, risks


def _snapshot(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


@pytest.mark.parametrize("other_match_active", [True, False])
def test_scoped_risk_calculation_leaves_other_asset_unchanged(session_factory, other_match_active):
    with session_factory() as db:
        assets, risks = _seed(db)
        db.get(models.VulnerabilityMatch, risks[1].match_id).active = other_match_active
        risks[1].review_status = "human_confirmed"
        risks[1].final_score = 93
        risks[1].candidate_fingerprint = "preserved"
        risks[1].priority_rank = 777
        db.commit()
        original = _snapshot(risks[1])
        assert calculate_risk(db, asset_id=assets[0].id) == 1
        db.refresh(risks[1])
        assert _snapshot(risks[1]) == original
        assert risks[0].candidate_fingerprint
        # Default remains all-assets and processes both active matches.
        assert calculate_risk(db) == (2 if other_match_active else 1)


def test_scoped_calculation_retires_target_only(session_factory):
    with session_factory() as db:
        assets, risks = _seed(db)
        for risk in risks:
            db.get(models.VulnerabilityMatch, risk.match_id).active = False
        db.commit()
        other = _snapshot(risks[1])
        assert calculate_risk(db, asset_id=assets[0].id) == 0
        assert risks[0].active is False
        db.refresh(risks[1])
        assert _snapshot(risks[1]) == other


def test_scoped_round_admits_target_only(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    with session_factory() as db:
        assets, risks = _seed(db)
        asset_id, target_risk_id = assets[0].id, risks[0].id
        other_risk_id = risks[1].id
        original = _snapshot(risks[1])
    # Exercise the real formal admission and fixed worker ID list, without model calls.
    pending_workers = []
    class DeferredThread:
        def __init__(self, target, daemon):
            pending_workers.append(target)
        def start(self):
            pass
    monkeypatch.setattr(adapter.threading, "Thread", DeferredThread)
    response = client.post("/api/rounds/start", headers=control_headers,
        json={"asset_id": asset_id, "batch_size": 4})
    assert response.status_code == 200
    body = response.json()
    assert body["risk_count"] == 1
    assert body["review_unavailable_reason"] is None
    assert body["review"]["selected_object_ids"] == [f"risk-{target_risk_id}"]
    assert body["review"]["candidate_count"] == 1
    assert len(pending_workers) == 1
    with session_factory() as db:
        report = db.query(models.AnalysisReport).one()
        assert json.loads(report.selected_object_ids_json) == [f"risk-{target_risk_id}"]
        assert _snapshot(db.get(models.RiskAssessment, other_risk_id)) == original


def test_scoped_analysis_empty_does_not_admit_foreign_candidate(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        assets, risks = _seed(db)
        risks[0].active = False
        db.commit()
        asset_id = assets[0].id
        other = _snapshot(risks[1])
    response = client.post(f"/api/analysis/runs?asset_id={asset_id}", headers=control_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "no_candidates"
    assert response.json()["selected_object_ids"] == []
    assert response.json()["candidate_count"] == 1  # raw candidate includes inactive target
    with session_factory() as db:
        assert db.query(models.AnalysisReport).count() == 0
        assert _snapshot(db.get(models.RiskAssessment, other["id"])) == other


def test_formal_adapter_rejects_foreign_risk_id(session_factory, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        assets, risks = _seed(db)
        other = _snapshot(risks[1])
        with pytest.raises(ValueError, match="risk_not_eligible_for_formal_analysis"):
            adapter.generate_and_save_report_unified(db, asset_id=assets[0].id, risk_id=risks[1].id)
        assert _snapshot(risks[1]) == other
        assert db.query(models.AnalysisReport).count() == 0


@pytest.mark.parametrize("legacy_ids", [False, True])
def test_retry_reset_keeps_asset_scope(session_factory, legacy_ids):
    from app.routers.analysis import _reset_latest_failed_objects
    with session_factory() as db:
        assets, risks = _seed(db)
        for risk in risks:
            risk.review_status = "pending_human_review"
            risk.audit_policy_reasons = '["pipeline_failure:retryable"]'
        object_ids = [f"asset-{r.asset_id}-{r.cve_id}" if legacy_ids else f"risk-{r.id}"
                      for r in reversed(risks)]
        db.add(models.AnalysisReport(status="human_review", selected_object_ids_json=json.dumps(object_ids)))
        db.commit()
        other = _snapshot(risks[1])
        assert _reset_latest_failed_objects(db, asset_id=assets[0].id) == 1
        assert risks[0].review_status == "reanalysis_required"
        assert _snapshot(risks[1]) == other

def test_scoped_analysis_preserves_global_busy_gate(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        assets, risks = _seed(db)
        risks[1].review_status = "agent_reviewing"
        db.commit()
        asset_id = assets[0].id
    response = client.post(f"/api/analysis/runs?asset_id={asset_id}", headers=control_headers)
    assert response.status_code == 409
