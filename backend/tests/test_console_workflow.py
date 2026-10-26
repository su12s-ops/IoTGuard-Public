import json
import pytest
from app import models
from app.services import console_workflow as workflow


def seed(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="workflow-test", distribution="ubuntu", os_version="24.04")
        db.add(asset)
        db.commit()
        return asset.id


@pytest.mark.parametrize("status,queued,deferred", [("running", 3, 0), ("partial", 0, 3), ("human_review", 0, 3)])
def test_finished_batch_does_not_display_unstarted_objects_as_queued(session_factory, status, queued, deferred):
    with session_factory() as db:
        result = workflow.live_execution(db, {"review_run": {
            "run_id": "queue-test", "status": status, "selected_object_count": 3}})
        assert result["queued_objects"] == queued
        assert result["deferred_objects"] == deferred


@pytest.mark.parametrize("cache", ["valid", "missing", "corrupt"])
def test_openwrt_network_outage_uses_only_verified_existing_snapshot(session_factory, monkeypatch, cache):
    from hashlib import sha256
    from urllib.error import URLError
    from app.services import openwrt_intel
    def unavailable(*args, **kwargs):
        raise URLError("temporary TLS interruption")
    monkeypatch.setattr(openwrt_intel, "fetch_advisory_rows", unavailable)
    with session_factory() as db:
        db.add(models.LinuxAsset(hostname="router", distribution="openwrt"))
        if cache != "missing":
            url = "https://github.com/openwrt/openwrt/security/advisories/GHSA-2345-2345-2345"
            payload = json.dumps({"html_url": url})
            db.add(models.IotOfficialAdvisory(ecosystem="openwrt", advisory_id="GHSA-2345-2345-2345",
                source_url=url, payload_json=payload,
                content_sha256=sha256(payload.encode()).hexdigest() if cache == "valid" else "wrong"))
            db.add(models.OpenWrtAdvisory(cve_id="CVE-2026-1111", package_name="daemon", release="24.10", source_url=url))
            db.add(models.VulnerabilityInfo(cve_id="CVE-2026-1111", title="Cached official advisory", affected_package="daemon"))
        db.commit()
        progress = []
        if cache == "valid":
            before = db.query(models.IotOfficialAdvisory).one().updated_at
            warnings = workflow.fetch_intelligence(db, 0, lambda stage, message: progress.append(message))
            assert "不代表最新" in warnings[0]
            assert db.query(models.IotOfficialAdvisory).one().updated_at == before
            assert any("已有官方快照" in message for message in progress)
        else:
            with pytest.raises(RuntimeError, match="没有可验证"):
                workflow.fetch_intelligence(db, 0, lambda *args: None)


def test_start_is_idempotent_and_refresh_cannot_race(client, session_factory, monkeypatch, control_headers):
    seed(session_factory)
    calls = []
    monkeypatch.setattr(workflow, "launch", calls.append)
    first = client.post("/api/console/start", json={}, headers=control_headers).json()
    second = client.post("/api/console/start", json={}, headers=control_headers).json()
    assert first["workflow"]["id"] == second["workflow"]["id"]
    assert len(calls) == 1 and second["reused"]
    assert client.post("/api/experiment/refresh", headers={"X-Experiment-Action": "refresh"}).status_code == 409
    current = client.get("/api/console/current").json()["workflow"]
    assert current["stage"] == "intelligence" and current["progress_percent"] == 0


def test_failed_intelligence_never_starts_analysis(client, session_factory, monkeypatch, control_headers):
    seed(session_factory)
    monkeypatch.setattr(workflow, "launch", lambda _: None)
    current = client.post("/api/console/start", json={}, headers=control_headers).json()["workflow"]
    def fail(*_):
        raise RuntimeError("official source unavailable")
    monkeypatch.setattr(workflow, "fetch_intelligence", fail)
    workflow.run(current["id"], session_factory)
    result = client.get("/api/console/current").json()["workflow"]
    assert result["status"] == "failed"
    assert "official source unavailable" in result["error"]
    assert result["steps"][0]["status"] == "failed"
    with session_factory() as db:
        assert db.query(models.AnalysisRound).count() == 0


def test_worker_orders_stages_and_reports_zero_candidates(client, session_factory, monkeypatch, control_headers):
    seed(session_factory)
    monkeypatch.setattr(workflow, "launch", lambda _: None)
    current = client.post("/api/console/start", json={}, headers=control_headers).json()["workflow"]
    calls = []
    def intelligence(db, asset_id, progress):
        calls.append("intelligence")
        return []
    def execute(payload, db, progress):
        for stage in ("matching", "risk"):
            progress(stage, stage)
            calls.append(stage)
        db.add(models.AnalysisRound(round_id="RND-ZERO", status="no_candidates"))
        db.commit()
        return {"round_id": "RND-ZERO"}
    monkeypatch.setattr(workflow, "fetch_intelligence", intelligence)
    monkeypatch.setattr("app.routers.rounds.execute_round", execute)
    workflow.run(current["id"], session_factory)
    result = client.get("/api/console/current").json()["workflow"]
    assert calls == ["intelligence", "matching", "risk"]
    assert result["status"] == "completed" and result["progress_percent"] == 100
    assert result["steps"][-1]["status"] == "skipped"


def test_human_audit_stays_at_eighty_until_decided(client, session_factory):
    asset_id = seed(session_factory)
    with session_factory() as db:
        risk = models.RiskAssessment(asset_id=asset_id, cve_id="CVE-2099-1", review_status="pending_human_review", human_review_required=True)
        db.add(risk)
        db.flush()
        db.add(models.AnalysisRound(round_id="RND-AUDIT", status="completed", selected_object_ids_json=json.dumps([f"risk-{risk.id}"])))
        db.add(models.ConsoleWorkflow(id="FLOW-AUDIT", round_id="RND-AUDIT", owner=workflow.OWNER, pipeline_done=True,
                                     steps_json=json.dumps(workflow.steps())))
        db.commit()
        risk_id = risk.id
    first = client.get("/api/console/current").json()["workflow"]
    assert first["status"] == "awaiting_review" and first["progress_percent"] == 80
    with session_factory() as db:
        risk = db.get(models.RiskAssessment, risk_id)
        risk.review_status, risk.human_review_required = "human_confirmed", False
        db.commit()
    final = client.get("/api/console/current").json()["workflow"]
    assert final["status"] == "completed" and final["progress_percent"] == 100


def test_process_restart_marks_unfinished_fetch_interrupted(client, session_factory):
    with session_factory() as db:
        db.add(models.ConsoleWorkflow(id="FLOW-STALE", owner="old-process", steps_json=json.dumps(workflow.steps())))
        db.commit()
    result = client.get("/api/console/current").json()["workflow"]
    assert result["status"] == "interrupted"
    assert result["progress_percent"] == 0


def test_start_requires_auth_and_valid_asset(client, control_headers):
    assert client.post("/api/console/start", json={}).status_code in (401, 503)
    assert client.post("/api/console/start", json={"asset_id": 99999}, headers=control_headers).status_code == 404


def test_real_matching_risk_and_formal_entry_are_connected(client, session_factory, monkeypatch, control_headers):
    from test_rounds_workflow import _seed_round_data
    ids = _seed_round_data(session_factory)
    monkeypatch.setattr(workflow, "launch", lambda _: None)
    monkeypatch.setattr(workflow, "fetch_intelligence", lambda *_: [])
    monkeypatch.setattr("app.config.UNIFIED_PIPELINE_MODE", "on")
    monkeypatch.setattr("app.config.DEEPSEEK_API_KEY", "isolated-test-key")
    def formal(**kwargs):
        db = kwargs["db"]
        risk = db.get(models.RiskAssessment, ids["risk_id"])
        risk.review_status, risk.human_review_required = "pending_human_review", True
        selected = json.dumps([f"risk-{risk.id}"])
        db.add(models.AnalysisReport(review_run_id="REVIEW-CONSOLE", status="completed",
                                     selected_object_ids_json=selected, selected_object_count=1,
                                     processed_object_count=1, progress_percent=100))
        db.commit()
        return {"run_id": "REVIEW-CONSOLE", "selected_object_ids": [f"risk-{risk.id}"], "selected_object_count": 1}
    monkeypatch.setattr("app.routers.analysis.create_run", formal)
    current = client.post("/api/console/start", json={"asset_id": ids["asset_id"]}, headers=control_headers).json()["workflow"]
    workflow.run(current["id"], session_factory)
    result = client.get("/api/console/current").json()["workflow"]
    assert result["status"] == "awaiting_review", result
    assert result["round"]["counts"]["matches"] >= 1
    assert result["round"]["counts"]["risks_calculated"] >= 1
    assert result["round"]["review_run_id"] == "REVIEW-CONSOLE"


@pytest.mark.parametrize("last_empty", [False, True])
def test_batches_continue_sequentially_and_audit_covers_previous_batches(client, session_factory, monkeypatch, control_headers, last_empty):
    asset_id = seed(session_factory)
    monkeypatch.setattr(workflow, "launch", lambda _: None)
    current = client.post("/api/console/start", json={}, headers=control_headers).json()["workflow"]
    monkeypatch.setattr(workflow, "fetch_intelligence", lambda *_: [])
    calls = []
    def execute(payload, db, progress):
        index = len(calls) + 1
        calls.append(index)
        progress("matching", "batch matching")
        empty = last_empty and index == 2
        selected = []
        if not empty:
            risk = models.RiskAssessment(asset_id=asset_id, cve_id=f"CVE-2099-{index}",
                                         review_status="pending_human_review", human_review_required=True)
            db.add(risk)
            db.flush()
            selected = [f"risk-{risk.id}"]
        db.add(models.AnalysisRound(round_id=f"RND-BATCH-{index}", status="no_candidates" if empty else "completed",
                                   selected_object_ids_json=json.dumps(selected), selected_object_count=len(selected),
                                   eligible_count=2 if index == 1 else 1, processed_object_count=len(selected)))
        db.commit()
        return {"round_id": f"RND-BATCH-{index}"}
    monkeypatch.setattr("app.routers.rounds.execute_round", execute)
    monkeypatch.setattr("app.services.review_common.select_candidates", lambda *_, **__: {"selected_object_count": 1 if len(calls) == 1 else 0})
    workflow.run(current["id"], session_factory)
    result = client.get("/api/console/current").json()["workflow"]
    assert calls == [1, 2]
    assert result["status"] == "awaiting_review"
    assert result["progress_percent"] == 80
    assert result["round"]["counts"]["selected"] == (1 if last_empty else 2)
    with session_factory() as db:
        assert len(workflow.audit_ids(db, db.get(models.ConsoleWorkflow, current["id"]))) == (1 if last_empty else 2)
