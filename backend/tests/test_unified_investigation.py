"""Safety regression with isolated fixtures; these are not real business evidence."""
import hashlib
import json

import pytest

from app import config, models
from app.services.unified import investigation as I
from app.services.unified.state import empty_state


@pytest.fixture
def case(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="investigation-host", distribution="ubuntu", os_version="24.04", inventory_complete=True)
        db.add(asset)
        db.flush()
        db.add(models.AssetPackage(asset_id=asset.id, package_name="curl", package_version="1.0"))
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-10001", package_name="curl")
        db.add(risk)
        db.flush()
        state = empty_state("parent", "risk_review", asset.hostname, "linux_host", "shadow").model_dump()
        state["decision"] = {"verdicts": [{"object_id": "risk-1", "confidence": .5}]}
        row = models.UnifiedAnalysisRun(run_id="parent", risk_id=risk.id, mode="shadow", target_ref=asset.hostname,
            target_type="linux_host", task_type="risk_review", state_json=json.dumps(state), status="completed")
        db.add(row)
        conn = models.DeviceConnection(asset_id=asset.id, enabled=True, host="127.0.0.1", username="test", host_key_sha256="SHA256:" + "a" * 43)
        db.add(conn)
        db.commit()
        yield db, row, conn


def proposal(db):
    return I.propose(db, "parent", {"target_agent": "vulnerability_analyst", "collection_capability": "inventory",
        "question": "What is the currently installed curl version?", "expected_effect": "Resolve current package version gap"})


def complete(db, item, conn):
    run = models.HarnessRun(id="collection", asset_id=conn.asset_id, connection_id=conn.id, status="completed", plan_json='{"goal":"collect"}', result_json=json.dumps({"inventory_evidence_id": "INV-real"}))
    db.add(run)
    db.add(models.CollectionEvidence(evidence_id="INV-real", run_id=run.id, asset_id=conn.asset_id,
        raw_text="raw inventory", content_sha256=hashlib.sha256(b"raw inventory").hexdigest()))
    asset = db.get(models.LinuxAsset, conn.asset_id)
    asset.inventory_metadata_json = json.dumps({"collection_run_id": run.id})
    item.status, item.collection_run_id, item.authorized_by = "authorized", run.id, "operator"
    db.commit()
    return run


def test_proposal_is_idempotent_and_does_not_dispatch(case):
    db, row, conn = case
    item = proposal(db)
    assert proposal(db).id == item.id
    assert item.status == "awaiting_authorization"
    assert db.query(models.HarnessRun).count() == 0


@pytest.mark.parametrize("change", ["runtime", "capability", "target", "missing_effect"])
def test_policy_rejects_unsupported_or_ambiguous_request(case, change):
    db, row, conn = case
    request = {"target_agent": "asset_investigator", "collection_capability": "inventory", "question": "version?", "expected_effect": "resolve version gap"}
    if change == "runtime": request["target_agent"] = "runtime_analyst"
    if change == "capability": request["collection_capability"] = "ssh_command"
    if change == "target": row.target_ref = "other-host"; db.commit()
    if change == "missing_effect": request["expected_effect"] = ""
    with pytest.raises(ValueError): I.propose(db, row.run_id, request)
    assert db.query(models.HarnessRun).count() == 0


def test_authorization_hash_and_asset_binding(case):
    db, row, conn = case
    item = proposal(db)
    with pytest.raises(ValueError, match="request_changed"):
        I.authorize(db, item, "a" * 64, conn.id, "operator", "readonly")
    other = models.LinuxAsset(hostname="other")
    db.add(other); db.commit()
    conn.asset_id = other.id; db.commit()
    with pytest.raises(ValueError, match="connection_asset_mismatch"):
        I.authorize(db, item, item.request_hash, conn.id, "operator", "readonly")


def test_missing_authorization_cannot_resume(case):
    db, row, conn = case
    with pytest.raises(ValueError, match="authorized_completed_collection_required"):
        I.resume(db, proposal(db))


def test_corrupt_raw_evidence_blocks_reanalysis(case):
    db, row, conn = case
    item = proposal(db); complete(db, item, conn)
    db.query(models.CollectionEvidence).one().raw_text = "tampered"; db.commit()
    with pytest.raises(ValueError, match="corrupt"):
        I.resume(db, item)


def test_same_facts_preserves_raw_confidence_and_formal(case, monkeypatch):
    from app.services.unified import runner
    db, row, conn = case
    item = proposal(db); complete(db, item, conn)
    before = db.query(models.RiskAssessment).one().review_status
    def fake_run(db, child, **kwargs):
        assert kwargs["force_full_review"] is True
        state = json.loads(row.state_json)
        state["decision"]["verdicts"][0]["confidence"] = .99
        child.state_json, child.status = json.dumps(state), "completed"
        child.decision_json = json.dumps(state["decision"])
        db.commit()
    monkeypatch.setattr(runner, "run_unified_sync", fake_run)
    child = I.resume(db, item)
    assert json.loads(child.decision_json)["verdicts"][0]["confidence"] == .99
    assert json.loads(item.result_json)["model_variance_only"] is True
    assert json.loads(item.result_json)["substantive_update"] is False
    assert db.query(models.RiskAssessment).one().review_status == before
    assert I.resume(db, item).run_id == child.run_id


def test_new_package_version_is_substantive(case):
    db, row, conn = case
    before = I.evidence_view(db, conn.asset_id)
    db.query(models.AssetPackage).one().package_version = "2.0"; db.commit()
    assert I.fingerprint(before) != I.fingerprint(I.evidence_view(db, conn.asset_id))


def test_formal_resume_keeps_formal_trace_and_publishes_current_report(case, monkeypatch):
    from app.services.unified import runner
    from app.services.unified.adapter import formal_sink
    from app.services.unified.state import UnifiedAnalysisState
    db, parent, connection = case
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    parent.mode = "formal"
    state = json.loads(parent.state_json)
    state["mode"] = "formal"
    state["object_id"] = f"risk-{parent.risk_id}"
    parent.state_json = json.dumps(state)
    risk = db.get(models.RiskAssessment, parent.risk_id)
    risk.review_status = "pending_human_review"
    risk.device_context_json = json.dumps({"unified_run_id": parent.run_id})
    db.commit()
    item = proposal(db)
    complete(db, item, connection)
    def run(db, child, **kwargs):
        assert child.mode == "formal" and kwargs["sink"] is formal_sink
        current = UnifiedAnalysisState.model_validate(state)
        current.run_id = child.run_id
        current.final = {"policy": {"status": "pending_human_review", "reasons": ["fixture_hold"], "adjustment": 0}}
        child.state_json = current.model_dump_json()
        child.decision_json = json.dumps(current.decision)
        child.status = "completed"
        formal_sink(db, child, current)
    monkeypatch.setattr(runner, "run_unified_sync", run)
    child = I.resume(db, item)
    first = db.query(models.TraceEvent).filter_by(trace_id=child.trace_id, event_type="task_started").one()
    assert json.loads(first.payload_json)["mode"] == "formal"
    assert db.query(models.AnalysisReport).order_by(models.AnalysisReport.id.desc()).first().review_run_id == child.run_id


def test_official_writer_and_shadow_sink_fail_closed(case, monkeypatch):
    from app.services.unified.adapter import formal_sink
    from app.services.unified.runner import run_unified_sync
    import importlib
    db, row, conn = case
    state = empty_state(row.run_id, row.task_type, row.target_ref, "linux_host", "shadow")
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    with pytest.raises(ModuleNotFoundError): importlib.import_module("app.services.event_review_pipeline")
    with pytest.raises(ValueError, match="formal_source_required"): formal_sink(db, row, state)
    with pytest.raises(ValueError, match="shadow_sink_forbidden"): run_unified_sync(db, row, sink=formal_sink)


def test_unified_on_api_cannot_be_second_formal_entry(client, monkeypatch, control_headers):
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    assert client.post("/api/unified/analyze", json={"hostname": "any"}).status_code in {401, 503}
    assert client.post("/api/unified/analyze", json={"hostname": "any"}, headers=control_headers).status_code == 409


def test_shadow_and_authorization_require_control(client, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "operator-token")
    assert client.post("/api/unified/shadow", json={"asset_id": 1}).status_code == 401
    assert client.post("/api/unified/investigations/anything/resume").status_code == 401


def test_candidate_uses_current_version_and_keeps_history(case):
    from app.services.unified.graph import _candidate_context
    db, row, conn = case
    risk = db.get(models.RiskAssessment, row.risk_id)
    match = models.VulnerabilityMatch(asset_id=conn.asset_id, cve_id=risk.cve_id, package_name="curl", installed_version="0.5")
    db.add(match); db.flush(); risk.match_id = match.id; db.commit()
    result = _candidate_context(db, empty_state("test", "risk_review", row.target_ref, "linux_host", "shadow"), risk)[0]
    assert result["installed_version"] == "1.0" and result["historical_installed_version"] == "0.5"


def test_linux_tools_keep_inventory_completeness_and_cve_scope(case):
    from app.services import agent_tools as tools
    db, row, conn = case
    risk = db.get(models.RiskAssessment, row.risk_id)
    db.add(models.VulnerabilityMatch(asset_id=conn.asset_id, cve_id=risk.cve_id + ":noble:curl", package_name="curl"))
    db.commit()
    profile = tools.tool_query_device_profile(db, host=row.target_ref)
    assert profile["inventory_complete"] is True
    assert profile["component_count"] == 1
    assert tools.tool_query_network_surface(db, host=row.target_ref)["found"] is True
    assert tools.tool_query_matched_vulnerabilities(db, host=row.target_ref, cve_id=risk.cve_id)["count"] == 1
    assert tools.tool_query_matched_vulnerabilities(db, host="unrelated", cve_id=risk.cve_id)["count"] == 0


def test_schema_expansion_and_new_receipt_are_not_substantive():
    assert I.substantive_change({"packages": [["curl", "1.0", "amd64"]]},
        {"packages": [["curl", "1.0", "amd64"]], "official": {"cve": "hash"}}) is False


def test_migration_rollback_plan_detects_drift_without_writing(case):
    from app.services.unified import migration
    db, row, conn = case
    manifest = migration.snapshot(db)
    risk = db.get(models.RiskAssessment, row.risk_id)
    risk.review_status = "pending_human_review"; db.commit()
    plan = migration.rollback_plan(db, manifest)
    assert plan["differences"][0]["changes"]["review_status"]["restore_to"] == manifest["risk_rows"][0]["review_status"]
    assert risk.review_status == "pending_human_review"
    assert db.query(models.UnifiedAnalysisRun).count() == 1
    manifest["risk_rows"][0]["review_status"] = "tampered"
    with pytest.raises(ValueError, match="corrupt"):
        migration.rollback_plan(db, manifest)


def test_proposal_budget_and_nested_decision_trace(case, session_factory):
    import copy
    from app.services import trace_service as tracing
    from app.services.unified.graph import RunContext, _run_specialist
    from app.services.unified.agents_def import DECISION_PLANNER_SPEC
    from tests.test_unified_pipeline import ScriptedClient, GOOD_DECISION, json_response
    db, row, conn = case
    for index in range(2):
        I.propose(db, row.run_id, {"target_agent": "asset_investigator", "collection_capability": "inventory",
            "question": f"version {index}?", "expected_effect": "resolve version gap"})
    with pytest.raises(ValueError, match="budget_exhausted"):
        proposal(db)
    trace = tracing.start_trace(db, task_type="unified_four_agent", target_type="linux_host", target_ref=row.target_ref)
    output = copy.deepcopy(GOOD_DECISION)
    output["verdicts"][0]["supporting_evidence_ids"] = ["INV-reference"]
    client = ScriptedClient({"研判与处置规划师": [json_response(output)]})
    ctx = RunContext(db_factory=session_factory, trace_id=trace.trace_id, client_factory=lambda: client)
    result, error = _run_specialist(ctx, DECISION_PLANNER_SPEC, "trace test")
    assert result is not None and not error
    finished = db.query(models.TraceEvent).filter_by(trace_id=trace.trace_id, event_type="agent_finished").one()
    assert "INV-reference" in json.loads(finished.evidence_refs_json)
