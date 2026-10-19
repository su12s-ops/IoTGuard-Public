"""All package bytes, devices, checks and CVEs here are isolated test doubles."""
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import models
from app.services import agent_harness as h
from app.services.matching_engine import run_matching
from test_iot_upgrade import seed_openwrt, add_advisory, control


@pytest.fixture
def rig(session_factory, tmp_path, monkeypatch):
    root = tmp_path / "registry"
    root.mkdir()
    check = root / "fixture_check.py"
    check.write_text('import json,sys\nt=json.load(sys.stdin)\nprint(json.dumps({"passed":bool(t.get("host")),"evidence":{"fixture_only":True}}))\n', encoding="utf-8")
    checksum = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    checks = {kind: {"path": check.name, "sha256": checksum(check)} for kind in ("regression", "business")}
    artifacts = []
    for name, version in (("fixed", "2.0.2-1"), ("old", "2.0.1-1")):
        path = root / (name + ".ipk")
        path.write_bytes(("TEST ONLY " + name).encode())
        artifacts.append(dict(id=name, package_name="mosquitto", version=version, release="24.10.2",
            board_name="test,board", package_manager="opkg", path=path.name, sha256=checksum(path),
            checks=checks, rollback_artifact_id="old"))
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"artifacts": artifacts}), encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_REPAIR_MANIFEST", str(manifest))
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "1")
    with session_factory() as db:
        asset = seed_openwrt(db)
        asset.repair_domain = "production"
        add_advisory(db)
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).one()
        risk = models.RiskAssessment(asset_id=asset.id, match_id=match.id, cve_id=match.cve_id,
            package_name="mosquitto", review_status="human_confirmed", risk_level="High",
            recommended_action="immediate_fix", human_review_required=False)
        connection = models.DeviceConnection(asset_id=asset.id, host="192.168.50.1", username="root",
            credential_env="LINUXGUARD_DEVICE_TEST", host_key_sha256="SHA256:" + "A" * 43)
        db.add_all([risk, connection])
        db.commit()
        task = models.RemediationTask(asset_id=asset.id, risk_id=risk.id, cve_id=risk.cve_id,
            package_name="mosquitto", status="pending")
        db.add(task)
        db.commit()
        calls = []

        def install(connection, item, path, rollback=False):
            calls.append({"artifact_id": item["id"], "rollback": rollback})
            package = next(p for p in asset.packages if p.package_name == item["package_name"])
            package.package_version = item["version"]
            db.commit()
            return {"test_double": True, "verification_pending": True}

        monkeypatch.setattr(h, "install_registered_package", install)
        monkeypatch.setattr(h, "_collect", lambda db, connection: h.inventory(db.get(models.LinuxAsset, connection.asset_id)))
        yield SimpleNamespace(db=db, asset=asset, risk=risk, match=match, connection=connection,
            task=task, calls=calls, root=root, manifest=manifest, artifacts=artifacts)


def planned(rig, approve=True):
    run = h.create_run(rig.db, rig.asset.id, rig.risk.id, goal="repair", artifact_id="fixed")
    assert run.status == "awaiting_approval", run.plan_json
    if approve:
        h.approve(rig.db, run, run.plan_hash, "test-operator", "isolated adapter test")
    return run


def test_full_repair_requires_version_regression_and_business(rig):
    run = planned(rig)
    h.execute(rig.db, run)
    assert run.status == "verified", run.error
    result = json.loads(run.result_json)
    assert result["version_verified"] and result["regression"]["passed"] and result["business"]["passed"]
    assert rig.risk.review_status == "resolved" and rig.task.status == "verified"
    assert result["runtime_comparison"]["verification_status"] == "requires_inventory_and_business_checks"
    assert len(rig.calls) == 1
    assert rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id, side_effect=True).count() == 1
    assert rig.db.query(models.HarnessAssetLock).count() == 0
    with pytest.raises(ValueError):
        h.execute(rig.db, run)
    assert len(rig.calls) == 1


def test_unapproved_plan_cannot_write(rig):
    run = planned(rig, approve=False)
    with pytest.raises(ValueError, match="批准"):
        h.execute(rig.db, run)
    with pytest.raises(ValueError):
        h.approve(rig.db, run, "f" * 64, "test", "wrong plan")
    assert rig.calls == []


def test_repair_domain_change_invalidates_existing_approval(rig, monkeypatch):
    run = planned(rig)
    rig.asset.repair_domain = "openwrt_lab"
    rig.db.commit()
    monkeypatch.setenv("LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", "1")
    monkeypatch.setenv("LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE", str(rig.asset.id))
    h.execute(rig.db, run)
    assert run.status == "failed" and "授权域" in run.error
    assert rig.calls == []


@pytest.mark.parametrize("mutation", ["connection", "inventory", "advisory", "review", "artifact", "manifest", "disabled"])
def test_changes_after_approval_prevent_write(rig, monkeypatch, mutation):
    run = planned(rig)
    if mutation == "connection":
        rig.connection.host = "192.168.50.2"
    elif mutation == "inventory":
        rig.asset.packages[0].package_version = "unapproved"
    elif mutation == "advisory":
        rig.db.query(models.OpenWrtAdvisory).one().fixed_versions_json = '["2.0.3-1"]'
    elif mutation == "review":
        rig.risk.review_evidence_ids = '["changed-evidence"]'
    elif mutation == "artifact":
        (rig.root / "fixed.ipk").write_bytes(b"tampered")
    elif mutation == "manifest":
        rig.artifacts[0]["checks"]["regression"]["path"] = "changed.py"
        rig.manifest.write_text(json.dumps({"artifacts": rig.artifacts}), encoding="utf-8")
    else:
        monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    rig.db.commit()
    h.execute(rig.db, run)
    assert run.status == "failed" and run.error
    assert rig.calls == []


@pytest.mark.parametrize("missing", ["review", "inventory", "manager", "model", "rollback"])
def test_unsuitable_plan_is_blocked(rig, missing):
    if missing == "review":
        rig.risk.review_status = "candidate"
    elif missing == "inventory":
        rig.asset.inventory_complete = False
    elif missing == "manager":
        next(p for p in rig.asset.packages if p.package_name == "mosquitto").package_manager = "apk"
    elif missing == "model":
        rig.asset.device_model = "different-board"
    else:
        (rig.root / "old.ipk").unlink()
    rig.db.commit()
    run = h.create_run(rig.db, rig.asset.id, rig.risk.id, goal="repair", artifact_id="fixed")
    assert run.status == "blocked"
    assert json.loads(run.plan_json)["blocked_reasons"]


@pytest.mark.parametrize("kind", ["regression", "business"])
def test_failed_check_does_not_close_risk(rig, monkeypatch, kind):
    run = planned(rig)
    monkeypatch.setattr(h, "_run_check", lambda item, root, current, target: {"passed": current != kind, "evidence": "fixture failure"})
    h.execute(rig.db, run)
    assert run.status == "verification_required"
    assert rig.task.status != "verified" and rig.risk.review_status != "resolved"
    with pytest.raises(ValueError):
        h.execute(rig.db, run)
    assert len(rig.calls) == 1


def test_uncertain_install_can_only_be_verified_without_replay(rig, monkeypatch):
    run = planned(rig)
    original = h.install_registered_package
    def uncertain(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("fixture network loss after install")
    monkeypatch.setattr(h, "install_registered_package", uncertain)
    h.execute(rig.db, run)
    assert run.status == "verification_required"
    h.execute(rig.db, run, verify_only=True)
    assert run.status == "verified", run.error
    assert len(rig.calls) == 1


def test_asset_lock_serializes_independent_runs(rig):
    first = planned(rig)
    second = planned(rig)
    h._claim(rig.db, first, {"approved"})
    with pytest.raises(ValueError, match="并发"):
        h.execute(rig.db, second)
    assert second.status == "approved" and rig.calls == []
    with pytest.raises(ValueError):
        h.cancel(rig.db, first)


def test_stale_approval_cannot_revive_cancelled_task(rig, session_factory):
    run = planned(rig, approve=False)
    with session_factory() as stale:
        old = stale.get(models.HarnessRun, run.id)
        h.cancel(rig.db, run)
        with pytest.raises(ValueError):
            h.approve(stale, old, old.plan_hash, "test", "stale approval")
    rig.db.refresh(run)
    assert run.status == "cancelled"


def test_verified_repair_can_rollback_without_claiming_cve_fixed(rig):
    run = planned(rig)
    h.execute(rig.db, run)
    h.rollback(rig.db, run, run.plan_hash, "test", "rollback fixture")
    assert run.status == "rolled_back", run.error
    assert rig.risk.review_status == "remediation_ready" and rig.task.status == "pending"
    assert json.loads(run.result_json)["vulnerability_resolved"] is False
    assert rig.calls[-1]["rollback"] is True


def test_uncertain_rollback_invalidates_previous_success(rig, monkeypatch):
    run = planned(rig)
    h.execute(rig.db, run)
    original = h.install_registered_package
    def uncertain(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("fixture interruption after downgrade")
    monkeypatch.setattr(h, "install_registered_package", uncertain)
    h.rollback(rig.db, run, run.plan_hash, "test", "rollback fixture")
    assert run.status == "verification_required"
    assert rig.risk.review_status != "resolved" and rig.task.status != "verified"


def test_interrupted_recovery_preserves_audit_and_never_replays(rig):
    run = planned(rig)
    h._claim(rig.db, run, {"approved"})
    run.updated_at = models.utcnow() - timedelta(minutes=20)
    rig.db.add(models.HarnessToolCall(run_id=run.id, tool="install_registered_package", side_effect=True))
    rig.db.commit()
    assert h.recover_interrupted(rig.db) == 1
    assert run.status == "interrupted" and rig.calls == []
    assert rig.db.query(models.HarnessAssetLock).count() == 0
    assert rig.db.query(models.HarnessToolCall).one().status == "interrupted"
    with pytest.raises(ValueError):
        h.execute(rig.db, run)


def test_registered_file_cannot_escape_manifest_directory(rig, tmp_path):
    outside = tmp_path / "outside.ipk"
    outside.write_bytes(b"test")
    with pytest.raises(ValueError):
        h.checked_file(rig.root, "../outside.ipk", hashlib.sha256(b"test").hexdigest())


def test_harness_embedded_model_review_is_retired(rig):
    with pytest.raises(ValueError, match="harness_embedded_llm_retired"):
        h.create_run(rig.db, rig.asset.id, rig.risk.id, model_review=True)
    assert rig.calls == []


def test_harness_api_requires_control_and_prevents_manual_verification(rig, client, control):
    assert client.post("/api/harness/runs", json={"asset_id": rig.asset.id}).status_code == 401
    response = client.post("/api/harness/runs", json={"asset_id": rig.asset.id}, headers=control)
    assert response.status_code == 200
    run_id = response.json()["id"]
    assert client.get("/api/harness/runs/" + run_id).json()["tool_calls"] == []
    response = client.patch("/api/remediation/tasks/" + str(rig.task.id), json={"status": "verified"}, headers=control)
    assert response.status_code in {400, 409}


def test_unrelated_package_change_requires_review(rig, monkeypatch):
    run = planned(rig)
    install = h.install_registered_package
    def changes_dependency(*args, **kwargs):
        result = install(*args, **kwargs)
        next(p for p in rig.asset.packages if p.package_name == "libopenssl3").package_version = "unexpected-version"
        rig.db.commit()
        return result
    monkeypatch.setattr(h, "install_registered_package", changes_dependency)
    h.execute(rig.db, run)
    assert run.status == "verification_required"
    assert json.loads(run.result_json)["inventory_scope_verified"] is False
    assert rig.risk.review_status != "resolved"


def test_verification_can_finish_after_risk_recalculation(rig, monkeypatch):
    run = planned(rig)
    install = h.install_registered_package
    def interrupted(*args, **kwargs):
        install(*args, **kwargs)
        raise TimeoutError("fixture interruption")
    monkeypatch.setattr(h, "install_registered_package", interrupted)
    h.execute(rig.db, run)
    rig.risk.active = False
    rig.risk.review_status = "resolved"
    rig.db.commit()
    h.execute(rig.db, run, verify_only=True)
    assert run.status == "verified", run.error


def test_rollback_has_reserved_budget(rig):
    run = planned(rig)
    h.execute(rig.db, run)
    while rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id).count() < 16:
        rig.db.add(models.HarnessToolCall(run_id=run.id, tool="fixture_read", status="completed"))
        rig.db.commit()
    h.rollback(rig.db, run, run.plan_hash, "operator", "recover business")
    assert run.status == "rolled_back", run.error


def test_running_harness_prevents_manual_connection_change(rig, client, control):
    run = planned(rig)
    h._claim(rig.db, run, {"approved"})
    response = client.post("/api/iot/connections/" + str(rig.connection.id) + "/collect", headers=control)
    assert response.status_code == 409


def test_risk_recalculation_cannot_bypass_failed_business_check(rig, monkeypatch):
    from app.services.risk_engine import calculate_risk
    run = planned(rig)
    monkeypatch.setattr(h, "_run_check", lambda *args: {"passed": False, "evidence": "fixture failed"})
    h.execute(rig.db, run)
    calculate_risk(rig.db)
    assert run.status == "verification_required"
    assert rig.risk.active and rig.risk.review_status == "verification"
    assert rig.task.status != "verified"
