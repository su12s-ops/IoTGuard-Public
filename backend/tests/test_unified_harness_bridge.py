"""Isolated metadata prechecks; no device, network, production DB or model call."""
import hashlib
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from app import models
from app.services import agent_harness as harness, device_access, ubuntu_repair
from app.services.unified import harness_bridge as bridge
from test_iot_upgrade import seed_openwrt, add_advisory
from app.services.matching_engine import run_matching


@pytest.fixture
def bridge_rig(session_factory, tmp_path, monkeypatch):
    root = tmp_path / "registry"
    root.mkdir()
    check = root / "check.py"
    check.write_text("raise AssertionError('must never execute registered check')\n", encoding="utf-8")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    checks = {name: {"path": check.name, "sha256": digest(check)} for name in ("regression", "business")}
    artifacts = []
    for name, version in (("fixed", "2.0.2-1"), ("old", "2.0.1-1")):
        package = root / (name + ".ipk")
        package.write_bytes(("ISOLATED TEST ONLY " + name).encode())
        artifacts.append({"id": name, "package_name": "mosquitto", "version": version,
            "release": "24.10.2", "board_name": "test,board", "package_manager": "opkg",
            "architecture": "x86_64", "path": package.name, "sha256": digest(package),
            "checks": checks, "rollback_artifact_id": "old"})
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"artifacts": artifacts}), encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_REPAIR_MANIFEST", str(manifest))
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0")
    with session_factory() as db:
        asset = seed_openwrt(db)
        asset.repair_domain = "production"
        add_advisory(db)
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).one()
        risk = models.RiskAssessment(asset_id=asset.id, match_id=match.id, cve_id=match.cve_id,
            package_name=match.package_name, review_status="human_confirmed", risk_level="High",
            recommended_action="scheduled_fix", human_review_required=False)
        connection = models.DeviceConnection(asset_id=asset.id, host="192.168.50.1",
            credential_env="LINUXGUARD_DEVICE_TEST", host_key_sha256="SHA256:" + "A" * 43)
        db.add_all([risk, connection])
        db.commit()
        state = {"run_id": "test-run", "target_ref": asset.hostname,
            "baseline": {"object_id": f"risk-{risk.id}", "packet_evidence_ids": ["INV-test"]},
            "evidence_snapshot_id": "snapshot-test", "evidence_snapshot": {
                "snapshot_id": "snapshot-test", "asset_id": asset.id, "risk_id": risk.id,
                "evidence_registry": {"INV-test": {"source": "isolated_fixture"}}}}
        yield SimpleNamespace(db=db, asset=asset, risk=risk, match=match, connection=connection,
            state=state, root=root, manifest=manifest, artifacts=artifacts)


def planned(rig, action="update_package", params=None):
    rig.state["harness_capabilities"] = bridge.query_capabilities(rig.db, rig.state)
    return bridge.build_candidate_intents(rig.state, {"original_evidence_ids": ["INV-test"],
        "actions": [{"action": action, "target": "mosquitto", "params": params or {}}]})


def rewrite_manifest(rig):
    rig.manifest.write_text(json.dumps({"artifacts": rig.artifacts}), encoding="utf-8")


def test_readonly_query_never_dispatches_flushes_commits_or_exposes_secrets(bridge_rig, monkeypatch):
    rig = bridge_rig
    def forbidden(*args, **kwargs):
        raise AssertionError("mutation/device IO forbidden")
    for name in ("create_run", "approve", "execute", "install_registered_package", "_collect", "_run_check"):
        monkeypatch.setattr(harness, name, forbidden)
    monkeypatch.setattr(ubuntu_repair, "queue", forbidden)
    monkeypatch.setattr(device_access, "open_connection", forbidden)
    monkeypatch.setattr(rig.db, "commit", forbidden)
    statements = []
    event.listen(rig.db.bind, "before_cursor_execute",
        lambda conn, cursor, statement, parameters, context, many: statements.append(statement))
    rig.db.autoflush = True
    rig.db.add(models.HarnessRun(id="pending-must-not-flush", asset_id=rig.asset.id))
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig))
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert result["device_writes"] is False and result["execution_authorized"] is False
    assert str(rig.root) not in json.dumps(result)
    assert "credential_env" not in json.dumps(result) and "192.168.50.1" not in json.dumps(result)


def test_closed_production_policy_is_terminal_but_keeps_technical_readiness(bridge_rig):
    rig = bridge_rig
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig))
    assert result["status"] == "policy_denied" and result["terminal"]
    assert result["feedback"][0]["technical_status"] == "executable"
    assert "production_device_write_disabled" in result["reasons"]
    assert "exact_plan_hash_and_operator_approval_required" in result["reasons"]
    assert result["capabilities"]["trusted_artifacts"][0]["integrity_verified"]


def test_metadata_readiness_still_requires_exact_approval(bridge_rig, monkeypatch):
    rig = bridge_rig
    monkeypatch.setattr(bridge, "_write_policy", lambda asset: (True, ""))
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig))
    assert result["status"] == "authorization_required"
    assert result["execution_authorized"] is False and result["terminal"] is False
    assert rig.db.query(models.HarnessRun).count() == 0


@pytest.mark.parametrize("mutation,status,reason", [
    ("missing", "missing_artifact", "trusted_matching_artifact_required"),
    ("checksum", "missing_artifact", "registered_artifact_integrity_or_policy_failed"),
    ("architecture", "incompatible_version", "artifact_architecture_mismatch"),
    ("architecture_unknown", "insufficient_evidence", "artifact_architecture_unverified"),
    ("release", "incompatible_version", "artifact_device_or_package_manager_mismatch"),
    ("recovery", "missing_recovery_point", "compatible_registered_rollback_artifact_required"),
])
def test_typed_technical_feedback(bridge_rig, monkeypatch, mutation, status, reason):
    rig = bridge_rig
    monkeypatch.setattr(bridge, "_write_policy", lambda asset: (True, ""))
    if mutation == "missing":
        rig.artifacts.clear()
    elif mutation == "checksum":
        rig.artifacts[0]["sha256"] = "f" * 64
    elif mutation == "architecture":
        rig.artifacts[0]["architecture"] = "mips"
    elif mutation == "architecture_unknown":
        rig.artifacts[0].pop("architecture")
    elif mutation == "release":
        rig.artifacts[0]["release"] = "unknown"
    elif mutation == "recovery":
        rig.artifacts.pop()
    rewrite_manifest(rig)
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig))
    assert result["status"] == status
    assert reason in result["reasons"]


def test_approval_and_artifacts_are_not_cached(bridge_rig, monkeypatch):
    rig = bridge_rig
    monkeypatch.setattr(bridge, "_write_policy", lambda asset: (True, ""))
    intents = planned(rig)
    rig.artifacts.clear()
    rewrite_manifest(rig)
    rig.risk.review_status = "pending"
    rig.db.commit()
    result = bridge.precheck_intents(rig.db, rig.state, intents)
    assert result["status"] == "missing_artifact"
    assert "eligible_risk_review_required" in result["reasons"]


def test_guessed_version_and_forged_evidence_are_rejected(bridge_rig):
    rig = bridge_rig
    intents = planned(rig, params={"version": "invented-99", "sha256": "f" * 64})
    assert intents[0]["expected_result"]["fixed_version"] == rig.match.fixed_version
    assert "sha256" not in intents[0]["artifact_requirements"]
    assert "model_version_conflicts_with_deterministic_fix" in intents[0]["unsatisfied_conditions"]
    intents[0]["evidence_ids"] = ["FORGED-evidence"]
    result = bridge.precheck_intents(rig.db, rig.state, intents)
    assert "validated_evidence_references_required" in result["reasons"]


def test_old_baseline_reference_cannot_escape_snapshot_registry(bridge_rig):
    rig = bridge_rig
    rig.state["baseline"]["packet_evidence_ids"].append("stale-baseline")
    planned(rig)
    intents = bridge.build_candidate_intents(rig.state, {"original_evidence_ids": ["stale-baseline"],
        "actions": [{"action": "update_package", "target": "mosquitto"}]})
    assert intents[0]["evidence_ids"] == []
    assert "unknown_evidence_references_rejected" in intents[0]["unsatisfied_conditions"]


def test_scope_or_unsupported_action_never_routes_to_replanning(bridge_rig):
    rig = bridge_rig
    intents = planned(rig, action="firmware_ota")
    intents[0]["asset_id"] += 1
    result = bridge.precheck_intents(rig.db, rig.state, intents)
    assert result["terminal"]
    assert "intent_identity_scope_mismatch" in result["reasons"]
    assert "unsupported_harness_action" in result["reasons"]


def test_inventory_change_invalidates_candidate_snapshot(bridge_rig, monkeypatch):
    rig = bridge_rig
    monkeypatch.setattr(bridge, "_write_policy", lambda asset: (True, ""))
    intents = planned(rig, action="collect_evidence")
    rig.asset.architecture = "changed-after-planner"
    rig.db.commit()
    result = bridge.precheck_intents(rig.db, rig.state, intents)
    assert result["status"] == "insufficient_evidence"
    assert "inventory_changed_since_candidate_intent" in result["reasons"]


def test_empty_snapshot_registry_cannot_fall_back_to_old_baseline(bridge_rig):
    rig = bridge_rig
    rig.state["evidence_snapshot"]["evidence_registry"] = {}
    intents = planned(rig)
    assert intents[0]["evidence_ids"] == []
    assert "validated_evidence_references_required" in intents[0]["unsatisfied_conditions"]


def test_readonly_intent_does_not_bypass_snapshot_scope(bridge_rig):
    rig = bridge_rig
    rig.state["evidence_snapshot"]["asset_id"] += 1
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig, action="collect_evidence"))
    assert result["status"] == "policy_denied" and result["terminal"]
    assert "snapshot_asset_scope_mismatch" in result["reasons"]


def test_fixed_s2_and_verified_harness_do_not_authorize_another_upgrade(bridge_rig):
    rig = bridge_rig
    rig.match.affected, rig.match.match_status = False, "fixed"
    rig.match.reason_code = "openwrt_exact_fixed_version"
    rig.db.add(models.HarnessRun(id="prior-test", asset_id=rig.asset.id, risk_id=rig.risk.id,
        status="verified", plan_hash="a" * 64, approval_hash="a" * 64))
    rig.db.commit()
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig))
    assert "repair_not_applicable_to_current_match" in result["reasons"]
    assert result["capabilities"]["current_harness"]["execution_verified"]
    assert result["business_accepted"] is False
    assert result["capabilities"]["current_harness"]["approval_reused"] is False


def test_zephyr_no_invented_ota_but_read_only_evidence_is_available(bridge_rig):
    rig = bridge_rig
    rig.asset.distribution = "zephyr"
    rig.db.commit()
    result = bridge.precheck_intents(rig.db, rig.state, planned(rig, action="update_package"))
    assert result["capabilities"]["adapter"] is None
    assert result["terminal"] and "repair_adapter_unavailable" in result["reasons"]
    read = bridge.precheck_intents(rig.db, rig.state, planned(rig, action="collect_evidence"))
    assert read["status"] == "executable" and read["execution_authorized"] is False


def test_pydantic_state_is_supported(bridge_rig):
    from app.services.unified.state import UnifiedAnalysisState
    rig = bridge_rig
    state = UnifiedAnalysisState(run_id="fixture", baseline=rig.state["baseline"])
    assert bridge.query_capabilities(rig.db, state)["identity"]["asset_id"] == rig.asset.id


def test_ubuntu_without_live_preflight_stays_incomplete(bridge_rig, monkeypatch):
    rig = bridge_rig
    rig.asset.distribution = "ubuntu"
    rig.asset.os_version = "24.04"
    rig.db.commit()
    monkeypatch.setattr(bridge, "_write_policy", lambda asset: (True, ""))
    capabilities = bridge.query_capabilities(rig.db, rig.state)
    assert capabilities["adapter"] == "ubuntu-apt-v1"
    assert capabilities["ubuntu"]["dry_run_performed_here"] is False
    reasons = {i["reason"] for i in capabilities["issues"]}
    assert "fresh_authenticated_ubuntu_dependency_dry_run_required" in reasons
    assert "ubuntu_clone_restore_permit_requires_execution_time_validation" in reasons
    assert rig.db.query(models.HarnessRun).count() == 0
