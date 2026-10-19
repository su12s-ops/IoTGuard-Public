import json
import pytest
from app import models
from app.services import agent_harness as h
from test_agent_harness_upgrade import rig, planned


def ready(rig, monkeypatch):
    run = planned(rig)
    monkeypatch.setattr(h, "_run_check", lambda *a: {"passed": False, "evidence": {"original_failure": True}})
    h.execute(rig.db, run)
    receipt = rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id, tool="install_registered_package").one()
    item = rig.artifacts[0]
    receipt.output_json = h.encode({"artifact_id": item["id"], "sha256": item["sha256"], "command_exit_success": True})
    rig.db.commit()
    replacement = {**item, "id": "verification"}
    rig.manifest.write_text(json.dumps({"artifacts": [*rig.artifacts, replacement]}), encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_VERIFICATION_ARTIFACT_ID", "verification")
    return run, receipt


def test_addendum_is_bound_append_only_and_idempotent(rig, monkeypatch):
    run, receipt = ready(rig, monkeypatch)
    original = (run.plan_json, run.plan_hash, run.approval_hash, receipt.output_json)
    proposal = h.verification_proposal(rig.db, run)
    with pytest.raises(ValueError, match="operator_approval"):
        h.execute(rig.db, run, verify_only=True)
    with pytest.raises(ValueError, match="hash_mismatch"):
        h.approve_verification(rig.db, run, "0"*64, "operator", "bad hash")
    for _ in range(2):
        h.approve_verification(rig.db, run, proposal["sha256"], "operator", "read-only verification")
    assert rig.db.query(models.HarnessToolCall).filter_by(tool="verification_addendum_approved").count() == 1
    def collect(db, connection):
        rig.asset.inventory_collected_at = models.utcnow()
        db.commit()
        return h.inventory(rig.asset)
    monkeypatch.setattr(h, "_collect", collect)
    monkeypatch.setattr(h, "_run_check", lambda *a: {"passed": True, "evidence": {"fixture": True}})
    monkeypatch.setattr(h, "_read_verification_logs", lambda c: {"passed": True, "evidence": {"fixture": True}})
    h.execute(rig.db, run, verify_only=True)
    assert run.status == "verified", run.error
    count = rig.db.query(models.HarnessToolCall).count()
    h.execute(rig.db, run, verify_only=True)
    assert rig.db.query(models.HarnessToolCall).count() == count
    assert len(rig.calls) == 1
    assert original == (run.plan_json, run.plan_hash, run.approval_hash, receipt.output_json)
    assert rig.db.query(models.HarnessToolCall).filter_by(tool="regression_check").first().output_json.find("original_failure") >= 0


@pytest.mark.parametrize("mutation", ["identity", "receipt", "package", "original_plan"])
def test_changed_bindings_rejected_before_collection(rig, monkeypatch, mutation):
    run, receipt = ready(rig, monkeypatch)
    proposal = h.verification_proposal(rig.db, run)
    h.approve_verification(rig.db, run, proposal["sha256"], "operator", "read-only verification")
    if mutation == "identity":
        rig.connection.host = "192.168.50.2"
    elif mutation == "receipt":
        receipt.output_json = "{}"
    elif mutation == "package":
        data = json.loads(rig.manifest.read_text())
        data["artifacts"][-1]["version"] = "unexpected"
        rig.manifest.write_text(json.dumps(data))
    else:
        run.plan_json = "{}"
    rig.db.commit()
    with pytest.raises(ValueError):
        h.execute(rig.db, run, verify_only=True)
    assert len(rig.calls) == 1
