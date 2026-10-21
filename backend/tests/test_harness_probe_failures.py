"""Isolated repair-to-verification tests; no real devices or model calls."""
import json

import pytest

from app import models
from app.services import agent_harness as h
from test_agent_harness_upgrade import rig, planned


@pytest.mark.parametrize("broken_kind", ["regression", "business"])
@pytest.mark.parametrize("error_type", [TimeoutError, ValueError])
def test_probe_error_preserves_results_and_can_resume(rig, monkeypatch, broken_kind, error_type):
    run = planned(rig)
    checks = []

    def check(item, root, kind, target):
        checks.append(kind)
        if kind == broken_kind:
            raise error_type("probe unavailable")
        return {"passed": True, "evidence": {"fixture": True}}

    monkeypatch.setattr(h, "_run_check", check)
    h.execute(rig.db, run)
    result = json.loads(run.result_json)
    assert checks == ["regression", "business"]
    assert run.status == "verification_required"
    assert result["verified"] is False
    assert result["validation_status"] == "inconclusive"
    assert result[broken_kind]["status"] == "inconclusive"
    assert rig.risk.review_status != "resolved"
    assert rig.task.status != "verified"
    assert rig.db.query(models.HarnessToolCall).filter_by(
        run_id=run.id, tool=broken_kind + "_check", status="failed").count() == 1
    assert rig.db.query(models.HarnessAssetLock).count() == 0

    monkeypatch.setattr(h, "_run_check", lambda *a: {"passed": True, "evidence": {"fixture": True}})
    h.execute(rig.db, run, verify_only=True)
    assert run.status == "verified", run.error
    assert json.loads(run.result_json)["validation_status"] == "passed"
    assert rig.risk.review_status == "resolved"
    assert rig.task.status == "verified"
    assert len(rig.calls) == 1  # Resume verification never reinstalls.


def test_negative_probe_is_failed_not_inconclusive(rig, monkeypatch):
    run = planned(rig)
    monkeypatch.setattr(h, "_run_check", lambda *a: {"passed": False, "evidence": {"fixture": True}})
    h.execute(rig.db, run)
    result = json.loads(run.result_json)
    assert result["validation_status"] == "failed"
    assert run.status == "verification_required"
    assert rig.risk.review_status != "resolved"
