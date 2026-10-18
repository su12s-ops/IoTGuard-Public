"""Isolated admission and periodic collection regressions; no device writes."""
import copy
import hashlib
import json
from datetime import timedelta

import pytest
from app import config, models
from app.services import collection_tasks as C, device_access
from app.services.review_common import governance as G
from app.services.unified.adapter import generate_and_save_report_unified, formal_sink
from tests.test_m5_native_governance import case
from tests.test_stage4_collection import rig, synthetic_document
from tests.test_unified_adapter import FULL_SCRIPT
from tests.test_unified_pipeline import ScriptedClient


def test_behavior_runtime_reuse_is_scoped_to_request_and_scenario(session_factory, monkeypatch):
    from app.services import agent_intelligence as A
    from tests.test_unified_adapter import _setup_risk
    for suffix in (1, 2, 3):
        _setup_risk(session_factory, cve_id=f"CVE-2099-{suffix:04}")
    with session_factory() as db:
        db.query(models.VulnerabilityInfo).filter_by(cve_id="CVE-2099-0003").one().description = "local user privilege escalation"
        db.commit()
        calls = []
        real = A._runtime_matches
        def observe(*args):
            calls.append(args[-1]["id"])
            return real(*args)
        monkeypatch.setattr(A, "_runtime_matches", observe)
        monkeypatch.setattr(A, "load_runtime_events", lambda **kw: [])
        assert len(A.build_behavior_chains(db)) == 3
        assert len(calls) == 2 and len(set(calls)) == 2
        A.build_behavior_chains(db)
        assert len(calls) == 4  # No stale cross-request runtime cache.


def test_postrepair_full_pipeline_keeps_original_history(case, session_factory, monkeypatch):
    import app.services.unified.runner as runner
    monkeypatch.setattr(runner, "SessionLocal", session_factory)
    db, risk = case
    risk.active, risk.review_status = False, "resolved"
    raw = "synthetic authenticated inventory"
    db.add(models.CollectionEvidence(evidence_id="INV-final-test", asset_id=risk.asset_id,
        run_id="fixture", raw_text=raw, content_sha256=hashlib.sha256(raw.encode()).hexdigest()))
    db.commit()
    before = G.snapshot(risk)
    result = generate_and_save_report_unified(db, run_id="postrepair-fixture", risk_id=risk.id,
        post_repair=True, client_factory=lambda: ScriptedClient(copy.deepcopy(FULL_SCRIPT)))
    db.refresh(risk)
    assert G.snapshot(risk) == before
    report = db.query(models.AnalysisReport).filter_by(review_run_id="postrepair-fixture").one()
    assert f"risk-{risk.id}" not in [i["object_id"] for i in json.loads(report.skipped_objects_json)]
    event = db.query(models.RiskGovernanceEvent).filter_by(kind="post_repair_assessment").one()
    assert json.loads(event.payload_json)["business_accepted"] is False
    row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=f"UA-postrepair-fixture-{risk.id}").one()
    assert row.mode == "formal" and row.status != "failed"


@pytest.mark.parametrize("status,raw,sha", [("inactive", "valid", None), ("resolved", "bad", "0"*64)])
def test_postrepair_rejects_archived_or_corrupted_inventory(case, status, raw, sha):
    db, risk = case
    risk.active, risk.review_status = False, status
    db.add(models.CollectionEvidence(evidence_id="INV-fixture", asset_id=risk.asset_id,
        run_id="fixture", raw_text=raw, content_sha256=sha or hashlib.sha256(raw.encode()).hexdigest()))
    db.commit()
    with pytest.raises(ValueError):
        generate_and_save_report_unified(db, risk_id=risk.id, post_repair=True)
    assert not db.query(models.RiskGovernanceEvent).count()


LOG = ("===== IDENTITY =====\nhostname: synthetic-openwrt\nboot_id: synthetic-boot\n"
       "device_local_offset: +0000\n===== LOGREAD =====\n"
       "Sun Oct 18 12:00:00 2026 daemon.info test[123]: fixture-only\n")


def setup_logs(rig, monkeypatch):
    from types import SimpleNamespace
    with rig.factory() as db:
        db.get(models.LinuxAsset, rig.initial["id"]).hostname = "synthetic-openwrt"
        db.commit()
    monkeypatch.setattr(device_access, "open_connection", lambda c: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(device_access, "run_fixed_script", lambda *a, **kw: LOG)
    monkeypatch.setenv("LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS", str(rig.connection["id"]))
    monkeypatch.setenv("LINUXGUARD_OPENWRT_LOG_INTERVAL_S", "60")


def test_periodic_logs_persist_raw_and_deduplicate_across_restart(rig, monkeypatch):
    setup_logs(rig, monkeypatch)
    with rig.factory() as db:
        C.runtime_schedule_tick(db, now=1800000000)
        rows = db.query(models.HarnessRun).all()
        assert len(rows) == 1 and rows[0].status == "completed", rows[0].error
        assert db.query(models.CollectionEvidence).one().raw_text == LOG
        assert db.query(models.RuntimeEvent).count() == 1
        C.runtime_schedule_tick(db, now=1800000015)
        assert db.query(models.HarnessRun).count() == 1
    with rig.factory() as db:
        C.runtime_schedule_tick(db, now=1800000060)
        assert db.query(models.RuntimeEvent).count() == 1
        rows = db.query(models.HarnessRun).order_by(models.HarnessRun.created_at).all()
        assert json.loads(rows[-1].result_json)["events_duplicates"] == 1
        assert db.query(models.CollectionEvidence).count() == 2
        assert db.query(models.HarnessAssetLock).count() == 0


def test_periodic_disabled_and_failed_identity_has_bounded_retries(rig, monkeypatch):
    setup_logs(rig, monkeypatch)
    monkeypatch.delenv("LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS")
    with rig.factory() as db:
        C.runtime_schedule_tick(db, now=1800000000)
        assert db.query(models.HarnessRun).count() == 0
        monkeypatch.setenv("LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS", str(rig.connection["id"]))
        monkeypatch.setattr(device_access, "run_fixed_script", lambda *a, **kw: LOG.replace("synthetic-openwrt", "foreign-host"))
        for _ in range(5):
            C.runtime_schedule_tick(db, now=1800000000)
        assert db.query(models.HarnessRun).count() == 2
        assert all(r.status == "failed" for r in db.query(models.HarnessRun))
        assert db.query(models.RuntimeEvent).count() == db.query(models.CollectionEvidence).count() == 0


def test_periodic_times_out_only_own_lock(rig, monkeypatch):
    setup_logs(rig, monkeypatch)
    with rig.factory() as db:
        run = C.create_run(db, rig.connection["id"], "stalled", "runtime_logs")
        run.status, run.created_at = "queued_remote", models.utcnow() - timedelta(seconds=901)
        db.add(models.HarnessAssetLock(asset_id=run.asset_id, run_id=run.id)); db.commit()
        C.runtime_schedule_tick(db)
        db.refresh(run)
        assert run.status == "interrupted"
        assert db.query(models.HarnessAssetLock).count() == 0


def test_periodic_and_postrepair_require_control_token(client, control_headers):
    assert client.post("/api/analysis/runs?risk_id=1&post_repair=true").status_code == 401
    assert client.post("/api/iot/connections/1/collection-runs", json={"purpose":"runtime_logs"}).status_code == 401


@pytest.mark.parametrize("mac", ["02:00:00:00:00:41", ""])
def test_runtime_identity_matches_inventory_suffix_and_rejects_foreign_host(rig, monkeypatch, mac):
    setup_logs(rig, monkeypatch)
    with rig.factory() as db:
        asset = db.get(models.LinuxAsset, rig.initial["id"])
        connection = db.get(models.DeviceConnection, rig.connection["id"])
        suffix = mac.replace(":", "") if mac else hashlib.sha256(connection.host_key_sha256.encode()).hexdigest()[:12]
        asset.hostname, asset.mac_address = "synthetic-openwrt-" + suffix, mac
        db.commit()
        C.ingest_runtime_logs(db, connection, LOG, {"run_id":"suffix-regression"})
        assert db.query(models.RuntimeEvent).one().asset_id == asset.id
        assert db.query(models.CollectionEvidence).one().raw_text == LOG
        with pytest.raises(ValueError, match="identity_mismatch"):
            C.ingest_runtime_logs(db, connection, LOG.replace("synthetic-openwrt", "foreign"), {"run_id":"rejected"})
        assert db.query(models.CollectionEvidence).count() == 1
