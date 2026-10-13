import json
from datetime import timedelta

from app import models
from app.services.ebpf_event_collector import normalize_event, append_events
from app.services.runtime_telemetry import timeline, coverage, compare_windows
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.risk_engine import _exploitability_status


def test_tetragon_kprobe_retains_process_file_and_socket_identity():
    payload = {"node_name": "fixture", "process_kprobe": {"function_name": "tcp_connect",
               "process": {"binary": "/usr/sbin/mosquitto", "pid": {"value": 17}, "exec_id": "exec-17", "start_time": "2026-09-30T00:00:00Z"},
               "parent": {"binary": "/sbin/procd", "pid": 1, "exec_id": "exec-1"},
               "args": [{"sock_arg": {"daddr": "192.0.2.1", "dport": 1883}}, {"file_arg": {"path": "/tmp/test"}}]}}
    event = normalize_event(payload)
    assert event["source"] == "tetragon"
    assert event["process_id"] == 17
    assert event["parent_exec_id"] == "exec-1"
    assert event["destination"] == "192.0.2.1"
    assert event["port"] == 1883
    assert event["file_path"] == "/tmp/test"


def test_timeline_does_not_join_reused_pid_or_other_assets(session_factory):
    with session_factory() as db:
        a, b = models.LinuxAsset(hostname="a"), models.LinuxAsset(hostname="b")
        db.add_all([a, b]); db.flush()
        for asset in (a, b):
            db.add_all([models.RuntimeEvent(asset_id=asset.id, process_id=10, event_type="exec"),
                        models.RuntimeEvent(asset_id=asset.id, process_id=10, event_type="connect")])
        db.commit()
        result = timeline(db, a.id)
        assert len(result["events"]) == 2
        assert len(result["processes"]) == 2
        assert result["edges"] == []
        assert not result["exploitation_confirmed"]


def test_stable_exec_ids_form_parent_edge(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="timeline")
        db.add(asset); db.flush()
        db.add_all([models.RuntimeEvent(asset_id=asset.id, process_exec_id="parent"),
                    models.RuntimeEvent(asset_id=asset.id, process_exec_id="child", parent_exec_id="parent"),
                    models.RuntimeEvent(asset_id=asset.id, process_exec_id="child", parent_exec_id="parent")])
        db.commit()
        result = timeline(db, asset.id)
        assert len(result["processes"]) == 2
        assert len(result["edges"]) == 1


def test_duplicate_event_replay_is_idempotent(session_factory, tmp_path, monkeypatch):
    from app.services import ebpf_event_collector as collector
    monkeypatch.setattr(collector, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        payload = {"hostname": "fixture", "timestamp": "2026-09-30T00:00:00Z", "event_type": "execve", "process_id": 10}
        result = append_events([payload, payload], db=db)
        assert db.query(models.RuntimeEvent).count() == 1
        assert result[1]["duplicate"]


def test_sensor_staleness_and_loss_are_visible(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="sensor")
        db.add(asset); db.flush()
        sensor = models.RuntimeSensor(asset_id=asset.id, sensor_id="test", source="falco", status="running", dropped_events=4)
        db.add(sensor); db.commit()
        assert coverage(db, asset.id)["status"] == "degraded"
        sensor.last_heartbeat_at = models.utcnow() - timedelta(minutes=5)
        db.commit()
        assert coverage(db, asset.id)["status"] == "stale"


def test_missing_observation_neither_reduces_risk_nor_proves_exploitation():
    asset = models.LinuxAsset(id=1, hostname="test")
    result = evaluate_runtime_evidence(asset, "mosquitto", [], [{"asset_id": 1, "process_name": "unrelated"}])
    assert result["status"] == "not_observed"
    assert result["adjustment_score"] == 0
    assert not result["absence_proves_safe"]
    assert _exploitability_status("internet_exposed", "verified", 95, None, 100) != "active"


def test_comparison_does_not_report_empty_window_as_fixed(session_factory):
    with session_factory() as db:
        result = compare_windows(db, 1, "2026-09-30T00:00:00Z")
        assert result["verification_status"] == "requires_inventory_and_business_checks"
        assert result["after"]["count"] == 0


def test_heartbeat_api_and_asset_conflict(client, session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "token")
    with session_factory() as db:
        a = models.LinuxAsset(hostname="test-host")
        db.add(a); db.commit(); asset_id = a.id
    result = client.post("/api/runtime/sensors/heartbeat", headers={"X-Control-Token": "token"}, json={"asset_id": asset_id, "sensor_id": "s1", "source": "tetragon", "status": "running"})
    assert result.status_code == 200
    assert result.json()["basis"] == "self_reported_collector_heartbeat"
    assert client.post("/api/runtime/ebpf/events", json={"asset_id": asset_id, "hostname": "wrong-host"}, headers={"X-Control-Token": "token"}).status_code == 400
