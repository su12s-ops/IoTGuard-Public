import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location("runtime_forwarder", Path(__file__).resolve().parents[2] / "collector" / "ebpf_event_collector.py")
forwarder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarder)


def test_enrichment_preserves_process_identity_and_rejects_conflicts():
    event = {"process_exec": {"process": {"pid": 12, "exec_id": "fixture"}}}
    result = forwarder.enrich_event(event, asset_id=7, sensor_id="s", boot_id="b")
    assert result["process_exec"] == event["process_exec"]
    assert result["asset_id"] == 7 and "asset_id" not in event
    with pytest.raises(ValueError):
        forwarder.enrich_event({"asset_id": 8}, asset_id=7)


def test_uploader_without_health_never_claims_probe_running(tmp_path):
    assert forwarder.sensor_health(None)["status"] == "degraded"
    file = tmp_path / "health.json"
    file.write_text(json.dumps({"status": "running", "dropped_events": 0, "capabilities": {"driver": "modern_bpf"}}))
    assert forwarder.sensor_health(file)["status"] == "running"
    os.utime(file, (time.time() - 200, time.time() - 200))
    assert forwarder.sensor_health(file)["status"] == "degraded"


def test_rejected_lines_are_visible_and_shutdown_is_stopped():
    args = SimpleNamespace(health_file=None, asset_id=2, sensor_id="fixture", source="falco")
    result = forwarder.heartbeat_payload(args, rejected=2, stopped=True)
    assert result["status"] == "stopped"
    assert result["capabilities"]["rejected_lines"] == 2
    assert result["dropped_events"] is None


def test_historical_file_does_not_receive_current_boot_id(tmp_path, monkeypatch):
    file = tmp_path / "events.jsonl"
    file.write_text('{"process_name":"fixture","timestamp":"2026-01-01T00:00:00Z"}\n')
    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(file)])
    monkeypatch.setattr(forwarder, "read_boot_id", lambda: "must-not-be-added")
    collected = []
    monkeypatch.setattr(forwarder, "post_event", lambda api, event, token: collected.append(event))
    assert forwarder.main() == 0
    assert "boot_id" not in collected[0]


def test_live_stream_heartbeat_and_failure_exit(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "fixture-token")
    monkeypatch.setattr(sys, "argv", ["collector", "--heartbeat", "--asset-id", "1", "--source", "falco"])
    monkeypatch.setattr(forwarder, "iter_lines", lambda path: iter(['{"rule":"fixture"}\n']))
    sent = []
    monkeypatch.setattr(forwarder, "post_json", lambda api, path, body, token: sent.append((path, body)))
    monkeypatch.setattr(forwarder, "post_event", lambda *args: (_ for _ in ()).throw(OSError("offline fixture")))
    assert forwarder.main() == 1
    assert sent[0][1]["status"] == "degraded"
    assert sent[-1][1]["status"] == "stopped"
