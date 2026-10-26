"""Exercise acceptance gates against missing, reset and tampered evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[2] / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


soak = load("runtime_soak")
acceptance = load("validate_device_acceptance")


def sample(elapsed, count):
    metrics = dict.fromkeys(soak.COUNTERS, 0)
    metrics.update(received=count, parsed=count, uploaded=count,
                   spool_pending=0, spool_bytes=0, spool_full=0, spool_corrupt_lines=0, spool_blocked_events=0)
    return {"elapsed_seconds": elapsed,
            "health": {"status": "ok", "database": "ok", "layers": {"collection_node": {"online": True}}},
            "reliability": {"evidence_processing": {"pending": 0, "retrying": 0}, "sensors": [{
                "asset_id": 1, "sensor_id": "s", "status": "running", "heartbeat_age_seconds": 1,
                "dropped_events": 0, "self_reported_metrics": metrics, "server_observed": {"stored_events": count}}]}}


def test_clean_samples_are_observations_not_24_hour_acceptance():
    result = soak.assess([sample(0, 10), sample(30, 12)], {(1, "s")}, 30)
    assert result["status"] == "incomplete" and not result["acceptance_passed"]
    assert "less_than_24_hours" in result["missing_evidence"]
    assert not result["issues"]


@pytest.mark.parametrize("kind,issue", [
    ("reset", "counter_reset_or_event_deletion"), ("gap", "sampling_gap"),
    ("missing", "sensor_missing"), ("queue", "evidence_queue_not_drained"),
    ("loss", "probe_drops_nonzero"), ("mismatch", "upload_storage_delta_mismatch")])
def test_monitor_detects_broken_chain(kind, issue):
    samples = [sample(0, 10), sample(30, 12)]
    row = samples[1]["reliability"]["sensors"][0]
    if kind == "reset":
        row["self_reported_metrics"]["received"] = 1
    elif kind == "gap":
        samples[1]["elapsed_seconds"] = 300
    elif kind == "missing":
        row["asset_id"] = 2
    elif kind == "queue":
        samples[1]["reliability"]["evidence_processing"]["pending"] = 10
    elif kind == "loss":
        row["dropped_events"] = 2
    else:
        row["server_observed"]["stored_events"] = 11
    result = soak.assess(samples, {(1, "s")}, 86400)
    assert result["status"] == "failed" and any(issue in value for value in result["issues"])


def test_unknown_loss_does_not_turn_into_zero():
    item = sample(0, 1)
    item["reliability"]["sensors"][0]["dropped_events"] = "unavailable"
    result = soak.assess([item, sample(30, 2)], {(1, "s")}, 86400)
    assert "1:s:probe_drops_unavailable" in result["missing_evidence"]
    assert not result["acceptance_passed"]


def test_transient_evidence_queue_is_allowed_when_it_drains():
    samples = [sample(0, 1), sample(30, 2)]
    samples[0]["reliability"]["evidence_processing"]["pending"] = 2
    assert not soak.assess(samples, {(1, "s")}, 30)["issues"]


def test_monitor_cli_writes_hash_verified_receipts_without_mutations(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import json
    import subprocess
    import sys
    import threading
    requests = []
    payload = sample(0, 1)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path))
            body = payload["health"] if self.path == "/api/health" else payload["reliability"]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = tmp_path / "new-observation"
    try:
        result = subprocess.run([sys.executable, soak.__file__, "--base-url", f"http://127.0.0.1:{server.server_port}",
                                 "--sensor", "1:s", "--seconds", "1", "--interval", "1", "--output", str(output)],
                                capture_output=True, text=True, timeout=15)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result.returncode == 2, result.stderr
    saved = json.loads((output / "result.json").read_text(encoding="utf-8"))
    assert not saved["acceptance_passed"] and saved["samples"] >= 2
    assert saved["samples_sha256"] == hashlib.sha256((output / "samples.jsonl").read_bytes()).hexdigest()
    assert requests and all(method == "GET" for method, _ in requests)


def test_acceptance_manifest_requires_real_hashes_scope_and_human_references(tmp_path):
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("actual device output", encoding="utf-8")
    evidence = {"path": receipt.name, "sha256": hashlib.sha256(receipt.read_bytes()).hexdigest()}
    record = dict.fromkeys(acceptance.IDENTITY, "test")
    record.update(environment="virtual", config_sha256="a" * 64,
                  started_at="2026-10-25T10:00:00Z", ended_at="2026-10-25T11:00:00Z",
                  checks={name: {"status": "passed", "evidence": [evidence]} for name in acceptance.CHECKS})
    record["checks"]["remediation"]["approval_ref"] = "operator-approval"
    record["checks"]["signoff"].update(reviewer="operator", decision_ref="signed-record")
    result = acceptance.validate(record, tmp_path)
    assert result["status"] == "record_complete" and not result["business_accepted"]
    no_signoff = copy.deepcopy(record)
    del no_signoff["checks"]["signoff"]["decision_ref"]
    assert "human_signoff_reference_missing" in acceptance.validate(no_signoff, tmp_path)["errors"]
    escaped = copy.deepcopy(record)
    escaped["checks"]["identity"]["evidence"] = [{"path": "../outside.txt", "sha256": "a" * 64}]
    assert "evidence_outside_root:identity" in acceptance.validate(escaped, tmp_path)["errors"]
    receipt.write_text("tampered", encoding="utf-8")
    assert acceptance.validate(record, tmp_path)["status"] == "invalid"
