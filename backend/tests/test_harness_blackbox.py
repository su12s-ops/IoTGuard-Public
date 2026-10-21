"""Public HTTP contract tests with isolated device I/O and real probe processes."""
import hashlib
import json

import pytest

from test_agent_harness_upgrade import rig
from test_iot_upgrade import control


@pytest.fixture
def boundary(rig, client, control):
    # Freeze probe bytes before approval. Only external observed state changes.
    probe = rig.root / "blackbox_probe.py"
    probe.write_text(
        'import json, pathlib, sys\n'
        'target = json.load(sys.stdin)\n'
        'mode = pathlib.Path("observed_state.txt").read_text()\n'
        'if mode == "invalid":\n'
        '    print("not-json")\n'
        'elif mode == "crash":\n'
        '    sys.exit(2)\n'
        'else:\n'
        '    print(json.dumps({"passed": mode == "healthy", '
        '"evidence": {"observed_state": mode, "host": target["host"]}}))\n',
        encoding="utf-8",
    )
    observed = rig.root / "observed_state.txt"
    observed.write_text("healthy", encoding="utf-8")
    manifest = json.loads(rig.manifest.read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        artifact["checks"]["business"] = {"path": probe.name,
            "sha256": hashlib.sha256(probe.read_bytes()).hexdigest()}
    rig.manifest.write_text(json.dumps(manifest), encoding="utf-8")
    response = client.post("/api/harness/runs", headers=control, json={
        "asset_id": rig.asset.id, "risk_id": rig.risk.id,
        "goal": "repair", "artifact_id": "fixed"})
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["status"] == "awaiting_approval"
    return "/api/harness/runs/" + run["id"], run, observed


def approve(client, control, url, run):
    response = client.post(url + "/approve", headers=control, json={
        "plan_hash": run["plan_hash"], "actor": "blackbox-operator",
        "reason": "isolated blackbox acceptance"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"


def test_api_authorization_and_plan_boundary(boundary, client, control):
    url, run, _ = boundary
    assert client.post(url + "/execute").status_code == 401
    assert client.post(url + "/execute", headers=control).status_code == 409
    response = client.post(url + "/approve", headers=control, json={
        "plan_hash": "0" * 64, "actor": "operator", "reason": "wrong plan"})
    assert response.status_code == 409
    detail = client.get(url).json()
    assert detail["status"] == "awaiting_approval"
    assert detail["tool_calls"] == []


def test_api_rejects_probe_changed_after_approval(boundary, rig, client, control):
    url, run, _ = boundary
    approve(client, control, url, run)
    (rig.root / "blackbox_probe.py").write_text("print('changed')", encoding="utf-8")
    response = client.post(url + "/execute", headers=control)
    assert response.status_code == 200, response.text
    detail = client.get(url).json()
    assert detail["status"] == "failed"
    assert detail["error"]
    assert not any(c["side_effect"] for c in detail["tool_calls"])


def test_api_verification_budget_stops_retries(boundary, client, control):
    url, run, observed = boundary
    approve(client, control, url, run)
    observed.write_text("unhealthy", encoding="utf-8")
    for action in ("execute", "verify", "verify"):
        response = client.post(url + "/" + action, headers=control)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "verification_required"
    before = client.get(url).json()
    assert before["attempts"] == 3
    assert client.post(url + "/verify", headers=control).status_code == 409
    after = client.get(url).json()
    assert after["tool_calls"] == before["tool_calls"]
    assert after["attempts"] == 3
    assert sum(c["side_effect"] for c in after["tool_calls"]) == 1


@pytest.mark.parametrize("mode, expected", [
    ("unhealthy", "failed"), ("invalid", "inconclusive"), ("crash", "inconclusive")])
def test_api_blackbox_failure_and_recovery(boundary, client, control, mode, expected):
    url, run, observed = boundary
    approve(client, control, url, run)
    observed.write_text(mode, encoding="utf-8")
    response = client.post(url + "/execute", headers=control)
    assert response.status_code == 200, response.text
    failed = client.get(url).json()
    assert failed["status"] == "verification_required"
    assert failed["result"]["verified"] is False
    assert failed["result"]["validation_status"] == expected
    assert failed["result"]["business"]["status"] == expected
    assert failed["result"]["regression"]["passed"] is True
    history = failed["tool_calls"]
    assert sum(c["side_effect"] for c in history) == 1
    assert client.post(url + "/execute", headers=control).status_code == 409

    observed.write_text("healthy", encoding="utf-8")
    response = client.post(url + "/verify", headers=control)
    assert response.status_code == 200, response.text
    final = client.get(url).json()
    assert final["status"] == "verified", final["error"]
    assert final["result"]["validation_status"] == "passed"
    assert final["result"]["business"]["evidence"]["observed_state"] == "healthy"
    assert sum(c["side_effect"] for c in final["tool_calls"]) == 1
    assert final["tool_calls"][:len(history)] == history
    assert final["plan_hash"] == run["plan_hash"]
    assert client.post(url + "/execute", headers=control).status_code == 409
