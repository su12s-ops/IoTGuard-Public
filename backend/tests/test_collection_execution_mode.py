"""Executor routing regression: isolated DB, no real SSH or credentials."""
import json

import pytest

from app import models
from app.services import collection_tasks as c, device_access


@pytest.fixture
def target(session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.0.2.0/24")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "test-pull")
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODES_JSON", raising=False)
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID", raising=False)
    monkeypatch.delenv("LINUXGUARD_DEVICE_TEST_KEY", raising=False)
    monkeypatch.delenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", raising=False)
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="test-wrt", distribution="openwrt", os_version="24.10")
        db.add(asset)
        db.flush()
        conn = models.DeviceConnection(asset_id=asset.id, host="192.0.2.10", username="tester",
            enabled=True, auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_TEST_KEY",
            host_key_sha256="SHA256:" + "A" * 43)
        db.add(conn)
        db.commit()
        yield db, conn


@pytest.mark.parametrize("mode,platform,pull", [
    ("auto", "Linux", False), ("auto", "Windows", True),
    ("pull", "Linux", True), ("pull", "Windows", True),
    ("local", "Linux", False), ("local", "Windows", False),
])
def test_routing_modes(monkeypatch, mode, platform, pull):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", mode)
    assert c.uses_pull_execution({"platform": platform}) is pull


def test_auto_default(monkeypatch):
    monkeypatch.delenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", raising=False)
    assert c.collection_execution_mode() == "auto"


def test_invalid_mode_fails_closed(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", "typo")
    with pytest.raises(ValueError, match="invalid_collection_execution_mode"):
        c.uses_pull_execution({"platform": "Linux"})


@pytest.mark.parametrize("purpose", ["inventory", "runtime_logs"])
def test_linux_pull_delegates_without_container_key(target, monkeypatch, purpose):
    db, conn = target
    monkeypatch.setenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", "pull")
    node = {"id": "api-container", "platform": "Linux", "mode": "standard"}
    monkeypatch.setattr(device_access, "collector_node", lambda: node)
    def forbidden(*args, **kwargs):
        pytest.fail("API container must not open device SSH")
    monkeypatch.setattr(device_access, "open_connection", forbidden)
    preflight = c.preflight(db, conn)
    assert preflight["ready"] is True
    assert preflight["node"]["platform"] == "Linux"
    assert "key_path_metadata" not in preflight["checks"]
    run = c.execute(db, c.create_run(db, conn.id, "docker-" + purpose, purpose))
    assert run.status == "queued_remote"
    assert json.loads(run.result_json)["queued_for_node"] == "test-pull"
    assignment = c.claim_for_node(db, "test-pull", "Linux")
    assert assignment["execution"] == "ssh"
    assert assignment["collector_type"] == ("openwrt_logread" if purpose == "runtime_logs" else "openwrt_ssh")


def test_pull_missing_node_never_falls_back(target, monkeypatch):
    db, conn = target
    monkeypatch.setenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", "pull")
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODE_ID")
    monkeypatch.setattr(device_access, "collector_node", lambda: {
        "id": "api-container", "platform": "Linux", "mode": "standard"})
    def forbidden(*args, **kwargs):
        pytest.fail("Missing pull node must not fall back to local SSH")
    monkeypatch.setattr(device_access, "open_connection", forbidden)
    assert c.preflight(db, conn)["ready"] is False
    run = c.execute(db, c.create_run(db, conn.id, "missing-node"))
    assert run.status == "failed"
    assert json.loads(run.result_json)["error_code"] == "node_platform_invalid"


def test_local_windows_not_made_capable_by_registered_node(target, monkeypatch):
    db, conn = target
    monkeypatch.setenv("LINUXGUARD_COLLECTION_EXECUTION_MODE", "local")
    monkeypatch.setattr(device_access, "collector_node", lambda: {
        "id": "windows-api", "platform": "Windows", "mode": "standard"})
    assert c.preflight(db, conn)["ready"] is False
    run = c.execute(db, c.create_run(db, conn.id, "local-windows"))
    assert run.status == "failed"
    assert json.loads(run.result_json)["error_code"] == "node_platform_invalid"


def test_auto_linux_still_requires_local_key_metadata(target, monkeypatch):
    db, conn = target
    monkeypatch.setattr(device_access, "collector_node", lambda: {
        "id": "linux-api", "platform": "Linux", "mode": "standard"})
    result = c.preflight(db, conn)
    assert result["ready"] is False
    assert result["checks"]["key_path_metadata"] is False
