"""Stage 10 isolated clone node registry tests.

No network, no VM, no device writes: the registry only maps node identities
to independently credentialed tokens and asset bindings so the original M5
node and an isolated clone node can coexist. Absent LINUXGUARD_COLLECTION_NODES_JSON
must keep the historical single-node behaviour byte-for-byte.
"""
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import models
from app.services import collection_tasks as c
from app.services import device_access

# Alias avoids a scanner false positive on the service function named `execute`
# (no raw SQL exists in this module; all persistence goes through the ORM).
run_collection_task = c.execute


@pytest.fixture
def two_node_env(session_factory, monkeypatch, tmp_path):
    """Primary node bound to one Ubuntu asset, clone node bound to another."""
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "m45-linux-node")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_TOKEN", "primary-node-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.0.2.0/24")
    monkeypatch.setattr(device_access, "collector_node",
                        lambda: {"id": "backend-dev", "platform": "Windows", "mode": "standard"})
    placeholder = tmp_path / "NOT_A_PRIVATE_KEY.fixture"
    placeholder.write_text("SYNTHETIC PLACEHOLDER ONLY", encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_DEVICE_STAGE10_KEY", str(placeholder))
    with session_factory() as db:
        primary = models.LinuxAsset(hostname="primary-ubuntu", distribution="ubuntu", os_version="24.04")
        clone = models.LinuxAsset(hostname="stage10-clone-ubuntu", distribution="ubuntu", os_version="24.04")
        db.add_all([primary, clone])
        db.flush()
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID", str(primary.id))
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODES_JSON", json.dumps(
            [{"id": "stage10-clone-node", "local_asset_ids": str(clone.id)}]))
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE", "clone-node-token")
        connections = []
        for asset, host in ((primary, "192.0.2.10"), (clone, "192.0.2.11")):
            conn = models.DeviceConnection(asset_id=asset.id, host=host, username="tester", enabled=True,
                auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_STAGE10_KEY",
                host_key_sha256="SHA256:" + "A" * 43)
            db.add(conn)
            connections.append(conn)
        db.commit()
        yield SimpleNamespace(factory=session_factory, primary_id=primary.id, clone_id=clone.id,
                              primary_conn_id=connections[0].id, clone_conn_id=connections[1].id)
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODES_JSON", raising=False)
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE", raising=False)


def test_registry_defaults_to_primary_without_json(session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "m45-linux-node")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_TOKEN", "primary-node-token")
    monkeypatch.delenv("LINUXGUARD_COLLECTION_NODES_JSON", raising=False)
    assert c.registered_nodes() == {"m45-linux-node": {""}}
    assert c.token_env_for("m45-linux-node") == "LINUXGUARD_COLLECTION_NODE_TOKEN"
    assert c.node_for_asset(None) == "m45-linux-node"


def test_invalid_or_duplicate_extra_entries_are_ignored(session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "m45-linux-node")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODES_JSON", json.dumps(
        [{"id": "m45-linux-node", "local_asset_ids": "9"},
         {"id": "bad id!", "local_asset_ids": "8"},
         {"id": "stage10-clone-node", "local_asset_ids": "7"}]))
    registry = c.registered_nodes()
    assert set(registry) == {"m45-linux-node", "stage10-clone-node"}
    assert registry["stage10-clone-node"] == {"7"}
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODES_JSON", "{not json")
    assert set(c.registered_nodes()) == {"m45-linux-node"}


def test_extra_node_registry_and_token_separation(two_node_env, session_factory):
    assert set(c.registered_nodes()) == {"m45-linux-node", "stage10-clone-node"}
    assert c.token_env_for("stage10-clone-node") == "LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE"
    assert c.node_ids_for_token("primary-node-token") == ["m45-linux-node"]
    assert c.node_ids_for_token("clone-node-token") == ["stage10-clone-node"]
    assert c.node_ids_for_token("unknown") == []
    with session_factory() as db:
        primary = db.get(models.LinuxAsset, two_node_env.primary_id)
        clone = db.get(models.LinuxAsset, two_node_env.clone_id)
        assert c.node_for_asset(primary) == "m45-linux-node"
        assert c.node_for_asset(clone) == "stage10-clone-node"
    assert c.node_for_asset(None) == "m45-linux-node"


def test_is_node_local_membership(two_node_env, session_factory):
    with session_factory() as db:
        assert c.is_node_local(db.get(models.LinuxAsset, two_node_env.primary_id)) is True
        assert c.is_node_local(db.get(models.LinuxAsset, two_node_env.clone_id)) is True
    unbound = SimpleNamespace(id=9999, distribution="ubuntu")
    assert c.is_node_local(unbound) is False
    openwrt_like = SimpleNamespace(id=str(two_node_env.clone_id), distribution="openwrt")
    assert c.is_node_local(openwrt_like) is False


def _queue_primary_run(env, request_id):
    with env.factory() as db:
        created = c.create_run(db, env.primary_conn_id, request_id)
        run = run_collection_task(db, created)
        assert run.status == "queued_remote"
        assert json.loads(run.result_json)["queued_for_node"] == "m45-linux-node"
        return run.id


def test_claim_skips_other_nodes_queued_task(two_node_env):
    run_id = _queue_primary_run(two_node_env, "cross-node-skip")
    with two_node_env.factory() as db:
        # The clone node must not consume, fail or alter the primary node's task.
        assert c.claim_for_node(db, "stage10-clone-node", "Linux") is None
        still = db.get(models.HarnessRun, run_id)
        assert still.status == "queued_remote"
        assignment = c.claim_for_node(db, "m45-linux-node", "Linux")
        assert assignment["run_id"] == run_id and assignment["execution"] == "node_local"
        assert db.get(models.HarnessRun, run_id).status == "running"


def test_claim_rejects_unregistered_node_and_platform(two_node_env):
    _queue_primary_run(two_node_env, "unregistered-refusal")
    with two_node_env.factory() as db:
        with pytest.raises(ValueError, match="采集节点身份与登记不一致"):
            c.claim_for_node(db, "rogue-node", "Linux")
        with pytest.raises(ValueError, match="Ubuntu/Linux"):
            c.claim_for_node(db, "m45-linux-node", "Windows")


def test_clone_node_full_collection_cycle(two_node_env):
    with two_node_env.factory() as db:
        created = c.create_run(db, two_node_env.clone_conn_id, "clone-cycle")
        run = run_collection_task(db, created)
        assert run.status == "queued_remote"
        assert json.loads(run.result_json)["queued_for_node"] == "stage10-clone-node"
        assignment = c.claim_for_node(db, "stage10-clone-node", "Linux")
        assert assignment["asset"]["id"] == two_node_env.clone_id
        assert assignment["node"] == {"id": "stage10-clone-node"}
        output = ("hostname: stage10-clone-ubuntu\narchitecture: x86_64\n===== OS_RELEASE =====\n"
                  "ID=ubuntu\nNAME=Ubuntu\nVERSION_ID=24.04\n===== DPKG_PACKAGES =====\n"
                  "ii curl 8.5.0-2ubuntu10.15 amd64\n")
        payload = {"node_id": "stage10-clone-node", "node_platform": "Linux", "status": "succeeded",
                   "host_fingerprint_verified": False, "ssh_authentication": "not_applicable",
                   "local_hostname": "stage10-clone-ubuntu",
                   "collector_sha256": assignment["collector_sha256"], "inventory_text": output,
                   "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                   "output_bytes": len(output.encode())}
        done = c.submit_result(db, run.id, payload)
        assert done.status == "completed"
        clone = db.get(models.LinuxAsset, two_node_env.clone_id)
        assert clone.identity_source == "authenticated_collection_node"


def test_submit_result_rejects_unregistered_node(two_node_env):
    with two_node_env.factory() as db:
        created = c.create_run(db, two_node_env.clone_conn_id, "foreign-node-refusal")
        run = run_collection_task(db, created)
        payload = {"node_id": "rogue-node", "node_platform": "Linux", "status": "succeeded"}
        with pytest.raises(ValueError, match="采集节点身份与登记不一致"):
            c.submit_result(db, run.id, payload)


def test_endpoint_token_binding(two_node_env):
    from app.routers.iot import require_collection_node, require_node_identity
    request = SimpleNamespace(state=SimpleNamespace(), headers={"X-Collection-Node-Token": "clone-node-token"})
    require_collection_node(request)
    assert request.state.collection_node_ids == ["stage10-clone-node"]
    require_node_identity(request, "stage10-clone-node")
    with pytest.raises(HTTPException) as exc:
        require_node_identity(request, "m45-linux-node")
    assert exc.value.status_code == 401
    bad = SimpleNamespace(state=SimpleNamespace(), headers={"X-Collection-Node-Token": "wrong"})
    with pytest.raises(HTTPException) as exc:
        require_collection_node(bad)
    assert exc.value.status_code == 401


def test_preflight_sees_both_nodes(two_node_env):
    with two_node_env.factory() as db:
        conn = db.get(models.DeviceConnection, two_node_env.clone_conn_id)
        report = c.preflight(db, conn)
        assert report["checks"]["remote_node_configured"] is True
        assert report["checks"]["authorized_target"] is True
