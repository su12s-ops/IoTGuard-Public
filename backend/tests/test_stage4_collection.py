"""182 SYNTHETIC packages, mocked SSH, temporary SQLite only.

These tests are not experimental evidence of any real connection or device.
No real inventory file or private key is read.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, text

from app import models
from app.integration_runtime import DATABASE_NAME, MARKER_NAME, validate_environment
from app.services import collection_tasks, device_access, iot_devices, agent_harness
from app.services.asset_parser import parse_asset_text


@pytest.fixture
def synthetic_document():
    packages = []
    for index in range(182):
        name = "synthetic-kernel" if index == 0 else f"synthetic-package-{index:03}"
        version = "6.12.94~" + "1" * 32 + "-r1" if index == 0 else f"2026.01.01~{index:08x}-r2"
        architecture = "x86_64" if index < 166 else "noarch"
        source, license = f"test-fixture/source/{index}", "" if index < 3 else "MIT"
        packages.append({"name": name, "version": version, "architecture": architecture, "source": source,
            "license": license, "status": "installed",
            "raw": f"{name}-{version} {architecture} {{{source}}} ({license}) [installed]"})
    return {"schema_version": "1.0", "asset_id": "SYNTHETIC-STAGE4-001", "asset_type": "synthetic_router",
        "collection_method": "offline", "generated_at": "2026-01-01T00:00:00Z",
        "device": {"hostname": "synthetic-openwrt", "model": "SYNTHETIC ONLY", "board_name": "synthetic-board",
            "kernel": "6.12.94", "firmware": {"distribution": "OpenWrt", "version": "25.12.5", "target": "x86/64"}},
        "software_inventory": {"source": "apk list --installed", "raw_count": 182, "package_count": 182,
                               "parse_error_count": 0, "packages": packages}}


def collector_output(document):
    packages = document["software_inventory"]["packages"]
    board = {"board_name": document["device"]["board_name"], "model": "SYNTHETIC ONLY", "kernel": "6.12.94",
             "release": {"version": "25.12.5", "target": "x86/64"}}
    return ("===== META =====\nhostname: synthetic-openwrt\narchitecture: x86_64\nmac_address: 02:00:00:00:00:41\n"
        "===== OS_RELEASE =====\nID=openwrt\nNAME=OpenWrt\nVERSION_ID=25.12.5\n"
        "===== KERNEL =====\n6.12.94\n===== SYSTEM_BOARD =====\n" + json.dumps(board) +
        "\n===== APK_PACKAGES =====\n" + "\n".join(f"{p['name']} {p['version']}" for p in packages) +
        "\n===== APK_PACKAGE_DETAILS =====\n" + "\n".join(p["raw"] for p in packages) +
        "\n===== INVENTORY_STATUS =====\npackages_complete: true\npackage_count: 182\n"
        "===== OPEN_PORTS =====\nfixture-ssh|22|tcp|0.0.0.0|fixture-ssh\n"
        "===== DHCP_LEASES =====\n0 02:00:00:00:00:42 192.168.50.2 fixture-sensor *\n")


@pytest.fixture
def rig(client, session_factory, synthetic_document, control_headers, monkeypatch, tmp_path):
    @event.listens_for(session_factory.kw["bind"], "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
    with session_factory.kw["bind"].connect() as connection:
        connection.execute(text("PRAGMA foreign_keys=ON"))
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.1/32")
    monkeypatch.setenv("LINUXGUARD_COLLECTOR_NODE_ID", "synthetic-ubuntu-node")
    monkeypatch.setattr(device_access, "collector_node", lambda: {"id": "synthetic-ubuntu-node", "platform": "Linux",
        "mode": os.getenv("LINUXGUARD_DEPLOYMENT_MODE", "standard")})
    placeholder = tmp_path / "NOT_A_PRIVATE_KEY.fixture"
    placeholder.write_text("SYNTHETIC PLACEHOLDER ONLY", encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_DEVICE_SYNTHETIC_KEY", str(placeholder))
    initial = client.post("/api/assets/upload", files={"file": ("synthetic.json", json.dumps(synthetic_document).encode())},
                          headers=control_headers).json()["asset"]
    payload = {"asset_id": initial["id"], "host": "192.168.50.1", "auth_type": "ssh_key",
               "key_path_env": "LINUXGUARD_DEVICE_SYNTHETIC_KEY", "host_key_sha256": "SHA256:" + "A" * 43}
    connection = client.post("/api/iot/connections", json=payload, headers=control_headers).json()
    calls = []
    fake = SimpleNamespace(close=lambda: calls.append("close"))
    monkeypatch.setattr(iot_devices, "open_connection", lambda connection: calls.append("open") or fake)
    output = collector_output(synthetic_document)
    monkeypatch.setattr(iot_devices, "run_fixed_script", lambda *args: calls.append("script") or output)
    return SimpleNamespace(client=client, factory=session_factory, initial=initial, connection=connection,
                           payload=payload, headers=control_headers, calls=calls, output=output, document=synthetic_document)


def create(rig, request_id="synthetic-request"):
    response = rig.client.post(f"/api/iot/connections/{rig.connection['id']}/collection-runs",
                               json={"request_id": request_id}, headers=rig.headers)
    assert response.status_code == 200, response.text
    return response.json()


def execute(rig, run):
    response = rig.client.post(f"/api/iot/collection-runs/{run['id']}/execute", headers=rig.headers)
    assert response.status_code == 200, response.text
    return response.json()


def readback(rig):
    return rig.client.get(f"/api/assets/{rig.initial['id']}", headers=rig.headers).json()


def test_182_package_collection_registration_audit_persistence_and_repeat_idempotency(rig):
    first = create(rig)
    assert first["status"] == "pending" and first["started_at"] is None
    assert rig.calls == []
    assert create(rig)["id"] == first["id"]
    done = execute(rig, first)
    assert done["status"] == "completed", done
    assert done["started_at"] and done["completed_at"]
    assert done["result"]["ssh_host_identity"] == "verified"
    assert done["result"]["ssh_authentication"] == done["result"]["asset_collection"] == "succeeded"
    assert done["result"]["cve_applicability"] == "not_evaluated"
    assert done["result"]["architecture_counts"] == {"x86_64": 166, "noarch": 16}
    assert done["collector_type"] == "openwrt_ssh" and done["result"]["collector_exit_status"] == 0
    assert done["result"]["output_sha256"] == hashlib.sha256(rig.output.encode()).hexdigest()
    before_calls = list(rig.calls)
    assert execute(rig, first)["id"] == done["id"]
    assert rig.calls == before_calls
    second = execute(rig, create(rig, "synthetic-second-request"))
    assert second["asset_id"] == rig.initial["id"]
    asset = readback(rig)
    expected = {p["name"]: (p["version"], p["architecture"]) for p in rig.document["software_inventory"]["packages"]}
    assert {p["package_name"]: (p["package_version"], p["architecture"]) for p in asset["packages"]} == expected
    assert asset["inventory_external_id"] == "openwrt-json:SYNTHETIC-STAGE4-001"
    assert asset["inventory_metadata"]["package_metadata"] == [
        {k: p[k] for k in ("name", "source", "license", "status")} for p in rig.document["software_inventory"]["packages"]]
    with rig.factory() as db:
        assert db.query(models.LinuxAsset).count() == 1
        assert db.query(models.AssetPackage).count() == 182
        assert db.query(models.VulnerabilityMatch).count() == db.query(models.RuntimeEvent).count() == 0
        assert db.query(models.HarnessRun).count() == 2
        assert db.query(models.HarnessAssetLock).count() == 0
        assert db.execute(text("PRAGMA foreign_key_check")).all() == []
        assert all(p.asset_id == asset["id"] for p in db.query(models.AssetPackage))
        rows = db.query(models.HarnessRun).all()
        assert all(json.loads(r.result_json)["cve_applicability"] == "not_evaluated" for r in rows)
    assert rig.client.get(f"/api/iot/collection-runs/{done['id']}", headers=rig.headers).json()["status"] == "completed"


@pytest.mark.parametrize("kind", ["timeout", "command_exit", "partial", "count", "malformed", "missing_details", "source",
                                  "model", "mac", "foreign_mac", "database_flush", "database_commit", "authentication", "host_key"])
def test_failures_never_replace_complete_inventory_and_have_separate_evidence(rig, monkeypatch, kind):
    run = create(rig, "failure-" + kind)
    original = readback(rig)
    if kind == "timeout":
        monkeypatch.setattr(iot_devices, "run_fixed_script", lambda *args: (_ for _ in ()).throw(TimeoutError("SYNTHETIC_SECRET")))
    elif kind == "command_exit":
        monkeypatch.setattr(iot_devices, "run_fixed_script", lambda *args: (_ for _ in ()).throw(
            device_access.DeviceOperationError("collector_exit_failed", "设备工具执行失败，退出码 3", exit_status=3)))
    elif kind in {"authentication", "host_key"}:
        error = device_access.DeviceOperationError("authentication_failed", "SSH 身份认证失败", host_identity="verified", authentication="failed") if kind == "authentication" else device_access.DeviceOperationError("host_key_mismatch", "SSH 主机指纹不匹配", host_identity="failed")
        monkeypatch.setattr(iot_devices, "open_connection", lambda *args: (_ for _ in ()).throw(error))
    elif kind == "foreign_mac":
        with rig.factory() as db:
            db.add(models.LinuxAsset(hostname="synthetic-other", distribution="openwrt", mac_address="02:00:00:00:00:41"))
            db.commit()
    elif kind == "mac":
        with rig.factory() as db:
            db.get(models.LinuxAsset, original["id"]).mac_address = "02:00:00:00:00:99"
            db.commit()
        original = readback(rig)
    elif kind == "database_flush":
        def fail_after_inventory(*args, **kwargs):
            raise RuntimeError("SYNTHETIC_SECRET_DATABASE_FAILURE")
        monkeypatch.setattr(iot_devices, "save_gateway_observations", fail_after_inventory)
    elif kind == "database_commit":
        # One-shot failure of the actual final success transaction, after flush.
        def refuse_success(session):
            if any(isinstance(row, models.HarnessRun) and row.status == "completed" for row in session.dirty):
                event.remove(rig.factory.class_, "before_commit", refuse_success)
                raise RuntimeError("SYNTHETIC_SECRET_DATABASE_FAILURE")
        event.listen(rig.factory.class_, "before_commit", refuse_success)
    else:
        changed = rig.output
        if kind == "partial": changed = changed.replace("packages_complete: true", "packages_complete: false")
        if kind == "count": changed = changed.replace("package_count: 182", "package_count: 183")
        if kind == "malformed": changed = changed.replace("synthetic-package-001 ", "broken-record ", 1)
        if kind == "missing_details": changed = changed.split("===== APK_PACKAGE_DETAILS =====")[0] + "===== INVENTORY_STATUS =====\npackages_complete: true\npackage_count: 182\n"
        if kind == "source": changed = changed.replace("{test-fixture/source/0}", "missing-source", 1)
        if kind == "model": changed = changed.replace("synthetic-board", "wrong-board")
        monkeypatch.setattr(iot_devices, "run_fixed_script", lambda *args: changed)
    failed = execute(rig, run)
    assert failed["status"] == "failed"
    assert failed["result"]["asset_collection"] == "failed" and failed["result"]["cve_applicability"] == "not_evaluated"
    assert failed["started_at"] and failed["completed_at"] and failed["tool_calls"][0]["status"] == "failed"
    assert "SYNTHETIC_SECRET" not in json.dumps(failed)
    assert readback(rig) == original
    if kind not in {"authentication", "host_key"}:
        assert failed["result"]["ssh_authentication"] == "succeeded"
    with rig.factory() as db:
        assert db.query(models.AssetPackage).count() == 182
        assert db.query(models.HarnessAssetLock).count() == 0
    before_calls = list(rig.calls)
    assert execute(rig, run)["status"] == "failed"
    assert rig.calls == before_calls


def test_preflight_is_metadata_only_and_never_loads_key_or_connects(rig):
    response = rig.client.get(f"/api/iot/connections/{rig.connection['id']}/preflight", headers=rig.headers)
    assert response.status_code == 200
    value = response.json()
    assert value["ready"] and not value["network_attempted"] and not value["key_loaded"]
    assert "NOT_A_PRIVATE_KEY" not in response.text and "SYNTHETIC PLACEHOLDER" not in response.text
    assert rig.calls == []


def test_binding_and_authorized_scope_are_required_before_ssh(rig):
    with rig.factory() as db:
        connection = db.get(models.DeviceConnection, rig.connection["id"])
        connection.host = "192.168.50.2"
        db.commit()
    failed = execute(rig, create(rig))
    assert failed["status"] == "failed" and rig.calls == []
    assert readback(rig) == rig.initial
    with rig.factory() as db:
        connection = db.get(models.DeviceConnection, rig.connection["id"])
        connection.asset_id = None
        db.commit()
    response = rig.client.post(f"/api/iot/connections/{rig.connection['id']}/collection-runs", json={"request_id": "unbound"}, headers=rig.headers)
    assert response.status_code == 400


def test_connection_change_invalidates_verification_and_pending_task(rig):
    execute(rig, create(rig))
    assert rig.client.get("/api/iot/connections").json()[0]["identity_verified"] is True
    pending = create(rig, "pending-before-change")
    payload = {**rig.payload, "host_key_sha256": "SHA256:" + "B" * 43}
    changed = rig.client.put(f"/api/iot/connections/{rig.connection['id']}", json=payload, headers=rig.headers)
    assert changed.status_code == 200 and changed.json()["identity_verified"] is False
    before_calls = list(rig.calls)
    result = execute(rig, pending)
    assert result["result"]["error_code"] == "connection_changed" and rig.calls == before_calls


def test_collector_change_and_asset_lock_prevent_ssh(rig, monkeypatch, tmp_path):
    run = create(rig)
    substitute = tmp_path / "changed.sh"
    substitute.write_text("# SYNTHETIC DIFFERENT SCRIPT", encoding="utf-8")
    monkeypatch.setattr(iot_devices, "COLLECTOR", substitute)
    result = execute(rig, run)
    assert result["result"]["error_code"] == "collector_changed" and rig.calls == []
    pending = create(rig, "locked")
    with rig.factory() as db:
        db.add(models.HarnessRun(id="another-synthetic-run", asset_id=rig.initial["id"], status="running"))
        db.flush()
        db.add(models.HarnessAssetLock(asset_id=rig.initial["id"], run_id="another-synthetic-run"))
        db.commit()
    response = rig.client.post(f"/api/iot/collection-runs/{pending['id']}/execute", headers=rig.headers)
    assert response.status_code == 409 and rig.calls == []
    assert rig.client.get(f"/api/iot/collection-runs/{pending['id']}", headers=rig.headers).json()["status"] == "pending"


def test_collection_only_mode_blocks_all_unrelated_mutations(rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DEPLOYMENT_MODE", "collection_only")
    assert rig.client.get("/api/assets").status_code == 401
    for path in ("/api/demo/start", "/api/iot/discovery", "/api/matching/run", "/api/risk/calculate",
                 "/api/runtime/ebpf/demo", "/api/scans/targets", "/api/remediation/workflow/mqtt-anonymous"):
        assert rig.client.post(path, headers=rig.headers).status_code == 403
    response = rig.client.post("/api/harness/runs", json={"asset_id": rig.initial["id"], "goal": "investigate"}, headers=rig.headers)
    assert response.status_code == 400
    assert rig.calls == []


def test_generic_harness_collect_goal_reuses_persistent_collection_mode(rig):
    response = rig.client.post("/api/harness/runs", json={"asset_id": rig.initial["id"], "goal": "collect"}, headers=rig.headers)
    assert response.status_code == 200
    run = response.json()
    assert run["plan"]["goal"] == "collect"
    response = rig.client.post(f"/api/harness/runs/{run['id']}/execute", headers=rig.headers)
    assert response.status_code == 200 and response.json()["status"] == "completed"
    assert response.json()["result"]["cve_applicability"] == "not_evaluated"


def test_recover_interruption_preserves_ssh_state_and_never_replays(rig):
    run = create(rig)
    with rig.factory() as db:
        row = db.get(models.HarnessRun, run["id"])
        row.status = "running"
        result = json.loads(row.result_json)
        result.update(ssh_host_identity="verified", ssh_authentication="succeeded")
        row.result_json = json.dumps(result)
        db.add(models.HarnessAssetLock(asset_id=row.asset_id, run_id=row.id))
        db.commit()
        assert collection_tasks.recover(db) == 1
    assert execute(rig, run)["status"] == "interrupted"
    assert rig.calls == [] and readback(rig) == rig.initial


def test_runtime_environment_refuses_unmarked_or_original_database(tmp_path):
    root = tmp_path / "new-runtime"
    root.mkdir()
    env = {"LINUXGUARD_INTEGRATION_RUNTIME": str(root), "LINUXGUARD_DATA_DIR": str(root / "data"),
           "LINUXGUARD_DATABASE_URL": "sqlite:///" + str(root / DATABASE_NAME),
           "LINUXGUARD_COLLECTOR_NODE_ID": "synthetic-node", "LINUXGUARD_DISCOVERY_CIDRS": "192.168.50.1/32"}
    with pytest.raises(RuntimeError): validate_environment(env)
    marker = {"profile": "collection_only", "database": DATABASE_NAME, "node_id": "synthetic-node", "target": "192.168.50.1"}
    (root / MARKER_NAME).write_text(json.dumps(marker), encoding="utf-8")
    assert validate_environment(env) == root.resolve()
    env["LINUXGUARD_DATABASE_URL"] = "sqlite:///" + str(tmp_path / "original-do-not-open.db")
    with pytest.raises(RuntimeError): validate_environment(env)


def test_launcher_check_does_not_create_storage_or_import_database(tmp_path, capsys):
    path = Path(__file__).resolve().parents[1] / "scripts" / "start_iot_integration.py"
    spec = importlib.util.spec_from_file_location("integration_launcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "not-yet-created"
    assert module.main(["--runtime-dir", str(root), "--node-id", "synthetic-node", "--target", "192.168.50.1", "--check"]) == 0
    assert not root.exists()
    value = json.loads(capsys.readouterr().out)
    assert not value["network_attempted"] and not value["key_loaded"]
    root.mkdir()
    (root / "old-data.txt").write_text("SYNTHETIC EXISTING DATA", encoding="utf-8")
    assert module.main(["--runtime-dir", str(root), "--node-id", "synthetic-node", "--target", "192.168.50.1", "--check"]) == 1


def test_unknown_host_key_is_rejected_without_acceptance():
    policy = device_access.PinnedHostKey("SHA256:" + "A" * 43)
    key = SimpleNamespace(asbytes=lambda: b"SYNTHETIC WRONG PUBLIC HOST KEY")
    with pytest.raises(device_access.HostKeyMismatch):
        policy.missing_host_key(SimpleNamespace(), "synthetic-host", key)


def test_details_keep_manifest_boundaries_and_reject_duplicate_or_truncated_version(synthetic_document):
    output = collector_output(synthetic_document)
    parsed = parse_asset_text(output)
    assert parsed.inventory_complete and len(parsed.packages) == 182
    assert parsed.packages[0]["package_version"] == synthetic_document["software_inventory"]["packages"][0]["version"]
    duplicate = output.replace("===== INVENTORY_STATUS =====", synthetic_document["software_inventory"]["packages"][0]["raw"] + "\n===== INVENTORY_STATUS =====")
    assert not parse_asset_text(duplicate).inventory_complete
    truncated = output.replace(parsed.packages[0]["package_version"], "6.12.94", 1)
    assert not parse_asset_text(truncated).inventory_complete


def test_matching_scope_does_not_deactivate_other_linux_assets(client, session_factory, control_headers):
    from app.services.matching_engine import run_matching
    with session_factory() as db:
        first = models.LinuxAsset(hostname="synthetic-linux-first", distribution="ubuntu", os_version="22.04")
        other = models.LinuxAsset(hostname="synthetic-linux-other", distribution="ubuntu", os_version="22.04")
        db.add_all([first, other])
        db.flush()
        db.add(models.VulnerabilityInfo(cve_id="CVE-2099-9944", title="SYNTHETIC ONLY", affected_package="synthetic", fixed_version="2-r1"))
        for asset in (first, other):
            db.add(models.AssetPackage(asset_id=asset.id, package_name="synthetic", package_version="1-r1", package_manager="dpkg"))
        db.commit()
        run_matching(db)
        first_id, other_id = first.id, other.id
    assert client.post("/api/matching/run").status_code == 401
    response = client.post(f"/api/matching/run?asset_id={first_id}", headers=control_headers)
    assert response.status_code == 200 and response.json()["count"] == 1
    with session_factory() as db:
        other = db.query(models.VulnerabilityMatch).filter_by(asset_id=other_id).one()
        assert other.active and other.affected and other.match_status == "potentially_affected"


@pytest.mark.parametrize("kind", ["authentication", "host_key"])
def test_real_adapter_maps_mocked_paramiko_failures_without_exposing_credentials(rig, monkeypatch, kind):
    import base64
    import paramiko
    key = SimpleNamespace(asbytes=lambda: b"SYNTHETIC PUBLIC HOST KEY ONLY")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    with rig.factory() as db:
        row = db.get(models.DeviceConnection, rig.connection["id"])
        row.host_key_sha256 = fingerprint if kind == "authentication" else "SHA256:" + "A" * 43
        db.commit()
    class MockSSH:
        def set_missing_host_key_policy(self, policy): self.policy = policy
        def connect(self, host, **kwargs):
            self.policy.missing_host_key(self, host, key)
            raise paramiko.AuthenticationException("SYNTHETIC_SECRET_MUST_NOT_LEAK")
        def close(self): pass
    monkeypatch.setattr(paramiko, "SSHClient", MockSSH)
    monkeypatch.setattr(paramiko.Ed25519Key, "from_private_key_file", lambda *args, **kwargs: object())
    monkeypatch.setattr(iot_devices, "open_connection", device_access.open_connection)
    outcome = execute(rig, create(rig, "adapter-" + kind))
    assert outcome["status"] == "failed"
    assert outcome["result"]["error_code"] == ("authentication_failed" if kind == "authentication" else "host_key_mismatch")
    assert outcome["result"]["ssh_host_identity"] == ("verified" if kind == "authentication" else "failed")
    assert "SYNTHETIC_SECRET" not in json.dumps(outcome)
    assert readback(rig) == rig.initial


def test_collection_only_upload_rejects_ambiguous_text_without_creating_asset(rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DEPLOYMENT_MODE", "collection_only")
    result = rig.client.post("/api/assets/upload", files={"file": ("synthetic.txt", rig.output.encode())}, headers=rig.headers)
    assert result.status_code == 400
    assert readback(rig) == rig.initial
    with rig.factory() as db:
        assert db.query(models.LinuxAsset).count() == 1


def test_legacy_collect_endpoint_returns_persistent_run_and_keeps_asset_id(rig):
    result = rig.client.post(f"/api/iot/connections/{rig.connection['id']}/collect", headers=rig.headers)
    assert result.status_code == 200
    assert result.json()["asset"]["id"] == rig.initial["id"]
    assert result.json()["collection_run"]["status"] == "completed"


def test_collection_profile_error_handler_never_echoes_exception_input(rig, monkeypatch):
    import asyncio
    from app.main import global_exception_handler
    monkeypatch.setenv("LINUXGUARD_DEPLOYMENT_MODE", "collection_only")
    request = SimpleNamespace(method="POST", url=SimpleNamespace(path="/api/synthetic-test"))
    result = asyncio.run(global_exception_handler(request, RuntimeError("SYNTHETIC_SECRET_DO_NOT_ECHO")))
    assert b"SYNTHETIC_SECRET" not in result.body


def test_collection_only_profile_refuses_windows_ssh_before_loading_key(rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DEPLOYMENT_MODE", "collection_only")
    monkeypatch.setattr(device_access.platform, "system", lambda: "Windows")
    monkeypatch.setattr(device_access, "collector_node", lambda: {"id": "synthetic-ubuntu-node", "platform": "Windows", "mode": "collection_only"})
    monkeypatch.setattr(iot_devices, "open_connection", device_access.open_connection)
    checked = rig.client.get(f"/api/iot/connections/{rig.connection['id']}/preflight", headers=rig.headers).json()
    assert not checked["ready"] and checked["checks"]["node_platform"] is False
    outcome = execute(rig, create(rig, "windows-refusal"))
    assert outcome["result"]["error_code"] == "node_platform_invalid"
    assert outcome["result"]["ssh_authentication"] == "not_attempted" and rig.calls == []
    assert readback(rig) == rig.initial


def test_script_change_between_plan_check_and_dispatch_is_blocked_before_ssh(rig, monkeypatch):
    run = create(rig, "script-race")
    original = iot_devices.COLLECTOR.read_text(encoding="utf-8")
    class ChangingCollector:
        reads = 0
        def read_text(self, **kwargs):
            self.reads += 1
            return original if self.reads == 1 else "# SYNTHETIC CHANGED SCRIPT"
    monkeypatch.setattr(iot_devices, "COLLECTOR", ChangingCollector())
    result = execute(rig, run)
    assert result["result"]["error_code"] == "collector_changed"
    assert rig.calls == [] and readback(rig) == rig.initial


def test_ambiguous_manifest_tokens_cannot_hide_a_missing_package_detail(synthetic_document):
    document = copy.deepcopy(synthetic_document)
    packages = document["software_inventory"]["packages"][:2]
    packages[0].update(name="synthetic-a", version="1-r1")
    packages[1].update(name="synthetic", version="a-1-r1")
    for package in packages:
        package["raw"] = f"{package['name']}-{package['version']} {package['architecture']} {{{package['source']}}} ({package['license']}) [installed]"
    document["software_inventory"]["packages"] = packages
    # Both manifest pairs produce the same raw first token. Removing one detailed
    # row must not silently lose its source/architecture while claiming complete.
    output = collector_output(document).replace(packages[0]["raw"] + "\n", "").replace("package_count: 182", "package_count: 2")
    with pytest.raises(ValueError):
        parse_asset_text(output)
