"""Isolated contract/authentication tests. No real device or private key is accessed."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text

from app import database, models
from app.services import device_access, iot_devices
from app.services.asset_import import parse_asset_document
from app.services.asset_parser import parse_asset_text, save_parsed_asset
from app.services.experiment_lifecycle import serialize_rows
from test_iot_upgrade import INVENTORY, control


@pytest.fixture
def structure_sample():
    # This operator-provided file is a partial structure sample, not a 182-package capture.
    path = Path(__file__).parent / "fixtures" / "openwrt_inventory_structure_sample.json"
    return json.loads(path.read_text(encoding="utf-8-sig"))


@pytest.fixture
def synthetic_export(structure_sample):
    value = copy.deepcopy(structure_sample)
    value["sample_only"] = False
    count = len(value["software_inventory"]["packages"])
    value["software_inventory"].update(raw_count=count, package_count=count)
    return value


def upload(client, payload, headers):
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return client.post("/api/assets/upload", files={"file": ("inventory.json", raw)}, headers=headers)


def test_supplied_structure_sample_is_not_imported_as_182_packages(client, structure_sample, control_headers):
    response = upload(client, structure_sample, control_headers)
    assert response.status_code == 400 and "sample_only" in response.json()["detail"]
    assert client.get("/api/assets").json() == []


def test_export_layout_maps_exact_versions_provenance_and_external_identity(client, synthetic_export, control_headers):
    result = upload(client, synthetic_export, control_headers)
    assert result.status_code == 200, result.text
    asset = result.json()["asset"]
    source = synthetic_export["software_inventory"]["packages"]
    assert [(p["package_name"], p["package_version"], p["architecture"]) for p in asset["packages"]] == [
        (p["name"], p["version"], p["architecture"]) for p in source]
    assert all(p["package_manager"] == "apk" for p in asset["packages"])
    assert asset["device_model"] == synthetic_export["device"]["board_name"]
    assert asset["firmware_version"] == synthetic_export["device"]["firmware"]["version"]
    assert asset["identity_source"] == "uploaded_inventory_id"
    assert asset["identity_confidence"] == 0.5
    assert asset["inventory_metadata"]["ssh_identity_verified_by_platform"] is False
    assert asset["inventory_metadata"]["device"]["firmware"]["revision"] == synthetic_export["device"]["firmware"]["revision"]
    assert asset["inventory_sha256"] == hashlib.sha256(json.dumps(synthetic_export, ensure_ascii=False).encode()).hexdigest()
    assert result.json()["package_parse_stats"]["parsed_count"] == len(source)
    synthetic_export["device"]["hostname"] = "renamed-fixture"
    again = upload(client, synthetic_export, control_headers)
    assert again.status_code == 200 and again.json()["asset"]["id"] == asset["id"]
    assert len(client.get("/api/assets").json()) == 1


@pytest.mark.parametrize("mutation", ["count", "errors", "duplicate", "raw", "status", "schema", "secret"])
def test_invalid_export_never_replaces_previous_inventory(client, synthetic_export, control_headers, mutation):
    initial = upload(client, synthetic_export, control_headers).json()["asset"]
    bad = copy.deepcopy(synthetic_export)
    inventory = bad["software_inventory"]
    if mutation == "count":
        inventory["package_count"] += 1
    elif mutation == "errors":
        inventory["parse_error_count"] = 1
    elif mutation == "duplicate":
        inventory["packages"].append(copy.deepcopy(inventory["packages"][0]))
        inventory["raw_count"] = inventory["package_count"] = len(inventory["packages"])
    elif mutation == "raw":
        inventory["packages"][0]["version"] = "99.0-r1"
    elif mutation == "status":
        inventory["packages"][0]["status"] = "available"
    elif mutation == "schema":
        bad["schema_version"] = True
    else:
        bad["private_key"] = "SYNTHETIC_VALUE_MUST_NOT_BE_ECHOED"
    response = upload(client, bad, control_headers)
    assert response.status_code == 400
    assert "SYNTHETIC_VALUE_MUST_NOT_BE_ECHOED" not in response.text
    current = client.get("/api/assets/" + str(initial["id"])).json()
    assert current["packages"] == initial["packages"] and current["inventory_sha256"] == initial["inventory_sha256"]


def test_manifest_count_and_malformed_line_protect_existing_packages(session_factory):
    with session_factory() as db:
        initial = save_parsed_asset(db, parse_asset_text(INVENTORY))
        raw = INVENTORY.replace("OPKG_PACKAGES", "APK_PACKAGES").replace(" - ", " ")
        parsed = parse_asset_text(raw.replace("packages_complete: true", "packages_complete: true\npackage_count: 2"))
        assert parsed.inventory_complete and parsed.package_parse_stats["parsed_count"] == 2
        broken = parse_asset_text(raw.replace("mosquitto 2.0.1-1", "unparseable-single-token"))
        assert not broken.inventory_complete and broken.package_parse_stats["rejected_count"] == 1
        with pytest.raises(ValueError):
            save_parsed_asset(db, broken)
        assert len(initial.packages) == 2
        mismatch = parse_asset_text(raw.replace("packages_complete: true", "packages_complete: true\npackage_count: 182"))
        with pytest.raises(ValueError):
            save_parsed_asset(db, mismatch)
        empty = parse_asset_text(raw.replace("mosquitto 2.0.1-1", "").replace("libopenssl3 3.0.1-2", ""))
        assert not empty.inventory_complete
        save_parsed_asset(db, empty)
        assert len(initial.packages) == 2


def test_versioned_standard_contract_and_duplicate_json_fields():
    payload = {"schema_version": 1, "asset": {"hostname": "fixture", "distribution": "ubuntu"},
        "collection": {"collected_at": "2026-10-13T00:00:00Z", "source": "synthetic_test",
                       "packages_complete": True, "package_count": 1, "parser_error_count": 0},
        "packages": [{"package_name": "fixture-package", "package_version": "1:2.0~rc1-1", "package_manager": "dpkg"}]}
    assert parse_asset_document(json.dumps(payload)).packages[0]["package_version"] == "1:2.0~rc1-1"
    with pytest.raises(ValueError):
        parse_asset_document('{"schema_version":1,"schema_version":1}')


def test_repeated_sections_and_stale_json_do_not_replace_inventory(client, synthetic_export, control_headers):
    with pytest.raises(ValueError):
        parse_asset_text(INVENTORY + "\n===== APK_PACKAGES =====\nfixture 1\n===== APK_PACKAGES =====\nfixture 2\n")
    initial = upload(client, synthetic_export, control_headers).json()["asset"]
    synthetic_export["generated_at"] = "2020-01-01T00:00:00Z"
    assert upload(client, synthetic_export, control_headers).status_code == 400
    assert client.get("/api/assets/" + str(initial["id"])).json()["inventory_sha256"] == initial["inventory_sha256"]


def test_ed25519_reference_uses_pinned_client_without_agent_or_password(control, tmp_path, monkeypatch):
    path = tmp_path / "synthetic-key-placeholder"
    path.write_text("SYNTHETIC PLACEHOLDER; loader is mocked", encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_DEVICE_TEST_KEY", str(path))
    monkeypatch.setenv("LINUXGUARD_DEVICE_TEST_PASSPHRASE", "SYNTHETIC_ONLY")
    sentinel = object()
    loading = []
    def load_key(filename, password=None):
        loading.append((filename, password))
        return sentinel
    monkeypatch.setattr(device_access.paramiko.Ed25519Key, "from_private_key_file", load_key)
    class FakeClient:
        def set_missing_host_key_policy(self, policy):
            self.policy = policy
        def connect(self, host, **kwargs):
            self.host, self.arguments = host, kwargs
    monkeypatch.setattr(device_access.paramiko, "SSHClient", FakeClient)
    row = SimpleNamespace(enabled=True, host="192.168.50.1", port=22, username="root", auth_type="ssh_key",
        credential_env="", key_path_env="LINUXGUARD_DEVICE_TEST_KEY", key_passphrase_env="LINUXGUARD_DEVICE_TEST_PASSPHRASE",
        host_key_sha256="SHA256:" + "A" * 43)
    client = device_access.open_connection(row)
    assert isinstance(client.policy, device_access.PinnedHostKey)
    assert client.arguments["pkey"] is sentinel and "password" not in client.arguments
    assert client.arguments["allow_agent"] is False and client.arguments["look_for_keys"] is False
    assert loading == [(str(path), "SYNTHETIC_ONLY")]
    monkeypatch.setattr(device_access.paramiko.Ed25519Key, "from_private_key_file",
                        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("SYNTHETIC_SECRET_ERROR")))
    with pytest.raises(ValueError) as error:
        device_access.open_connection(row)
    assert "SYNTHETIC_SECRET_ERROR" not in str(error.value)


def test_key_reference_api_binds_existing_import_without_duplicate_asset(client, synthetic_export, control, monkeypatch):
    # Explicitly simulate an Ubuntu executor; this is not a real SSH connection.
    monkeypatch.setattr(device_access, "collector_node", lambda: {"id": "synthetic-ubuntu-node", "platform": "Linux", "mode": "standard"})
    asset = upload(client, synthetic_export, control).json()["asset"]
    payload = {"asset_id": asset["id"], "host": "192.168.50.1", "auth_type": "ssh_key",
               "key_path_env": "LINUXGUARD_DEVICE_TEST_KEY", "host_key_sha256": "SHA256:" + "A" * 43}
    connection = client.post("/api/iot/connections", json=payload, headers=control)
    assert connection.status_code == 200
    assert connection.json()["identity_verified"] is False
    assert "private_key" not in connection.json() and "password" not in connection.json()
    fake = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(iot_devices, "open_connection", lambda row: fake)
    text_inventory = INVENTORY.replace('"test,board"', json.dumps(synthetic_export["device"]["board_name"]))
    monkeypatch.setattr(iot_devices, "run_fixed_script", lambda *args: text_inventory)
    result = client.post("/api/iot/connections/" + str(connection.json()["id"]) + "/collect", headers=control)
    assert result.status_code == 200, result.text
    assert result.json()["asset"]["id"] == asset["id"]
    assert result.json()["asset"]["mac_address"] == "02:00:00:00:00:01"
    assert len(client.get("/api/assets").json()) == 1
    assert client.get("/api/iot/connections").json()[0]["identity_verified"] is True


def test_validation_never_echoes_submitted_key_material(client, control):
    payload = {"host": "192.168.50.1", "auth_type": "ssh_key", "key_path_env": "LINUXGUARD_DEVICE_TEST_KEY",
               "host_key_sha256": "SHA256:" + "A" * 43, "private_key": "SYNTHETIC_SECRET_DO_NOT_ECHO"}
    response = client.post("/api/iot/connections", json=payload, headers=control)
    assert response.status_code == 422 and "SYNTHETIC_SECRET_DO_NOT_ECHO" not in response.text


@pytest.mark.parametrize("path,method", [("/api/assets/upload", "post"), ("/api/runtime/ebpf/events", "post"),
    ("/api/runtime/ebpf/upload", "post"), ("/api/runtime/ebpf/demo", "post"), ("/api/runtime/ebpf/events", "delete"),
    ("/api/analysis/risks/1/human-review", "post"), ("/api/demo/targets", "get"),
    ("/api/demo/targets", "put"), ("/api/demo/start", "post")])
def test_mutation_gates_fail_before_any_work(client, control_headers, path, method):
    assert getattr(client, method)(path).status_code == 401
    assert getattr(client, method)(path, headers={"X-Control-Token": "wrong"}).status_code == 401


def test_legacy_password_requires_explicit_reference_migration(client, session_factory, control_headers, monkeypatch):
    synthetic_secret = "SYNTHETIC_" + "SECRET"
    with session_factory() as db:
        target = models.DemoTarget(label="synthetic", target_type="ssh", host="192.0.2.1",
                                  username="fixture", password=synthetic_secret)
        db.add(target); db.commit()
    response = client.get("/api/demo/targets", headers=control_headers)
    assert synthetic_secret not in response.text
    row = response.json()["targets"][0]
    assert row["credential_migration_required"]
    assert client.post("/api/demo/start", headers=control_headers).status_code == 409
    row["credential_env"] = "LINUXGUARD_DEMO_FIXTURE"
    monkeypatch.setenv("LINUXGUARD_DEMO_FIXTURE", synthetic_secret)
    assert client.put("/api/demo/targets", json={"targets": [row]}, headers=control_headers).status_code == 200
    with session_factory() as db:
        target = db.get(models.DemoTarget, row["id"])
        assert target.password == ""
        assert target.credential_env == "LINUXGUARD_DEMO_FIXTURE"
        assert "password" not in serialize_rows([target])[0]


def test_historical_archive_view_and_download_redact_without_rewriting(client, tmp_path, monkeypatch):
    synthetic_secret = "SYNTHETIC_" + "SECRET"   # 合成夹具值（同上）
    synthetic_key = "SYNTHETIC_" + "KEY"         # 合成夹具值（同上）
    payload = {"targets": [{"password": synthetic_secret, "label": "fixture"}], "nested": {"api_key": synthetic_key}}
    file = tmp_path / "archive.json"
    original = json.dumps(payload).encode()
    file.write_bytes(original)
    monkeypatch.setenv("REPORT_ARCHIVE_DIR", str(tmp_path))
    for suffix in ("", "/download"):
        response = client.get("/api/reports/archives/archive.json" + suffix)
        assert response.status_code == 200 and synthetic_secret not in response.text and synthetic_key not in response.text
    assert file.read_bytes() == original


def test_additive_auth_and_inventory_migration_keeps_legacy_rows(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "legacy.db"))
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE linux_asset (id INTEGER PRIMARY KEY, hostname VARCHAR(128))"))
        conn.execute(text("INSERT INTO linux_asset VALUES (1, 'preserved')"))
        conn.execute(text("CREATE TABLE device_connection (id INTEGER PRIMARY KEY, credential_env VARCHAR(128))"))
        conn.execute(text("INSERT INTO device_connection VALUES (1, 'LINUXGUARD_DEVICE_LEGACY')"))
    monkeypatch.setattr(database, "engine", engine)
    changes = database._migrate_sqlite_schema()
    assert "device_connection.auth_type" in changes and "linux_asset.inventory_external_id" in changes
    assert database._migrate_sqlite_schema() == []
    with engine.connect() as conn:
        assert conn.execute(text("SELECT hostname FROM linux_asset")).scalar() == "preserved"
        assert conn.execute(text("SELECT auth_type, credential_env FROM device_connection")).one() == ("password", "LINUXGUARD_DEVICE_LEGACY")
    engine.dispose()
