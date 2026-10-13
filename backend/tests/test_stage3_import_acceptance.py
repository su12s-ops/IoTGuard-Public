"""Synthetic regression tests; the real inventory is never stored as a fixture."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from app.schemas import OpenWrtExportDocument


@pytest.fixture
def full_export_shape():
    sample = json.loads((Path(__file__).parent / "fixtures" /
                         "openwrt_inventory_structure_sample.json").read_text(encoding="utf-8-sig"))
    sample["sample_only"] = False
    size = len(sample["software_inventory"]["packages"])
    sample["software_inventory"].update(raw_count=size, package_count=size)
    sample["management"] = {"ip_address": "192.168.50.1", "protocol": "ssh", "port": 22,
                            "authentication": "ed25519_key", "key_reference": "synthetic-reference-only"}
    sample["integrity"] = {"device_json_sha256": "a" * 64, "packages_json_sha256": "b" * 64}
    return sample


def upload(client, value, headers):
    return client.post("/api/assets/upload", files={"file": ("fixture.json", json.dumps(value).encode())},
                       headers=headers)


def test_new_blocks_and_management_address_round_trip_without_creating_connection(
        client, session_factory, full_export_shape, control_headers):
    from app import models
    response = upload(client, full_export_shape, control_headers)
    assert response.status_code == 200
    asset = response.json()["asset"]
    assert asset["ip_address"] == "192.168.50.1"
    assert asset["inventory_metadata"]["management"] == full_export_shape["management"]
    assert asset["inventory_metadata"]["integrity"] == full_export_shape["integrity"]
    assert asset["inventory_metadata"]["source_file_hash_verification"] == "not_verified_external_files_unavailable"
    assert asset["inventory_metadata"]["ssh_identity_verified_by_platform"] is False
    with session_factory() as db:
        assert db.query(models.DeviceConnection).count() == 0
    again = upload(client, full_export_shape, control_headers)
    assert again.status_code == 200 and again.json()["asset"]["id"] == asset["id"]


@pytest.mark.parametrize("mutation", ["bad_hash", "bad_address", "conflicting_address", "string_port",
                                     "invalid_port", "password_field", "unknown_integrity", "multiline_reference"])
def test_invalid_new_fields_preserve_existing_asset(client, full_export_shape, control_headers, mutation):
    initial = upload(client, full_export_shape, control_headers).json()["asset"]
    value = copy.deepcopy(full_export_shape)
    if mutation == "bad_hash":
        value["integrity"]["device_json_sha256"] = "invalid"
    elif mutation == "bad_address":
        value["management"]["ip_address"] = "invalid-host"
    elif mutation == "conflicting_address":
        value["device"]["ip_address"] = "192.168.50.2"
    elif mutation == "string_port":
        value["management"]["port"] = "22"
    elif mutation == "invalid_port":
        value["management"]["port"] = 65536
    elif mutation == "password_field":
        value["management"]["password"] = "SYNTHETIC_DO_NOT_ECHO"
    elif mutation == "unknown_integrity":
        value["integrity"]["unknown"] = "SYNTHETIC_DO_NOT_ECHO"
    else:
        value["management"]["key_reference"] = "synthetic\nreference"
    response = upload(client, value, control_headers)
    assert response.status_code == 400
    assert "SYNTHETIC_DO_NOT_ECHO" not in response.text
    readback = client.get(f"/api/assets/{initial['id']}").json()
    assert readback["packages"] == initial["packages"]
    assert readback["inventory_sha256"] == initial["inventory_sha256"]


def test_previous_export_without_optional_blocks_remains_supported(full_export_shape):
    del full_export_shape["management"]
    del full_export_shape["integrity"]
    assert OpenWrtExportDocument.model_validate(full_export_shape).management is None


def test_linux_text_import_and_detection_coexist_with_openwrt_json(
        client, session_factory, full_export_shape, control_headers):
    from app import models
    from app.services.matching_engine import run_matching
    # Synthetic local regression only; no scan, collector, or remote connection.
    linux_text = """hostname: synthetic-linux-legacy
architecture: x86_64
===== OS_RELEASE =====
NAME="Ubuntu"
VERSION_ID="22.04"
ID=ubuntu
===== DPKG_PACKAGES =====
ii synthetic-linux-only 1:2.0~rc1-1 amd64
===== OPEN_PORTS =====
synthetic-service|443|tcp|0.0.0.0|synthetic-service
"""
    response = client.post("/api/assets/upload", files={"file": ("fixture.txt", linux_text.encode())},
                           headers=control_headers)
    assert response.status_code == 200
    linux = response.json()["asset"]
    assert linux["distribution"] == "ubuntu"
    assert linux["packages"][0]["package_manager"] == "dpkg"
    assert linux["packages"][0]["package_version"] == "1:2.0~rc1-1"
    assert upload(client, full_export_shape, control_headers).status_code == 200
    assert upload(client, full_export_shape, control_headers).status_code == 200
    assert client.get(f"/api/assets/{linux['id']}").json() == linux
    with session_factory() as db:
        db.add(models.VulnerabilityInfo(cve_id="CVE-2099-9998", title="SYNTHETIC REGRESSION ONLY",
               affected_package="synthetic-linux-only", fixed_version="1:2.0-1", source="synthetic_test"))
        db.commit()
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(asset_id=linux["id"]).one()
        assert match.reason_code == "installed_version_below_fixed"
        assert match.match_status == "potentially_affected"
        assert db.query(models.LinuxAsset).count() == 2


def test_linux_standard_json_preserves_dpkg_version(client, control_headers):
    document = {"schema_version": 1, "asset": {"hostname": "synthetic-linux-json", "distribution": "ubuntu"},
                "collection": {"collected_at": "2026-10-13T00:00:00Z", "source": "synthetic_test",
                               "packages_complete": True, "package_count": 1, "parser_error_count": 0},
                "packages": [{"package_name": "synthetic-package", "package_version": "2:1.0~rc1-1+esm2",
                              "package_manager": "dpkg", "architecture": "amd64"}]}
    response = upload(client, document, control_headers)
    assert response.status_code == 200
    assert response.json()["asset"]["packages"][0]["package_version"] == "2:1.0~rc1-1+esm2"


@pytest.fixture
def acceptance_helpers():
    path = Path(__file__).resolve().parents[1] / "scripts" / "verify_openwrt_inventory_import.py"
    spec = importlib.util.spec_from_file_location("offline_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exact_raw_check_preserves_full_kernel_version_and_allows_empty_license(acceptance_helpers):
    version = "6.12.94~" + "a" * 32 + "-r1"
    package = {"name": "synthetic-kernel", "version": version, "architecture": "x86_64",
               "source": "synthetic/source", "license": "", "status": "installed"}
    package["raw"] = f"synthetic-kernel-{version} x86_64 {{synthetic/source}} () [installed]"
    assert acceptance_helpers.check_package_records([package])["exact_raw_matches"] == 1
    package["version"] = "6.12.94"
    with pytest.raises(ValueError):
        acceptance_helpers.check_package_records([package])


def test_raw_source_mismatch_is_rejected(acceptance_helpers):
    package = {"name": "synthetic", "version": "1-r1", "architecture": "noarch", "source": "incorrect",
               "license": "MIT", "status": "installed", "raw": "synthetic-1-r1 noarch {correct} (MIT) [installed]"}
    with pytest.raises(ValueError):
        acceptance_helpers.check_package_records([package])


def test_acceptance_json_rejects_duplicate_fields_and_credentials(acceptance_helpers):
    with pytest.raises(ValueError):
        json.loads('{"same":1,"same":2}', object_pairs_hook=acceptance_helpers.unique_object)
    # 合成负样本：拼接送检（测凭据检测器本身），值不含任何真实密钥材料
    redaction_probe_a = "SYNTHETIC_" + "ONLY"
    redaction_probe_b = "-----BEGIN OPENSSH " + "PRIVATE KEY----- SYNTHETIC_ONLY"
    for value in ({"management": {"password": redaction_probe_a}},
                  {"data": redaction_probe_b}):
        with pytest.raises(ValueError):
            acceptance_helpers.check_no_credentials(value)


def test_offline_guard_rejects_other_databases_network_and_environment_files(
        acceptance_helpers, monkeypatch, tmp_path):
    hooks = []
    monkeypatch.setattr(acceptance_helpers.sys, "addaudithook", hooks.append)
    allowed = tmp_path / "acceptance.sqlite3"
    acceptance_helpers.install_offline_guard(allowed)
    guard = hooks[0]
    guard("sqlite3.connect", (str(allowed),))
    for event, arguments in (
            ("sqlite3.connect", (str(tmp_path / "other.sqlite3"),)),
            ("socket.connect", (object(), ("192.168.50.1", 22))),
            ("open", (str(tmp_path / ".env.local"), "r", 0)),
            ("open", (str(tmp_path / "id_ed25519"), "r", 0))):
        with pytest.raises(ValueError):
            guard(event, arguments)
    with pytest.raises(RuntimeError):
        guard("subprocess.Popen", ())
