"""Synthetic fixtures for adapters; none represents a real CVE or connected device."""
import json
import hashlib
import base64
from datetime import timedelta

import paramiko
import pytest
from sqlalchemy import create_engine, text

from app import models, database
from app.services.asset_parser import parse_asset_text, save_parsed_asset
from app.services.iot_devices import discover, save_gateway_observations
from app.services.matching_engine import run_matching
from app.services.device_access import PinnedHostKey

INVENTORY = '''===== META =====
hostname: OpenWrt
architecture: x86_64
mac_address: 02:00:00:00:00:01
===== OS_RELEASE =====
ID=openwrt
NAME=OpenWrt
VERSION_ID=24.10.2
===== SYSTEM_BOARD =====
{"kernel":"6.6.1","board_name":"test,board","model":"Test only","release":{"version":"24.10.2"}}
===== OPKG_PACKAGES =====
mosquitto - 2.0.1-1
libopenssl3 - 3.0.1-2
===== INVENTORY_STATUS =====
packages_complete: true
===== OPEN_PORTS =====
mosquitto|1883|tcp|0.0.0.0|mosquitto
===== DHCP_LEASES =====
0 02:00:00:00:00:02 192.168.50.20 sensor-fixture *
===== BPF_CAPABILITIES =====
btf: present
falco: unavailable
'''


@pytest.fixture
def control(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "isolated-test-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")
    return {"X-Control-Token": "isolated-test-token"}


def seed_openwrt(db):
    return save_parsed_asset(db, parse_asset_text(INVENTORY))


def add_advisory(db, package="mosquitto", release="24.10.2"):
    db.add(models.OpenWrtAdvisory(cve_id="CVE-2099-9999", package_name=package, release=release,
           affected_versions_json='["2.0.1-1"]', fixed_versions_json='["2.0.2-1"]', source_url="https://openwrt.org/advisory/test-fixture"))
    if not db.query(models.VulnerabilityInfo).filter_by(cve_id="CVE-2099-9999").first():
        db.add(models.VulnerabilityInfo(cve_id="CVE-2099-9999", title="TEST ONLY", affected_package=package, fixed_version="999-ubuntu1"))
    db.commit()


def test_opkg_and_capability_parsing():
    parsed = parse_asset_text(INVENTORY)
    assert parsed.hostname.endswith("020000000001")
    assert parsed.device_type == "iot_gateway"
    assert parsed.packages[0]["package_version"] == "2.0.1-1"
    assert parsed.packages[0]["package_manager"] == "opkg"
    assert json.loads(parsed.capabilities_json)["collector_compatibility"] == "requires_probe"
    assert parsed.observations[0]["hostname"] == "sensor-fixture"


def test_apk_manifest_parsing():
    parsed = parse_asset_text(INVENTORY.replace("OPKG_PACKAGES", "APK_PACKAGES").replace(" - ", " "))
    assert parsed.packages[0]["package_manager"] == "apk"
    assert parsed.packages[0]["package_version"] == "2.0.1-1"


def test_partial_inventory_does_not_erase_packages(session_factory):
    with session_factory() as db:
        asset = seed_openwrt(db)
        partial = parse_asset_text(INVENTORY.replace("packages_complete: true", "packages_complete: false"))
        save_parsed_asset(db, partial)
        assert db.query(models.AssetPackage).filter_by(asset_id=asset.id).count() == 2
        assert not asset.inventory_complete


def test_duplicate_default_hostnames_do_not_merge_devices(session_factory):
    with session_factory() as db:
        seed_openwrt(db)
        save_parsed_asset(db, parse_asset_text(INVENTORY.replace("00:00:00:00:00:01", "00:00:00:00:00:02").replace("02:00:00:00:00:01", "02:00:00:00:00:02")))
        assert db.query(models.LinuxAsset).count() == 2


def test_inventory_upload_surfaces_device_and_lease(client, control_headers):
    result = client.post("/api/assets/upload", files={"file": ("inventory.txt", INVENTORY.encode())}, headers=control_headers)
    assert result.status_code == 200
    assert result.json()["asset"]["firmware_version"] == "24.10.2"
    row = client.get("/api/iot/observations").json()[0]
    assert row["presence"] == "lease_record"
    assert row["evidence"]["online_verified"] is False


def connection_payload():
    return {"host": "192.168.50.1", "credential_env": "LINUXGUARD_DEVICE_TEST", "host_key_sha256": "SHA256:" + "A" * 43}


def test_device_controls_require_configured_token(client, control):
    assert client.post("/api/iot/connections", json=connection_payload()).status_code == 401
    result = client.post("/api/iot/connections", json=connection_payload(), headers=control)
    assert result.status_code == 200
    assert "password" not in result.json()
    assert client.post("/api/iot/connections", json=connection_payload(), headers=control).status_code == 409


@pytest.mark.parametrize("changes", [{"host": "8.8.8.8"}, {"host": "example.com"}, {"credential_env": "DEEPSEEK_API_KEY"}, {"username": "root;id"}, {"password": "never-store-this"}])
def test_invalid_device_inputs_are_rejected(client, control, changes):
    result = client.post("/api/iot/connections", json={**connection_payload(), **changes}, headers=control)
    assert result.status_code in {400, 422}


def test_pin_policy_rejects_wrong_host_key():
    key = paramiko.RSAKey.generate(1024)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    PinnedHostKey(fingerprint).missing_host_key(None, "fixture", key)
    with pytest.raises(paramiko.SSHException):
        PinnedHostKey("SHA256:" + "A" * 43).missing_host_key(None, "fixture", key)


def test_discovery_bounds_and_unknown_identity(session_factory, control, monkeypatch):
    from app.services import iot_devices
    calls = []
    monkeypatch.setattr(iot_devices, "_probe", lambda address, ports, timeout: (calls.append(address) or address, [1883]))
    with session_factory() as db:
        with pytest.raises(ValueError):
            discover(db, "192.168.50.0/24", [22])
        with pytest.raises(ValueError):
            discover(db, "10.0.0.0/30", [22])
        assert calls == []
        result = discover(db, "192.168.50.0/30", [1883])
        assert result["responding_devices"] == 2
        row = db.query(models.DeviceObservation).first()
        assert json.loads(row.evidence_json)["device_type"] == "unknown"
        assert db.query(models.LinuxAsset).count() == 0


def test_openwrt_uses_exact_vendor_versions(session_factory):
    with session_factory() as db:
        asset = seed_openwrt(db)
        add_advisory(db)
        run_matching(db)
        row = db.query(models.VulnerabilityMatch).one()
        assert row.reason_code == "openwrt_exact_affected_version"
        assert row.fixed_version == "2.0.2-1"
        package = next(p for p in asset.packages if p.package_name == "mosquitto")
        package.package_version = "2.0.2-1"
        db.commit()
        run_matching(db)
        assert row.match_status == "fixed"
        package.package_version = "99.9-custom"
        db.commit()
        run_matching(db)
        assert row.match_status == "insufficient_data"
        assert row.affected


def test_wrong_firmware_and_incomplete_inventory_never_confirm_fixed(session_factory):
    with session_factory() as db:
        asset = seed_openwrt(db)
        add_advisory(db, release="25.12.0")
        run_matching(db)
        row = db.query(models.VulnerabilityMatch).one()
        assert row.reason_code == "openwrt_applicability_missing"
        assert row.fixed_version == ""
        asset.inventory_complete = False
        db.commit()
        run_matching(db)
        assert row.reason_code == "inventory_incomplete"


def test_advisory_validation(client, control):
    payload = {"cve_id": "CVE-2099-9999", "package_name": "mosquitto", "release": "24.10.2",
               "affected_versions": ["2.0.1-1"], "fixed_versions": ["2.0.2-1"], "source_url": "https://openwrt.org/advisory/test-fixture"}
    assert client.post("/api/iot/advisories", json=payload, headers=control).status_code == 200
    assert client.post("/api/iot/advisories", json={**payload, "source_url": "https://example.com"}, headers=control).status_code == 422
    assert client.post("/api/iot/advisories", json={**payload, "fixed_versions": ["2.0.1-1"]}, headers=control).status_code == 400


def test_additive_migration_keeps_legacy_asset(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "old.db"))
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE linux_asset (id INTEGER PRIMARY KEY, hostname VARCHAR(128))"))
        conn.execute(text("INSERT INTO linux_asset VALUES (1, 'legacy-preserved')"))
    monkeypatch.setattr(database, "engine", engine)
    changes = database._migrate_sqlite_schema()
    assert "linux_asset.device_type" in changes
    assert database._migrate_sqlite_schema() == []
    with engine.connect() as conn:
        assert conn.execute(text("SELECT hostname, device_type FROM linux_asset")).one() == ("legacy-preserved", "linux_server")
    engine.dispose()


def test_import_without_stable_identity_is_rejected(client, control_headers):
    raw = INVENTORY.replace("mac_address: 02:00:00:00:00:01", "")
    response = client.post("/api/assets/upload", files={"file": ("inventory.txt", raw.encode())}, headers=control_headers)
    assert response.status_code == 400
    assert client.get("/api/assets").json() == []


def test_retained_openwrt_advisory_rebuilds_intel_after_reset(session_factory):
    from app.services.experiment_lifecycle import clear_derived_data
    with session_factory() as db:
        seed_openwrt(db)
        add_advisory(db)
        clear_derived_data(db)
        run_matching(db)
        assert db.query(models.VulnerabilityInfo).one().source == "openwrt_operator_advisory"
        assert db.query(models.VulnerabilityMatch).one().reason_code == "openwrt_exact_affected_version"


def test_openwrt_only_advisory_does_not_apply_to_ubuntu(client, session_factory, control):
    payload = {"cve_id": "CVE-2099-9999", "package_name": "mosquitto", "release": "24.10.2",
               "affected_versions": ["2.0.1-1"], "fixed_versions": ["2.0.2-1"], "source_url": "https://openwrt.org/advisory/test-fixture"}
    assert client.post("/api/iot/advisories", json=payload, headers=control).status_code == 200
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="ubuntu-test", distribution="ubuntu", os_version="24.04")
        db.add(asset)
        db.flush()
        db.add(models.AssetPackage(asset_id=asset.id, package_name="mosquitto", package_version="2.0.1-1"))
        db.commit()
        run_matching(db)
        assert db.query(models.VulnerabilityMatch).count() == 0
