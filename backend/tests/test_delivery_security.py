"""Execution-boundary regressions, with isolated databases and no device I/O."""
from types import SimpleNamespace

import pytest

from app import models
from app.services import agent_harness as h
from app.services.unified.graph import RunContext, _vulnerability_evidence_validator


@pytest.mark.parametrize("status", ["unavailable", "error", "stale", "available"])
def test_transport_state_is_never_vendor_applicability(status):
    from app.services.unified.evidence_prep import detect_vendor_patch_semantics
    result = detect_vendor_patch_semantics({"canonical": {"status": status}}, "1.0")
    assert result["release_status"] == ""


@pytest.mark.parametrize("domain,production,lab,scope,allowed", [
    ("unassigned", "1", "1", "1", False),
    ("openwrt_lab", "1", "0", "1", False),
    ("openwrt_lab", "1", "1", "2", False),
    ("openwrt_lab", "0", "1", "1", True),
    ("production", "0", "1", "1", False),
    ("production", "1", "0", "", True),
])
def test_final_install_boundary(session_factory, monkeypatch, tmp_path,
                                domain, production, lab, scope, allowed):
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", production)
    monkeypatch.setenv("LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", lab)
    monkeypatch.setenv("LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE", scope)
    reached = []
    def connect(_):
        reached.append(True)
        raise RuntimeError("isolated transport boundary reached")
    monkeypatch.setattr(h.device_access, "open_connection", connect)
    with session_factory() as db:
        db.add(models.LinuxAsset(id=1, hostname="test", distribution="openwrt", repair_domain=domain))
        conn = models.DeviceConnection(asset_id=1, host="192.0.2.1", host_key_sha256="SHA256:" + "A" * 43)
        db.add(conn)
        db.commit()
        with pytest.raises((RuntimeError if allowed else ValueError)):
            h.install_registered_package(conn, {}, tmp_path / "unused.apk")
        assert bool(reached) is allowed


def test_domain_registration_is_authenticated_persistent_and_immutable(client, session_factory, control_headers):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="domain-test", distribution="openwrt")
        db.add(asset); db.commit(); asset_id = asset.id
    url = f"/api/assets/{asset_id}/repair-domain"
    payload = {"domain": "openwrt_lab", "actor": "operator", "reason": "isolated clone"}
    assert client.post(url, json=payload).status_code == 401
    assert client.post(url, json=payload, headers=control_headers).status_code == 200
    assert client.post(url, json={**payload, "domain": "production"}, headers=control_headers).status_code == 409
    with session_factory() as db:
        row = db.get(models.LinuxAsset, asset_id)
        assert row.repair_domain == "openwrt_lab"
        assert row.repair_domain_actor == "operator"


def test_empty_registry_never_accepts_external_identifiers(session_factory):
    validator = _vulnerability_evidence_validator(RunContext(db_factory=session_factory, trace_id=""))
    for ref in ["CVE-2099-12345", "GHSA-xxxx-yyyy-zzzz", "https://example.org/advisory", "a" * 64]:
        assert validator({"findings": [{"supporting_evidence_ids": [ref]}]})
    assert not validator({"findings": [{"supporting_evidence_ids": []}]})


def test_demo_rejects_secrets_without_echo_or_storage(client, session_factory, control_headers):
    payload = {"targets": [{"label": "test", "target_type": "ssh", "host": "192.0.2.1", "password": "synthetic-secret"}]}
    response = client.put("/api/demo/targets", json=payload, headers=control_headers)
    assert response.status_code == 400
    assert "synthetic-secret" not in response.text
    with session_factory() as db:
        assert db.query(models.DemoTarget).count() == 0


def test_bootstrap_stores_only_reference(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setenv("VM_HOST", "192.0.2.1")
    monkeypatch.setenv("VM_USER", "test")
    monkeypatch.setenv("VM_PASS", "synthetic-secret")
    response = client.get("/api/demo/targets", headers=control_headers)
    assert response.status_code == 200
    assert "synthetic-secret" not in response.text
    with session_factory() as db:
        row = db.query(models.DemoTarget).one()
        assert row.password == "" and row.credential_env == "VM_PASS"


def test_demo_runtime_reads_existing_sensor_without_generating_events(monkeypatch):
    from app.routers import demo
    commands = []
    def execute(command, *args, **kwargs):
        commands.append(command)
        return ("FALCO_OK" if "command -v falco" in command else "", "", 0)
    monkeypatch.setattr(demo, "_ssh_exec", execute)
    monkeypatch.setattr(demo, "append_events", lambda *a, **k: [])
    target = SimpleNamespace(install_falco_if_missing=False, asset_hostname="fixture")
    count, _ = demo._capture_falco_via_ssh(target, "fixture", None)
    assert count == 0
    assert any("journalctl" in command for command in commands)
    assert not any(word in " ".join(commands) for word in ("systemctl stop", "/etc/shadow", "lg_capture", "apt-get"))
