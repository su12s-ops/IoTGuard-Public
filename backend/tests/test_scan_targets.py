"""阶段六：互联网授权目标登记——双重授权、令牌门禁与输入校验。

不使用 mock：目标登记的真实约束（IP 字面量、网段白名单、授权依据必填、
令牌校验）全部经由真实 API 与真实环境变量校验。
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def scan_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "scan-test-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")


def _auth():
    return {"X-Control-Token": "scan-test-token"}


def _payload(**overrides):
    base = {
        "name": "自有测试主机",
        "ip": "127.0.0.1",
        "authorization_basis": "本人本地测试环境，授权扫描",
        "ports": [22, 80, 443],
    }
    base.update(overrides)
    return base


def test_capabilities_reports_limits_and_gate(client, scan_env):
    data = client.get("/api/scans/capabilities").json()
    assert data["control_configured"] is True
    assert data["allowed_networks"] == ["127.0.0.0/8"]
    assert data["limits"]["max_ports"] >= 1
    assert "不做漏洞利用验证" in data["note"]


def test_register_target_requires_control_token(client, scan_env):
    resp = client.post("/api/scans/targets", json=_payload())
    assert resp.status_code == 401


def test_register_and_list_target(client, scan_env):
    resp = client.post("/api/scans/targets", json=_payload(), headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["ip"] == "127.0.0.1"
    assert body["ports"] == [22, 80, 443]
    assert body["enabled"] is True

    listed = client.get("/api/scans/targets").json()
    assert [item["ip"] for item in listed] == ["127.0.0.1"]
    assert listed[0]["authorization_basis"]


def test_register_target_rejects_hostname(client, scan_env):
    resp = client.post("/api/scans/targets", json=_payload(ip="example.com"), headers=_auth())
    assert resp.status_code == 400
    assert "必须是明确的 IP" in resp.json()["detail"]


def test_register_target_rejects_ip_outside_allowed_networks(client, scan_env):
    resp = client.post("/api/scans/targets", json=_payload(ip="203.0.113.7"), headers=_auth())
    assert resp.status_code == 400
    assert "允许网段" in resp.json()["detail"]


def test_register_target_requires_authorization_basis(client, scan_env):
    resp = client.post("/api/scans/targets", json=_payload(authorization_basis="短"), headers=_auth())
    assert resp.status_code == 422


def test_register_target_validates_ports(client, scan_env):
    assert client.post("/api/scans/targets", json=_payload(ports=[0]), headers=_auth()).status_code == 422
    assert client.post("/api/scans/targets", json=_payload(ports=[70000]), headers=_auth()).status_code == 422


def test_register_target_rejects_duplicate_ip(client, scan_env):
    assert client.post("/api/scans/targets", json=_payload(), headers=_auth()).status_code == 200
    resp = client.post("/api/scans/targets", json=_payload(name="重复登记"), headers=_auth())
    assert resp.status_code == 409


def _register(client) -> int:
    resp = client.post("/api/scans/targets", json=_payload(), headers=_auth())
    assert resp.status_code == 200
    return resp.json()["id"]


def test_update_target_ports_enabled_notes(client, scan_env):
    target_id = _register(client)
    resp = client.patch(f"/api/scans/targets/{target_id}",
                        json={"ports": [8080], "notes": "备注", "enabled": False}, headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["ports"] == [8080]
    assert body["enabled"] is False
    assert body["notes"] == "备注"

    # 停用目标不能发起扫描
    run = client.post("/api/scans/runs", json={"target_id": target_id}, headers=_auth())
    assert run.status_code == 422
    assert "停用" in run.json()["detail"]


def test_update_target_rejects_invalid_ports_and_requires_auth(client, scan_env):
    target_id = _register(client)
    assert client.patch(f"/api/scans/targets/{target_id}", json={"ports": [-1]}).status_code == 401
    resp = client.patch(f"/api/scans/targets/{target_id}", json={"ports": [-1]}, headers=_auth())
    assert resp.status_code == 422


def test_update_target_ip_is_immovable_via_update(client, scan_env):
    """更新接口没有 ip 字段（extra=forbid）：改 IP 必须删掉重登，授权依据随之重填。"""
    target_id = _register(client)
    resp = client.patch(f"/api/scans/targets/{target_id}", json={"ip": "127.0.0.2"}, headers=_auth())
    assert resp.status_code == 422


def test_delete_target(client, scan_env):
    target_id = _register(client)
    assert client.delete(f"/api/scans/targets/{target_id}", headers=_auth()).status_code == 200
    assert client.get("/api/scans/targets").json() == []
    resp = client.patch(f"/api/scans/targets/{target_id}", json={"enabled": True}, headers=_auth())
    assert resp.status_code == 404


def test_start_scan_requires_existing_target_and_token(client, scan_env):
    assert client.post("/api/scans/runs", json={"target_id": 999}).status_code == 401
    resp = client.post("/api/scans/runs", json={"target_id": 999}, headers=_auth())
    assert resp.status_code == 404
