"""发现闭环边界用例：设备身份合并与 DHCP 关联的两个已知风险点。

用独立测试数据（Mock 底层探测，无真实网络）验证：
1. MAC 缺失时，两台同厂商/型号设备（不同主机）不会被错误合并；
   同一主机上的两个实例会合并——这是键设计的已知边界（证据无法区分），如实记录。
2. DHCP 租约 IP 变化：MAC 优先关联保证不错误关联；
   MAC 缺失时的 IP 复用不会覆盖首次关联（防错联保护）。
"""
from __future__ import annotations

import json

from app import models
from app.services import device_inventory, iot_devices
from app.services.discovery_pipeline import discover_and_enroll

CIDR = "192.168.50.0/25"


def _allow(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")


def _sweep(monkeypatch, responders: dict[str, list[int]]):
    def probe(address, ports, timeout):
        return address, list(responders.get(address, []))
    monkeypatch.setattr(iot_devices, "_probe", probe)


def _identity_probes(monkeypatch, host_map: dict[str, tuple[int, dict]]):
    """host_map: {host: (http_port, /api/system 身份字典)}；仅 HTTP 可识别。"""
    def probe_http(host, port, timeout=2.0, path="/"):
        entry = host_map.get(host)
        if entry and port == entry[0]:
            product = entry[1].get("model", "device") + " httpd/1.0"
            return ({"service_type": "http", "product": product, "version": "1.0",
                     "banner": "HTTP/1.0 200 OK", "auth_state": "unknown",
                     "evidence": {"status_line": "HTTP/1.0 200 OK", "server": product,
                                  "title": entry[1].get("device_name", "")}}, "")
        return None, ""

    def probe_json(host, port, path, timeout=2.0):
        entry = host_map.get(host)
        if entry and port == entry[0] and path in ("/api/system", "/system/info"):
            return entry[1]
        return None

    monkeypatch.setattr(device_inventory, "probe_http", probe_http)
    monkeypatch.setattr(device_inventory, "_http_json", probe_json)
    for name in ("probe_ssh", "probe_https", "probe_rtsp", "probe_mqtt", "probe_banner"):
        monkeypatch.setattr(device_inventory, name, lambda *a, **k: None)


def _no_mac_identity(vendor: str, model: str) -> dict:
    return {"device_name": model, "device_type": "ip_camera", "vendor": vendor,
            "model": model, "firmware_version": "1.0.0",
            "services": [{"type": "http", "port": 80, "product": model + " httpd/1.0"}]}
    # 关键：不含 mac_address → _device_key 退化为 vendor|model|host


# ── 问题一（1）：不同主机、同厂商型号、均无 MAC → 不得错误合并 ────────────────

def test_same_vendor_model_without_mac_on_different_hosts_not_merged(session_factory, monkeypatch):
    _allow(monkeypatch)
    _sweep(monkeypatch, {"192.168.50.10": [80], "192.168.50.20": [80]})
    _identity_probes(monkeypatch, {
        "192.168.50.10": (80, _no_mac_identity("Acme", "CamZ")),
        "192.168.50.20": (80, _no_mac_identity("Acme", "CamZ")),  # 完全相同的自报身份
    })
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["enrolled_new"] == 2
        devices = db.query(models.IotDevice).all()
        assert len(devices) == 2  # 键含 host：两台设备各自建档，未合并
        assert len({d.device_id for d in devices}) == 2
        assert db.query(models.DeviceObservation).filter_by(source="tcp_connect").count() == 2
    finally:
        db.close()


# ── 问题一（2）：同一主机两个实例、无 MAC → 合并（键设计边界，如实记录） ──────

def test_same_host_instances_without_mac_merge_is_documented_limit(session_factory, monkeypatch):
    _allow(monkeypatch)
    # 同一主机上两个实例分别占用 80 与 8080，自报身份完全一致且无 MAC
    _sweep(monkeypatch, {"192.168.50.10": [80, 8080]})
    identity = _no_mac_identity("Acme", "CamZ")

    def probe_http(host, port, timeout=2.0, path="/"):
        if host == "192.168.50.10" and port in (80, 8080):
            product = "CamZ httpd/1.0"
            return ({"service_type": "http", "product": product, "version": "1.0",
                     "banner": "HTTP/1.0 200 OK", "auth_state": "unknown",
                     "evidence": {"status_line": "HTTP/1.0 200 OK", "server": product, "title": "CamZ"}}, "")
        return None, ""

    monkeypatch.setattr(device_inventory, "probe_http", probe_http)
    monkeypatch.setattr(device_inventory, "_http_json",
                        lambda host, port, path, timeout=2.0: identity
                        if host == "192.168.50.10" and port in (80, 8080)
                        and path in ("/api/system", "/system/info") else None)
    for name in ("probe_ssh", "probe_https", "probe_rtsp", "probe_mqtt", "probe_banner"):
        monkeypatch.setattr(device_inventory, name, lambda *a, **k: None)
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [80, 8080])
        devices = db.query(models.IotDevice).all()
        assert len(devices) == 1, summary  # 已知边界：host 相同 + 身份自报一致 + 无 MAC → 证据无法区分，合并为一条
        services = db.query(models.IotDeviceService).count()
        assert services == 2, summary      # 但两个端口的服务证据都保留
    finally:
        db.close()


# ── 问题二（1）：DHCP 租约 IP 变化（同 MAC 换地址）→ 按 MAC 正确关联 ──────────

def test_dhcp_ip_change_correlates_by_mac_not_ip(session_factory, monkeypatch):
    _allow(monkeypatch)
    mac = "a4:cf:12:9b:e3:40"
    _sweep(monkeypatch, {"192.168.50.11": [80]})
    identity = {"device_name": "CamM", "device_type": "ip_camera", "vendor": "Acme",
                "model": "CamM", "firmware_version": "1.0.0", "mac_address": mac.upper(),
                "services": [{"type": "http", "port": 80, "product": "CamM httpd/1.0"}]}
    _identity_probes(monkeypatch, {"192.168.50.11": (80, identity)})
    db = session_factory()
    try:
        gateway = models.LinuxAsset(hostname="gw", distribution="openwrt")
        db.add(gateway)
        db.commit()
        # 昨天的租约 .10，今天续租换到 .11（同一 MAC → 同一观察行，IP 更新）
        iot_devices.save_gateway_observations(db, gateway, [
            {"ip_address": "192.168.50.10", "mac_address": mac, "hostname": "cam", "lease_expiry": ""}])
        iot_devices.save_gateway_observations(db, gateway, [
            {"ip_address": "192.168.50.11", "mac_address": mac, "hostname": "cam", "lease_expiry": ""}])
        lease = db.query(models.DeviceObservation).filter_by(source="dhcp_lease").one()
        assert lease.ip_address == "192.168.50.11"  # 租约行已随续租更新

        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["dhcp_correlated"] == 1
        device = db.query(models.IotDevice).one()
        db.refresh(lease)
        assert lease.promoted_device_id == device.device_id  # MAC 关联到当前在线设备
        assert json.loads(lease.evidence_json)["correlation"]["basis"] == "mac"
    finally:
        db.close()


# ── 问题二（2）：MAC 缺失时 IP 被新设备复用 → 不覆盖首次关联（防错联） ────────

def test_dhcp_ip_reuse_without_mac_keeps_first_correlation(session_factory, monkeypatch):
    _allow(monkeypatch)
    _sweep(monkeypatch, {"192.168.50.10": [80]})
    _identity_probes(monkeypatch, {"192.168.50.10": (80, _no_mac_identity("Acme", "CamZ"))})
    db = session_factory()
    try:
        gateway = models.LinuxAsset(hostname="gw", distribution="openwrt")
        db.add(gateway)
        db.commit()
        # 无 MAC 的租约（廉价设备常见）：只能按 IP 关联
        iot_devices.save_gateway_observations(db, gateway, [
            {"ip_address": "192.168.50.10", "mac_address": "", "hostname": "unknown", "lease_expiry": ""}])
        first = discover_and_enroll(db, CIDR, [80])
        assert first["dhcp_correlated"] == 1
        device_one = db.query(models.IotDevice).one()

        # 该 IP 后来被另一台同样无 MAC 的不同设备复用
        _identity_probes(monkeypatch, {"192.168.50.10": (80, _no_mac_identity("OtherCorp", "CamY"))})
        second = discover_and_enroll(db, CIDR, [80])
        assert second["enrolled_new"] == 1
        assert db.query(models.IotDevice).count() == 2  # 新设备独立建档（键含 vendor|model）
        lease = db.query(models.DeviceObservation).filter_by(source="dhcp_lease").one()
        # 防错联保护：无 MAC 证据不足以改写关联，保留首次结论并留痕
        assert lease.promoted_device_id == device_one.device_id
        assert json.loads(lease.evidence_json)["correlation"]["basis"] == "ip"
    finally:
        db.close()


# ── 问题二（3）：设备 MAC 与租约 MAC 不一致（同 IP）→ 不建立关联 ──────────────

def test_dhcp_mac_mismatch_at_same_ip_does_not_link(session_factory, monkeypatch):
    _allow(monkeypatch)
    _sweep(monkeypatch, {"192.168.50.11": [80]})
    identity = {"device_name": "CamA", "device_type": "ip_camera", "vendor": "Acme",
                "model": "CamA", "firmware_version": "1.0.0", "mac_address": "AA:AA:AA:AA:AA:AA",
                "services": [{"type": "http", "port": 80, "product": "CamA httpd/1.0"}]}
    _identity_probes(monkeypatch, {"192.168.50.11": (80, identity)})
    db = session_factory()
    try:
        gateway = models.LinuxAsset(hostname="gw", distribution="openwrt")
        db.add(gateway)
        db.commit()
        iot_devices.save_gateway_observations(db, gateway, [
            {"ip_address": "192.168.50.11", "mac_address": "bb:bb:bb:bb:bb:bb",
             "hostname": "someone-else", "lease_expiry": ""}])
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["dhcp_correlated"] == 0  # MAC 不一致且设备侧 MAC 可信 → 拒绝按 IP 强行关联
        lease = db.query(models.DeviceObservation).filter_by(source="dhcp_lease").one()
        assert lease.promoted_device_id == ""
        assert lease.review_status == "pending"
    finally:
        db.close()
