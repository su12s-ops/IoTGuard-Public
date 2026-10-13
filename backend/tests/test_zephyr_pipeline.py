"""第七阶段：Zephyr RTOS 终端接入（Mock 层专项测试）。

模拟 Zephyr-Sensor-01 固件的真实 /api/system 身份结构（与固件 main.c 输出一致），
验证：协议识别 → 身份/固件元数据建档 → 版本化组件 → CVE 三层分级 →
同固件不同设备不合并 → 幂等 → unsupported 能力如实标注。
真实 QEMU 端到端联调由 firmware/zephyr-sensor-01/ + 后端脚本另行执行并留证。
"""
from __future__ import annotations

import json
import re

from app import models
from app.services import device_inventory, iot_devices
from app.services.discovery_pipeline import discover_and_enroll

CIDR = "192.168.50.0/25"
Z1, Z2 = "192.168.50.21", "192.168.50.22"
FW_VERSION = "0.1.0-stage7"
OS_VERSION = "Zephyr RTOS 4.4.2"


def _zephyr_identity(device_uid: str, mac: str, fw: str = FW_VERSION) -> dict:
    """与固件 build_identity_json 输出一致的 /api/system 身份结构。"""
    return {
        "device_name": "Zephyr-Sensor-01", "device_type": "zephyr_sensor",
        "vendor": "IoTGuard-Lab", "model": "Zephyr-Sensor-01",
        "firmware_version": fw, "os": OS_VERSION, "device_id": device_uid,
        "board": "qemu_x86_64", "soc": "qemu_x86_64", "arch": "x86_64",
        "build_id": "Oct 13 2026 19:00:00", "status": "online",
        "mac_address": mac,
        "telemetry": {"temperature_c": {"value": 25.1, "simulated": True},
                      "humidity_pct": {"value": 57.2, "simulated": True}},
        "services": [{"type": "http", "port": 80,
                      "product": f"zephyr-sensor-httpd {fw}"}],
    }


def _allow(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")


def _mock_zephyr(monkeypatch, responders: dict[str, list[int]],
                 identities: dict[str, dict]):
    def probe(address, ports, timeout):
        return address, list(responders.get(address, []))

    def probe_http(host, port, timeout=2.0, path="/"):
        if host not in identities or port != 80:
            return None, ""
        ident = identities[host]
        # 模拟真实探测：产品串来自设备自报 services，版本按尾部 token 解析
        # （与 build_identity 的 reported 覆盖逻辑一致；无版本产品串 → 无版本）
        product = ident["services"][0]["product"]
        version_match = re.search(r"([0-9][A-Za-z0-9_.-]*)\s*$", product)
        version = version_match.group(1) if version_match else ""
        return ({"service_type": "http", "product": product,
                 "version": version, "banner": "HTTP/1.0 200 OK",
                 "auth_state": "unknown",
                 "evidence": {"status_line": "HTTP/1.0 200 OK", "server": product,
                              "title": ident["device_name"]}},
                "<html><title>Zephyr-Sensor-01</title></html>")

    def probe_json(host, port, path, timeout=2.0):
        if host in identities and port == 80 and path in ("/api/system", "/system/info"):
            return identities[host]
        return None

    monkeypatch.setattr(iot_devices, "_probe", probe)
    monkeypatch.setattr(device_inventory, "probe_http", probe_http)
    monkeypatch.setattr(device_inventory, "_http_json", probe_json)
    for name in ("probe_ssh", "probe_https", "probe_rtsp", "probe_mqtt", "probe_banner"):
        monkeypatch.setattr(device_inventory, name, lambda *a, **k: None)


# ── 1. 发现 → Zephyr 身份识别 → 建档 → 版本化组件 → 能力标注 ─────────────────

def test_zephyr_discovery_enrollment_with_metadata(session_factory, monkeypatch):
    _allow(monkeypatch)
    ident = _zephyr_identity("ZEPHYR-SENSOR-0001", "52:54:00:12:34:56")
    _mock_zephyr(monkeypatch, {Z1: [80]}, {Z1: ident})
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["identified"] == 1 and summary["enrolled_new"] == 1
        device = db.query(models.IotDevice).one()
        assert device.device_type == "zephyr_sensor"
        assert device.os == OS_VERSION                 # 真实 Zephyr 版本来自固件自报
        assert device.firmware_version == FW_VERSION   # 实际固件版本
        assert device.identity_source == "device_identity_endpoint"
        assert device.identity_confidence == 0.9
        # 元数据含 board/build_id/遥测（simulated 标记）
        meta = json.loads(device.metadata_json)
        assert meta["board"] == "qemu_x86_64" and "build_id" in meta
        assert meta["telemetry"]["temperature_c"]["simulated"] is True
        # 组件：固件（版本化）+ httpd（版本化）→ 进入 CVE 消费
        components = {c.component_name: c.version for c in device.components}
        assert components.get("Zephyr-Sensor-01 firmware") == FW_VERSION
        assert components.get(f"zephyr-sensor-httpd {FW_VERSION}") == FW_VERSION
        assert summary["cve_matched"] == 1
        # 能力边界如实标注（不伪造支持）
        observation = db.query(models.DeviceObservation).filter_by(source="tcp_connect").one()
        enrollment = json.loads(observation.evidence_json)["enrollment"]
        caps = enrollment["capabilities"]
        assert caps["ssh_inventory"].startswith("unsupported")
        assert caps["package_inventory"].startswith("unsupported")
        assert caps["ebpf_runtime"].startswith("unsupported")
    finally:
        db.close()


# ── 2. 同固件、不同设备 ID（不同 MAC 实例）不得合并 ─────────────────────────

def test_two_zephyr_instances_same_firmware_not_merged(session_factory, monkeypatch):
    _allow(monkeypatch)
    identities = {
        Z1: _zephyr_identity("ZEPHYR-SENSOR-0001", "52:54:00:12:34:56"),
        Z2: _zephyr_identity("ZEPHYR-SENSOR-0002", "52:54:00:12:34:57"),  # 相同固件版本
    }
    _mock_zephyr(monkeypatch, {Z1: [80], Z2: [80]}, identities)
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["enrolled_new"] == 2
        devices = db.query(models.IotDevice).all()
        assert len(devices) == 2 and len({d.device_id for d in devices}) == 2
        assert {d.firmware_version for d in devices} == {FW_VERSION}
        # 重复扫描：两台各自幂等刷新，不新建资产
        again = discover_and_enroll(db, CIDR, [80])
        assert again["enrolled_new"] == 0 and db.query(models.IotDevice).count() == 2
    finally:
        db.close()


# ── 3. CVE 三层分级（合成公告与情报，仅测试内使用） ─────────────────────────

def test_zephyr_cve_three_tiers(session_factory, monkeypatch):
    _allow(monkeypatch)
    _mock_zephyr(monkeypatch, {Z1: [80]}, {Z1: _zephyr_identity(
        "ZEPHYR-SENSOR-0001", "52:54:00:12:34:56")})
    from app.services.device_vulnerability import register_advisory
    db = session_factory()
    try:
        # 层1：厂商公告精确版本（affected_versions 含真实固件版本）
        register_advisory(db, {"cve_id": "CVE-2026-80001", "vendor": "IoTGuard-Lab",
                               "model": "Zephyr-Sensor-01",
                               "component_name": "Zephyr-Sensor-01 firmware",
                               "affected_versions": [FW_VERSION],
                               "fixed_versions": ["0.2.0"],
                               "source_url": "https://iotguard.example/advisory-1",
                               "cvss_score": 7.5, "cvss_severity": "High"})
        # 层2：NVD 通用情报（httpd 组件，低于修复版本 → 候选）
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2026-80002", title="generic httpd issue",
            affected_package=f"zephyr-sensor-httpd {FW_VERSION}", fixed_version="1.0.0",
            cvss_score=5.3, cvss_severity="Medium", source="nvd_synthetic"))
        db.commit()
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["cve_matched"] == 1
        device = db.query(models.IotDevice).one()
        from app.services.device_vulnerability import device_matches
        by_cve = {m["cve_id"]: m for m in device_matches(db, device)}
        tier1 = by_cve["CVE-2026-80001"]
        assert tier1["match_status"] == "affected"           # 精确版本证据 → 确认层
        assert tier1["applicability_source"] == "vendor_advisory"
        assert tier1["confidence"] == 0.95
        tier2 = by_cve["CVE-2026-80002"]
        assert tier2["match_status"] == "potentially_affected"  # 通用情报 → 候选层
        assert tier2["applicability_source"] == "nvd_generic"
        # 层3：任何与设备组件无关的 CVE 不得出现在设备结果中（无证据不确认）
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2026-80003", title="unrelated",
            affected_package="some-other-component", fixed_version="2.0.0",
            source="nvd_synthetic"))
        db.commit()
        from app.services.device_vulnerability import run_device_matching
        run_device_matching(db, device)
        ids = {m["cve_id"] for m in device_matches(db, device)}
        assert "CVE-2026-80003" not in ids
        # OS 版本不得被直接解释为必然存在相关 CVE：无组件/公告关联的 OS 条目同样不出现
        assert all(c.startswith("CVE-2026-8000") for c in ids)
    finally:
        db.close()


# ── 4. 无版本证据时延迟匹配（不伪造命中） ──────────────────────────────────

def test_zephyr_without_version_evidence_defers(session_factory, monkeypatch):
    _allow(monkeypatch)
    ident = _zephyr_identity("ZEPHYR-SENSOR-0003", "52:54:00:aa:bb:cc", fw="0.0.0-dev")
    ident["services"] = [{"type": "http", "port": 80, "product": "zephyr-httpd"}]  # 无版本产品串
    _mock_zephyr(monkeypatch, {Z2: [80]}, {Z2: ident})
    db = session_factory()
    try:
        discover_and_enroll(db, CIDR, [80])
        device = db.query(models.IotDevice).one()
        httpd = [c for c in device.components if "httpd" in c.component_name]
        assert httpd and all(not (c.version or "").strip() for c in httpd)  # httpd 无版本证据
        # 无版本组件不进入匹配；固件组件 0.0.0-dev 属版本化证据（可进入匹配，但无公告→零命中）
        from app.services.device_vulnerability import device_matches
        assert device_matches(db, device) == []
    finally:
        db.close()


# ── 5. 能力画像端点（增量字段，向后兼容） ──────────────────────────────────

def test_capabilities_expose_os_profiles(client, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")
    response = client.get("/api/iot/capabilities")
    assert response.status_code == 200
    profiles = response.json()["os_capability_profiles"]
    assert profiles["zephyr"]["ssh_inventory"] == "unsupported"
    assert profiles["zephyr"]["cve_exact_versions"].startswith("supported")
    assert profiles["linux/openwrt"]["ssh_inventory"] == "supported"
