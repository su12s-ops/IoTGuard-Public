"""阶段五：发现闭环（扫描 → 观察 → 识别 → 建档 → CVE 匹配）测试。

不使用真实网络（conftest 审计钩子禁止真实 socket）：网段层用
monkeypatch 替换 iot_devices._probe（与 test_iot_upgrade.py 同模式），
协议层替换 device_inventory 的底层探测函数，identify_service /
build_identity / upsert_device / run_device_matching 均为真实实现。
"""
from __future__ import annotations

import json

import pytest

from app import models
from app.services import device_inventory, iot_devices
from app.services.discovery_pipeline import (
    IDENTIFY_CONFIDENCE_FLOOR,
    discover_and_enroll,
    enroll_scope,
)

CIDR = "192.168.50.0/25"  # 128 地址，满足 discover 的上限
CAM_IP = "192.168.50.10"

SMARTCAM_SYSTEM = {
    "device_name": "SmartCam-X1",
    "device_type": "ip_camera",
    "vendor": "SmartCam Technologies",
    "model": "SmartCam-X1",
    "firmware_version": "2.4.7",
    "os": "SmartCamOS 2.4.7",
    "mac_address": "A4:CF:12:9B:E3:40",
    "services": [
        {"type": "http", "port": 80, "product": "SmartCam-X1 httpd/2.4.7"},
        {"type": "ssh", "port": 22, "product": "dropbear SSH 2022.83"},
        {"type": "mqtt", "port": 1883, "product": "SmartCam MQTT broker 1.6.2"},
        {"type": "rtsp", "port": 554, "product": "SmartCam-X1 RTSP/2.4.7"},
    ],
}


def _allow_cidrs(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.0/24")


def _fake_sweep(monkeypatch, responders: dict[str, list[int]]):
    """替换 iot_devices._probe：只有 responders 中的地址返回开放端口。"""
    def probe(address, ports, timeout):
        return address, list(responders.get(address, []))
    monkeypatch.setattr(iot_devices, "_probe", probe)


def _fake_smartcam_probes(monkeypatch, ip: str = CAM_IP, identity: dict | None = SMARTCAM_SYSTEM,
                          http_port: int = 80, ssh_port: int = 22, mqtt_port: int = 1883):
    """替换 device_inventory 底层探测：模拟 SmartCam 真实协议响应（端口可参数化）。"""
    def probe_ssh(host, port, timeout=2.0):
        if host == ip and port == ssh_port:
            return {"service_type": "ssh", "product": "dropbear_2022.83", "version": "2022.83",
                    "banner": "SSH-2.0-dropbear_2022.83", "auth_state": "auth_required",
                    "evidence": {"banner": "SSH-2.0-dropbear_2022.83"}}
        return None

    def probe_http(host, port, timeout=2.0, path="/"):
        if host != ip or port != http_port:
            return None, ""
        result = {"service_type": "http", "product": "SmartCam-X1 httpd/2.4.7", "version": "2.4.7",
                  "banner": "HTTP/1.0 200 OK", "auth_state": "unknown",
                  "evidence": {"status_line": "HTTP/1.0 200 OK", "server": "SmartCam-X1 httpd/2.4.7",
                               "title": "SmartCam-X1"}}
        return result, "<html><title>SmartCam-X1</title></html>"

    def probe_mqtt(host, port, timeout=2.0):
        if host == ip and port == mqtt_port:
            return {"service_type": "mqtt", "product": "mqtt-broker", "version": "", "banner": "",
                    "auth_state": "anonymous_accepted", "evidence": {"connack_return_code": 0}}
        return None

    def probe_json(host, port, path, timeout=2.0):
        if host == ip and port == http_port and path in ("/api/system", "/system/info"):
            return identity
        return None

    monkeypatch.setattr(device_inventory, "probe_ssh", probe_ssh)
    monkeypatch.setattr(device_inventory, "probe_http", probe_http)
    monkeypatch.setattr(device_inventory, "probe_https", lambda *a, **k: None)
    monkeypatch.setattr(device_inventory, "probe_mqtt", probe_mqtt)
    monkeypatch.setattr(device_inventory, "probe_rtsp", lambda *a, **k: None)
    monkeypatch.setattr(device_inventory, "probe_banner", lambda *a, **k: None)
    monkeypatch.setattr(device_inventory, "_http_json", probe_json)


def _seed_gateway_dhcp(db):
    asset = models.LinuxAsset(hostname="openwrt-gw", distribution="openwrt")
    db.add(asset)
    db.commit()
    iot_devices.save_gateway_observations(db, asset, [
        {"ip_address": CAM_IP, "mac_address": "a4:cf:12:9b:e3:40", "hostname": "cam10", "lease_expiry": ""},
    ])
    return asset


def _seed_mqtt_cve(db):
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-77701", title="SmartCam MQTT broker RCE",
        affected_package="SmartCam MQTT broker", fixed_version="1.7.0",
        cvss_score=9.8, cvss_severity="Critical", source="nvd_test"))
    db.commit()


# ── 1. 未知设备首次发现与自动建档 ─────────────────────────────────────────────

def test_first_discovery_enrolls_unknown_device(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [22, 80, 1883]})
    _fake_smartcam_probes(monkeypatch)
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [22, 80, 1883])
        assert summary["scan"]["responding_devices"] == 1
        assert summary["processed"] == 1
        assert summary["identified"] == 1
        assert summary["enrolled_new"] == 1
        device = db.query(models.IotDevice).one()
        assert device.vendor == "SmartCam Technologies"
        assert device.device_type == "ip_camera"
        assert device.identity_confidence >= IDENTIFY_CONFIDENCE_FLOOR
        observation = db.query(models.DeviceObservation).filter_by(source="tcp_connect").one()
        assert observation.review_status == "identified"
        assert observation.promoted_device_id == device.device_id
        assert observation.review_attempts == 1
        evidence = json.loads(observation.evidence_json)
        assert evidence["open_ports"] == [22, 80, 1883]  # 原始证据保留
        assert evidence["enrollment"]["device_id"] == device.device_id
        assert evidence["enrollment"]["identity_confidence"] == device.identity_confidence
    finally:
        db.close()


# ── 2. 同一设备重复扫描不产生重复资产 ─────────────────────────────────────────

def test_repeat_scan_creates_no_duplicate_assets(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [22, 80, 1883]})
    _fake_smartcam_probes(monkeypatch)
    db = session_factory()
    try:
        first = discover_and_enroll(db, CIDR, [22, 80, 1883])
        second = discover_and_enroll(db, CIDR, [22, 80, 1883])
        assert first["enrolled_new"] == 1 and first["enrolled_existing"] == 0
        # 第二轮：已识别观察幂等刷新既有设备，不新建资产
        assert second["processed"] == 1
        assert second["enrolled_new"] == 0 and second["enrolled_existing"] == 1
        assert db.query(models.IotDevice).count() == 1  # upsert 幂等，无重复资产
        assert db.query(models.DeviceObservation).filter_by(source="tcp_connect").count() == 1
        assert db.query(models.IotDeviceService).count() == 3
    finally:
        db.close()


# ── 3. DHCP 被动观察与主动扫描结果关联 ────────────────────────────────────────

def test_dhcp_observation_correlates_with_active_discovery(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [80]})
    _fake_smartcam_probes(monkeypatch)
    db = session_factory()
    try:
        _seed_gateway_dhcp(db)
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["dhcp_correlated"] == 1
        device = db.query(models.IotDevice).one()
        dhcp_row = db.query(models.DeviceObservation).filter_by(source="dhcp_lease").one()
        assert dhcp_row.review_status == "identified"
        assert dhcp_row.promoted_device_id == device.device_id
        assert dhcp_row.presence == "lease_record"  # 租约语义未被改写
        assert json.loads(dhcp_row.evidence_json)["correlation"]["basis"] == "mac"
    finally:
        db.close()


# ── 4. 无法识别的设备保留观察证据，并支持安全重试 ─────────────────────────────

def test_unidentifiable_device_keeps_evidence_and_supports_retry(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {"192.168.50.11": [8080]})
    # 所有协议探测与横幅兜底均无响应 → upsert_device 拒绝建档
    # （probe_http 真实实现返回元组，假件须保持同一契约）
    for name in ("probe_ssh", "probe_https", "probe_rtsp", "probe_mqtt", "probe_banner"):
        monkeypatch.setattr(device_inventory, name, lambda *a, **k: None)
    monkeypatch.setattr(device_inventory, "probe_http", lambda *a, **k: (None, ""))
    monkeypatch.setattr(device_inventory, "_http_json", lambda *a, **k: None)
    db = session_factory()
    try:
        summary = discover_and_enroll(db, CIDR, [8080])
        assert summary["insufficient_evidence"] == 1
        assert db.query(models.IotDevice).count() == 0  # 不伪造设备
        observation = db.query(models.DeviceObservation).filter_by(source="tcp_connect").one()
        assert observation.review_status == "insufficient_evidence"
        assert observation.promoted_device_id == ""
        assert json.loads(observation.evidence_json)["open_ports"] == [8080]  # 原始证据仍在

        # 设备随后可识别（例如 Web 服务换到 8080 端口上线）：不重扫，仅重试该范围
        _fake_smartcam_probes(monkeypatch, ip="192.168.50.11", http_port=8080)
        retry = enroll_scope(db, summary["scope"])
        assert retry["identified"] == 1 and retry["enrolled_new"] == 1
        db.refresh(observation)
        assert observation.review_status == "identified"
        assert observation.promoted_device_id != ""
    finally:
        db.close()


# ── 5. 已确认组件版本的设备进入 CVE 检测（保持候选语义） ──────────────────────

def test_versioned_components_enter_cve_matching_as_candidates(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [22, 80, 1883]})
    _fake_smartcam_probes(monkeypatch)
    db = session_factory()
    try:
        _seed_mqtt_cve(db)
        summary = discover_and_enroll(db, CIDR, [22, 80, 1883])
        assert summary["cve_matched"] == 1
        device = db.query(models.IotDevice).one()
        component = next(c for c in device.components if c.component_name == "SmartCam MQTT broker")
        assert component.version == "1.6.2"
        match = db.query(models.DeviceVulnerabilityMatch).one()
        assert match.match_status == "potentially_affected"  # NVD 通用候选，不得提升为已确认
        assert match.applicability_source == "nvd_generic"
        assert match.affected is True and match.confidence == 0.7
        db.refresh(device)
        assert device.security_status == "at_risk"
    finally:
        db.close()


# ── 6. 证据不足时不产生已确认漏洞 ────────────────────────────────────────────

def test_insufficient_evidence_defers_cve_and_never_confirms(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [80]})
    # 仅返回无版本信息的 HTTP 横幅，无身份接口 → 组件无版本证据
    def probe_http(host, port, timeout=2.0, path="/"):
        if host == CAM_IP and port == 80:
            return ({"service_type": "http", "product": "httpd", "version": "",
                     "banner": "HTTP/1.0 200 OK", "auth_state": "unknown",
                     "evidence": {"server": "httpd", "title": "Unknown Box"}}, "")
        return None, ""
    for name in ("probe_ssh", "probe_https", "probe_rtsp", "probe_mqtt", "probe_banner"):
        monkeypatch.setattr(device_inventory, name, lambda *a, **k: None)
    monkeypatch.setattr(device_inventory, "probe_http", probe_http)
    monkeypatch.setattr(device_inventory, "_http_json", lambda *a, **k: None)

    from app.services import device_vulnerability, discovery_pipeline
    def _forbidden(*args, **kwargs):
        raise AssertionError("证据不足时不得调用 CVE 匹配")
    monkeypatch.setattr(device_vulnerability, "run_device_matching", _forbidden)
    # discovery_pipeline 通过模块属性调用，补丁生效性验证
    assert discovery_pipeline.device_vulnerability.run_device_matching is _forbidden

    db = session_factory()
    try:
        _seed_mqtt_cve(db)
        summary = discover_and_enroll(db, CIDR, [80])
        assert summary["cve_deferred"] == 1 and summary["cve_matched"] == 0
        device = db.query(models.IotDevice).one()
        assert device.vendor == "" and device.model == ""  # 不伪造厂商/型号
        assert db.query(models.DeviceVulnerabilityMatch).count() == 0  # 无任何"已确认"漏洞
        observation = db.query(models.DeviceObservation).filter_by(source="tcp_connect").one()
        assert observation.review_status == "insufficient_evidence"
        evidence = json.loads(observation.evidence_json)
        assert evidence["enrollment"]["cve"]["status"] == "deferred_no_version_evidence"
    finally:
        db.close()


# ── 7. 未授权网段与超范围网段被拒绝 ──────────────────────────────────────────

def test_unauthorized_or_oversized_cidr_rejected(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {})
    db = session_factory()
    try:
        with pytest.raises(ValueError):
            discover_and_enroll(db, "10.9.9.0/30", [22])  # 不在白名单
        with pytest.raises(ValueError):
            discover_and_enroll(db, "192.168.50.0/24", [22])  # 256 地址超出 128 上限
        assert db.query(models.DeviceObservation).count() == 0
        assert db.query(models.IotDevice).count() == 0
    finally:
        db.close()


# ── 8. 发现流程绝不自动触发设备修复 / Harness ────────────────────────────────

def test_discovery_never_triggers_repair_or_harness(session_factory, monkeypatch):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [22, 80, 1883]})
    _fake_smartcam_probes(monkeypatch)
    from app.services import agent_harness, remediation_engine
    def _forbidden(*args, **kwargs):
        raise AssertionError("发现流程不得触发修复或 Harness")
    monkeypatch.setattr(remediation_engine, "generate_remediation_tasks", _forbidden)
    monkeypatch.setattr(agent_harness, "create_run", _forbidden)
    db = session_factory()
    try:
        _seed_mqtt_cve(db)
        discover_and_enroll(db, CIDR, [22, 80, 1883])
        assert db.query(models.HarnessRun).count() == 0
        assert db.query(models.HarnessToolCall).count() == 0
        assert db.query(models.RemediationTask).count() == 0
        assert db.query(models.RemediationWorkflowRun).count() == 0
    finally:
        db.close()


# ── 9. API 兼容：enroll 参数与 observations 新字段，旧行为不变 ────────────────

def test_api_discovery_enroll_and_legacy_modes(client, monkeypatch, control_headers):
    _allow_cidrs(monkeypatch)
    _fake_sweep(monkeypatch, {CAM_IP: [80]})
    _fake_smartcam_probes(monkeypatch)
    # 旧行为：不带 enroll → 仅扫描，返回原 summary 结构
    legacy = client.post("/api/iot/discovery", json={"cidr": CIDR, "ports": [80]}, headers=control_headers)
    assert legacy.status_code == 200
    assert "responding_devices" in legacy.json() and "processed" not in legacy.json()
    # 新行为：enroll=true → 闭环
    closed = client.post("/api/iot/discovery",
                         json={"cidr": CIDR, "ports": [80], "enroll": True}, headers=control_headers)
    assert closed.status_code == 200
    body = closed.json()
    assert body["identified"] == 1 and body["enrolled_new"] == 1
    observations = client.get("/api/iot/observations").json()
    row = next(r for r in observations if r["source"] == "tcp_connect")
    assert row["review_status"] == "identified"
    assert row["promoted_device_id"]
    assert row["review_attempts"] >= 1
    # 未授权网段 → 400
    rejected = client.post("/api/iot/discovery",
                           json={"cidr": "10.9.9.0/30", "ports": [22], "enroll": True}, headers=control_headers)
    assert rejected.status_code == 400
