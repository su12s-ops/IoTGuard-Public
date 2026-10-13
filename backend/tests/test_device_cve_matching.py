"""阶段六：设备级 CVE 匹配（厂商公告精确版本 → 设备风险 → 智能体工具）。"""
from __future__ import annotations

import pytest

from app import models
from app.services import device_vulnerability as DV
from app.services.agents import tools as agent_tools

DEVICE_ID = "DEV-SCX1-MATCH"
ADVISORY = {
    "cve_id": "CVE-2026-31001",
    "vendor": "SmartCam Technologies",
    "model": "SmartCam-X1",
    "component_name": "SmartCam MQTT broker",
    "affected_versions": ["1.6.2"],
    "fixed_versions": ["1.6.3"],
    "source_url": "https://example-vendor.example.com/security/CVE-2026-31001",
    "notes": "测试公告：操作员依据厂商公告人工登记",
}


@pytest.fixture()
def device_with_components(session_factory):
    db = session_factory()
    device = models.IotDevice(device_id=DEVICE_ID, device_name="SmartCam-X1",
                              device_type="ip_camera", vendor="SmartCam Technologies",
                              model="SmartCam-X1", firmware_version="2.4.7",
                              ip="10.1.1.50", status="online")
    db.add(device)
    db.flush()
    db.add_all([
        models.IotDeviceComponent(device_row_id=device.id,
                                  component_name="SmartCam MQTT broker", version="1.6.2"),
        models.IotDeviceComponent(device_row_id=device.id,
                                  component_name="dropbear ssh", version="2022.83"),
        models.IotDeviceComponent(device_row_id=device.id,
                                  component_name="SmartCam-X1 firmware", version="2.4.7",
                                  component_type="firmware"),
    ])
    db.commit()
    try:
        yield db, device
    finally:
        db.close()


def test_register_advisory_creates_cve_metadata(device_with_components):
    db, device = device_with_components
    row = DV.register_advisory(db, ADVISORY)
    assert row.cve_id == "CVE-2026-31001"
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id="CVE-2026-31001").one()
    assert vuln.affected_package == "SmartCam MQTT broker"
    assert vuln.source == "iot_vendor_operator_advisory"


def test_matching_affected_by_exact_vendor_version(device_with_components):
    db, device = device_with_components
    DV.register_advisory(db, ADVISORY)
    result = DV.run_device_matching(db, device)
    assert result["stats"]["affected"] == 1
    match = db.query(models.DeviceVulnerabilityMatch).filter_by(
        cve_id="CVE-2026-31001").one()
    assert match.match_status == "affected"
    assert match.installed_version == "1.6.2" and match.fixed_version == "1.6.3"
    assert match.applicability_source == "vendor_advisory" and match.confidence == 0.95
    # 设备风险被真实匹配结果更新
    assert result["affected_count"] == 1
    assert device.security_status == "at_risk"
    assert device.risk_score_basis == "cve_match" and device.risk_score > 0


def test_matching_fixed_when_version_patched(device_with_components):
    db, device = device_with_components
    DV.register_advisory(db, ADVISORY)
    component = next(c for c in device.components if c.component_name == "SmartCam MQTT broker")
    component.version = "1.6.3"  # 已升级到修复版本
    db.commit()
    result = DV.run_device_matching(db, device)
    assert result["stats"]["fixed"] == 1 and result["affected_count"] == 0
    assert device.security_status == "no_known_cve"


def test_matching_component_absent_is_not_applicable(session_factory):
    """公告针对另一台设备型号或组件缺失时，不下受影响结论。"""
    db = session_factory()
    try:
        other = models.IotDevice(device_id="DEV-OTHER", device_name="Other-Cam",
                                 model="OtherCam-2", ip="10.1.1.51", status="online")
        db.add(other)
        db.flush()
        db.add(models.IotDeviceComponent(device_row_id=other.id,
                                         component_name="busybox", version="1.36"))
        db.commit()
        DV.register_advisory(db, ADVISORY)  # SmartCam-X1 公告
        result = DV.run_device_matching(db, other)
        assert result["affected_count"] == 0
    finally:
        db.close()


def test_nvd_generic_route_flags_potentially_affected(device_with_components):
    """无厂商公告时，同名组件走 NVD 通用路线：低置信 + 需复核标注。"""
    db, device = device_with_components
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-32002", title="dropbear 命令注入", cvss_score=8.1,
        cvss_severity="High", affected_package="dropbear ssh",
        fixed_version="2022.84", source="nvd"))
    db.commit()
    DV.run_device_matching(db, device)
    match = db.query(models.DeviceVulnerabilityMatch).filter_by(
        cve_id="CVE-2026-32002").one()
    assert match.match_status == "potentially_affected"
    assert match.applicability_source == "nvd_generic" and match.confidence == 0.7
    assert "需复核" in match.match_reason


def test_device_api_vulnerability_count_is_real(client, device_with_components, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "stage2-test-token")
    db, device = device_with_components
    # 未匹配时计数为真实 0
    listing = client.get("/api/devices").json()
    summary = next(d for d in listing if d["device_id"] == DEVICE_ID)
    assert summary["vulnerability_count"] == 0

    headers = {"X-Control-Token": "stage2-test-token"}
    DV.register_advisory(db, ADVISORY)
    matched = client.post(f"/api/devices/{DEVICE_ID}/match", headers=headers)
    assert matched.status_code == 200, matched.text
    assert matched.json()["stats"]["affected"] == 1

    listing = client.get("/api/devices").json()
    summary = next(d for d in listing if d["device_id"] == DEVICE_ID)
    assert summary["vulnerability_count"] == 1
    assert summary["security_status"] == "at_risk"

    vulns = client.get(f"/api/devices/{DEVICE_ID}/vulnerabilities").json()
    assert vulns["affected_count"] == 1
    assert vulns["matches"][0]["cve_id"] == "CVE-2026-31001"
    assert vulns["matches"][0]["fixed_version"] == "1.6.3"


def test_advisory_api_requires_token_and_https(client, device_with_components, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "t")
    body = {k: v for k, v in ADVISORY.items() if k not in ("vendor", "model")}
    # 无令牌 → 401
    assert client.post(f"/api/devices/{DEVICE_ID}/advisories", json=body).status_code == 401
    # 非 HTTPS 来源 → 422
    bad = {**body, "source_url": "http://example.com/advisory"}
    response = client.post(f"/api/devices/{DEVICE_ID}/advisories", json=bad,
                           headers={"X-Control-Token": "t"})
    assert response.status_code == 422


def test_agent_tools_read_device_cve_matches(device_with_components):
    db, device = device_with_components
    DV.register_advisory(db, ADVISORY)
    DV.run_device_matching(db, device)

    vuln_tool = agent_tools.tool_query_matched_vulnerabilities(db, device_id=DEVICE_ID)
    assert vuln_tool["device_count"] == 1
    device_match = vuln_tool["device_matches"][0]
    assert device_match["cve_id"] == "CVE-2026-31001"
    assert device_match["match_status"] == "affected"

    remediation_tool = agent_tools.tool_query_remediation_targets(db, device_id=DEVICE_ID)
    assert remediation_tool["device_targets"]
    target = remediation_tool["device_targets"][0]
    assert target["authorized"] is False  # 设备修复必须走 Harness 审批
    assert "Harness" in target["note"]
