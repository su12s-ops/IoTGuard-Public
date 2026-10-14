"""eBPF 2.0 最终交付轮 P1-4：CVE 关联视图与证据下钻。

验收点（审计轮 §4.2 P1-4 原定义）：
- 行为链详情页可下钻查看"该 CVE 相关进程证据"（SecurityEvidence 级）；
- 匹配语义与风险评估共用 package_match_reasons（直接/上下文命中同源）；
- 证据按 P1-3 会话键聚合展示；
- 诚实边界：上下文关联≠漏洞被利用（exploitation_confirmed 恒 False）；
  无风险记录 404 ≠ 有记录无证据 not_observed（两种语义不混淆）。
"""
from __future__ import annotations

import pytest

from app import models
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.runtime_telemetry import cve_runtime_evidence

CVE = "CVE-2026-P14TEST"


@pytest.fixture()
def cve_asset(session_factory):
    """资产 + mosquitto 服务 + 该资产上的 CVE 风险记录。"""
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="p14-host", ip_address="10.0.0.20", os_name="Ubuntu",
                                  os_version="24.04", distribution="ubuntu")
        db.add(asset)
        db.flush()
        db.add(models.AssetService(asset_id=asset.id, service_name="mosquitto", port=1883,
                                   process_name="mosquitto"))
        db.add(models.RiskAssessment(asset_id=asset.id, cve_id=CVE, package_name="mosquitto",
                                     active=True, runtime_status="waiting"))
        db.commit()
        return asset.id
    finally:
        db.close()


def _evidence(db, asset_id, **overrides):
    row = models.SecurityEvidence(
        evidence_id=overrides.pop("evidence_id"), evidence_hash=overrides.pop("evidence_hash"),
        device_id="p14-host", asset_id=asset_id,
        evidence_type=overrides.pop("evidence_type"), timestamp=overrides.pop("timestamp", "2026-10-14T09:00:00Z"),
        severity=overrides.pop("severity", "info"), severity_score=overrides.pop("severity_score", 0),
        process=overrides.pop("process", ""), pid=overrides.pop("pid", 100),
        commandline=overrides.pop("commandline", ""),
        destination_ip=overrides.pop("destination_ip", ""), destination_port=overrides.pop("destination_port", 0),
        file_path=overrides.pop("file_path", ""), raw_data=overrides.pop("raw_data", "{}"),
        process_exec_id=overrides.pop("process_exec_id", ""))
    db.add(row)
    return row


def test_direct_and_contextual_matches_grouped_by_session(session_factory, cve_asset):
    db = session_factory()
    try:
        _evidence(db, cve_asset, evidence_id="SE-direct1", evidence_hash="h1", evidence_type="process",
                  process="mosquitto", pid=1200, commandline="/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf",
                  process_exec_id="lg-p14-1200-11")
        _evidence(db, cve_asset, evidence_id="SE-ctx1", evidence_hash="h2", evidence_type="network",
                  process="curl", pid=1300, destination_ip="127.0.0.1", destination_port=1883,
                  process_exec_id="lg-p14-1300-22")
        _evidence(db, cve_asset, evidence_id="SE-unrel", evidence_hash="h3", evidence_type="file",
                  process="wget", pid=1400, file_path="/etc/shadow", severity="warning", severity_score=58,
                  process_exec_id="lg-p14-1400-33")
        db.commit()
    finally:
        db.close()

    db = session_factory()
    try:
        result = cve_runtime_evidence(db, CVE, cve_asset)
    finally:
        db.close()
    assert result is not None and result["asset_count"] == 1
    block = result["assets"][0]
    assert block["runtime_status"] == "verified", "mosquitto 进程名直接命中 → verified"
    assert block["signals"]["direct_count"] == 1
    assert block["signals"]["contextual_count"] == 1, "1883 端口（mosquitto 服务端口）为上下文命中"
    assert block["signals"]["by_type"] == {"process": 1, "network": 1}, "无关文件证据不得混入"

    ids = {item["evidence_id"] for item in block["evidence"]}
    assert ids == {"SE-direct1", "SE-ctx1"}
    direct = next(item for item in block["evidence"] if item["match_type"] == "direct")
    assert direct["match_reasons"] == ["process"]
    ctx = next(item for item in block["evidence"] if item["match_type"] == "contextual")
    assert "service_port" in ctx["match_reasons"]

    # P1-3 会话聚合：两个进程实例 → 两个会话，证据归位
    session_ids = {s["id"] for s in block["sessions"]}
    assert session_ids == {f"{cve_asset}:exec:lg-p14-1200-11", f"{cve_asset}:exec:lg-p14-1300-22"}
    by_id = {s["id"]: s for s in block["sessions"]}
    assert by_id[f"{cve_asset}:exec:lg-p14-1200-11"]["evidence_ids"] == ["SE-direct1"]
    assert block["exploitation_confirmed"] is False
    assert "不构成" in block["note"]


def test_risk_without_evidence_is_not_observed_never_fabricated(session_factory, cve_asset):
    db = session_factory()
    try:
        result = cve_runtime_evidence(db, CVE, cve_asset)
    finally:
        db.close()
    block = result["assets"][0]
    assert block["runtime_status"] == "not_observed"
    assert block["evidence"] == [] and block["sessions"] == []
    assert block["signals"]["direct_count"] == 0
    assert block["exploitation_confirmed"] is False and block["absence_proves_safe"] is False


def test_semantics_parity_with_risk_evaluation(session_factory, cve_asset):
    """下钻视图与风险评估（evaluate_runtime_evidence）对同一事件给出一致的
    verified/contextual/not_observed 结论——共用匹配语义的回归锚。"""
    events = [
        {"asset_id": cve_asset, "timestamp": "2026-10-14T09:00:00Z", "category": "process_execution",
         "process_name": "mosquitto", "commandline": "/usr/sbin/mosquitto", "raw": {}, "severity_score": 30},
        {"asset_id": cve_asset, "timestamp": "2026-10-14T09:01:00Z", "category": "network_activity",
         "process_name": "curl", "commandline": "curl mqtt", "port": 1883, "raw": {}, "severity_score": 10},
    ]
    db = session_factory()
    try:
        asset = db.get(models.LinuxAsset, cve_asset)
        services = db.query(models.AssetService).filter_by(asset_id=cve_asset).all()
        expected = evaluate_runtime_evidence(asset, "mosquitto", services, events)
        for index, event in enumerate(events):
            db.add(models.SecurityEvidence(
                evidence_id=f"SE-parity{index}", evidence_hash=f"ph{index}", device_id="p14-host",
                asset_id=cve_asset, evidence_type="process" if event["category"] == "process_execution" else "network",
                timestamp=event["timestamp"], severity="info", severity_score=event["severity_score"],
                process=event["process_name"], pid=2000 + index, commandline=event["commandline"],
                destination_port=event.get("port", 0), raw_data="{}"))
        db.commit()
        result = cve_runtime_evidence(db, CVE, cve_asset)
    finally:
        db.close()
    block = result["assets"][0]
    assert block["runtime_status"] == expected["status"], \
        f"下钻与风险评估语义不一致：{block['runtime_status']} vs {expected['status']}"
    assert block["signals"]["direct_count"] == expected["signals"]["direct_count"]


def test_endpoint_scoping_and_404(client, session_factory, cve_asset):
    # 无风险记录的 CVE → 404（与"有记录无证据"的 not_observed 语义区分）
    assert client.get("/api/runtime/cve-evidence", params={"cve_id": "CVE-2026-NORISK"}).status_code == 404

    # 另一个资产：查询范围限定后查不到该 CVE 的风险 → 404
    db = session_factory()
    try:
        other = models.LinuxAsset(hostname="p14-other", ip_address="10.0.0.21", os_name="Ubuntu",
                                  os_version="24.04", distribution="ubuntu")
        db.add(other)
        db.commit()
        other_id = other.id
    finally:
        db.close()
    scoped = client.get("/api/runtime/cve-evidence", params={"cve_id": CVE, "asset_id": other_id})
    assert scoped.status_code == 404

    response = client.get("/api/runtime/cve-evidence", params={"cve_id": CVE, "asset_id": cve_asset})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["cve_id"] == CVE and body["asset_count"] == 1
    assert body["assets"][0]["runtime_status"] == "not_observed"

    # 不带 asset_id：返回该 CVE 全部活跃风险对应资产
    unscoped = client.get("/api/runtime/cve-evidence", params={"cve_id": CVE})
    assert unscoped.status_code == 200
    assert unscoped.json()["assets"][0]["asset_id"] == cve_asset
