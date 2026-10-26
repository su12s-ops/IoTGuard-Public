"""eBPF 2.0 最终交付轮 P2-3：智能体运行时数据质量工具。

验收点（审计轮 §4.2 P2-3）：智能体可查询 coverage / dropped / freshness /
data_gaps；语义边界与 reliability_snapshot 一致——真实零丢失是数值 0，
未上报是 unavailable，绝不虚构为零；缺口如实列出供智能体 data_gaps 声明。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import models
from app.services.unified.agents_def import specs_summary
from app.services.agent_tools import tool_query_runtime_data_quality


@pytest.fixture()
def quality_asset(session_factory):
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="p23-host", ip_address="10.0.0.30", os_name="Ubuntu",
                                  os_version="24.04", distribution="ubuntu")
        db.add(asset)
        db.commit()
        return asset.id
    finally:
        db.close()


def _add_sensor(session_factory, asset_id, sensor_id, *, dropped=None, minutes_ago=1, status="running"):
    db = session_factory()
    try:
        db.add(models.RuntimeSensor(
            asset_id=asset_id, sensor_id=sensor_id, source="falco", status=status,
            dropped_events=dropped, detail="",
            capabilities_json="{}",
            last_heartbeat_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)))
        db.commit()
    finally:
        db.close()


def _add_evidence(session_factory, asset_id, evidence_id, *, evidence_type="process",
                  age_hours=1.0, process_exec_id="lg-p23-1-1"):
    db = session_factory()
    try:
        db.add(models.SecurityEvidence(
            evidence_id=evidence_id, evidence_hash=f"h-{evidence_id}", device_id="p23-host",
            asset_id=asset_id, evidence_type=evidence_type,
            timestamp=(datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat(),
            severity="info", severity_score=10, process="proc", pid=100,
            process_exec_id=process_exec_id))
        db.commit()
    finally:
        db.close()


def test_real_zero_dropped_distinct_from_unavailable(session_factory, quality_asset):
    _add_sensor(session_factory, quality_asset, "falco-live", dropped=0)
    _add_sensor(session_factory, quality_asset, "ebpf-live", dropped=None)
    db = session_factory()
    try:
        result = tool_query_runtime_data_quality(db, "p23-host")
    finally:
        db.close()
    assert result["found"] is True
    assert result["dropped_events"] == {"falco-live": 0, "ebpf-live": "unavailable"}, \
        "真实零丢失必须是数值 0；未上报必须是 unavailable"
    assert any("ebpf-live" in gap and "unavailable" in gap for gap in result["data_gaps"])
    assert not any("falco-live" in gap for gap in result["data_gaps"]), "真实零丢失不得报缺口"
    assert result["coverage"]["status"] == "running"


def test_freshness_buckets_and_no_evidence_gap(session_factory, quality_asset):
    _add_sensor(session_factory, quality_asset, "s1", dropped=0)
    _add_evidence(session_factory, quality_asset, "SE-fresh", evidence_type="process", age_hours=2)
    _add_evidence(session_factory, quality_asset, "SE-old", evidence_type="network", age_hours=48)
    db = session_factory()
    try:
        result = tool_query_runtime_data_quality(db, "p23-host")
    finally:
        db.close()
    assert result["freshness"]["process"]["freshness"] == "fresh"
    assert result["freshness"]["network"]["freshness"] == "stale"
    assert result["freshness"]["file"]["freshness"] == "no_evidence"
    assert any("file" in gap and "覆盖为零" in gap for gap in result["data_gaps"])
    assert any("network" in gap and "过期" in gap for gap in result["data_gaps"])


def test_stale_heartbeat_flagged(session_factory, quality_asset):
    _add_sensor(session_factory, quality_asset, "s-stale", dropped=0, minutes_ago=10)  # >120s
    db = session_factory()
    try:
        result = tool_query_runtime_data_quality(db, "p23-host")
    finally:
        db.close()
    assert result["coverage"]["status"] == "stale"
    assert any("s-stale" in gap and "过期" in gap for gap in result["data_gaps"])


def test_sessionless_legacy_evidence_counted_as_gap(session_factory, quality_asset):
    _add_sensor(session_factory, quality_asset, "s1", dropped=0)
    _add_evidence(session_factory, quality_asset, "SE-new", process_exec_id="lg-p23-100-9")
    _add_evidence(session_factory, quality_asset, "SE-legacy", process_exec_id="")
    db = session_factory()
    try:
        result = tool_query_runtime_data_quality(db, "p23-host")
    finally:
        db.close()
    assert any("1 条证据缺进程会话身份" in gap for gap in result["data_gaps"])


def test_unknown_device_reports_gap_not_fabrication(session_factory):
    db = session_factory()
    try:
        result = tool_query_runtime_data_quality(db, "no-such-host")
    finally:
        db.close()
    assert result["found"] is False
    assert result["data_gaps"], "未知设备必须如实报缺口"


def test_runtime_agent_spec_registers_quality_tool():
    spec = next(s for s in specs_summary() if s["name"] == "runtime_analyst")
    assert "query_runtime_data_quality" in spec["tools"]


def test_evidence_keys_reconcile_device_and_host_lines(session_factory):
    """回归（M4.3 真实 E2E 发现）：同一物理机的设备线档案（IotDevice，DEV-* 键）
    与主机线资产（LinuxAsset，SSH 采集自报主机名 OpenWrt-<hash>）必须互相传递
    证据键——logread/eBPF 证据锚定的是设备自报主机名，否则设备面研判会因键
    失配错误得到"无运行时证据"。"""
    from app.services.agent_tools import _evidence_keys

    db = session_factory()
    try:
        db.add(models.LinuxAsset(hostname="OpenWrt-000c2915a8c8", ip_address="192.168.100.1",
                                 distribution="openwrt", os_name="OpenWrt"))
        db.add(models.IotDevice(device_id="DEV-59CCB87534B7", ip="192.168.100.1",
                                device_name="unknown-device-192.168.100.1"))
        db.commit()
        # 设备键 → 传递到同 IP 主机线资产的自报主机名
        keys_from_device = _evidence_keys(db, "DEV-59CCB87534B7")
        assert "OpenWrt-000c2915a8c8" in keys_from_device
        # 主机键 → 传递到同 IP 设备线档案
        keys_from_asset = _evidence_keys(db, "OpenWrt-000c2915a8c8")
        assert "DEV-59CCB87534B7" in keys_from_asset
    finally:
        db.close()


def test_evidence_keys_resolve_via_pinned_connection_when_asset_ip_missing(session_factory):
    """操作员上传的主机线资产可以没有 IP 字段（清单不含管理地址）；此时经
    指纹钉扎的 DeviceConnection（host↔asset_id，平台权威同机绑定）解析。"""
    from app.services.agent_tools import _evidence_keys

    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="OpenWrt-000c2915a8c8", ip_address="",
                                  distribution="openwrt", os_name="OpenWrt")
        db.add(asset)
        db.flush()
        db.add(models.DeviceConnection(
            asset_id=asset.id, label="lab", host="192.168.100.1", port=22,
            username="root", auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_K",
            host_key_sha256="SHA256:" + "A" * 43, enabled=True))
        db.add(models.IotDevice(device_id="DEV-59CCB87534B7", ip="192.168.100.1",
                                device_name="unknown-device-192.168.100.1"))
        db.commit()
        keys_from_device = _evidence_keys(db, "DEV-59CCB87534B7")
        assert "OpenWrt-000c2915a8c8" in keys_from_device
    finally:
        db.close()
