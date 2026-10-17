"""eBPF 2.0 P2-2 专项测试：OpenWrt logread 降级采集（纯解析 + 管线语义）。

覆盖任务书验收点的可测内核（真实 OpenWrt 采集由
backend/scripts/ebpf_p22_openwrt_live.py 执行，证据落 reports/，本文件锁定语义）：
- logread 行解析（实测格式：周 月 日 时:分:秒 年 facility.level process[pid]: msg）；
- 时间语义：设备本地时间按采集偏移换算 UTC；偏移未知按 UTC 并如实标注；
- 缺少年份 / 不可解析行 → 跳过并计数（不虚构年份 → 保 P0 判重身份与幂等）；
- 事件接入 P0 管线：source=openwrt_logread、观察模式=syslog（绝不伪装 eBPF）、
  重复采集指纹幂等、资产绑定、SecurityEvidence 同步生成；
- 设备重启语义：boot_id 参与指纹（跨重启不误合并）；ring 窗口重置不做拼接；
- 拉取式传感器心跳：dropped=unavailable（ring 覆盖丢失不可测，非零）；
- 统一 Trace：runtime_log_collection 已登记且可运行；
- 智能体数据质量：OpenWrt 资产缺 logread 采集 → 显式 data_gap；已有 →
  降级采集边界如实声明；
- SensorHeartbeat 接受 logread 源。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.services import openwrt_runtime_log as ortlog  # noqa: E402
from app.services.ebpf_event_collector import (  # noqa: E402
    _observation_mode, append_events, load_runtime_events)


SAMPLE_OUTPUT = """===== IDENTITY =====
hostname: OpenWrt
boot_id: abbc3748-54a5-4d36-bbb2-8fc2bcb5d19c
device_utc_epoch: 1792030917
device_local_offset: +0000
tz_spec: GMT0
===== LOGREAD =====
Thu Oct 15 00:13:30 2026 kern.debug kernel: [    0.134074] pcpu-alloc: [0] 112 113
Thu Oct 15 02:21:57 2026 auth.err dropbear[1234]: Password auth failed for 'root' from 198.51.100.5:51234
Thu Oct 15 02:22:01 2026 daemon.info dnsmasq[882]: started, version 2.90 cachesize 150
"""

# 缺少年份的 RFC3164 防御形态（logread 实测带年份；此为兜底路径验证）
YEAR_MISSING_LINE = "Thu Oct 15 02:21:57 auth.err dropbear[1234]: Password auth failed"
UNPARSEABLE_LINE = "random garbage without syslog structure"


def _capture(offset: str = "+0000", extra_lines: tuple[str, ...] = ()) -> dict:
    identity = f"""===== IDENTITY =====
hostname: OpenWrt
boot_id: abbc3748-54a5-4d36-bbb2-8fc2bcb5d19c
device_utc_epoch: 1792030917
device_local_offset: {offset}
tz_spec: GMT0
"""
    body = SAMPLE_OUTPUT.split("===== LOGREAD =====")[1].strip("\n")
    for line in extra_lines:
        body += "\n" + line
    return ortlog.parse_capture_output(identity + "===== LOGREAD =====\n" + body + "\n")


# ── 解析与时间语义 ───────────────────────────────────────────────────────────


class TestParseCaptureOutput:
    def test_identity_and_lines(self):
        capture = _capture()
        assert capture["identity"]["hostname"] == "OpenWrt"
        assert capture["identity"]["boot_id"] == "abbc3748-54a5-4d36-bbb2-8fc2bcb5d19c"
        assert capture["identity"]["device_local_offset"] == "+0000"
        assert len(capture["log_lines"]) == 3
        assert not capture["truncated"]

    def test_missing_identity_fields_are_empty_not_guessed(self):
        capture = ortlog.parse_capture_output("===== LOGREAD =====\n")
        assert capture["identity"] == {}
        assert capture["log_lines"] == []


class TestOffsetConversion:
    def test_zero_offset(self):
        events, meta = ortlog.build_events(_capture(), asset_hostname="OpenWrt", asset_id=1,
                                           sensor_id="s1")
        assert meta["timezone_offset_seconds"] == 0
        assert events[0]["timestamp"] == "2026-10-15T00:13:30+00:00"

    def test_positive_offset_converts_to_utc(self):
        # 设备本地 +0800：本地 10:00 → UTC 02:00
        events, meta = ortlog.build_events(_capture(offset="+0800"), asset_hostname="OpenWrt",
                                           asset_id=1, sensor_id="s1")
        assert meta["timezone_offset_seconds"] == 8 * 3600
        assert events[0]["timestamp"] == "2026-10-14T16:13:30+00:00"

    def test_unknown_offset_falls_back_utc_with_note(self):
        events, meta = ortlog.build_events(_capture(offset=""), asset_hostname="OpenWrt",
                                           asset_id=1, sensor_id="s1")
        assert meta["timezone_offset_seconds"] is None
        assert events[0]["timestamp"].endswith("+00:00")  # 按 UTC 处理，不虚构偏移
        assert "不可追溯" in meta["timezone_basis"]

    def test_parse_offset_formats(self):
        assert ortlog.parse_offset("+0530") == 5 * 3600 + 30 * 60
        assert ortlog.parse_offset("-0800") == -8 * 3600
        assert ortlog.parse_offset("") is None
        assert ortlog.parse_offset("garbage") is None


class TestSkipSemantics:
    def test_year_missing_skipped_and_counted(self):
        events, meta = ortlog.build_events(
            _capture(extra_lines=(YEAR_MISSING_LINE,)), asset_hostname="OpenWrt",
            asset_id=1, sensor_id="s1")
        assert meta["events_built"] == 3
        assert meta["year_missing_lines"] == 1
        assert any("auth.err" in sample for sample in meta["skipped_samples"])

    def test_unparseable_skipped_and_counted(self):
        events, meta = ortlog.build_events(
            _capture(extra_lines=(UNPARSEABLE_LINE,)), asset_hostname="OpenWrt",
            asset_id=1, sensor_id="s1")
        assert meta["unparseable_lines"] == 1
        assert meta["events_built"] == 3

    def test_skipped_lines_never_become_events(self):
        events, meta = ortlog.build_events(
            _capture(extra_lines=(YEAR_MISSING_LINE, UNPARSEABLE_LINE)),
            asset_hostname="OpenWrt", asset_id=1, sensor_id="s1")
        # 防御行绝无可能进事件：逐行比对（跳过行只出现在计数与样本里）
        assert all(event["raw"]["line"] != YEAR_MISSING_LINE for event in events)
        assert all(event["raw"]["line"] != UNPARSEABLE_LINE for event in events)


class TestEventShape:
    def test_source_and_fields(self):
        events, _ = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                        asset_id=7, sensor_id="openwrt-logread-1")
        dropbear = events[1]
        assert dropbear["source"] == "openwrt_logread"
        assert dropbear["event_type"] == "syslog"
        assert dropbear["process_name"] == "dropbear"
        assert dropbear["process_id"] == 1234
        assert dropbear["severity"] == "error"  # auth.err → error（映射后）
        assert dropbear["rule"] == "auth.err"
        assert dropbear["boot_id"] == "abbc3748-54a5-4d36-bbb2-8fc2bcb5d19c"
        assert dropbear["asset_id"] == 7
        assert dropbear["raw"]["facility"] == "auth"
        assert dropbear["raw"]["hostname"] == "OpenWrt"  # 设备锚点进 raw
        assert dropbear["raw"]["transport"] == "logread_remote_pull"
        # 指纹稳定性根基：raw 里的时间为原始本地文本（跨采集不变）
        assert dropbear["raw"]["timestamp"] == "Oct 15 02:21:57 2026"

    def test_kernel_line_without_pid(self):
        events, _ = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                        asset_id=1, sensor_id="s1")
        kernel = events[0]
        assert kernel["process_name"] == "kernel"
        assert kernel["process_id"] == 0  # 无 pid 如实为 0，不虚构
        assert kernel["severity"] == "debug"

    def test_level_mapping(self):
        assert ortlog.LEVEL_NORMALIZE == {"warn": "warning", "err": "error",
                                          "crit": "critical", "emerg": "emergency"}


# ── 观察模式与心跳源（绝不伪装 eBPF） ─────────────────────────────────────────


class TestObservationModeAndHeartbeat:
    def test_logread_is_syslog_never_ebpf(self):
        assert _observation_mode("openwrt_logread") == "syslog"
        assert _observation_mode("logread") == "syslog"
        assert _observation_mode("syslog_local") == "syslog"
        assert _observation_mode("openwrt_logread") != "ebpf"

    def test_existing_modes_unchanged(self):
        assert _observation_mode("demo") == "simulation"
        assert _observation_mode("tetragon") == "ebpf"
        assert _observation_mode("bpftrace") == "ebpf"
        assert _observation_mode("falco") == "sensor"
        assert _observation_mode("runtime_probe_wget") == "probe"
        assert _observation_mode("something_else") == "runtime"

    def test_sensor_heartbeat_accepts_logread(self):
        from app.routers.runtime import SensorHeartbeat
        payload = SensorHeartbeat(asset_id=1, sensor_id="openwrt-logread-1",
                                  source="logread", status="stopped")
        assert payload.source == "logread"


# ── P0 管线接入：幂等 / 绑定 / 证据 / 重启身份 ────────────────────────────────


@pytest.fixture()
def db(session_factory):
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def openwrt_asset(session_factory):
    from app import models

    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="OpenWrt", ip_address="198.51.100.1", os_name="OpenWrt",
                                  os_version="25.12.5", distribution="openwrt", device_type="iot_gateway",
                                  identity_source="test", identity_confidence=0.9)
        db.add(asset)
        db.commit()
        yield asset
    finally:
        db.close()


class TestPipelineIntegration:
    def test_collect_twice_idempotent(self, db, openwrt_asset):
        events, meta = ortlog.build_events(_capture(), asset_hostname=openwrt_asset.hostname,
                                           asset_id=openwrt_asset.id, sensor_id="openwrt-logread-1")
        first = append_events(events, db=db)
        second = append_events(events, db=db)
        assert sum(1 for e in first if not e.get("duplicate")) == 3
        assert sum(1 for e in first if e.get("duplicate")) == 0
        assert sum(1 for e in second if e.get("duplicate")) == 3  # 全部幂等命中
        assert sum(1 for e in second if not e.get("duplicate")) == 0
        rows = load_runtime_events(db=db, limit=100)
        assert len(rows) == 3
        assert all(row["source"] == "openwrt_logread" for row in rows)
        assert all(row["asset_id"] == openwrt_asset.id for row in rows)  # 资产绑定

    def test_evidence_generated_and_attributed(self, db, openwrt_asset):
        from app import models

        events, _ = ortlog.build_events(_capture(), asset_hostname=openwrt_asset.hostname,
                                        asset_id=openwrt_asset.id, sensor_id="openwrt-logread-1")
        append_events(events, db=db)
        evidences = db.query(models.SecurityEvidence).filter_by(
            asset_id=openwrt_asset.id).all()
        assert len(evidences) == 3  # RuntimeEvent 与 SecurityEvidence 一一对应
        assert all(ev.device_id == "OpenWrt" for ev in evidences)

    def test_reboot_changes_identity(self, db, openwrt_asset):
        """boot_id 参与指纹：同一行日志跨重启是两条独立事件（ring 重置不误合并）。"""
        from app.ebpf_identity import stable_event_fingerprint

        events_a, _ = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                          asset_id=openwrt_asset.id, sensor_id="s1")
        rebooted = ortlog.parse_capture_output(SAMPLE_OUTPUT.replace(
            "abbc3748-54a5-4d36-bbb2-8fc2bcb5d19c", "11111111-2222-3333-4444-555555555555"))
        events_b, _ = ortlog.build_events(rebooted, asset_hostname="OpenWrt",
                                          asset_id=openwrt_asset.id, sensor_id="s1")
        fp_a = {stable_event_fingerprint(e["raw"], hostname_hint="OpenWrt") for e in events_a}
        fp_b = {stable_event_fingerprint(e["raw"], hostname_hint="OpenWrt") for e in events_b}
        assert fp_a and fp_b and not (fp_a & fp_b)  # 跨重启身份完全区分

    def test_window_metadata_reports_boundaries(self):
        events, meta = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                           asset_id=1, sensor_id="s1")
        assert meta["window_first"] == "2026-10-15T00:13:30+00:00"
        assert meta["window_last"] == "2026-10-15T02:22:01+00:00"
        assert "unavailable" in meta["ring_loss_semantics"]  # ring 覆盖丢失不可知


# ── 智能体数据质量与统一 Trace ────────────────────────────────────────────────


class TestAgentDataQuality:
    def test_gap_when_openwrt_asset_has_no_logread(self, db, openwrt_asset):
        from app.services.agent_tools import tool_query_runtime_data_quality

        result = tool_query_runtime_data_quality(db, "OpenWrt")
        assert result["found"] is True
        assert any("logread 运行时日志采集记录" in gap for gap in result["data_gaps"])

    def test_sensor_recorded_and_gap_declares_degraded_basis(self, db, openwrt_asset):
        from app.services.agent_tools import tool_query_runtime_data_quality

        events, meta = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                           asset_id=openwrt_asset.id, sensor_id="openwrt-logread-1")
        append_events(events, db=db)
        ortlog._record_sensor(db, asset_id=openwrt_asset.id,
                              sensor_id="openwrt-logread-1", meta=meta,
                              stored_new=3, duplicates=0)
        result = tool_query_runtime_data_quality(db, "OpenWrt")
        sensors = result["coverage"]["sensors"]
        assert any(s["source"] == "logread" for s in sensors)
        logread_sensor = next(s for s in sensors if s["source"] == "logread")
        assert logread_sensor["dropped_events"] is None  # 原始层 None（coverage 原样传递）
        assert result["dropped_events"]["openwrt-logread-1"] == "unavailable"  # 汇总层 unavailable
        assert any("拉取式降级采集" in gap and "非 eBPF" in gap for gap in result["data_gaps"])

    def test_coverage_endpoint_sees_sensor(self, db, openwrt_asset):
        from app.services.runtime_telemetry import coverage

        events, meta = ortlog.build_events(_capture(), asset_hostname="OpenWrt",
                                           asset_id=openwrt_asset.id, sensor_id="openwrt-logread-1")
        ortlog._record_sensor(db, asset_id=openwrt_asset.id,
                              sensor_id="openwrt-logread-1", meta=meta,
                              stored_new=3, duplicates=0)
        view = coverage(db, openwrt_asset.id)
        assert any(s["source"] == "logread" for s in view["sensors"])
        sensor = next(s for s in view["sensors"] if s["source"] == "logread")
        assert sensor["dropped_events"] is None  # None→unavailable 语义（coverage 原样传递）


class TestTraceRegistration:
    def test_task_type_registered_and_trace_runs(self, db, openwrt_asset):
        from app.services import trace_service as tracing

        assert "runtime_log_collection" in tracing.TASK_TYPES
        trace = tracing.start_trace(db, task_type="runtime_log_collection",
                                    target_type="linux_asset", target_ref=str(openwrt_asset.id))
        tracing.emit(db, trace.trace_id, "logread_collected", actor="collector",
                     status="completed", payload={"stored_new": 3})
        tracing.finish_trace(db, trace.trace_id, "completed", summary={"stored_new": 3})
        from app import models
        rows = db.query(models.TraceRun).filter_by(trace_id=trace.trace_id).all()
        assert rows[0].status == "completed"
        events = db.query(models.TraceEvent).filter_by(trace_id=trace.trace_id).all()
        assert {e.event_type for e in events} == {"task_started", "logread_collected", "task_finished"}
