"""eBPF 2.0 P2-1 性能评测专项测试：指标纯函数 + 编排器归因/解析 + 采集源标识。

覆盖任务书"性能评测"验收点的可测内核（真实评测由 backend/scripts/ebpf_p21_perf.py
在各形态上执行，证据落 reports/ebpf-p21-*/，本文件锁定语义正确性）：
- 百分位（最近邻秩）与延迟汇总：无样本 → unavailable（None + 说明），绝不虚构 0；
- 端到端延迟：不可解析时间计入 unparsed_time_count（不进分布、不冒充 0）；
- 丢失对账：expected 未知 → 不给丢失率；三层独立来源不互相虚构；
- CPU 换算与 /proc 采样汇总：字段缺失 → unavailable；
- 负载归因（execve/connect/openat 严格按受控标记，噪声不计入）；
- journal→事件（journal UTC 为时间基准；falco 消息时间仅同时钟基准（≤2s）时细化 μs，
  本地时区消息（实测 +8h）回退 journal 并计数 tz_mismatch；informational→info）；
- bpftrace 成为受支持采集源（心跳 Literal / 转发器 choices / 观察模式归类 ebpf——
  真实内核采集不得误标 runtime）。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.services import ebpf_perf as perf  # noqa: E402
from app.services.ebpf_event_collector import _observation_mode  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "ebpf_p21_perf_orchestrator", ROOT_DIR / "backend" / "scripts" / "ebpf_p21_perf.py")
orchestrator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(orchestrator)

_spec_forwarder = importlib.util.spec_from_file_location(
    "runtime_forwarder_p21", ROOT_DIR / "collector" / "ebpf_event_collector.py")
forwarder = importlib.util.module_from_spec(_spec_forwarder)
_spec_forwarder.loader.exec_module(forwarder)


# ── 百分位与延迟汇总 ─────────────────────────────────────────────────────────


class TestPercentile:
    def test_empty_returns_none_not_zero(self):
        # 无样本 = unavailable（None），绝不能冒充 0
        assert perf.percentile([], 50) is None

    def test_single_sample_all_percentiles(self):
        assert perf.percentile([7.5], 50) == 7.5
        assert perf.percentile([7.5], 99) == 7.5

    def test_nearest_rank_uses_ceil(self):
        # 最近邻秩：rank = ceil(p/100 * n)；n=100 → P50=第 50 小、P95=第 95 小、P99=第 99 小
        values = [float(i) for i in range(1, 101)]
        assert perf.percentile(values, 50) == 50.0
        assert perf.percentile(values, 95) == 95.0
        assert perf.percentile(values, 99) == 99.0

    def test_unsorted_input_is_sorted(self):
        assert perf.percentile([30, 10, 20], 50) == 20.0

    def test_invalid_pct(self):
        assert perf.percentile([1.0], 0) is None
        assert perf.percentile([1.0], 101) is None


class TestLatencyStats:
    def test_empty_all_none_with_note(self):
        stats = perf.latency_stats_ms([])
        assert stats["count"] == 0
        for key in ("p50_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms"):
            assert stats[key] is None
        assert "unavailable" in stats["note"]

    def test_full_stats_shape(self):
        stats = perf.latency_stats_ms([1.0, 2.0, 3.0, 4.0])
        assert stats["count"] == 4
        assert stats["p50_ms"] == 2.0 or stats["p50_ms"] == 3.0  # 最近邻秩 n=4 P50 → 第 2 小
        assert stats["p50_ms"] == perf.percentile([1.0, 2.0, 3.0, 4.0], 50)
        assert stats["max_ms"] == 4.0


# ── 时间解析与端到端延迟 ─────────────────────────────────────────────────────


class TestTimeParsing:
    def test_parse_created_at_naive_assumed_utc(self):
        parsed = perf.parse_created_at("2026-10-15T08:00:00")
        assert parsed is not None and parsed.utcoffset() == timedelta(0)

    def test_parse_created_at_iso_with_z(self):
        assert perf.parse_created_at("2026-10-15T08:00:00Z") is not None

    def test_parse_event_time_epoch_ns_fallback(self):
        # 17+ 位纯数字按 epoch 纳秒兜底
        parsed = perf.parse_event_time("1760000000000000000")
        assert parsed == datetime.fromtimestamp(1760000000, tz=timezone.utc)

    def test_parse_event_time_garbage_is_none(self):
        assert perf.parse_event_time("") is None
        assert perf.parse_event_time(None) is None
        assert perf.parse_event_time("not-a-time") is None


class TestEndToEndLatency:
    def _row(self, occurred: str, created_min_ago: float) -> dict:
        created = datetime.now(timezone.utc) - timedelta(minutes=created_min_ago)
        return {"occurred_at": occurred, "created_at": created.isoformat()}

    def test_normal_latency(self):
        occurred = (datetime.now(timezone.utc) - timedelta(milliseconds=250)).isoformat()
        stats = perf.end_to_end_latency_ms([self._row(occurred, 0)])
        assert stats["count"] == 1
        assert 0 < stats["p50_ms"] < 5000

    def test_unparseable_times_counted_not_zeroed(self):
        rows = [{"occurred_at": "garbage", "created_at": datetime.now(timezone.utc).isoformat()},
                {"occurred_at": "", "created_at": None}]
        stats = perf.end_to_end_latency_ms(rows)
        assert stats["count"] == 0
        assert stats["unparsed_time_count"] == 2
        assert stats["p50_ms"] is None

    def test_clock_skew_clamped_to_zero(self):
        # created_at 略早于事件时间（同机顺序处理/时钟回拨）→ 0，不为负
        future = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()
        stats = perf.end_to_end_latency_ms([{"occurred_at": future,
                                             "created_at": datetime.now(timezone.utc).isoformat()}])
        assert stats["p50_ms"] == 0.0


# ── 吞吐与丢失对账 ───────────────────────────────────────────────────────────


class TestEps:
    def test_none_inputs_are_unavailable(self):
        assert perf.eps(None, 10.0) is None
        assert perf.eps(100, None) is None
        assert perf.eps(100, 0) is None

    def test_simple_rate(self):
        assert perf.eps(300, 60.0) == 5.0


class TestLossReconciliation:
    def test_no_expected_means_no_loss_rate(self):
        # 观察态采集（无受控负载）→ 只呈现捕获/入库数，不给丢失率（不虚构）
        result = perf.loss_reconciliation(expected=None, captured=120, stored=120,
                                          probe_reported_lost=None)
        assert result["loss_rate"] is None
        assert "无受控负载" in result["note"]
        assert result["captured"] == 120

    def test_full_capture_zero_loss_is_real_zero(self):
        result = perf.loss_reconciliation(expected=100, captured=100, stored=100,
                                          probe_reported_lost=0)
        assert result["loss_rate_pre_capture"] == 0.0
        assert result["transport_gap"] == 0
        assert result["probe_reported_lost"] == 0  # 真实为零（探针自报）

    def test_pre_capture_loss(self):
        result = perf.loss_reconciliation(expected=1000, captured=990, stored=990,
                                          probe_reported_lost=8)
        assert result["lost_pre_capture"] == 10
        assert result["loss_rate_pre_capture"] == 0.01
        assert result["probe_reported_lost"] == 8  # 独立来源如实呈现，不与对账数互相覆盖

    def test_transport_gap_only_when_both_known(self):
        result = perf.loss_reconciliation(expected=None, captured=200, stored=180,
                                          probe_reported_lost=None)
        assert result["transport_gap"] == 20
        assert "lost_pre_capture" not in result

    def test_probe_unavailable_is_none_not_zero(self):
        result = perf.loss_reconciliation(expected=100, captured=100, stored=100,
                                          probe_reported_lost=None)
        assert result["probe_reported_lost"] is None  # 未报告 = unavailable，不是 0


# ── CPU 换算与采样汇总 ───────────────────────────────────────────────────────


class TestCpuAndSamples:
    def test_cpu_seconds_none_when_missing(self):
        assert perf.cpu_seconds(None, 5) is None
        assert perf.cpu_seconds(5, None) is None

    def test_cpu_seconds_jiffies(self):
        assert perf.cpu_seconds(100, 100) == 2.0

    def test_summarize_proc_samples_missing_file(self, tmp_path):
        summary = orchestrator._summarize_proc_samples(tmp_path / "nope.txt")
        assert "unavailable" in summary["note"]

    def test_summarize_proc_samples(self, tmp_path):
        path = tmp_path / "samples.txt"
        path.write_text(
            "1760000000000000000 100 100 40960\n1760000001000000000 300 300 81920\n", encoding="utf-8")
        summary = orchestrator._summarize_proc_samples(path)
        assert summary["samples"] == 2
        assert summary["cpu_seconds_total"] == 6.0  # (300+300)/100
        assert summary["rss_kb_peak"] == 81920

    def test_summarize_proc_samples_garbage_only(self, tmp_path):
        path = tmp_path / "samples.txt"
        path.write_text("garbage line\n\n", encoding="utf-8")
        summary = orchestrator._summarize_proc_samples(path)
        assert "unavailable" in summary["note"]


# ── 负载归因（受控对账只认归因事件） ─────────────────────────────────────────


class TestLoadgenAttribution:
    def test_attribution_by_marker(self):
        lines = "\n".join([
            json.dumps({"source": "ebpf_bpftrace", "event_type": "execve",
                        "argv": ["/bin/true", "-lgperf"]}),
            json.dumps({"source": "ebpf_bpftrace", "event_type": "execve",
                        "argv": ["/usr/bin/head", "-1"]}),  # 环境噪声：非负载
            json.dumps({"source": "ebpf_bpftrace", "event_type": "connect",
                        "destination": "127.0.0.1", "port": 18099}),
            json.dumps({"source": "ebpf_bpftrace", "event_type": "connect",
                        "destination": "10.0.0.8", "port": 443}),  # 噪声
            json.dumps({"source": "ebpf_bpftrace", "event_type": "openat",
                        "file_path": "/opt/firmware/.lgperf"}),
            json.dumps({"source": "ebpf_bpftrace", "event_type": "openat",
                        "file_path": "/etc/passwd"}),  # passwd 单独计数（噪声可混入）
        ])
        result = orchestrator.loadgen_attribution(lines, 18099)
        assert result["execve_attributed"] == 1
        assert result["connect_attributed"] == 1
        assert result["openat_firmware_attributed"] == 1
        assert result["openat_passwd_seen"] == 1
        assert result["total_events"] == 6

    def test_attribution_skips_bad_lines(self):
        result = orchestrator.loadgen_attribution("not json\n\n", 18099)
        assert result["total_events"] == 0
        assert result["execve_attributed"] == 0


# ── journal → 事件（VM falco 拉取路径） ──────────────────────────────────────


def _journal_entry(message: str, realtime_us: int) -> str:
    return json.dumps({"MESSAGE": message, "__REALTIME_TIMESTAMP": str(realtime_us),
                       "_BOOT_ID": "b011", "_SYSTEMD_UNIT": "falco-modern-bpf.service",
                       "__CURSOR": "c1"})


class TestJournalToEvents:
    def test_message_time_within_window_takes_precedence(self, tmp_path):
        # 消息时间与 journal 时间同时钟基准（≤2s）→ 用消息内核时间细化到 μs
        base = datetime(2026, 10, 15, 12, 0, 5, tzinfo=timezone.utc).timestamp()
        entry = _journal_entry("12:00:04.998500000: Warning LG-IoT process exec: user=u", int(base * 1e6))
        path = tmp_path / "j.jsonl"
        path.write_text(entry + "\n", encoding="utf-8")
        events, meta = orchestrator.journal_to_events(path, device="vm-host")
        assert meta["journal_entries"] == 1
        assert meta["message_time_refined"] == 1
        assert events[0]["timestamp"].startswith("2026-10-15T12:00:04.9985")
        assert events[0]["severity"] == "warning"
        assert events[0]["source"] == "falco_journal"  # 如实标注拉取路径，不伪装 eBPF 直采

    def test_local_timezone_message_falls_back_to_journal_utc(self, tmp_path):
        # 真实数据实测（2026-10-15）：falco 消息时间为 VM 本地时区（UTC+8），
        # journal 01:36:56 vs 消息 09:36:56——直接拼接会造出未来 8h 的
        # occurred_at，端到端延迟被钳位成伪 0。必须回退 journal UTC 并计数。
        base = datetime(2026, 10, 15, 1, 36, 56, tzinfo=timezone.utc).timestamp()
        entry = _journal_entry("09:36:56.000452617: Notice LG-IoT watched file read", int(base * 1e6))
        path = tmp_path / "j.jsonl"
        path.write_text(entry + "\n", encoding="utf-8")
        events, meta = orchestrator.journal_to_events(path, device="vm-host")
        assert meta["tz_mismatch_fallback"] == 1
        assert meta["message_time_refined"] == 0
        assert events[0]["timestamp"].startswith("2026-10-15T01:36:56")  # journal UTC 基准

    def test_informational_maps_to_info(self, tmp_path):
        base = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        entry = _journal_entry("12:00:00.100: Informational LG-IoT local connect", int(base * 1e6))
        path = tmp_path / "j.jsonl"
        path.write_text(entry + "\n", encoding="utf-8")
        events, _ = orchestrator.journal_to_events(path, device="vm-host")
        assert events[0]["severity"] == "info"

    def test_fallback_to_journal_time_and_lg_count(self, tmp_path):
        base = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        entries = [
            _journal_entry("Falco initialized. version 0.44.1", int(base * 1e6)),  # 非 LG 消息
            _journal_entry("12:00:01.000: Informational LG-IoT watched file read", int((base + 1) * 1e6)),
            "not json",  # 坏行跳过
        ]
        path = tmp_path / "j.jsonl"
        path.write_text("\n".join(entries) + "\n", encoding="utf-8")
        events, meta = orchestrator.journal_to_events(path, device="vm-host")
        assert meta["journal_entries"] == 2
        assert meta["lg_events"] == 1
        # 无消息时间结构 → 退回 journal 写入时间（不虚构）
        assert events[0]["timestamp"].startswith("2026-10-15T12:00:00")

    def test_identity_fields_carried(self, tmp_path):
        base = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        path = tmp_path / "j.jsonl"
        path.write_text(_journal_entry("12:00:00: Notice x", int(base * 1e6)) + "\n", encoding="utf-8")
        events, _ = orchestrator.journal_to_events(path, device="vm-host")
        assert events[0]["hostname"] == "vm-host"
        assert events[0]["boot_id"] == "b011"
        assert events[0]["raw"]["journal_cursor"] == "c1"


# ── bpftrace 采集源标识（P2-1 新增） ──────────────────────────────────────────


class TestBpftraceSourceIdentity:
    def test_observation_mode_bpftrace_is_ebpf(self):
        # 真实内核采集（collector/ebpf_trace_capture.sh）不得误标 runtime
        assert _observation_mode("ebpf_bpftrace") == "ebpf"
        assert _observation_mode("bpftrace") == "ebpf"

    def test_observation_mode_existing_sources_unchanged(self):
        assert _observation_mode("demo") == "simulation"
        assert _observation_mode("tetragon") == "ebpf"
        assert _observation_mode("falco") == "sensor"
        assert _observation_mode("runtime_probe_wget") == "probe"
        assert _observation_mode("something_else") == "runtime"

    def test_sensor_heartbeat_accepts_bpftrace(self):
        from app.routers.runtime import SensorHeartbeat
        payload = SensorHeartbeat(asset_id=1, sensor_id="perf-wsl-bpftrace", source="bpftrace",
                                  status="running", dropped_events=0)
        assert payload.source == "bpftrace"

    def test_forwarder_source_choices_include_bpftrace(self):
        # 从转发器源码取 --source choices（与 main() 实际注册一致）
        import re as _re
        src = (ROOT_DIR / "collector" / "ebpf_event_collector.py").read_text(encoding="utf-8")
        match = _re.search(r'--source", choices=\[([^\]]+)\]', src)
        assert match, "forwarder --source choices not found"
        choices = [c.strip().strip('"') for c in match.group(1).split(",")]
        assert "bpftrace" in choices
        assert set(choices) <= {"falco", "tetragon", "bpftrace", "runtime_probe"}


# ── 幂等判重索引（P2-1 实测缺陷的回归锁定） ──────────────────────────────────


class TestFingerprintDedupIndex:
    def test_dedup_query_uses_index(self):
        # P2-1 实测：P0 部分唯一索引不被判重查询命中（SCAN 全表，吞吐随表
        # 规模线性劣化）→ 补建全量索引 ix_runtime_event_event_fingerprint。
        # 本测试用 EXPLAIN QUERY PLAN 锁定判重路径必须走索引。
        from sqlalchemy import text
        from app.database import engine, init_db
        init_db()  # 幂等；同时实测旧库补建路径（表已存在 → 走 CREATE INDEX IF NOT EXISTS）
        with engine.connect() as conn:
            plan = conn.execute(text(
                "EXPLAIN QUERY PLAN SELECT id FROM runtime_event WHERE event_fingerprint = :fp"),
                {"fp": "x" * 64}).fetchall()
        detail = " ".join(str(row) for row in plan).lower()
        assert "scan runtime_event" not in detail
        assert "using covering index ix_runtime_event_event_fingerprint" in detail

    def test_full_index_exists_besides_partial_unique(self):
        # 部分唯一索引（并发防线）保留；全量索引（判重路径）并存
        from sqlalchemy import text
        from app.database import engine, init_db
        init_db()
        with engine.connect() as conn:
            names = [row[0] for row in conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='runtime_event'"))]
        assert "ix_runtime_event_event_fingerprint" in names


# ── summarize_run 结构 ───────────────────────────────────────────────────────


class TestSummarizeRun:
    def test_eps_derived_and_none_propagates(self):
        summary = perf.summarize_run(
            "x", window_seconds=10.0, captured=200, stored_new=200, stored_duplicates=0,
            forwarder_metrics={}, latency={}, loss={}, resources={},
            environment={})
        assert summary["capture_eps"] == 20.0
        assert summary["ingest_eps"] == 20.0

    def test_unmeasured_stays_none(self):
        summary = perf.summarize_run(
            "x", window_seconds=None, captured=None, stored_new=None, stored_duplicates=None,
            forwarder_metrics=None, latency=None, loss=None, resources=None, environment={})
        assert summary["capture_eps"] is None
        assert summary["ingest_eps"] is None
