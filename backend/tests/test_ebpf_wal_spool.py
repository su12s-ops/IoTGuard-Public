"""eBPF 2.0 最终交付轮：Write-Ahead Spool + 有界 spool 专项测试。

覆盖任务书"端到端可靠性升级"验收点：
- 写前持久化不变量（发送前事件必已落 WAL）；
- SIGKILL 真实恢复（子进程硬杀 + 重启续传 + 服务端幂等去重对账）；
- 确认后移除 / 崩溃窗口重放去重（at-least-once + 服务端幂等 = 恰一次入库）；
- P0 旧 spool 格式兼容迁移；有界容量/磁盘保护背压（明确降级，不静默丢弃、
  不删除未确认数据）；告警阈值；指标与心跳呈现。
"""
import importlib.util
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "runtime_forwarder", Path(__file__).resolve().parents[2] / "collector" / "ebpf_event_collector.py")
forwarder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarder)


def _event(pid: int) -> dict:
    return {"timestamp": "2026-01-01T00:00:00Z", "hostname": "wal-host", "source": "falco",
            "event_type": "process", "process_name": "proc", "process_id": pid}


def test_write_ahead_persisted_before_send(tmp_path, monkeypatch):
    """不变量：post_batch 被调用时，事件必已持久化到 WAL 文件。"""
    spool = tmp_path / "wal.jsonl"
    infile = tmp_path / "in.jsonl"
    infile.write_text(chr(10).join(json.dumps(_event(n)) for n in range(5)) + chr(10), encoding="utf-8")

    def guarded_post_batch(api, events, token):
        on_disk = [json.loads(line) for line in spool.read_text(encoding="utf-8").splitlines() if line.strip()]
        on_disk_ids = {e["process_id"] for e in on_disk}
        for event in events:
            assert event["process_id"] in on_disk_ids, "发送前事件必须已在 WAL 中（write-ahead 不变量）"
        return {"ack": True, "received": len(events), "accepted": len(events),
                "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(infile), "--wal-fsync", "off",
                                      "--spool-file", str(spool)])
    monkeypatch.setattr(forwarder, "post_batch", guarded_post_batch)
    assert forwarder.main() == 0
    assert not spool.read_text(encoding="utf-8").strip(), "全部确认后 WAL 收缩为空"


def test_sigkill_recovery_replays_and_dedupes(tmp_path):
    """真实 SIGKILL：硬杀正在运行的转发器进程，重启后未确认事件全部续传。

    服务端存根按 process_id 幂等去重（模拟后端指纹判重）；对账：唯一事件
    恰为喂入的 20 条，重复计数 = 崩溃窗口重放（如实呈现，不重复入库语义）。
    """
    spool = tmp_path / "wal-kill.jsonl"
    events = [_event(pid=1000 + n) for n in range(20)]

    seen: list[int] = []
    seen_lock = threading.Lock()
    state = {"down": True}

    class Stub(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if state["down"]:
                self.send_response(503)
                self.end_headers()
                return
            batch = body.get("events", [])
            fresh = 0
            duplicates = 0
            with seen_lock:
                for event in batch:
                    if event["process_id"] in seen:
                        duplicates += 1
                    else:
                        seen.append(event["process_id"])
                        fresh += 1
            payload = json.dumps({"ack": True, "received": len(batch), "accepted": fresh,
                                  "duplicates": duplicates, "rejected": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # 静默存根日志
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        api = f"http://127.0.0.1:{server.server_address[1]}/api"
        base_cmd = [sys.executable, str(Path(__file__).resolve().parents[2] / "collector" / "ebpf_event_collector.py"),
                    "--api", api, "--spool-file", str(spool), "--batch-size", "5",
                    "--flush-seconds", "0.2", "--max-retries", "0", "--wal-fsync", "off"]

        # 进程 1：活流模式（不关 stdin 保持存活），喂 20 条，服务端 down → 全部滞留 WAL
        proc1 = __import__("subprocess").Popen(base_cmd, stdin=__import__("subprocess").PIPE,
                                               stdout=__import__("subprocess").DEVNULL,
                                               stderr=__import__("subprocess").DEVNULL, text=True)
        try:
            for event in events:
                proc1.stdin.write(json.dumps(event) + "\n")
            proc1.stdin.flush()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not spool.exists():
                time.sleep(0.05)
            lines = 0
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                lines = len([l for l in spool.read_text(encoding="utf-8").splitlines() if l.strip()]) \
                    if spool.exists() else 0
                if lines >= 20:
                    break
                time.sleep(0.05)
            time.sleep(0.8)  # 让写前持久化稳定覆盖全部事件
            proc1.kill()  # SIGKILL 等价（Windows TerminateProcess）：无清理机会
        finally:
            proc1.stdin.close()
            proc1.wait(timeout=30)
        assert lines >= 20, f"硬杀前 WAL 应已持久化全部事件，实际 {lines}"

        # 进程 2：服务端恢复 → 重启续传
        state["down"] = False
        proc2 = __import__("subprocess").Popen(base_cmd, stdin=__import__("subprocess").PIPE,
                                               stdout=__import__("subprocess").PIPE,
                                               stderr=__import__("subprocess").PIPE, text=True)
        # communicate owns EOF/flush; pre-closing stdin fails on POSIX.
        out, err = proc2.communicate(input="", timeout=120)
        assert proc2.returncode == 0, f"恢复运行应成功退出：{out} / {err}"
        with seen_lock:
            assert sorted(set(seen)) == [1000 + n for n in range(20)], \
                f"对账失败：唯一入库 {sorted(set(seen))}"
    finally:
        server.shutdown()
        server.server_close()


def test_ack_removed_and_second_run_replays_nothing(tmp_path, monkeypatch):
    """确认后移除：全部确认 → 重启重放零条（不重复发送已确认数据）。"""
    spool = tmp_path / "wal.jsonl"
    infile = tmp_path / "in.jsonl"
    infile.write_text(chr(10).join(json.dumps(_event(n)) for n in range(4)) + chr(10), encoding="utf-8")
    calls = {"n": 0}

    def acking(api, events, token):
        calls["n"] += 1
        return {"ack": True, "received": len(events), "accepted": len(events),
                "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(infile), "--wal-fsync", "off",
                                      "--spool-file", str(spool)])
    monkeypatch.setattr(forwarder, "post_batch", acking)
    assert forwarder.main() == 0
    first = calls["n"]

    infile.write_text("", encoding="utf-8")  # 第二次运行无新事件
    assert forwarder.main() == 0
    assert calls["n"] == first, "已确认事件不得重放（WAL 已移除）"


def test_p0_legacy_spool_file_migrates(tmp_path, monkeypatch):
    """P0 旧 spool（每行 JSON 数组）兼容载入；确认收缩后迁移为纯 v2 格式。"""
    spool = tmp_path / "wal-legacy.jsonl"
    legacy_events = [_event(pid=1), _event(pid=2)]
    spool.write_text(json.dumps(legacy_events) + "\n" + json.dumps([_event(pid=3)]) + "\n",
                     encoding="utf-8")
    collected = []

    def acking(api, events, token):
        collected.extend(events)
        return {"ack": True, "received": len(events), "accepted": len(events),
                "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(tmp_path / "empty.jsonl"),
                                      "--wal-fsync", "off", "--spool-file", str(spool)])
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    monkeypatch.setattr(forwarder, "post_batch", acking)
    assert forwarder.main() == 0
    assert sorted(e["process_id"] for e in collected) == [1, 2, 3]
    assert not spool.read_text(encoding="utf-8").strip(), "全部确认后旧格式文件收缩为空（迁移完成）"


def test_capacity_backpressure_delays_but_never_drops(tmp_path, monkeypatch):
    """有界容量：满则背压暂存；容量释放后全部送达——零丢失、零删除。"""
    spool = tmp_path / "wal.jsonl"
    infile = tmp_path / "in.jsonl"
    infile.write_text(chr(10).join(json.dumps(_event(n)) for n in range(5)) + chr(10), encoding="utf-8")
    state = {"fail_left": 1}
    delivered = []

    def flaky(api, events, token):
        if state["fail_left"] > 0:
            state["fail_left"] -= 1
            raise OSError("fixture offline")
        delivered.extend(events)
        return {"ack": True, "received": len(events), "accepted": len(events),
                "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(infile), "--wal-fsync", "off",
                                      "--spool-file", str(spool), "--batch-size", "1",
                                      "--max-retries", "0", "--spool-max-events", "3"])
    monkeypatch.setattr(forwarder, "post_batch", flaky)
    rc = forwarder.main()
    # 5 条全部送达（首批发送失败事件也在其中——容量释放后按 FIFO 逐一续传）
    assert sorted(e["process_id"] for e in delivered) == [0, 1, 2, 3, 4], \
        f"背压不得丢事件：实际送达 {sorted(e['process_id'] for e in delivered)}"
    assert not spool.read_text(encoding="utf-8").strip()
    assert rc == 1, "本轮存在未确认周期 → 非零退出码（契约保持）"


def test_eof_backpressure_reports_explicitly_never_silent(tmp_path, monkeypatch, capsys):
    """EOF 时仍无容量：暂存事件无法持久化 → CRITICAL 显式报告（非静默）。"""
    spool = tmp_path / "wal.jsonl"
    infile = tmp_path / "in.jsonl"
    infile.write_text(chr(10).join(json.dumps(_event(n)) for n in range(5)) + chr(10), encoding="utf-8")

    def always_fail(api, events, token):
        raise OSError("fixture offline")

    monkeypatch.setattr(sys, "argv", ["collector", "--file", str(infile), "--wal-fsync", "off",
                                      "--spool-file", str(spool), "--batch-size", "1",
                                      "--max-retries", "0", "--spool-max-events", "3"])
    monkeypatch.setattr(forwarder, "post_batch", always_fail)
    rc = forwarder.main()
    assert rc == 1
    err = capsys.readouterr().err
    assert "CRITICAL" in err and "NOT delivered" in err, "未持久化事件必须显式报告，禁止静默丢弃"
    on_disk = [line for line in spool.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(on_disk) == 3, "WAL 有界：恰好容量上限 3 条，其余如实报告"


def test_disk_free_guard_blocks_then_recovers(tmp_path, monkeypatch):
    """磁盘剩余空间保护：低于下限拒绝写入（背压），恢复后可写入。"""
    spool = tmp_path / "wal.jsonl"
    wal = forwarder.WalSpool(str(spool), min_free_bytes=1_000_000, fsync_mode="off")
    real_usage = __import__("shutil").disk_usage

    def low_disk(path):
        usage = real_usage(path)
        return SimpleNamespace(free=100, total=usage.total, used=usage.used)

    monkeypatch.setattr(forwarder.shutil, "disk_usage", low_disk)
    assert wal.append(_event(1)) is False, "磁盘低于下限必须触发保护"
    assert wal.full and wal.blocked_events == 1
    monkeypatch.setattr(forwarder.shutil, "disk_usage", real_usage)
    assert wal.append(_event(1)) is True, "空间恢复后背压解除"
    assert wal.full is False and wal.blocked_events == 1  # 计数保留（发生过即如实）


def test_backlog_warning_threshold(tmp_path):
    wal = forwarder.WalSpool(str(tmp_path / "wal.jsonl"), max_events=10, fsync_mode="off")
    for n in range(7):
        assert wal.append(_event(n)) is True
    assert wal.backlog_warn() == ""  # 7/10 < 80%
    assert wal.append(_event(7)) is True  # 8/10 = 80%
    assert wal.backlog_warn() == "spool backlog warning"
    assert wal.full is False, "告警阈值不等于保护触发（仍可写入）"


def test_compact_never_drops_unconfirmed(tmp_path):
    """收缩不变量：只移除已确认行；未确认数据在任何时刻重载均完整。"""
    spool = tmp_path / "wal.jsonl"
    wal = forwarder.WalSpool(str(spool), fsync_mode="off")
    for pid in (1, 2, 3):
        assert wal.append(_event(pid)) is True
    wal.ack(1)
    wal.compact(force=True)
    assert wal.pending_count() == 2
    on_disk = [json.loads(line)["process_id"] for line in spool.read_text(encoding="utf-8").splitlines()]
    assert on_disk == [2, 3], "收缩只移除已确认行"
    reloaded = forwarder.WalSpool(str(spool), fsync_mode="off")
    assert [obj["process_id"] for _l, obj in reloaded.take(10)] == [2, 3], "崩溃/重载后未确认数据完整"


def test_corrupt_lines_counted_not_silent(tmp_path, capsys):
    spool = tmp_path / "wal.jsonl"
    spool.write_text(json.dumps(_event(1)) + "\n" + "NOT-JSON{{{" + "\n", encoding="utf-8")
    wal = forwarder.WalSpool(str(spool), fsync_mode="off")
    assert wal.pending_count() == 1 and wal.corrupt_lines == 1
    err = capsys.readouterr().err  # main() 打印；类层面仅计数
    metrics = forwarder.ReliabilityMetrics()
    metrics.spool_corrupt_lines = wal.corrupt_lines
    assert metrics.snapshot()["spool_corrupt_lines"] == 1


def test_metrics_and_heartbeat_present_wal_state():
    metrics = forwarder.ReliabilityMetrics()
    metrics.spool_bytes = 1234
    metrics.spool_blocked_events = 2
    metrics.spool_corrupt_lines = 1
    metrics.spool_full = True
    snapshot = metrics.snapshot()
    for key in ("spool_bytes", "spool_blocked_events", "spool_corrupt_lines"):
        assert key in snapshot
    args = SimpleNamespace(health_file=None, asset_id=2, sensor_id="fixture", source="falco",
                           legacy_single=False)
    beat = forwarder.heartbeat_payload(args, rejected=0, metrics=metrics)
    assert beat["status"] == "degraded", "spool_full 触发 → 心跳 degraded"
    assert beat["capabilities"]["spool_full"] is True


def test_argument_validation_bounds(tmp_path, monkeypatch):
    for bad in (["--spool-max-events", "-1"], ["--spool-max-bytes", str(65 * 1024**3)],
                ["--spool-min-free-mb", "-5"], ["--wal-fsync", "sometimes"]):
        monkeypatch.setattr(sys, "argv", ["collector", "--spool-file", str(tmp_path / "w.jsonl")] + bad)
        with pytest.raises(SystemExit):
            forwarder.main()
