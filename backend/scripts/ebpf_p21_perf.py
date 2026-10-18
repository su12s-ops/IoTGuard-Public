#!/usr/bin/env python3
"""eBPF 2.0 P2-1 性能评测编排器（独立进程，不起 pytest）。

四种测试形态严格区分，绝不混称：
  synthetic      模拟负载 —— 编排器内直接生成结构化事件 POST 批量端点，
                 只测后端摄取路径（无内核、无转发器）；
  replay         离线回放 —— 真实采集夹具（阶段二 WSL 真实内核事件）以限速
                 stdin 流经生产转发器 ebpf_event_collector.py（无内核，测
                 转发器 + WAL spool + 重试 + 服务端幂等全链，含断网中断）；
  real-wsl       真实内核采集 —— WSL2 Ubuntu bpftrace 探针 + 受控真实负载
                 （execve/connect/openat 真实 syscall）+ WSL 侧转发器 → 后端；
  real-vm-falco  真实内核采集 —— Ubuntu VM 常驻 falco-modern-bpf（LG-IoT 规则）
                 + VM 上受控真实负载 + journalctl 只读拉取 → 后端（拉取式）；
  bounded-spool  有界 spool 保护（确定性小场景：后端不可达 + 容量触界）。

每一形态产出一组指标（EPS / 端到端延迟 P50/P95/P99 / CPU 与内存 / 丢失对账 /
spool 行为），原始数据与汇总全部落盘 reports/ebpf-p21-<ts>/。
语义约定：数值 0=真实为零；无法测得=unavailable（绝不写 0%）。

用法（在仓库根目录）：
  python backend/scripts/ebpf_p21_perf.py --mode synthetic [--duration 60]
  python backend/scripts/ebpf_p21_perf.py --mode replay [--duration 90] [--interrupt-after 25] [--interrupt-seconds 20]
  python backend/scripts/ebpf_p21_perf.py --mode real-wsl [--duration 120] [--target-eps 240]
  python backend/scripts/ebpf_p21_perf.py --mode real-vm-falco [--duration 120] [--target-eps 120]
  python backend/scripts/ebpf_p21_perf.py --mode bounded-spool
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app.services import ebpf_perf as perf  # noqa: E402

REPORTS_DIR = ROOT / "reports"
COLLECTOR_DIR = ROOT / "collector"
FIXTURE = ROOT / "backend" / "tests" / "fixtures" / "ebpf_real_capture.jsonl"
# WSL 侧仓库路径（perf 专用；可用 LINUXGUARD_PERF_WSL_ROOT 覆盖）
WSL_COLLECTOR = os.getenv("LINUXGUARD_PERF_WSL_ROOT", "/mnt/e/IoTGuard-Public/collector")
# ── 实验室 VM 连接参数：仅经环境变量提供（仓库惯例：私网地址/用户名/密钥
#    不写入跟踪文件，本地实际值仅存 reports/ 证据目录，不入库） ──
VM_SSH_HOST = os.getenv("LINUXGUARD_PERF_VM_HOST", "")
VM_SSH_USER = os.getenv("LINUXGUARD_PERF_VM_USER", "")
VM_SSH_KEY = Path(os.getenv("LINUXGUARD_PERF_VM_KEY",
                            str(Path(os.getenv("USERPROFILE", "")) / ".ssh" / "id_ed25519_vms")))
VM_BACKEND_BASE_TEMPLATE = os.getenv("LINUXGUARD_PERF_VM_API", "")  # 形如 http://<主机侧地址>:{port}/api

HOST_ENV = {
    "os": "Windows 11 Home 10.0.26300",
    "cpu": "Intel Core Ultra 5 125H（18 逻辑核）",
    "ram_gb": 31.5,
    "backend_python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    "backend_stack": "FastAPI + SQLite（单进程 uvicorn）",
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sh(cmd: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=False, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def wsl(cmd: str, *, timeout: int = 300) -> subprocess.CompletedProcess:
    return sh(["wsl", "-u", "root", "-e", "bash", "-c", cmd], timeout=timeout)


def _strip_wsl_banner(text: str) -> str:
    """剔除 wsl.exe 启动告警（管道下以 UTF-16LE 写出，混入 NUL 字节），保留真实输出行。"""
    return "\n".join(line for line in text.splitlines() if "\x00" not in line)


def write_wsl_script(path: Path, body: str) -> None:
    """把采集侧 shell 写成脚本文件（LF 行尾）；WSL 侧以 bash <wsl路径> 执行。

    首次真实执行暴露的缺陷：内联 wsl bash -c '...' 形式里 '\\' 转义写在
    双引号上下文中（bash EOF 报错、采集未启动）。脚本文件形式不经
    Windows argv 传递，引号语义完全由本仓库控制；WSL 侧路径由调用方
    以 /mnt/<盘符>/... 形式引用。
    """
    path.write_text(body, encoding="utf-8", newline="\n")


def ssh_vm(command: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return sh(["ssh", "-i", str(VM_SSH_KEY), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
               f"{VM_SSH_USER}@{VM_SSH_HOST}", command], timeout=timeout)


# ── 后端生命周期（一次性 perf 库，不触碰 linuxguard.db） ─────────────────────


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class PerfBackend:
    """独立 uvicorn + 一次性 SQLite：与开发库完全隔离（验收后整目录留档）。"""

    def __init__(self, report_dir: Path, bind_all: bool = False):
        self.port = free_port()
        self.token = "perf-" + secrets.token_hex(12)
        self.db_path = report_dir / "perf.db"
        self.bind_all = bind_all
        self.host = "0.0.0.0" if bind_all else "127.0.0.1"
        self.base = f"http://127.0.0.1:{self.port}/api"
        self.proc: subprocess.Popen | None = None

    def start(self):
        env = dict(os.environ)
        env.update({
            "LINUXGUARD_DATABASE_URL": f"sqlite:///{self.db_path.as_posix()}",
            "LINUXGUARD_CONTROL_TOKEN": self.token,
            "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
            "LINUXGUARD_DISCOVERY_CIDRS": "127.0.0.0/8,172.16.0.0/12,192.168.100.0/24",
        })
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", self.host,
             "--port", str(self.port), "--log-level", "warning"],
            cwd=str(ROOT / "backend"), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError("perf backend 未能在 30s 内就绪")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)

    def post(self, path: str, payload: dict, timeout: int = 30) -> dict:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            _checked_backend_url(self.base, path), data=data,
            headers={"Content-Type": "application/json", "X-Control-Token": self.token},
            method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")

    def get(self, path: str, timeout: int = 30) -> dict:
        request = urllib.request.Request(_checked_backend_url(self.base, path),
                                         headers={"X-Control-Token": self.token})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")


def _checked_backend_url(base: str, path: str) -> str:
    """CWE-918 缓解：编排器只与本进程自建的评测后端通信——地址必须是
    http(s) 且主机为环回；不满足即拒绝（fail-closed，不做隐式放宽）。"""
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"评测后端地址不在允许范围（仅环回 http/https）: {base!r}")
    return base.rstrip("/") + path


def db_query(db_path: Path, sql: str, args: tuple = ()) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def db_exec(db_path: Path, sql: str, args: tuple = ()):
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()


def ensure_asset(backend: PerfBackend, hostname: str) -> int:
    """在 perf 库登记资产（心跳与绑定需要；幂等：同名单行复用已有行，不重复建档）。"""
    db_exec(backend.db_path,
            "INSERT OR IGNORE INTO linux_asset (hostname, ip_address, os_name, os_version, distribution,"
            " device_type, owner, business_level, exposure_level, identity_source, identity_confidence,"
            " inventory_complete, created_at, updated_at) VALUES (?,?,?,?,?,?, 'perf','core','internal',"
            " 'perf_harness', 0.5, 1, datetime('now'), datetime('now'))",
            (hostname, "127.0.0.1", "Linux", "perf", "perf", "host"))
    return int(db_query(backend.db_path, "SELECT id FROM linux_asset WHERE hostname=?", (hostname,))[0]["id"])


def process_summary(pid: int | None) -> dict:
    if pid is None:
        return {"note": "unavailable"}
    try:
        import psutil
        proc = psutil.Process(pid)
        with proc.oneshot():
            cpu = proc.cpu_times()
            return {"pid": pid, "cpu_seconds_total": round(cpu.user + cpu.system, 3),
                    "rss_mb_end": round(proc.memory_info().rss / 1e6, 1),
                    "create_time": datetime.fromtimestamp(proc.create_time(), tz=timezone.utc).isoformat()}
    except Exception:  # noqa: BLE001 —— 进程已退出或 psutil 不可用
        return {"pid": pid, "note": "unavailable（进程已退出或不可查询）"}


def loadgen_attribution(capture_jsonl_text: str, port: int) -> dict:
    """把后处理 JSONL 归因为负载发生器行为（受控对账只对归因事件进行）。

    归因规则（唯一且保守）：
    - execve：argv 含 -lgperf（负载专用参数）；
    - connect：目的端口 == 负载监听端口；
    - openat：file_path 为 /opt/firmware/.lgperf（专用文件）；/etc/passwd
      读取单独计数（环境噪声可能混入，不用于丢失结论）。
    """
    exec_n = conn_n = fw_n = passwd_n = total = 0
    for line in capture_jsonl_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        etype = event.get("event_type")
        if etype == "execve" and "-lgperf" in (event.get("argv") or []):
            exec_n += 1
        elif etype == "connect" and int(event.get("port") or 0) == port:
            conn_n += 1
        elif etype == "openat":
            path = str(event.get("file_path") or "")
            if path == "/opt/firmware/.lgperf":
                fw_n += 1
            elif path == "/etc/passwd":
                passwd_n += 1
    return {"total_events": total, "execve_attributed": exec_n, "connect_attributed": conn_n,
            "openat_firmware_attributed": fw_n, "openat_passwd_seen": passwd_n}


# ── 形态一：模拟负载（synthetic） ────────────────────────────────────────────


def mode_synthetic(report_dir: Path, duration: float) -> dict:
    backend = PerfBackend(report_dir)
    backend.start()
    try:
        started = time.monotonic()
        accepted = duplicates = rejected = batches = seq = 0
        token = secrets.token_hex(8)
        submit_ms: list[float] = []
        deadline = started + duration
        while time.monotonic() < deadline:
            events = []
            for _ in range(500):
                seq += 1
                events.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "hostname": "perf-synthetic-host",
                    "source": "perf_synthetic",
                    "event_type": "execve",
                    "process_name": "synthetic-probe",
                    "commandline": f"synthetic --seq {seq}",
                    "sensor_id": f"perf-synthetic-{token}",
                    "raw": {"generator": "p21-synthetic", "seq": seq, "token": token},
                })
            t0 = time.monotonic()
            result = backend.post("/runtime/ebpf/events/batch", {"events": events}, timeout=120)
            submit_ms.append((time.monotonic() - t0) * 1000)
            accepted += int(result.get("accepted", 0))
            duplicates += int(result.get("duplicates", 0))
            rejected += len(result.get("rejected", []))
            batches += 1
        window = time.monotonic() - started

        rows = db_query(backend.db_path,
                        "SELECT occurred_at, created_at FROM runtime_event WHERE sensor_id LIKE 'perf-synthetic-%'")
        return perf.summarize_run(
            "synthetic（模拟负载：无内核、无转发器，只测后端摄取路径）",
            window_seconds=round(window, 2), captured=None, stored_new=accepted,
            stored_duplicates=duplicates,
            forwarder_metrics={"batches": batches, "rejected": rejected,
                               "batch_rtt_ms": perf.latency_stats_ms(submit_ms)},
            latency=perf.end_to_end_latency_ms(rows), loss=None,
            resources={"backend_process": process_summary(backend.proc.pid)},
            environment={**HOST_ENV, "note": "合成事件直 POST /runtime/ebpf/events/batch（每批 500）"},
            notes=["captured=unavailable（无内核探针）；丢失对账不适用（模拟负载不经过采集链）"])
    finally:
        backend.stop()


# ── 形态二：离线回放（replay，含断网中断恢复） ───────────────────────────────


def mode_replay(report_dir: Path, duration: float, interrupt_after: float,
                interrupt_seconds: float, rate_lines_per_s: float = 80.0) -> dict:
    fixture_lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]
    backend = PerfBackend(report_dir)
    backend.start()
    ensure_asset(backend, "lab-ebpf-host")
    spool_file = report_dir / "replay-wal.jsonl"
    interruption: dict = {}
    fed = 0

    forwarder = subprocess.Popen(
        [sys.executable, str(COLLECTOR_DIR / "ebpf_event_collector.py"),
         "--api", backend.base, "--batch-size", "50", "--flush-seconds", "1",
         "--spool-file", str(spool_file), "--max-retries", "8",
         "--sensor-id", "perf-replay-sensor", "--boot-id", "perf-replay-boot"],
        env={**os.environ, "LINUXGUARD_CONTROL_TOKEN": backend.token},
        cwd=str(COLLECTOR_DIR),
        stdin=subprocess.PIPE,
        stdout=(report_dir / "forwarder-replay.out").open("wb"),
        stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    try:
        started = time.monotonic()

        def feed():
            nonlocal fed
            slot = 1.0 / rate_lines_per_s
            next_slot = time.monotonic()
            end = started + duration
            while time.monotonic() < end:
                if fed >= len(fixture_lines) * 10_000:  # 防御性上限
                    break
                line = fixture_lines[fed % len(fixture_lines)]
                try:
                    forwarder.stdin.write(line + "\n")
                    forwarder.stdin.flush()
                except (OSError, ValueError):
                    return
                fed += 1
                next_slot += slot
                delay = next_slot - time.monotonic()
                if delay > 0:
                    time.sleep(delay)

        writer = threading.Thread(target=feed)
        writer.start()
        # ── 断网窗口：停后端（转发器应退避重试 + 事件留 WAL，不丢不弃） ──
        time.sleep(interrupt_after)
        backend.stop()
        t_down = time.monotonic()
        time.sleep(interrupt_seconds)
        backend.start()  # 同端口重启（客户端视角=网络恢复）
        t_up = time.monotonic()
        writer.join(timeout=max(60, duration))
        forwarder.stdin.close()
        forwarder.wait(timeout=max(300, duration))
        total = time.monotonic() - started
        interruption = {"down_at_s": round(t_down - started, 1), "up_at_s": round(t_up - started, 1),
                        "down_duration_s": round(t_up - t_down, 1)}

        out_text = (report_dir / "forwarder-replay.out").read_text(encoding="utf-8", errors="replace")
        counts = db_query(backend.db_path,
                          "SELECT (SELECT COUNT(*) FROM runtime_event WHERE sensor_id='perf-replay-sensor') AS stored,"
                          " (SELECT COUNT(*) FROM security_evidence) AS evidence")[0]
        spool_pending = sum(1 for line in spool_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                            if line.strip())
        unique_expected = len(set(fixture_lines))
        loss = perf.loss_reconciliation(expected=fed, captured=fed, stored=counts["stored"],
                                        probe_reported_lost=None)
        loss.update({
            "dedup_note": (f"同夹具循环喂入 {fed} 行、唯一事件 {unique_expected} 条：服务端指纹幂等使"
                           f" stored 收敛到唯一事件数，duplicates 如实计数（重试/重放安全）"),
            "stored_unique": counts["stored"], "expected_unique": unique_expected,
            "idempotent_ok": counts["stored"] <= unique_expected,
        })
        return perf.summarize_run(
            "replay（离线回放：真实夹具限速流经生产转发器，含断网中断恢复）",
            window_seconds=round(total, 2), captured=fed, stored_new=counts["stored"],
            stored_duplicates=max(0, fed - counts["stored"]),
            forwarder_metrics={
                "exit_code": forwarder.returncode,
                "final_line": out_text.strip().splitlines()[-1] if out_text.strip() else "",
                "fed_lines": fed,
                "rate_target": rate_lines_per_s,
                "spool_pending_after": spool_pending,
                "security_evidence_rows": counts["evidence"],
                "interruption": interruption,
            },
            latency={"note": "unavailable：夹具事件时间戳为历史采集时间（离线回放无实时采集时间），"
                             "端到端延迟见 real-* 形态"},
            loss=loss,
            resources={"note": "转发器与后端同机（Windows）；转发器输出见 forwarder-replay.out"},
            environment={**HOST_ENV, "fixture": str(FIXTURE), "fixture_real_lines": len(fixture_lines)},
            notes=["中断恢复验收：断网期间事件留 WAL（未确认≠丢失），恢复后重放由服务端幂等去重",
                   f"验收判据：exit_code==0 且 spool_pending_after==0 且 stored<=唯一事件数"])
    finally:
        backend.stop()
        if forwarder.poll() is None:
            forwarder.kill()


def mode_bounded_spool(report_dir: Path, run_seconds: float = 60.0) -> dict:
    """有界 spool 保护：后端不可达 + 喂入远超容量，验证背压与未确认数据保全。

    语义说明（如实）：转发器对不可达后端按设计无限重试、背压期间暂停接收，
    不会自行退出（这是韧性设计，常驻进程由运维/编排器停止）。因此本场景
    由编排器有界运行 run_seconds 后显式终止（Windows TerminateProcess=硬杀），
    断言的是盘上不变量：WAL ≤ 容量、告警可见、未确认事件未被删除。
    """
    fixture_lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]
    stream = report_dir / "bounded-stream.jsonl"
    with stream.open("w", encoding="utf-8") as handle:
        for i in range(300):
            handle.write(fixture_lines[i % len(fixture_lines)] + "\n")
    spool = report_dir / "bounded-wal.jsonl"
    for stale in (spool, report_dir / "forwarder-bounded.out"):
        if stale.exists():
            stale.unlink()  # 清理上次运行残留：场景从空 WAL 开始，确定可复现
    started = time.monotonic()
    with (report_dir / "forwarder-bounded.out").open("wb") as out:
        proc = subprocess.Popen(
            [sys.executable, str(COLLECTOR_DIR / "ebpf_event_collector.py"),
             "--api", "http://127.0.0.1:9", "--file", str(stream),
             # 批 50 × 容量 80：两批即触界（本机实测环回连接拒绝 ≈2s/次 +
             # 排水退避 ≤16s，批 10 在分钟级窗内填不满容量，触界不可复现）
             "--batch-size", "50", "--max-retries", "1", "--spool-file", str(spool),
             "--spool-max-events", "80", "--sensor-id", "perf-bounded-sensor"],
            stdout=out, stderr=subprocess.STDOUT,
            env={**os.environ, "LINUXGUARD_CONTROL_TOKEN": "unused"},
            cwd=str(COLLECTOR_DIR))
        exited_early = True
        try:
            proc.wait(timeout=run_seconds)
        except subprocess.TimeoutExpired:
            exited_early = False
            proc.kill()  # Windows 无 SIGTERM 优雅路径：硬杀后按盘上状态断言
            proc.wait(timeout=30)
        wall = round(time.monotonic() - started, 1)
    text = (report_dir / "forwarder-bounded.out").read_text(encoding="utf-8", errors="replace")
    pending = [line for line in spool.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    return {
        "mode": "bounded-spool（有界 spool 保护：容量 80 事件 / 喂入 300 行 / 后端不可达 / "
                f"{run_seconds:.0f}s 后编排器显式终止 / 批大小 50）",
        "forwarder_returncode": proc.returncode,
        "forwarder_exited_before_deadline": exited_early,
        "killed_by_harness": not exited_early,
        "wall_seconds": wall,
        "spool_lines_after": len(pending),
        "spool_capacity_events": 80,
        "capacity_respected": len(pending) <= 80,
        "backpressure_alerts_seen": text.count("spool protection"),
        "alert_sample": next((line for line in text.splitlines() if "spool protection" in line), ""),
        "unconfirmed_events_preserved": len(pending) > 0,
        "expected_behavior": "背压告警可见；spool ≤ 容量；未确认数据保留在 WAL 未被删除；"
                             "进程按设计持续重试不可达后端（常驻语义），由编排器有界终止",
    }


# ── 形态三：真实内核采集（WSL2 bpftrace） ────────────────────────────────────


def mode_real_wsl(report_dir: Path, duration: float, target_eps: float) -> dict:
    probe = wsl("uname -r; bpftrace --version 2>/dev/null | head -1; python3 --version 2>&1; hostname")
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    if len(lines) < 4:
        raise RuntimeError(f"WSL 环境探测失败：{probe.stdout}\n{probe.stderr}")
    kernel, bpftrace_version, _py, wsl_hostname = lines[0], lines[1], lines[2], lines[3]
    gateway = wsl("ip route show default | awk '{print $3}' | head -1").stdout.strip()
    if not gateway:
        raise RuntimeError("无法确定 WSL → Windows 网关地址")

    backend = PerfBackend(report_dir, bind_all=True)
    wsl_base = f"http://{gateway}:{backend.port}/api"
    backend.start()
    asset_id = ensure_asset(backend, wsl_hostname)
    # 每次运行独立 sensor 身份（同 synthetic 形态）：perf.db 跨运行累积，
    # 固定 sensor_id 会使 stored/延迟统计混入历史运行行（attempt4→5 重跑实测）
    sensor = f"perf-wsl-bpftrace-{secrets.token_hex(6)}"
    counts_remote = "/tmp/lg-perf-counts.json"
    capture_jsonl = "/tmp/lg-perf-capture.jsonl"
    sampler_file = "/tmp/lg-perf-proc-samples.txt"
    loadgen_port = 18099
    wsl_root = WSL_COLLECTOR.rsplit("/", 1)[0]  # /mnt/e/IoTGuard-Public
    wsl_report_dir = f"{wsl_root}/reports/{report_dir.name}"
    try:
        health = wsl(f"curl -fsS -m 4 {wsl_base}/health").stdout.strip()
        if '"ok"' not in health:
            raise RuntimeError(f"WSL 无法访问 Windows 后端（{wsl_base}）：{health!r}；"
                               "请检查 Windows 防火墙对 WSL NAT 网段的入站规则")

        # 1) bpftrace 采集为前台（wsl 调用等待其完成）；负载与 /proc 采样为后台。
        #    负载延迟 3s 启动，给探针编译/attach 留窗口（attach 前的行为不计入制造数对账误差）。
        #    命令体见 write_wsl_script 注释：脚本文件形式规避 wsl.exe argv 引号缺陷。
        capture_script = f"""set -u
cd {WSL_COLLECTOR}
rm -f {capture_jsonl} {counts_remote} {sampler_file} /tmp/linuxguard-probe-health.json
( sleep 3; python3 ebpf_perf_loadgen.py --duration {int(duration)} --target-eps {target_eps} --counts-file {counts_remote} > /tmp/lg-perf-loadgen.out 2>&1 ) &
( for i in $(seq 1 {int(duration) * 4 + 16}); do PID=$(pgrep -x bpftrace | head -1); [ -n "$PID" ] && echo "$(date +%s%N) $(awk '{{print $14, $15}}' /proc/$PID/stat 2>/dev/null) $(awk '/VmRSS/ {{print $2}}' /proc/$PID/status 2>/dev/null)"; sleep 0.25; done > {sampler_file} ) &
bash ebpf_trace_capture.sh {capture_jsonl} {int(duration) + 8} 2>&1 | tail -4
"""
        write_wsl_script(report_dir / "wsl-capture-run.sh", capture_script)
        result = wsl(f"bash {wsl_report_dir}/wsl-capture-run.sh", timeout=int(duration) + 300)
        capture_log = _strip_wsl_banner(result.stdout + "\n" + result.stderr).strip()

        # 2) 采集产物：原始行数（awk 稳定处理 0 匹配）+ 探针健康文件（丢失计数单一来源）
        raw_count = wsl(f"awk '/^LG\\|/ {{n++}} END {{print n+0}}' {capture_jsonl}.raw 2>/dev/null").stdout.strip()
        health_json_text = wsl("cat /tmp/linuxguard-probe-health.json 2>/dev/null || echo '{}'").stdout
        try:
            health_file = json.loads(health_json_text)
        except json.JSONDecodeError:
            health_file = {}
        dropped = health_file.get("dropped_events")
        lost_n = int(dropped) if isinstance(dropped, int) else None  # null → unavailable（非 0）
        counts_json = wsl(f"cat {counts_remote} 2>/dev/null || echo '{{}}'").stdout

        # 3) WSL 侧生产转发器：stdin 管道（激活心跳路径）+ 探针健康文件 + 真实跨主机 HTTP。
        #    不注入 --boot-id：真实采集事件自带真实内核 boot_id（enrich_event 拒绝伪造身份
        #    覆盖真实身份——attempt3 实测 Conflicting upstream boot_id 即此防线生效）；
        #    stdin 模式下转发器心跳从 /proc 自读真实 boot_id，与事件一致。
        forwarder_script = f"""set -u
cd {WSL_COLLECTOR}
export LINUXGUARD_CONTROL_TOKEN={backend.token}
cat {capture_jsonl} | python3 ebpf_event_collector.py --api {wsl_base} --batch-size 100 --flush-seconds 1 --spool-file /tmp/lg-perf-wal.jsonl --max-retries 5 --sensor-id {sensor} --heartbeat --heartbeat-seconds 10 --asset-id {asset_id} --health-file /tmp/linuxguard-probe-health.json --source bpftrace
"""
        write_wsl_script(report_dir / "wsl-forwarder-run.sh", forwarder_script)
        fwd = wsl(f"bash {wsl_report_dir}/wsl-forwarder-run.sh 2>&1 | tail -3", timeout=600)
        forwarder_out = _strip_wsl_banner(fwd.stdout + "\n" + fwd.stderr).strip()

        # 4) 证据回传 Windows 报告目录（/mnt/e 同一仓库）
        wsl(f"mkdir -p {wsl_report_dir} && cp {capture_jsonl} {wsl_report_dir}/wsl-capture.jsonl; "
            f"cp {capture_jsonl}.raw {wsl_report_dir}/wsl-capture.raw; "
            f"cp {capture_jsonl}.err {wsl_report_dir}/wsl-capture.err; "
            f"cp {sampler_file} {wsl_report_dir}/wsl-proc-samples.txt; "
            f"cp /tmp/lg-perf-loadgen.out {wsl_report_dir}/wsl-loadgen.out; "
            f"cp /tmp/linuxguard-probe-health.json {wsl_report_dir}/wsl-probe-health.json; "
            f"cp /tmp/lg-perf-wal.jsonl {wsl_report_dir}/wsl-wal-after.jsonl 2>/dev/null; true")

        capture_text = (report_dir / "wsl-capture.jsonl").read_text(encoding="utf-8", errors="ignore") \
            if (report_dir / "wsl-capture.jsonl").exists() else ""
        attribution = loadgen_attribution(capture_text, loadgen_port)
        expected = json.loads(counts_json) if counts_json.strip().startswith("{") else {}

        rows = db_query(backend.db_path,
                        "SELECT occurred_at, created_at FROM runtime_event WHERE sensor_id=?", (sensor,))
        stored = db_query(backend.db_path,
                          "SELECT (SELECT COUNT(*) FROM runtime_event WHERE sensor_id=?) AS n,"
                          " (SELECT COUNT(*) FROM security_evidence) AS e", (sensor,))[0]
        reliability = backend.get("/runtime/ebpf/reliability")

        captured_n = int(raw_count) if raw_count.isdigit() else None
        # 对账口径严格对齐：expected 只含可归因行为（exec + connect + firmware 写）。
        # /etc/passwd 读制造数与捕获数都可能混入环境噪声（其他进程读 passwd），
        # 双方都不可靠 → 不进丢失结论，单独呈现（attempt3 实测曾因口径错配虚报 25% 丢失）。
        expected_attn = (expected.get("execve_made", 0) + expected.get("connect_made", 0)
                         + expected.get("openat_write_made", 0))
        captured_attn = (attribution["execve_attributed"] + attribution["connect_attributed"]
                         + attribution["openat_firmware_attributed"])
        loss = perf.loss_reconciliation(
            expected=expected_attn, captured=captured_attn,
            stored=stored["n"], probe_reported_lost=lost_n)
        loss["attribution_detail"] = attribution
        loss["expected_breakdown"] = {k: expected.get(k) for k in
                                      ("execve_made", "connect_made", "openat_read_made",
                                       "openat_write_made", "openat_no_perm")}
        loss["note_overall"] = (f"总捕获 {captured_n} 含环境噪声；对账只按归因事件"
                                f"（expected {expected_attn} vs captured {captured_attn}）；"
                                "/etc/passwd 读取因环境噪声可能混入，不用于丢失结论")
        sampler_summary = _summarize_proc_samples(report_dir / "wsl-proc-samples.txt")
        return perf.summarize_run(
            f"real-wsl（真实内核采集：{duration:.0f}s @ 目标 {target_eps:.0f} EPS 受控真实负载）",
            window_seconds=duration, captured=captured_n, stored_new=stored["n"],
            stored_duplicates=None,
            forwarder_metrics={"final_line": forwarder_out.splitlines()[-1] if forwarder_out else "",
                               "forwarder_tail": forwarder_out,
                               "probe_health": health_file,
                               "reliability_endpoint": reliability},
            latency=perf.end_to_end_latency_ms(rows), loss=loss,
            resources={"bpftrace_cpu": sampler_summary,
                       "backend_process": process_summary(backend.proc.pid)},
            environment={**HOST_ENV, "collector": f"WSL2 Ubuntu / 内核 {kernel} / {bpftrace_version}",
                         "wsl_gateway": gateway, "health_check": health,
                         "capture_log_tail": capture_log[-400:]},
            notes=[f"负载发生器实际速率 {expected.get('actual_eps')} EPS（目标 {target_eps}；延迟 3s 启动等探针 attach）",
                   "丢失三层对账：制造数 vs bpftrace 归因捕获数 vs 服务端入库数 + 探针 stderr 自报丢失",
                   "延迟 = 内核事件时间（bpftrace nsecs→ISO）→ 服务端持久化时间（created_at）"])
    finally:
        backend.stop()


def _summarize_proc_samples(path: Path) -> dict:
    """/proc/<bpftrace>/stat 采样（0.25s）→ CPU 秒与 RSS 峰值；无样本=unavailable。"""
    if not path.exists():
        return {"note": "unavailable（采样文件缺失）"}
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            try:
                rows.append((int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])))
            except ValueError:
                continue
    if not rows:
        return {"note": "unavailable（无有效样本——探针进程名/pgrep 未命中）"}
    first, last = rows[0], rows[-1]
    return {
        "samples": len(rows),
        "cpu_seconds_total": perf.cpu_seconds(last[1], last[2]),
        "rss_kb_peak": max(r[3] for r in rows),
        "rss_kb_first": first[3],
        "note": "utime+stime（jiffies/100→秒）；探针常驻期间累计",
    }


# ── 形态四：真实内核采集（Ubuntu VM falco via journalctl，只读拉取） ──────────


FALCO_MSG_RE = re.compile(r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d+):\s+(?P<priority>\w+)\s+(?P<body>.*)$")


def mode_real_vm_falco(report_dir: Path, duration: float, target_eps: float) -> dict:
    missing = [name for name, value in (
        ("LINUXGUARD_PERF_VM_HOST", VM_SSH_HOST),
        ("LINUXGUARD_PERF_VM_USER", VM_SSH_USER),
        ("LINUXGUARD_PERF_VM_API", VM_BACKEND_BASE_TEMPLATE)) if not value]
    if missing:
        return {"mode": "real-vm-falco", "error": "VM 连接环境变量未提供：" + ", ".join(missing)
                + "（私网地址/用户名不入跟踪文件，运行前由本地环境注入；见脚本头部说明）"}
    probe = ssh_vm("uname -r; falco --version 2>/dev/null | head -1; systemctl is-active falco-modern-bpf; hostname")
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    if len(lines) < 4 or lines[2] != "active":
        return {"mode": "real-vm-falco", "error": "VM falco-modern-bpf 服务不可用", "probe": probe.stdout}
    vm_kernel, falco_version, vm_hostname = lines[0], lines[1], lines[3]

    backend = PerfBackend(report_dir, bind_all=True)
    vm_base = VM_BACKEND_BASE_TEMPLATE.format(port=backend.port)
    backend.start()
    ensure_asset(backend, vm_hostname)
    counts_remote = "/tmp/lg-perf-counts-vm.json"
    try:
        health = ssh_vm(f"curl -fsS -m 4 {vm_base}/health").stdout.strip()
        if '"ok"' not in health:
            raise RuntimeError(f"VM 无法访问 Windows 后端（{vm_base}）：{health!r}；"
                               "请确认 VMnet8 主机侧地址与既有入站放行规则")

        scp = sh(["scp", "-i", str(VM_SSH_KEY), str(COLLECTOR_DIR / "ebpf_perf_loadgen.py"),
                  f"{VM_SSH_USER}@{VM_SSH_HOST}:/tmp/ebpf_perf_loadgen.py"], timeout=60)
        if scp.returncode != 0:
            raise RuntimeError(f"负载发生器上传失败：{scp.stderr}")

        # 时间窗以 VM 时钟为准（避免主机间时钟偏差造成窗口错切）
        since = ssh_vm("date --iso-8601=seconds").stdout.strip()
        started = time.monotonic()
        ssh_vm(f"nohup python3 /tmp/ebpf_perf_loadgen.py --duration {int(duration)} "
               f"--target-eps {target_eps} --counts-file {counts_remote} "
               f"> /tmp/lg-perf-loadgen-vm.out 2>&1 & echo started")
        time.sleep(duration + 4)
        until = ssh_vm("date --iso-8601=seconds").stdout.strip()
        wall = time.monotonic() - started

        # journalctl 单次拉取（-o json 真实时间戳；只读，零改动）
        journal_file = report_dir / "vm-falco-journal.jsonl"
        pull = ssh_vm(f"journalctl -u falco-modern-bpf --since '{since}' --until '{until}' "
                      f"-o json --no-pager", timeout=300)
        journal_file.write_text(pull.stdout, encoding="utf-8")

        counts_json = ssh_vm(f"cat {counts_remote} 2>/dev/null || echo '{{}}'").stdout
        ssh_vm("rm -f /tmp/ebpf_perf_loadgen.py /tmp/lg-perf-counts-vm.json /tmp/lg-perf-loadgen-vm.out")
        expected = json.loads(counts_json) if counts_json.strip().startswith("{") else {}

        events, parse_meta = journal_to_events(journal_file, device=vm_hostname,
                                               sensor_id=f"perf-vm-falco-{secrets.token_hex(6)}")
        run_sensor = events[0]["sensor_id"] if events else "perf-vm-falco-none"
        (report_dir / "vm-falco-events.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
        accepted = duplicates = 0
        for i in range(0, len(events), 500):
            result = backend.post("/runtime/ebpf/events/batch", {"events": events[i:i + 500]}, timeout=120)
            accepted += int(result.get("accepted", 0))
            duplicates += int(result.get("duplicates", 0))

        rows = db_query(backend.db_path,
                        "SELECT occurred_at, created_at FROM runtime_event WHERE sensor_id=?", (run_sensor,))
        stored = db_query(backend.db_path,
                          "SELECT (SELECT COUNT(*) FROM runtime_event WHERE sensor_id=?) AS n,"
                          " (SELECT COUNT(*) FROM security_evidence) AS e", (run_sensor,))[0]
        # 对账基准：LG-IoT 规则集对 execve 全捕获（args=%proc.cmdline 含 -lgperf）；
        # connect/openat 受规则条件与 VM 侧用户无 root 权限影响，单独呈现不进丢失结论
        def _msg(e: dict) -> str:
            return str(e.get("commandline", "")) + " " + str((e.get("raw") or {}).get("message", ""))
        exec_captured = sum(1 for e in events if "LG-IoT process exec" in _msg(e) and "lgperf" in _msg(e))
        connect_seen = sum(1 for e in events if "LG-IoT local connect" in _msg(e) and "18099" in _msg(e))
        file_seen = sum(1 for e in events if "LG-IoT watched file" in _msg(e) and "lgperf" in _msg(e))
        passwd_seen = sum(1 for e in events if "LG-IoT watched file read" in _msg(e) and "/etc/passwd" in _msg(e))
        loss = perf.loss_reconciliation(
            expected=expected.get("execve_made"), captured=exec_captured,
            stored=stored["n"], probe_reported_lost=None)
        loss["reconciliation_basis"] = ("execve 制造数 vs journal『LG-IoT process exec』中 -lgperf 归因捕获数"
                                        " vs 入库总数；connect/openat 受 LG-IoT 规则条件影响单独呈现")
        return perf.summarize_run(
            f"real-vm-falco（真实内核采集：VM 常驻 falco-modern-bpf + journalctl 只读拉取，{duration:.0f}s）",
            window_seconds=round(wall, 1),
            captured=parse_meta.get("lg_events"), stored_new=stored["n"], stored_duplicates=duplicates,
            forwarder_metrics={"upload_path": "Windows 编排器直 POST 批量端点（拉取式，非常驻转发器）",
                               "journal_entries": parse_meta.get("journal_entries"),
                               "lg_events": parse_meta.get("lg_events"),
                               "message_time_refined": parse_meta.get("message_time_refined"),
                               "tz_mismatch_fallback": parse_meta.get("tz_mismatch_fallback"),
                               "exec_attributed": exec_captured,
                               "connect_attributed_seen": connect_seen,
                               "file_lgperf_attributed_seen": file_seen,
                               "passwd_read_seen": passwd_seen,
                               "upload_accepted": accepted, "upload_duplicates": duplicates},
            latency=perf.end_to_end_latency_ms(rows), loss=loss,
            resources={"note": "falco 为系统常驻服务（root 进程），本轮无 sudo 无法对其采样：CPU unavailable"},
            environment={**HOST_ENV,
                         "collector": f"Ubuntu VM {vm_hostname} / 内核 {vm_kernel} / {falco_version}"
                                      "（modern_ebpf，LG-IoT 规则已部署为 falco-modern-bpf）",
                         "access": "SSH 只读 + journalctl 拉取（adm 组），对 VM 零改动",
                         "expected_breakdown": {k: expected.get(k) for k in
                                                ("execve_made", "connect_made", "openat_made", "openat_no_perm")}},
            notes=[f"负载发生器实际速率 {expected.get('actual_eps')} EPS（目标 {target_eps}；VM 侧用户无 root："
                   "文件写项如实降级 no_perm）",
                   "falco 引擎自身 drop 统计未在 journal 呈现：unavailable（非零丢失）",
                   "延迟含 journal 落盘与拉取间隔（批式拉取路径，非常驻转发），如实标注"])
    finally:
        backend.stop()


def journal_to_events(journal_file: Path, device: str, sensor_id: str = "perf-vm-falco-journal") -> tuple[list[dict], dict]:
    """journalctl -o json → 后端统一事件（source=falco_journal；不得伪装 eBPF 直采）。

    事件时间基准 = journal __REALTIME_TIMESTAMP（epoch UTC，跨主机可比）。
    真实数据实测（2026-10-15）：falco 消息内嵌 HH:MM:SS.μs 为 VM 本地时区
    （journal 01:36:56 vs 消息 09:36:56，恰 +8h）——直接拼 journal 日期会造出
    未来 8h 的 occurred_at，端到端延迟被 max(0,·) 钳位成伪 0。因此消息时间
    仅当与 journal 时间相差 ≤2s（同时钟基准佐证）时用于细化到 μs；否则回退
    journal 时间并计入 tz_mismatch（如实计数，不虚构、不产生伪零延迟）。
    """
    events: list[dict] = []
    entries = lg_events = refined_n = tz_mismatch = 0
    for line in journal_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries += 1
        message = str(entry.get("MESSAGE", ""))
        realtime_us = entry.get("__REALTIME_TIMESTAMP")
        journal_dt = (datetime.fromtimestamp(int(realtime_us) / 1e6, tz=timezone.utc)
                      if realtime_us else datetime.now(timezone.utc))
        ts = journal_dt.isoformat()
        priority = "info"
        match = FALCO_MSG_RE.match(message)
        if match:
            priority = match.group("priority").lower()
            if priority == "informational":
                priority = "info"
            try:
                # 分数位位数不定（falco 常见 6 位 μs，亦有 9 位 ns）：按 0.<frac> 秒解析
                frac_text = match.group("time")[9:]
                microsecond = int(round(float("0." + frac_text) * 1e6)) if frac_text else 0
                candidate = journal_dt.replace(
                    hour=int(match.group("time")[0:2]), minute=int(match.group("time")[3:5]),
                    second=int(match.group("time")[6:8]), microsecond=min(microsecond, 999_999))
                if abs((candidate - journal_dt).total_seconds()) <= 2.0:
                    ts = candidate.isoformat()  # 同时钟基准：消息内核时间（μs 精度）优先
                    refined_n += 1
                else:
                    tz_mismatch += 1  # 本地时区消息时间：回退 journal UTC，如实计数
            except (ValueError, OverflowError):
                pass
        if "LG-IoT" in message:
            lg_events += 1
        events.append({
            "timestamp": ts,
            "hostname": device,
            "source": "falco_journal",
            "event_type": "falco_rule_alert" if "LG-IoT" in message else "falco_other",
            "severity": priority,
            "commandline": message[:1000],
            "sensor_id": sensor_id,
            "boot_id": str(entry.get("_BOOT_ID", ""))[:64],
            "raw": {"message": message[:4000], "systemd_unit": entry.get("_SYSTEMD_UNIT", ""),
                    "journal_cursor": str(entry.get("__CURSOR", ""))[:200]},
        })
    return events, {"journal_entries": entries, "lg_events": lg_events,
                    "message_time_refined": refined_n, "tz_mismatch_fallback": tz_mismatch}


# ── 报告输出 ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="eBPF 2.0 P2-1 performance benchmark orchestrator")
    parser.add_argument("--mode", required=True,
                        choices=["synthetic", "replay", "real-wsl", "real-vm-falco", "bounded-spool"])
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--target-eps", type=float, default=200.0)
    parser.add_argument("--interrupt-after", type=float, default=25.0)
    parser.add_argument("--interrupt-seconds", type=float, default=20.0)
    parser.add_argument("--report-name", default=None)
    args = parser.parse_args()

    report_dir = REPORTS_DIR / (args.report_name or f"ebpf-p21-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    report_dir.mkdir(parents=True, exist_ok=True)
    print(f"[p21] mode={args.mode} → {report_dir}", flush=True)

    if args.mode == "synthetic":
        summary = mode_synthetic(report_dir, args.duration)
    elif args.mode == "replay":
        summary = mode_replay(report_dir, args.duration, args.interrupt_after, args.interrupt_seconds)
    elif args.mode == "real-wsl":
        summary = mode_real_wsl(report_dir, args.duration, args.target_eps)
    elif args.mode == "real-vm-falco":
        summary = mode_real_vm_falco(report_dir, args.duration, args.target_eps)
    else:
        summary = mode_bounded_spool(report_dir)

    out = report_dir / "summary.json"
    runs: list[dict] = []
    if out.exists():
        try:
            loaded = json.loads(out.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                runs = loaded
        except (OSError, json.JSONDecodeError):
            runs = []
    runs.append(summary)
    out.write_text(json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print(f"[p21] summary → {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
