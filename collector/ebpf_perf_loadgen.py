#!/usr/bin/env python3
"""LinuxGuard eBPF 2.0 P2-1 性能评测：受控行为负载发生器（真实 syscall，非模拟事件）。

在采集窗口内按目标节拍真实制造三类可被 eBPF 探针捕获的内核行为：

  execve  —— subprocess 执行 /bin/true -lgperf（每次真实 exec）
  connect —— socket 短连接 127.0.0.1:<port>（retval=0；P2-4 守卫后失败连接
             不产生事件，故自带本地监听器保证连接成功）
  openat  —— 读 /etc/passwd + 追加写 /opt/firmware/.lgperf（受控路径）

诚实边界：
- 本进程制造的全部可捕获行为都精确计数并写入 counts 文件；与探针捕获数的
  差 = 采集链路丢失（由 P2-1 编排脚本对账，本脚本不虚构对齐）；
- "目标 EPS"是节拍上限：达到生成器能力上限时按实际能力输出（actual_eps
  如实反映），不宣称达标；
- /opt/firmware 不可写时文件写项如实计数为 openat_no_perm（降级可见），
  绝不计入成功数。

用法: python3 ebpf_perf_loadgen.py --duration 60 --target-eps 200 \
          [--counts-file /tmp/lg-perf-counts.json] [--port 18099]
无需 root（探针侧另行以 root 运行）。
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

EXEC_ARGS = ("/bin/true", "-lgperf")
OPEN_READ_PATH = "/etc/passwd"
OPEN_WRITE_DIR = Path("/opt/firmware")
OPEN_WRITE_PATH = OPEN_WRITE_DIR / ".lgperf"


def start_listener(port: int, stop: threading.Event) -> threading.Thread:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(256)
    server.settimeout(1.0)

    def drain() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return
        server.close()

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlled real-syscall load generator for eBPF perf tests")
    parser.add_argument("--duration", type=float, required=True, help="生成窗口时长（秒）")
    parser.add_argument("--target-eps", type=float, default=200.0, help="目标每秒行为数（节拍上限）")
    parser.add_argument("--counts-file", default="/tmp/linuxguard-perf-loadgen-counts.json")
    parser.add_argument("--port", type=int, default=18099, help="本地 connect 监听端口")
    args = parser.parse_args()
    if args.duration <= 0 or args.target_eps <= 0:
        parser.error("--duration 与 --target-eps 必须为正数")

    stop = threading.Event()
    start_listener(args.port, stop)

    writable = True
    try:
        OPEN_WRITE_DIR.mkdir(parents=True, exist_ok=True)
        with OPEN_WRITE_PATH.open("a", encoding="utf-8"):
            pass
    except OSError:
        writable = False
        print(f"[loadgen] WARN: {OPEN_WRITE_PATH} 不可写，文件写项将如实降级为 no_perm", file=sys.stderr)

    counts = {"execve_made": 0, "connect_made": 0, "openat_made": 0,
              "openat_read_made": 0, "openat_write_made": 0, "openat_no_perm": 0}
    start_ns = time.time_ns()
    start_iso = datetime.now(timezone.utc).isoformat()
    deadline = start_ns + args.duration * 1e9
    slot_ns = 3e9 / args.target_eps  # 每拍三类行为各一次
    next_slot = start_ns

    while True:
        now = time.time_ns()
        if now >= deadline:
            break
        if now < next_slot:
            time.sleep((next_slot - now) / 1e9)
        # execve（失败按未制造处理，不计数——探针也捕获不到失败 exec 的本探针事件）
        try:
            subprocess.run(EXEC_ARGS, check=True)
            counts["execve_made"] += 1
        except (OSError, subprocess.CalledProcessError):
            pass
        # connect（成功才计数；失败连接本就不产生事件）
        try:
            with socket.create_connection(("127.0.0.1", args.port), timeout=2):
                counts["connect_made"] += 1
        except OSError:
            pass
        # openat：受控路径读 + 追加写（读写分开计数——对账只认可归因的写路径，
        # /etc/passwd 读因环境噪声可能混入，不进丢失结论）
        try:
            with open(OPEN_READ_PATH, "rb") as handle:
                handle.read(8)
            counts["openat_made"] += 1
            counts["openat_read_made"] += 1
        except OSError:
            pass
        if writable:
            try:
                with OPEN_WRITE_PATH.open("a", encoding="utf-8") as handle:
                    handle.write(f"lgperf {now}\n")
                counts["openat_made"] += 1
                counts["openat_write_made"] += 1
            except OSError:
                counts["openat_no_perm"] += 1
        else:
            counts["openat_no_perm"] += 1
        next_slot += slot_ns

    end_ns = time.time_ns()
    stop.set()
    time.sleep(0.2)

    result = {
        **counts,
        "actions_total": counts["execve_made"] + counts["connect_made"] + counts["openat_made"],
        "wall_ns": end_ns - start_ns,
        "target_eps": args.target_eps,
        "actual_eps": round(
            (counts["execve_made"] + counts["connect_made"] + counts["openat_made"])
            / ((end_ns - start_ns) / 1e9), 2),
        "started_at": start_iso,
        "ended_at": datetime.now(timezone.utc).isoformat(),
    }
    Path(args.counts_file).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
