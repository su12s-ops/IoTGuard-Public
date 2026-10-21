#!/usr/bin/env python3
"""
Read Falco/Tetragon JSONL events and upload them to LinuxGuard (forwarder 2.0, eBPF P0).

P0 可靠性升级（在既有单条路径上增量，协议向后兼容）：
- 批量上传：按批（默认 50 条或 2 秒）POST /runtime/ebpf/events/batch；
- 有界重试 + 指数退避：默认 5 次（1s,2s,4s,8s,16s + 抖动），仍失败则将整批
  写入本地 spool 文件并在后续恢复重传（断点续传）；
- 确认协议：仅当 HTTP 200 且响应 JSON 含 ack=true 才视为服务端已持久化；
  "请求已发出"不等于已确认；
- 服务端幂等：批量端点按稳定原始事件指纹判重，重试/重放不会重复入库
  （duplicates 计数如实返回）；
- 明确状态：失败与未确认事件留在 spool（未确认 ≠ 丢失），退出码非零提示；
- 指标计数：received/parsed/uploaded/duplicates/rejected/retries/failed_batches/
  spool_pending/last_success_at 随心跳上报（P0 采集可靠性指标）。

2.1 Write-Ahead Spool（eBPF 2.0 最终交付轮）：
- 写前持久化：事件在首次发送前先落 WAL（默认逐事件 fsync），服务端确认后才
  从 WAL 移除——SIGKILL/断电只可能丢"尚未送达本进程"的管道尾部，已接收事件
  不因进程死亡而丢失；崩溃窗口的已确认未收缩行重放由服务端指纹幂等去重
  （duplicates 如实计数）。即 at-least-once 投递 + 服务端幂等 = 恰一次入库。
- 有界 spool：条数/字节容量上限 + spool 所在盘剩余空间下限；触界 → 明确降级
  （背压暂停接收、stderr 告警、心跳 spool_full 标记），绝不静默丢弃事件，
  绝不删除未确认数据（收缩只移除已确认行）。
- 运行中自愈：发送失败的事件保留在 WAL 前端按退避节奏重试，后端恢复后
  无需重启进程即续传（心跳失败不再致命；P0 语义为失败入 spool 等下次启动）。
- 可靠性边界（诚实声明）：falco→转发器管道中、尚未被本进程读入的事件，
  在背压触发后可能于 falco 侧丢弃（计入 falco 自身 drop 统计，可观测）；
  WAL 损坏行跳过不阻塞恢复（计数呈现，不虚构完整）。

Usage on Ubuntu VM:
  falco -o json_output=true 2>/dev/null | python3 ebpf_event_collector.py --api http://WINDOWS_IP:8000/api
  tetragon --export-filename /tmp/tetragon.jsonl
  python3 ebpf_event_collector.py --file /tmp/tetragon.jsonl --api http://WINDOWS_IP:8000/api
"""

import argparse
import itertools
import json
import os
import queue
import random
import re
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

DEFAULT_BATCH_SIZE = 50
DEFAULT_BATCH_FLUSH_S = 2.0
DEFAULT_MAX_RETRIES = 5

# falco ≥0.37 在退出时向 stdout 追加的统计摘要块（纯文本，非事件）。
# 实测（falco 0.44.1，VM 2026-10-14）：首行如下之一，其后跟随任意格式的
# 缩进明细行（severity/rule 计数）。摘要总在流末尾（引擎退出时输出）——
# 进入摘要态后跳过全部后续行，不计 received/rejected（非事件、非解析失败）。
FALCO_EXIT_SUMMARY_PREFIXES = (
    "Events detected:",
    "Rule counts by severity:",
    "Triggered rules by rule name:",
    "Syscall event drop monitoring:",
    "- event drop detected:",
    "- num times actions taken:",
)
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 16.0
BATCH_ENDPOINT = "/runtime/ebpf/events/batch"


def _checked_api_base(api_base: str) -> str:
    """请求前校验 API 基址：仅 http/https、禁止 URL 内嵌凭据、主机非空。

    本工具是操作员显式指定的可信内网上报端点（默认本机后端），
    不适用公网目标约束；此处阻断的是协议与凭据注入面。
    """
    parsed = urllib.parse.urlsplit(api_base)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"API 基址仅允许 http/https: {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise ValueError("API 基址不允许携带用户名/密码")
    if not parsed.hostname:
        raise ValueError("API 基址缺少主机名")
    return api_base.rstrip("/")


def post_json(api_base: str, path: str, event: dict, token: str = "", timeout: int = 15) -> dict:
    base = _checked_api_base(api_base)
    data = json.dumps(event).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Control-Token"] = token
    request = urllib.request.Request(
        base + path,
        data=data,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
    try:
        parsed = json.loads(payload or b"{}")
    except ValueError as exc:
        raise ValueError(f"服务端响应不可解析（不视为已确认）: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("服务端响应不是 JSON 对象（不视为已确认）")
    return parsed


def post_event(api_base: str, event: dict, token: str = "") -> None:
    post_json(api_base, "/runtime/ebpf/events", event, token)


def post_batch(api_base: str, events: list[dict], token: str = "") -> dict:
    """批量确认协议：响应含 ack 布尔与 accepted/duplicates/rejected 计数。

    仅当 HTTP 200 且响应 JSON 可解析时返回（即服务端确认已持久化）；
    任何网络错误/非 2xx/解析失败均抛异常，调用方按未确认处理。
    """
    result = post_json(api_base, BATCH_ENDPOINT, {"events": events}, token)
    if result.get("ack") is not True:
        raise ValueError("服务端未返回 ack=true（不视为已确认）")
    # Keep the entire batch in WAL on partial rejection. Accepted entries replay
    # idempotently; rejected entries remain available for operator correction.
    if result.get("rejected"):
        raise ValueError("Server rejected events; batch retained in WAL")
    accepted, duplicates = result.get("accepted"), result.get("duplicates")
    if (type(accepted) is not int or type(duplicates) is not int or
            accepted < 0 or duplicates < 0 or accepted + duplicates != len(events)):
        raise ValueError("Incomplete batch acknowledgement; retained in WAL")
    return result


def backoff_delay(attempt: int) -> float:
    """第 attempt 次（从 1 起）重试前的退避时长：1,2,4,...,16s + 0~30% 抖动。

    抖动仅用于错峰重连（防惊群），采用系统级安全随机源。
    """
    delay = min(BACKOFF_BASE_S * (2 ** (attempt - 1)), BACKOFF_CAP_S)
    return delay * (1.0 + _SYSTEM_RANDOM.uniform(0.0, 0.3))


_SYSTEM_RANDOM = random.SystemRandom()


def enrich_event(event, *, asset_id=None, hostname="", sensor_id="", boot_id=""):
    """Preserve upstream identity; a conflicting asset binding is rejected."""
    if not isinstance(event, dict):
        raise ValueError("Expected one JSON object per line")
    result = dict(event)
    for key, value in (("asset_id", asset_id), ("hostname", hostname), ("sensor_id", sensor_id), ("boot_id", boot_id)):
        if value and result.get(key) not in (None, "", value):
            raise ValueError("Conflicting upstream " + key)
        if value:
            result[key] = value
    return result


def read_boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


class ReliabilityMetrics:
    """P0 采集可靠性计数（0=真实为零；从未发生计 0；无法得知不入此层，
    由 sensor_health 的 unavailable 语义表达）。"""

    def __init__(self):
        self.received = 0          # 读到的原始行数
        self.parsed = 0            # 成功解析为事件对象的行数
        self.uploaded = 0          # 服务端确认新入库
        self.duplicates = 0        # 服务端确认的幂等命中（重试/重放安全）
        self.rejected = 0          # 客户端拒绝行（格式/超长）+ 服务端逐条拒绝
        self.retries = 0           # 已执行的重试次数
        self.failed_batches = 0    # 重试耗尽仍未确认的批次数
        self.spool_pending = 0     # 当前 WAL 中未确认事件数
        self.spool_bytes = 0           # WAL 未确认字节（有界性可见）
        self.spool_blocked_events = 0  # 背压暂拒接收计数（明确降级，非丢弃）
        self.spool_corrupt_lines = 0   # WAL 损坏行（跳过不阻塞恢复，如实计数）
        self.spool_full = False    # 容量/磁盘保护触发态（心跳 degraded 依据）
        self.last_success_at = ""  # 最后一次服务端确认时间（ISO）

    def snapshot(self) -> dict:
        return {
            "received": self.received, "parsed": self.parsed,
            "uploaded": self.uploaded, "duplicates": self.duplicates,
            "rejected": self.rejected, "retries": self.retries,
            "failed_batches": self.failed_batches, "spool_pending": self.spool_pending,
            "spool_bytes": self.spool_bytes,
            "spool_blocked_events": self.spool_blocked_events,
            "spool_corrupt_lines": self.spool_corrupt_lines,
            "last_success_at": self.last_success_at or "unknown",
        }

    def note_success(self, result: dict, now_iso: str) -> None:
        self.uploaded += int(result.get("accepted", 0))
        self.duplicates += int(result.get("duplicates", 0))
        self.rejected += int(len(result.get("rejected", []) or []))
        self.last_success_at = now_iso


class Spool:
    """本地断点续传：未确认批次逐行追加（每行一个 JSON 数组），确认后截断。

    语义：spool 中的事件是"已接收、未确认"，不是丢失；退出时非空即非零退出码。
    """

    def __init__(self, path: str):
        self.path = Path(path)

    def append(self, events: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(events, ensure_ascii=False, default=str) + "\n")

    def load(self):
        """读取全部未确认行：返回 (原行, 事件列表)；损坏行跳过（不阻塞恢复）。"""
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events = json.loads(line)
            except ValueError:
                continue
            if isinstance(events, list) and events:
                entries.append((line, events))
        return entries

    def rewrite(self, keep_lines):
        """以仍未确认的行整体重写 spool（已确认行不写回，避免重复重传）。"""
        if not keep_lines:
            if self.path.exists():
                self.path.write_text("", encoding="utf-8")
            return
        self.path.write_text(chr(10).join(keep_lines) + chr(10), encoding="utf-8")

    def pending_count(self):
        return sum(len(events) for _, events in self.load())


class WalSpool:
    """Write-Ahead Spool：事件在首次发送前持久化，服务端确认后移除。

    文件格式（单文件，向后兼容 P0 旧 spool）：
      "[" 开头行 = P0 旧批次行（JSON 数组），载入时展开为单事件；
      "{" 开头行 = v2 单事件行（write-ahead 记录）。
    首次确认收缩（compact）后文件自然迁移为纯 v2 格式（旧格式无需停机迁移）。

    崩溃时序与语义（诚实边界）：
      append(+fsync) → send → ack（内存移除）→ compact（原子重写）。
    - 发送前崩溃：事件仍在 WAL → 重启续传，不丢失；
    - ack 与 compact 之间崩溃：已确认事件被重放 → 服务端指纹幂等去重
      （duplicates 如实计数），不产生重复入库；
    - compact 以临时文件 + os.replace 原子替换，崩溃于替换前后均为完整文件；
    - 损坏行载入时跳过（不阻塞恢复）并如实计数；收缩时不再保留
      （不可重放的残行无限保留只会无界增长）——非静默：计数呈现。

    有界性：条数/字节容量上限 + spool 所在盘剩余空间下限。append 触界返回
    False（调用方背压暂存重试），绝不静默丢弃；compact 只移除已确认行，
    未确认数据永不被本类删除。

    线程模型：全部方法仅在主循环线程调用（读线程只经 queue 交接），无锁。
    """

    WARN_RATIO = 0.8  # 告警阈值：已用量达到容量 80% 时心跳/日志提示

    def __init__(self, path: str, *, max_events: int = 0, max_bytes: int = 0,
                 min_free_bytes: int = 0, fsync_mode: str = "always"):
        if fsync_mode not in ("always", "batch", "off"):
            raise ValueError(f"unknown wal fsync mode: {fsync_mode!r}")
        self.path = Path(path)
        self.max_events = max_events        # 0 = 不限（不推荐；默认应有界）
        self.max_bytes = max_bytes
        self.min_free_bytes = min_free_bytes
        self.fsync_mode = fsync_mode
        self._events: deque[tuple[str, dict]] = deque()  # 未确认事件（FIFO）
        self._acked_uncompacted = 0
        self.full = False                   # 保护触发态（背压中）
        self.blocked_events = 0             # 背压暂拒接收的事件数
        self.corrupt_lines = 0              # 载入时跳过的损坏行数
        self._last_alert = 0.0
        self._load()

    # ── 载入（兼容 P0 旧批次行；启动时调用一次） ──
    def _load(self):
        if not self.path.exists():
            return
        for raw in self.path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                self.corrupt_lines += 1
                continue
            if isinstance(data, list):
                for event in data:
                    if isinstance(event, dict):
                        self._events.append((json.dumps(event, ensure_ascii=False, default=str), event))
            elif isinstance(data, dict):
                self._events.append((line, data))

    # ── 有界性检查 ──
    def pending_bytes(self) -> int:
        return sum(len(line) + 1 for line, _obj in self._events)

    def _disk_free(self):
        try:
            return shutil.disk_usage(self.path.parent if str(self.path.parent) else ".").free
        except OSError:
            return None  # 无法判定 → 不启用磁盘保护（如实，不虚构可用空间）

    def capacity_reason(self, incoming_bytes: int = 0) -> str:
        """返回触界原因串；未触发返回空串。含即将写入事件自身的体积。"""
        if self.max_events and len(self._events) + 1 > self.max_events:
            return f"spool events {len(self._events) + 1} > capacity {self.max_events}"
        if self.max_bytes and self.pending_bytes() + incoming_bytes > self.max_bytes:
            return f"spool bytes {self.pending_bytes() + incoming_bytes} > capacity {self.max_bytes}"
        free = self._disk_free()
        if self.min_free_bytes and free is not None and free < self.min_free_bytes:
            return f"disk free {free} bytes < floor {self.min_free_bytes}"
        return ""

    def backlog_warn(self) -> str:
        """积压告警：当前用量达到任一容量阈值 80% 返回原因串（不阻断写入）。"""
        ratios = []
        if self.max_events:
            ratios.append(len(self._events) / self.max_events)
        if self.max_bytes:
            ratios.append(self.pending_bytes() / self.max_bytes)
        return "spool backlog warning" if ratios and max(ratios) >= self.WARN_RATIO else ""

    def _alert(self, reason: str) -> None:
        now = time.monotonic()
        if now - self._last_alert >= 30.0:  # 告警限频，避免日志风暴
            self._last_alert = now
            print(f"[ALERT] IoTGuard spool protection: {reason}; backpressure engaged "
                  f"(events delayed and retried, none dropped; unconfirmed data never deleted)",
                  file=sys.stderr, flush=True)

    # ── 写前持久化 ──
    def append(self, event: dict) -> bool:
        """write-ahead：先持久化后发送。返回 False = 保护触发，事件未写入
        （调用方暂存重试——明确降级，不丢弃）。"""
        line = json.dumps(event, ensure_ascii=False, default=str)
        reason = self.capacity_reason(len(line) + 1)
        if reason:
            self.full = True
            self.blocked_events += 1
            self._alert(reason)
            return False
        self.full = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            if self.fsync_mode == "always":
                os.fsync(handle.fileno())
        self._events.append((line, event))
        warn = self.backlog_warn()
        if warn:
            self._alert(warn)
        return True

    def fsync_batch(self) -> None:
        """batch 模式：发送前整文件落盘（保证已发送事件已持久化）。"""
        if self.fsync_mode != "batch" or not self._events:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.flush()
            os.fsync(handle.fileno())

    # ── 发送 / 确认 / 收缩 ──
    def take(self, n: int) -> list[tuple[str, dict]]:
        """FIFO 取前 n 个 (行, 事件)；不修改 WAL（确认前数据不离开）。"""
        return [item for item in itertools.islice(self._events, max(0, n))]

    def ack(self, n: int) -> None:
        """服务端确认前 n 个事件。文件收缩延迟到 compact——ack 与收缩之间
        崩溃导致重放时由服务端幂等去重（不重复入库）。"""
        for _ in range(min(n, len(self._events))):
            self._events.popleft()
        self._acked_uncompacted += n

    def compact(self, force: bool = False) -> None:
        """把仍未确认事件原子重写回文件（临时文件 + os.replace）。
        只移除已确认行——任何未确认数据永不被本方法丢弃。"""
        if not self._acked_uncompacted:
            return
        if not force and self._acked_uncompacted < max(32, len(self._events)):
            return  # 攒批收缩，避免每批整文件重写
        tmp = self.path.with_name(self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8") as handle:
            for line, _obj in self._events:
                handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        self._acked_uncompacted = 0

    def pending_count(self) -> int:
        return len(self._events)


def send_batch_with_retry(api_base, events, token, transport, metrics: ReliabilityMetrics,
                          max_retries: int = DEFAULT_MAX_RETRIES) -> bool:
    """有界重试 + 指数退避发送一批事件；成功返回 True（已获服务端确认）。"""
    for attempt in range(1 + max_retries):
        if attempt:
            metrics.retries += 1
            time.sleep(backoff_delay(attempt))
        try:
            result = transport(api_base, events, token)
        except (OSError, ValueError):
            continue
        metrics.note_success(result, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        return True
    metrics.failed_batches += 1
    return False


def sensor_health(path):
    """A live uploader alone does not prove the upstream probe is healthy.

    A supervisor can atomically publish a JSON health file after independently
    checking the probe. Stale or missing health is explicitly degraded.
    探针丢失计数（dropped_events）只有在该文件中如实出现时才为数值，
    否则 None → 上层呈现 unavailable（绝不虚构为零）。
    """
    fallback = {"status": "degraded", "dropped_events": None, "capabilities": {},
                "detail": "Uploader alive; upstream probe health/coverage not confirmed"}
    if not path:
        return fallback
    try:
        file = Path(path)
        if file.stat().st_size > 10000 or time.time() - file.stat().st_mtime > 90:
            return {**fallback, "detail": "Probe health file stale or oversized"}
        result = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("status") not in {"running", "degraded", "stopped", "unsupported"}:
            return fallback
        drops = result.get("dropped_events")
        if drops is not None and (type(drops) is not int or drops < 0):
            return fallback
        capabilities = result.get("capabilities", {})
        if not isinstance(capabilities, dict):
            return fallback
        return {"status": result["status"], "dropped_events": drops, "capabilities": capabilities,
                "detail": str(result.get("detail", "Supervisor-reported probe health"))[:800]}
    except (OSError, ValueError, TypeError):
        return fallback


def heartbeat_payload(args, rejected=0, stopped=False, metrics: ReliabilityMetrics | None = None):
    health = sensor_health(args.health_file)
    if stopped:
        health["status"] = "stopped"
    elif rejected or (metrics and (metrics.failed_batches or metrics.spool_full)):
        health["status"] = "degraded"
    capabilities = dict(health["capabilities"])
    capabilities["transport"] = "batch_confirm_v2" if not getattr(args, "legacy_single", False) else "jsonl_forwarder"
    capabilities["rejected_lines"] = rejected
    capabilities["upstream_health_source"] = "supervisor_file" if args.health_file else "unavailable"
    capabilities["spool_full"] = bool(getattr(metrics, "spool_full", False))
    if metrics is not None:
        capabilities["metrics"] = metrics.snapshot()
    health["capabilities"] = capabilities
    return {"asset_id": args.asset_id, "sensor_id": args.sensor_id, "source": args.source, **health}


def parse_falco_text(line: str) -> dict | None:
    match = re.search(
        r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"(?P<severity>Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug)\s+"
        r"(?P<message>.*)",
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    message = match.group("message")
    proc = re.search(r"(?:proc\.name|proc_exepath|proc\.exepath)=([^\s)]+)", message)
    return {
        "timestamp": match.group("time"),
        "source": "falco_text",
        "event_type": "falco_rule_alert",
        "severity": match.group("severity").lower(),
        "rule": message.split("(", 1)[0].strip(),
        "process_name": proc.group(1).split("/")[-1] if proc else "",
        "commandline": message,
        "raw": {"line": line},
    }


def iter_lines(path: str | None):
    if path:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            yield from handle
    else:
        yield from sys.stdin


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload Falco/Tetragon JSONL events to LinuxGuard (batch+retry+spool).")
    parser.add_argument("--api", default="http://localhost:8000/api", help="LinuxGuard API base URL")
    parser.add_argument("--file", help="JSONL file path. If omitted, read stdin.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max number of events to upload")
    parser.add_argument("--asset-id", type=int, help="Explicit registered asset ID")
    parser.add_argument("--hostname", default="", help="Registered hostname; never silently overwrite upstream identity")
    parser.add_argument("--sensor-id", default="", help="Stable identifier of this device's probe")
    parser.add_argument("--boot-id", default="", help="Explicit boot ID; historical files never inherit the current boot ID")
    parser.add_argument("--source", choices=["falco", "tetragon", "bpftrace", "c_ebpf", "runtime_probe"], default="runtime_probe")
    parser.add_argument("--heartbeat", action="store_true", help="Publish coverage heartbeats for a live stdin stream")
    parser.add_argument("--heartbeat-seconds", type=int, default=30)
    parser.add_argument("--health-file", help="Fresh JSON status published by a probe supervisor (not by this uploader)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Events per batch (default 50)")
    parser.add_argument("--flush-seconds", type=float, default=DEFAULT_BATCH_FLUSH_S, help="Flush interval (default 2s)")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help="Bounded retries per batch (default 5)")
    parser.add_argument("--spool-file", default="/tmp/linuxguard-forwarder-spool.jsonl",
                        help="Write-ahead spool file (unconfirmed events resume on restart)")
    parser.add_argument("--spool-max-events", type=int, default=200_000,
                        help="WAL capacity bound in events; 0=unlimited (not recommended)")
    parser.add_argument("--spool-max-bytes", type=int, default=256 * 1024 * 1024,
                        help="WAL capacity bound in bytes; 0=unlimited (not recommended)")
    parser.add_argument("--spool-min-free-mb", type=int, default=200,
                        help="Keep this much disk free where the spool lives; 0=disabled")
    parser.add_argument("--wal-fsync", choices=["always", "batch", "off"], default="always",
                        help="Durability: fsync per appended event / per batch before send / off")
    parser.add_argument("--legacy-single", action="store_true",
                        help="Use the legacy one-event-per-POST path (compatibility; no batch ack)")
    args = parser.parse_args()
    token = os.getenv("LINUXGUARD_CONTROL_TOKEN", "")
    if args.asset_id is not None and args.asset_id < 1:
        parser.error("--asset-id must be positive")
    if args.heartbeat and (args.file or not args.asset_id or not token):
        parser.error("--heartbeat requires live stdin, --asset-id and LINUXGUARD_CONTROL_TOKEN")
    if not 5 <= args.heartbeat_seconds <= 60:
        parser.error("--heartbeat-seconds must be between 5 and 60")
    if not 1 <= args.batch_size <= 500:
        parser.error("--batch-size must be between 1 and 500")
    if not 0 <= args.max_retries <= 10:
        parser.error("--max-retries must be between 0 and 10")
    if not 0 <= args.spool_max_events <= 10_000_000:
        parser.error("--spool-max-events must be between 0 and 10000000")
    if not 0 <= args.spool_max_bytes <= 64 * 1024 * 1024 * 1024:
        parser.error("--spool-max-bytes must be between 0 and 64GiB")
    if not 0 <= args.spool_min_free_mb <= 1_000_000:
        parser.error("--spool-min-free-mb must be between 0 and 1000000")
    args.sensor_id = args.sensor_id or socket.gethostname() + ":" + args.source
    boot_id = args.boot_id or (read_boot_id() if not args.file else "")
    metrics = ReliabilityMetrics()
    wal = WalSpool(args.spool_file,
                   max_events=args.spool_max_events,
                   max_bytes=args.spool_max_bytes,
                   min_free_bytes=args.spool_min_free_mb * 1024 * 1024,
                   fsync_mode=args.wal_fsync)
    transport = post_event if args.legacy_single else post_batch
    if wal.corrupt_lines:
        metrics.spool_corrupt_lines = wal.corrupt_lines
        print(f"WAL recovery: skipped {wal.corrupt_lines} corrupt line(s) "
              f"(counted, not silently dropped)", file=sys.stderr)

    def sync_spool_metrics():
        metrics.spool_pending = wal.pending_count()
        metrics.spool_bytes = wal.pending_bytes()
        metrics.spool_blocked_events = wal.blocked_events
        metrics.spool_full = wal.full

    uploaded = 0
    unconfirmed = 0

    def send_chunk() -> bool:
        """发送 WAL 前端一个批次；仅服务端确认后从 WAL 移除（确认前数据
        不离开 WAL）。返回 False = 该批次未获确认（保留在 WAL，未确认 ≠ 丢失）。"""
        nonlocal uploaded, unconfirmed
        chunk = wal.take(args.batch_size)
        if not chunk:
            return True
        wal.fsync_batch()  # batch 模式：发送前落盘（always 模式已在 append 时落盘）
        if args.legacy_single:
            sent = 0
            for _line, obj in chunk:
                try:
                    transport(args.api, obj, token)
                    sent += 1
                except (OSError, ValueError):
                    break
            if sent:
                wal.ack(sent)
                uploaded += sent
                metrics.uploaded += sent
            if sent < len(chunk):
                metrics.failed_batches += 1
                unconfirmed += 1
                return False
            return True
        if send_batch_with_retry(args.api, [obj for _line, obj in chunk], token,
                                 post_batch, metrics, args.max_retries):
            wal.ack(len(chunk))
            uploaded += len(chunk)
            return True
        unconfirmed += 1
        return False

    # ── 恢复：write-ahead 重放（兼容 P0 旧批次行，载入即展开）──
    # 离线时保留在 WAL；实时循环按退避节奏继续尝试——后端恢复后无需重启即续传。
    while wal.pending_count():
        if not send_chunk():
            break
        wal.compact()
    sync_spool_metrics()

    pending_queue: queue.Queue = queue.Queue(maxsize=2048)
    finished = object()

    def read_input():
        try:
            for line in iter_lines(args.file):
                pending_queue.put(line)
        except Exception as exc:  # 顶层读线程把异常带回主循环
            pending_queue.put(exc)
        finally:
            pending_queue.put(finished)

    threading.Thread(target=read_input, daemon=True).start()

    rejected = 0
    staged: deque = deque()  # 背压暂存（≤队列上限 2048，内存镜像）：等待 WAL 容量释放
    staged_eof_attempts = 0
    next_send_at = 0.0
    next_heartbeat = 0.0
    input_done = False
    stop_reading = False
    in_exit_summary = False

    try:
        while True:
            if args.heartbeat and time.monotonic() >= next_heartbeat:
                # 心跳失败不再致命：后端离线时转发器必须存活并退避重试
                # （P0 语义为心跳异常即退出，依赖 systemd 重启；2.1 起运行中自愈）。
                try:
                    post_json(args.api, "/runtime/sensors/heartbeat",
                              heartbeat_payload(args, rejected, metrics=metrics), token)
                except (OSError, ValueError) as exc:
                    print(f"Heartbeat unavailable ({exc}); continuing offline retry", file=sys.stderr)
                next_heartbeat = time.monotonic() + args.heartbeat_seconds

            # 背压恢复：优先把暂存事件写入 WAL（确认收缩释放容量后立即继续）
            while staged and wal.append(staged[0]):
                staged.popleft()

            line = None
            if not stop_reading and not input_done and len(staged) < 2048:
                try:
                    line = pending_queue.get(timeout=0.25 if (wal.pending_count() or staged) else 1)
                except queue.Empty:
                    pass
            if line is finished:
                input_done = True
                line = None
            elif isinstance(line, Exception):
                raise line

            if line is not None:
                line = line.strip()
                if line and not in_exit_summary:
                    if line.startswith(FALCO_EXIT_SUMMARY_PREFIXES):
                        in_exit_summary = True
                    else:
                        metrics.received += 1
                        if len(line) > 1_000_000:
                            rejected += 1
                            metrics.rejected += 1
                        else:
                            try:
                                event = json.loads(line)
                            except json.JSONDecodeError:
                                event = parse_falco_text(line)
                            if not isinstance(event, dict):
                                rejected += 1
                                metrics.rejected += 1
                            else:
                                metrics.parsed += 1
                                event = enrich_event(event, asset_id=args.asset_id, hostname=args.hostname,
                                                     sensor_id=args.sensor_id, boot_id=boot_id)
                                if wal.append(event):
                                    # 不足一批也按时发送（flush_seconds 内）
                                    next_send_at = min(next_send_at or time.monotonic() + args.flush_seconds,
                                                       time.monotonic() + args.flush_seconds)
                                    if args.limit and metrics.parsed >= args.limit:
                                        stop_reading = True
                                else:
                                    # 明确降级：容量/磁盘保护触发 → 背压暂存（内存镜像，
                                    # ≤队列上限），事件不丢弃；暂存满即停止读入 → 上游
                                    # 管道自然反压，falco 侧丢弃计入其自身统计（可观测）。
                                    # blocked 计数由 WalSpool（append 拒绝次数）统计。
                                    staged.append(event)

            pending = wal.pending_count()
            eof_drain = input_done and not staged
            if pending and (pending >= args.batch_size or time.monotonic() >= next_send_at or eof_drain):
                if not send_chunk():
                    if eof_drain:
                        break  # EOF 最终尝试仍失败：保留 WAL，非零退出（下次启动续传）
                else:
                    wal.compact()
                next_send_at = time.monotonic() + args.flush_seconds
            if eof_drain and not wal.pending_count():
                break
            if input_done and staged:
                # EOF + 背压：给容量释放留出有限宽限期，之后如实上报未送达
                staged_eof_attempts += 1
                time.sleep(0.5)
                if staged_eof_attempts > 10:
                    print(f"CRITICAL: {len(staged)} in-flight event(s) could not be persisted "
                          f"to WAL (spool protection active at EOF); explicitly NOT delivered "
                          f"(counted, not silent)", file=sys.stderr)
                    break
            if line is None and wal.pending_count() and time.monotonic() < next_send_at:
                time.sleep(0.05)  # EOF/无输入：等待下一发送节拍（避免忙等）
            sync_spool_metrics()
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        # KeyboardInterrupt（服务停止信号 KillSignal=SIGINT）：在途事件已在
        # WAL（write-ahead 不变量）；仅背压暂存事件需尽力补写——"未确认 ≠ 丢失"。
        print("Upload stopped: " + (str(exc) or "interrupted"), file=sys.stderr)
        while staged and wal.append(staged[0]):  # 停止信号：尽力持久化暂存事件
            staged.popleft()
        if staged:
            print(f"CRITICAL: {len(staged)} in-flight event(s) could not be persisted to WAL "
                  f"on stop (spool protection active); explicitly NOT delivered", file=sys.stderr)
        wal.compact(force=True)  # 干净边界：文件收敛为未确认集合（下次启动续传）
        sync_spool_metrics()
        return 1
    finally:
        if args.heartbeat:
            try:
                post_json(args.api, "/runtime/sensors/heartbeat",
                          heartbeat_payload(args, rejected, stopped=True, metrics=metrics), token)
            except OSError:
                print("Final heartbeat unavailable; server will expire the last heartbeat.",
                      file=sys.stderr)

    spool_left = wal.pending_count()
    wal.compact(force=True)  # 干净边界：文件收敛为未确认集合（下次启动续传）
    sync_spool_metrics()
    summary = metrics.snapshot()
    print(f"Uploaded {uploaded} runtime events; duplicates {summary['duplicates']}; "
          f"rejected {rejected} lines; retries {summary['retries']}; "
          f"failed_batches {summary['failed_batches']}; spool_pending {spool_left} "
          f"({summary['spool_bytes']} bytes; blocked {summary['spool_blocked_events']})")
    # 明确失败/未确认状态：WAL 非空、背压暂存或存在未确认批次 → 非零退出码
    return 1 if (rejected or spool_left or unconfirmed or staged) else 0


if __name__ == "__main__":
    raise SystemExit(main())
