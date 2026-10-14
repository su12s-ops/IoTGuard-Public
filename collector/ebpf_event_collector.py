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

Usage on Ubuntu VM:
  falco -o json_output=true 2>/dev/null | python3 ebpf_event_collector.py --api http://WINDOWS_IP:8000/api
  tetragon --export-filename /tmp/tetragon.jsonl
  python3 ebpf_event_collector.py --file /tmp/tetragon.jsonl --api http://WINDOWS_IP:8000/api
"""

import argparse
import json
import os
import queue
import random
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
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
        self.spool_pending = 0     # 当前 spool 中未确认事件数
        self.last_success_at = ""  # 最后一次服务端确认时间（ISO）

    def snapshot(self) -> dict:
        return {
            "received": self.received, "parsed": self.parsed,
            "uploaded": self.uploaded, "duplicates": self.duplicates,
            "rejected": self.rejected, "retries": self.retries,
            "failed_batches": self.failed_batches, "spool_pending": self.spool_pending,
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
    elif rejected or (metrics and metrics.failed_batches):
        health["status"] = "degraded"
    capabilities = dict(health["capabilities"])
    capabilities["transport"] = "batch_confirm_v2" if not getattr(args, "legacy_single", False) else "jsonl_forwarder"
    capabilities["rejected_lines"] = rejected
    capabilities["upstream_health_source"] = "supervisor_file" if args.health_file else "unavailable"
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
    parser.add_argument("--source", choices=["falco", "tetragon", "runtime_probe"], default="runtime_probe")
    parser.add_argument("--heartbeat", action="store_true", help="Publish coverage heartbeats for a live stdin stream")
    parser.add_argument("--heartbeat-seconds", type=int, default=30)
    parser.add_argument("--health-file", help="Fresh JSON status published by a probe supervisor (not by this uploader)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Events per batch (default 50)")
    parser.add_argument("--flush-seconds", type=float, default=DEFAULT_BATCH_FLUSH_S, help="Flush interval (default 2s)")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help="Bounded retries per batch (default 5)")
    parser.add_argument("--spool-file", default="/tmp/linuxguard-forwarder-spool.jsonl",
                        help="Local spool for unconfirmed batches (resume on restart)")
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
    args.sensor_id = args.sensor_id or socket.gethostname() + ":" + args.source
    boot_id = args.boot_id or (read_boot_id() if not args.file else "")
    metrics = ReliabilityMetrics()
    spool = Spool(args.spool_file)
    transport = post_event if args.legacy_single else post_batch

    # ── 恢复：先重传历史未确认批次（spool 断点续传；已确认行不写回） ──
    keep_lines = []
    for line, pending in spool.load():
        if send_batch_with_retry(args.api, pending, token, post_batch, metrics, args.max_retries):
            continue
        keep_lines.append(line)  # 仍失败：留在 spool（未确认，不是丢失）
    spool.rewrite(keep_lines)
    metrics.spool_pending = spool.pending_count()


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
    uploaded = 0
    batch: list = []
    batch_deadline = 0.0
    next_heartbeat = 0.0
    input_done = False
    unconfirmed = metrics.failed_batches
    in_exit_summary = False

    def flush_batch(force=False):
        nonlocal batch, uploaded, unconfirmed, batch_deadline
        if not batch:
            return
        if not force and len(batch) < args.batch_size and time.monotonic() < batch_deadline:
            return
        events = batch
        batch = []
        if args.legacy_single:
            sent = 0
            for event in events:
                try:
                    transport(args.api, event, token)
                    sent += 1
                except (OSError, ValueError):
                    spool.append([event])
                    unconfirmed += 1
            uploaded += sent
            metrics.uploaded += sent
        elif send_batch_with_retry(args.api, events, token, transport, metrics, args.max_retries):
            uploaded += len(events)
        else:
            spool.append(events)
            unconfirmed += 1
            metrics.spool_pending = spool.pending_count()
        batch_deadline = time.monotonic() + args.flush_seconds

    try:
        while True:
            if args.heartbeat and time.monotonic() >= next_heartbeat:
                post_json(args.api, "/runtime/sensors/heartbeat",
                          heartbeat_payload(args, rejected, metrics=metrics), token)
                next_heartbeat = time.monotonic() + args.heartbeat_seconds
            try:
                line = pending_queue.get(timeout=0.25 if batch else 1)
                input_done = False
            except queue.Empty:
                if input_done:
                    break
                flush_batch()
                continue
            if line is finished:
                input_done = True
                flush_batch()
                continue
            if isinstance(line, Exception):
                raise line
            line = line.strip()
            if not line:
                continue
            if in_exit_summary:
                continue
            if line.startswith(FALCO_EXIT_SUMMARY_PREFIXES):
                in_exit_summary = True
                continue
            metrics.received += 1
            if len(line) > 1_000_000:
                rejected += 1
                metrics.rejected += 1
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = parse_falco_text(line)
            if not isinstance(event, dict):
                rejected += 1
                metrics.rejected += 1
                continue
            metrics.parsed += 1
            event = enrich_event(event, asset_id=args.asset_id, hostname=args.hostname,
                                 sensor_id=args.sensor_id, boot_id=boot_id)
            batch.append(event)
            if not batch_deadline:
                batch_deadline = time.monotonic() + args.flush_seconds
            if len(batch) >= args.batch_size:
                flush_batch(force=True)
            if args.limit and metrics.parsed >= args.limit:
                flush_batch(force=True)
                break
        flush_batch(force=True)
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        # KeyboardInterrupt（服务停止信号 KillSignal=SIGINT）：在途批次入
        # spool 后退出——"未确认 ≠ 丢失"，下次启动断点续传（P0 语义）。
        print("Upload stopped: " + (str(exc) or "interrupted"), file=sys.stderr)
        if batch:
            spool.append(batch)
            metrics.spool_pending = spool.pending_count()
        return 1
    finally:
        if args.heartbeat:
            try:
                post_json(args.api, "/runtime/sensors/heartbeat",
                          heartbeat_payload(args, rejected, stopped=True, metrics=metrics), token)
            except OSError:
                print("Final heartbeat unavailable; server will expire the last heartbeat.",
                      file=sys.stderr)

    spool_left = spool.pending_count()
    summary = metrics.snapshot()
    print(f"Uploaded {uploaded} runtime events; duplicates {summary['duplicates']}; "
          f"rejected {rejected} lines; retries {summary['retries']}; "
          f"failed_batches {summary['failed_batches']}; spool_pending {spool_left}")
    # 明确失败/未确认状态：spool 非空或存在未确认批次 → 非零退出码
    return 1 if (rejected or spool_left or unconfirmed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
