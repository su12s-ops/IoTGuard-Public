#!/usr/bin/env python3
"""
Read Falco/Tetragon JSONL events and upload them to LinuxGuard.

Usage on Ubuntu VM:
  falco -o json_output=true 2>/dev/null | python3 ebpf_event_collector.py --api http://WINDOWS_IP:8000/api
  tetragon --export-filename /tmp/tetragon.jsonl
  python3 ebpf_event_collector.py --file /tmp/tetragon.jsonl --api http://WINDOWS_IP:8000/api
"""

import argparse
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path


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


def post_json(api_base: str, path: str, event: dict, token: str = "") -> None:
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
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def post_event(api_base: str, event: dict, token: str = "") -> None:
    post_json(api_base, "/runtime/ebpf/events", event, token)


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


def sensor_health(path):
    """A live uploader alone does not prove the upstream probe is healthy.

    A supervisor can atomically publish a JSON health file after independently
    checking the probe. Stale or missing health is explicitly degraded.
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


def heartbeat_payload(args, rejected=0, stopped=False):
    health = sensor_health(args.health_file)
    if stopped:
        health["status"] = "stopped"
    elif rejected:
        health["status"] = "degraded"
    health["capabilities"] = {**health["capabilities"], "transport": "jsonl_forwarder",
                              "rejected_lines": rejected, "upstream_health_source": "supervisor_file" if args.health_file else "unavailable"}
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
    parser = argparse.ArgumentParser(description="Upload Falco/Tetragon JSONL events to LinuxGuard.")
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
    args = parser.parse_args()
    token = os.getenv("LINUXGUARD_CONTROL_TOKEN", "")
    if args.asset_id is not None and args.asset_id < 1:
        parser.error("--asset-id must be positive")
    if args.heartbeat and (args.file or not args.asset_id or not token):
        parser.error("--heartbeat requires live stdin, --asset-id and LINUXGUARD_CONTROL_TOKEN")
    if not 5 <= args.heartbeat_seconds <= 60:
        parser.error("--heartbeat-seconds must be between 5 and 60")
    args.sensor_id = args.sensor_id or socket.gethostname() + ":" + args.source
    boot_id = args.boot_id or (read_boot_id() if not args.file else "")
    pending = queue.Queue(maxsize=256)
    finished = object()
    def read_input():
        try:
            for line in iter_lines(args.file):
                pending.put(line)
        except Exception as exc:
            pending.put(exc)
        finally:
            pending.put(finished)
    threading.Thread(target=read_input, daemon=True).start()
    uploaded = 0
    rejected = 0
    next_heartbeat = 0
    try:
        while True:
            if args.heartbeat and time.monotonic() >= next_heartbeat:
                post_json(args.api, "/runtime/sensors/heartbeat", heartbeat_payload(args, rejected), token)
                next_heartbeat = time.monotonic() + args.heartbeat_seconds
            try:
                line = pending.get(timeout=1)
            except queue.Empty:
                continue
            if line is finished:
                break
            if isinstance(line, Exception):
                raise line
            line = line.strip()
            if not line:
                continue
            if len(line) > 1_000_000:
                rejected += 1
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = parse_falco_text(line)
            if not isinstance(event, dict):
                rejected += 1
                continue
            event = enrich_event(event, asset_id=args.asset_id, hostname=args.hostname,
                                 sensor_id=args.sensor_id, boot_id=boot_id)
            post_event(args.api, event, token)
            uploaded += 1
            if args.limit and uploaded >= args.limit:
                break
    except (OSError, ValueError) as exc:
        print("Upload stopped: " + str(exc), file=sys.stderr)
        return 1
    finally:
        if args.heartbeat:
            try:
                post_json(args.api, "/runtime/sensors/heartbeat", heartbeat_payload(args, rejected, stopped=True), token)
            except OSError:
                print("Final heartbeat unavailable; server will expire the last heartbeat.", file=sys.stderr)
    print(f"Uploaded {uploaded} runtime events; rejected {rejected} lines")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
