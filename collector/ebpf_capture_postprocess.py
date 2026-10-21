#!/usr/bin/env python3
"""bpftrace 管道行 → 后端统一事件 JSONL（P1 增强后处理，独立可测）。

输入：collector/ebpf_trace_capture.sh 中 bpftrace 输出的 ``LG|`` 管道行。

P1 增强（eBPF 2.0 P1-1：execve argv + process start_time + 合成会话键）：
- execve 新格式：``LG|execve|nsecs|pid|ppid|uid|comm|start_time|argv段``；
  argv 以 ``\\x1f`` 分隔，NULL 以 ``\\x1e`` 标记（内核侧带 NULL 守卫，
  读取不会越过 argv 终止符进入 envp）。BPF 栈 512B 预算下不重复读
  内核 filename（argv[0] 即程序名来源）；父进程名由本模块按 pid 顺序
  跟踪补齐（与旧 @procname map 同为"探针启动后已知"语义，不虚构）；
- connect/openat 同样携带 start_time，供同一进程实例的行为关联；
- process_exec_id = ``lg-{boot_id前8}-{pid}-{start_time}``（确定性合成
  会话键：PID 复用可区分，boot_id 区分同主机跨重启）；
- boot_id 采自 /proc/sys/kernel/random/boot_id，属于采集端可自证的
  事件内容（转发器仍不注入身份键——P0 语义不变）。

向后兼容：支持解析 P0 及更早的无 start_time/argv 旧格式（按字段数
区分新旧；旧格式输出与原行为一致，不虚构新字段）。
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:  # Linux 真实采集环境
    import pwd
except ImportError:  # Windows 测试环境：以数字 uid 呈现，不虚构用户名
    pwd = None

# argv 段分隔符（与 bpftrace printf 中的 \x1f / \x1e 对应）
ARGV_SEP = "\x1f"
ARGV_NULL = "\x1e"

# 会话键中的 boot_id 截断长度（仅降低噪声，不影响区分度）
SESSION_BOOT_PREFIX = 8

_users: dict[int, str] = {}


def read_boot_id() -> str:
    """读取本机 boot_id；不可用时返回空串（会话键退化为 pid+start_time）。"""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return ""


def read_boot_epoch() -> int | None:
    """读取 /proc/stat btime（开机纪元秒）；不可用时返回 None。"""
    try:
        for line in Path("/proc/stat").read_text(encoding="ascii").splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def user_name(uid: int) -> str:
    if uid not in _users:
        try:
            _users[uid] = pwd.getpwuid(uid).pw_name if pwd else str(uid)
        except KeyError:
            _users[uid] = str(uid)
    return _users[uid]


def to_iso(nsecs: str, boot_epoch: int | None) -> str:
    """bpftrace nsecs（自开机单调纳秒）+ btime → ISO 8601 墙上时间。"""
    value = int(nsecs) / 1e9
    if boot_epoch:
        value += boot_epoch
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _sanitize(value: str) -> str:
    """去除 C0 控制字符与残留分隔标记，保证 JSONL/展示安全。"""
    return "".join(
        " " if (ord(ch) < 0x20 or ord(ch) == 0x7F or ch in (ARGV_SEP, ARGV_NULL)) else ch
        for ch in value
    )


def parse_argv(section: str | None) -> list[str] | None:
    """解析 argv 段：\\x1f 分隔、\\x1e 终止（NULL 之后的占位全部丢弃）。"""
    if not section:
        return None
    items: list[str] = []
    for item in section.split(ARGV_SEP):
        if ARGV_NULL in item:  # NULL 边界：之后是内核侧守卫占位，不是参数
            head = item.split(ARGV_NULL, 1)[0]
            if head:  # 边界前有残余字符才并入（正常情况 NULL 独占一段）
                items.append(_sanitize(head))
            break
        items.append(_sanitize(item))
    return items


def synthetic_session_id(pid: int, start_time: str, boot_id: str) -> str:
    """合成进程会话键：boot_id + pid + start_time（确定性、可复算）。"""
    prefix = (boot_id or "").replace("-", "")[:SESSION_BOOT_PREFIX]
    return f"lg-{prefix}-{pid}-{start_time}" if prefix else f"lg-{pid}-{start_time}"


def _parse_line(line: str) -> dict[str, Any] | None:
    """解析一行 LG| 管道报文；新旧格式兼容，坏行返回 None（跳过）。"""
    if not line.startswith("LG|"):
        return None
    # execve：前 8 段定长，第 9 段起整体为 argv（段内允许字面 "|"）
    parts = line.split("|", 8) if line.startswith("LG|execve|") else line.split("|", 10)
    kind = parts[1] if len(parts) > 1 else ""
    try:
        if kind == "execve":
            # 新 v2：LG|execve|nsecs|pid|ppid|uid|comm|start|argv段（必含 \x1f）
            # 旧：LG|execve|nsecs|pid|ppid|uid|comm|filename|parent
            if len(parts) == 9 and parts[7].isdigit() and ARGV_SEP in parts[8]:
                _, _, nsecs, pid, ppid, uid, comm, start, argv = parts
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "ppid": int(ppid),
                        "uid": int(uid), "comm": comm, "filename": "",
                        "parent": "", "start_time": start, "argv_section": argv}
            elif len(parts) == 9:
                _, _, nsecs, pid, ppid, uid, comm, filename, parent = parts
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "ppid": int(ppid),
                        "uid": int(uid), "comm": comm, "filename": filename,
                        "parent": parent, "start_time": "", "argv_section": None}
        elif kind == "connect":
            # 新：LG|connect|nsecs|pid|uid|comm|ip|port|start
            if len(parts) >= 9 and parts[8].isdigit():
                _, _, nsecs, pid, uid, comm, ip, port, start = parts[:9]
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "uid": int(uid),
                        "comm": comm, "ip": ip, "port": int(port), "start_time": start}
            if len(parts) == 8:
                _, _, nsecs, pid, uid, comm, ip, port = parts
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "uid": int(uid),
                        "comm": comm, "ip": ip, "port": int(port), "start_time": ""}
        elif kind == "openat":
            # 新：LG|openat|nsecs|pid|ppid|uid|comm|filename|mode|start
            if len(parts) == 10:
                _, _, nsecs, pid, ppid, uid, comm, filename, mode, start = parts
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "ppid": int(ppid),
                        "uid": int(uid), "comm": comm, "filename": filename,
                        "mode": mode, "start_time": start}
            if len(parts) == 9:
                _, _, nsecs, pid, ppid, uid, comm, filename, mode = parts
                return {"kind": kind, "nsecs": nsecs, "pid": int(pid), "ppid": int(ppid),
                        "uid": int(uid), "comm": comm, "filename": filename,
                        "mode": mode, "start_time": ""}
    except (ValueError, IndexError):
        return None
    return None


def _base_event(msg: dict[str, Any], hostname: str, boot_id: str,
                boot_epoch: int | None) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": to_iso(msg["nsecs"], boot_epoch),
        "hostname": hostname,
        "source": "ebpf_bpftrace",
        "operation": {"execve": "exec", "openat": "open", "connect": "connect"}[msg["kind"]],
        "result": "initiated" if msg["kind"] == "connect" else "attempt",
        "user": user_name(msg["uid"]),
        "process_id": msg["pid"],
    }
    # 仅新格式（带 start_time）附带 boot_id 与合成会话键：
    # 旧格式保持 P0 行为逐字段一致（事件身份不因升级漂移）；
    # 转发器路径的 boot_id 列仍由转发器自报（P0 语义不变）。
    if msg.get("start_time"):
        event["process_start_time"] = msg["start_time"]
        event["process_exec_id"] = synthetic_session_id(msg["pid"], msg["start_time"], boot_id)
        event["boot_id"] = boot_id
    return event


def _execve_event(msg: dict[str, Any], hostname: str, boot_id: str,
                  boot_epoch: int | None) -> dict[str, Any]:
    event = _base_event(msg, hostname, boot_id, boot_epoch)
    parent_name = msg["parent"]
    parent = os.path.basename(parent_name) if "/" in parent_name else (parent_name or msg["comm"])
    argv = msg["argv_items"] if "argv_items" in msg else parse_argv(msg.get("argv_section"))
    filename = msg["filename"]
    commandline = " ".join(argv) if argv else filename
    raw: dict[str, Any] = {"kind": "execve", "uid": msg["uid"], "comm": msg["comm"],
                           "filename": filename, "parent_name": parent_name}
    if msg.get("start_time"):
        raw["start_time"] = int(msg["start_time"])
    if argv is not None:
        raw["argv"] = argv
        event["argv"] = argv
    event.update({
        "event_type": "execve",
        "process_name": os.path.basename(filename),
        "parent_process": parent,
        "commandline": commandline,
        "parent_process_id": msg["ppid"],
        "severity": "info",
        "rule": "LG-eBPF process execution",
        "raw": raw,
    })
    return event


def _connect_event(msg: dict[str, Any], hostname: str, boot_id: str,
                   boot_epoch: int | None) -> dict[str, Any]:
    event = _base_event(msg, hostname, boot_id, boot_epoch)
    ip, port = msg["ip"], msg["port"]
    raw: dict[str, Any] = {"kind": "connect", "uid": msg["uid"], "comm": msg["comm"],
                           "daddr": ip, "dport": port}
    if msg.get("start_time"):
        raw["start_time"] = int(msg["start_time"])
    event.update({
        "event_type": "connect",
        "process_name": msg["comm"],
        "commandline": f"{msg['comm']} -> {ip}:{port}",
        "destination": ip,
        "port": port,
        "severity": "notice",
        "rule": "LG-eBPF outbound connection",
        "raw": raw,
    })
    return event


def _openat_event(msg: dict[str, Any], hostname: str, boot_id: str,
                  boot_epoch: int | None) -> dict[str, Any]:
    event = _base_event(msg, hostname, boot_id, boot_epoch)
    filename, mode = msg["filename"], msg["mode"]
    raw: dict[str, Any] = {"kind": "openat", "uid": msg["uid"], "comm": msg["comm"],
                           "filename": filename, "mode": mode}
    if msg.get("start_time"):
        raw["start_time"] = int(msg["start_time"])
    event.update({
        "event_type": "openat",
        "process_name": msg["comm"],
        "commandline": f"{msg['comm']} {mode} {filename}",
        "file_path": filename,
        "parent_process_id": msg["ppid"],
        "severity": "warning" if mode == "write" else "info",
        "rule": f"LG-eBPF watched file {mode}",
        "raw": raw,
    })
    return event


def convert_lines(lines: Iterable[str], hostname: str, boot_id: str = "",
                  boot_epoch: int | None = None) -> list[dict[str, Any]]:
    """把原始管道行集合转换为统一事件列表（内存版，供测试与脚本共用）。"""
    if boot_epoch is None:
        boot_epoch = read_boot_epoch()
    if not boot_id:
        boot_id = read_boot_id()
    builders = {"execve": _execve_event, "connect": _connect_event, "openat": _openat_event}
    events: list[dict[str, Any]] = []
    pid_names: dict[int, str] = {}
    for line in lines:
        msg = _parse_line(line.rstrip("\n"))
        if msg is None:
            continue
        if msg["kind"] == "execve":
            if msg.get("argv_section") is not None:
                msg["argv_items"] = parse_argv(msg["argv_section"])
            if not msg.get("filename"):
                msg["filename"] = (msg.get("argv_items") or [""])[0] or msg["comm"]
            if not msg.get("parent"):
                msg["parent"] = pid_names.get(msg["ppid"], "")
            pid_names[msg["pid"]] = msg["filename"]
        builder = builders.get(msg["kind"])
        if builder:
            events.append(builder(msg, hostname, boot_id, boot_epoch))
    return events


def _validated_cli_path(value: str) -> Path:
    """CWE-22 缓解：本工具常随探针以 root 运行，CLI 路径含穿越分量（..）即拒绝
    （fail-closed）；仅接受净化后的 Path 供 open 使用。"""
    path = Path(value)
    if ".." in path.parts:
        print(f"[LinuxGuard] 拒绝可疑路径（含 .. 穿越分量）: {value}", file=sys.stderr)
        raise SystemExit(2)
    return path


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) < 3:
        print(f"用法: {Path(sys.argv[0]).name} <raw文件> <输出.jsonl> <hostname>", file=sys.stderr)
        return 2
    raw_file = _validated_cli_path(args[0])
    out_file = _validated_cli_path(args[1])
    hostname = args[2]
    with raw_file.open(encoding="utf-8", errors="replace") as fh:
        events = convert_lines(fh, hostname)
    with out_file.open("w", encoding="utf-8") as out:
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"[LinuxGuard] 归一化完成：{len(events)} 条事件 -> {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
