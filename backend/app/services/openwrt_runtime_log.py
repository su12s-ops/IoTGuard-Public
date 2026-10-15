"""eBPF 2.0 P2-2：OpenWrt 轻量化降级采集（logread 只读拉取 → 统一运行时事件）。

在不安装 eBPF、不修改设备任何配置的前提下，经既有 DeviceConnection
（SSH 主机指纹钉扎 + 凭据环境变量引用，见 device_access.py）执行固定只读
脚本 collector/openwrt_logread_capture.sh，把 logread 环形缓冲全量拉回并
标准化为统一运行时事件，走 P0 既有管线（append_events → RuntimeEvent /
SecurityEvidence，指纹幂等 + 资产绑定 + 证据回绑），不建第二套事件库。

诚实边界（验收基线）：
- source 恒为 ``openwrt_logread``，观察模式归类 ``syslog``——设备原生日志
  采集，绝不伪装 eBPF；
- logread 时间为设备本地时间：按采集时刻捕获的 ``date +%z`` 偏移换算 UTC。
  偏移仅在采集时刻成立，历史 TZ/时钟变更不可追溯（raw 保留原始行全文，
  换算依据随采集审计留档）；
- 行时间缺少年份或不可解析 → 跳过并计数（year_missing / unparseable，
  附样本行），不虚构年份：无完整时间的事件不具备 P0 判重身份，跳过以保
  重复采集幂等；
- 设备重启：boot_id 参与事件指纹（同主机名跨重启不误合并）；ring 缓冲
  随重启重置为自然窗口边界，不做跨重启拼接；
- ring 中已被覆盖的历史行不可知：丢失计数 unavailable（非零丢失）；
- 每次采集全量拉取（设备不留游标状态），重复行由服务端指纹判重收敛。
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services import device_access

LOGREAD_COLLECTOR = Path(__file__).resolve().parents[3] / "collector" / "openwrt_logread_capture.sh"
SOURCE = "openwrt_logread"
SENSOR_SOURCE = "logread"

# BusyBox logread 行格式（实测 OpenWrt 25.12.5）：
#   Thu Oct 15 00:13:30 2026 kern.debug kernel: [    0.134074] pcpu-alloc: ...
#   Thu Oct 15 02:21:57 2026 auth.err dropbear[1234]: Password auth failed ...
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_DOW = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
LOGREAD_LINE_RE = re.compile(
    r"^(?P<dow>" + "|".join(_DOW) + r")\s+"
    r"(?P<mon>" + "|".join(_MONTHS) + r")\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+"
    r"(?P<year>\d{4})\s+"
    r"(?P<facility>[a-z0-9]+)\.(?P<level>emerg|alert|crit|err|warning|warn|notice|info|debug)\s+"
    r"(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$",
)
# 缺少年份的防御形态（RFC3164 风格）：识别后跳过并计数，不猜测年份
YEAR_MISSING_RE = re.compile(
    r"^(?P<dow>" + "|".join(_DOW) + r")\s+"
    r"(?P<mon>" + "|".join(_MONTHS) + r")\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+"
    r"(?P<facility>[a-z0-9]+)\.(?P<level>emerg|alert|crit|err|warning|warn|notice|info|debug)\s+",
)

LEVEL_NORMALIZE = {"warn": "warning", "err": "error", "crit": "critical", "emerg": "emergency"}

MAX_LOG_LINES = 20000  # 单次拉取上限（超限即停止解析并如实报告，防失控设备）


def parse_offset(value: str) -> int | None:
    """``date +%z`` 输出（±HHMM）→ 秒；无法解析返回 None（时区不确定）。"""
    text = (value or "").strip()
    match = re.fullmatch(r"([+-])(\d{2})(\d{2})", text)
    if not match:
        return None
    sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
    offset = hours * 3600 + minutes * 60
    return offset if sign == "+" else -offset


def parse_capture_output(text: str) -> dict[str, Any]:
    """设备脚本输出 → 身份段 + 日志行列表 + 计数（纯函数，供专项测试）。

    解析失败的身份字段为空串（调用方据此如实降级），不抛异常。
    """
    identity: dict[str, str] = {}
    lines: list[str] = []
    section = ""
    for raw_line in text.splitlines():
        if raw_line.startswith("====="):
            section = raw_line.strip("= ").strip()
            continue
        if section == "IDENTITY":
            key, sep, value = raw_line.partition(":")
            if sep:
                identity[key.strip()] = value.strip()
        elif section == "LOGREAD":
            lines.append(raw_line)
    return {"identity": identity, "log_lines": lines[:MAX_LOG_LINES],
            "truncated": len(lines) > MAX_LOG_LINES}


def line_to_utc(match: re.Match, offset_seconds: int | None) -> str:
    """logread 本地时间 + 采集偏移 → UTC ISO；偏移未知（None）按 UTC 并标注。"""
    naive = datetime(int(match.group("year")), _MONTHS[match.group("mon")],
                     int(match.group("day")), int(match.group("hh")),
                     int(match.group("mm")), int(match.group("ss")))
    if offset_seconds is None:
        return naive.replace(tzinfo=timezone.utc).isoformat()
    from datetime import timedelta
    return (naive - timedelta(seconds=offset_seconds)).replace(tzinfo=timezone.utc).isoformat()


def logread_line_to_event(line: str, match: re.Match, *, device_hostname: str,
                          boot_id: str, offset_seconds: int | None,
                          offset_raw: str, asset_id: int, sensor_id: str) -> dict[str, Any]:
    """单条 logread 行 → 统一事件 payload（交 append_events 走 P0 管线）。

    身份稳定性（重复采集幂等的根基）：
    - payload["timestamp"]（raw 内同步出现）= 原始行本地时间文本，跨采集不变；
    - 转换后的 UTC 时间只出现在顶层 timestamp，换算偏移只记录文本值
      （同一设备同一 TZ 下不变）；采集时刻等每次变化的信息一律不进 payload。
    """
    level = LEVEL_NORMALIZE.get(match.group("level"), match.group("level"))
    pid_text = match.group("pid")
    process = match.group("process")
    # 设备自报主机名进 raw（设备锚点，见 app/ebpf_identity.py）
    return {
        "timestamp": line_to_utc(match, offset_seconds),
        "hostname": device_hostname,
        "source": SOURCE,
        "event_type": "syslog",
        "process_name": process,
        "severity": level,
        "rule": f"{match.group('facility')}.{match.group('level')}",
        "process_id": int(pid_text) if pid_text else 0,
        "boot_id": boot_id,
        "sensor_id": sensor_id,
        "asset_id": asset_id,
        "raw": {
            "line": line,
            "timestamp": (f"{match.group('mon')} {match.group('day')} "
                          f"{match.group('hh')}:{match.group('mm')}:{match.group('ss')} "
                          f"{match.group('year')}"),
            "hostname": device_hostname,
            "boot_id": boot_id,
            "facility": match.group("facility"),
            "level": match.group("level"),
            "process": process,
            "pid": int(pid_text) if pid_text else 0,
            "message": match.group("message"),
            "timezone_offset": offset_raw,
            # 命名注意：值不得包含 classify_event 关键词子串（如 "ssh"/"root"/
            # "credential"——实测 "logread_ssh_pull" 使全量事件误判敏感文件访问）
            "transport": "logread_remote_pull",
        },
    }


def build_events(capture: dict[str, Any], *, asset_hostname: str, asset_id: int,
                 sensor_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """解析全部日志行 → 事件列表 + 采集元数据（跳过项如实计数，附样本）。"""
    identity = capture["identity"]
    device_hostname = identity.get("hostname") or asset_hostname
    boot_id = identity.get("boot_id", "")
    offset_raw = identity.get("device_local_offset", "")
    offset_seconds = parse_offset(offset_raw)
    events: list[dict[str, Any]] = []
    year_missing = unparseable = 0
    skipped_samples: list[str] = []
    for line in capture["log_lines"]:
        stripped = line.strip()
        if not stripped:
            continue
        match = LOGREAD_LINE_RE.match(stripped)
        if match:
            events.append(logread_line_to_event(
                stripped, match, device_hostname=device_hostname, boot_id=boot_id,
                offset_seconds=offset_seconds, offset_raw=offset_raw,
                asset_id=asset_id, sensor_id=sensor_id))
            continue
        if YEAR_MISSING_RE.match(stripped):
            year_missing += 1
        else:
            unparseable += 1
        if len(skipped_samples) < 3:
            skipped_samples.append(stripped[:200])
    timestamps = [event["timestamp"] for event in events]
    meta = {
        "device_hostname": device_hostname,
        "boot_id": boot_id,
        "timezone_offset": offset_raw,
        "timezone_offset_seconds": offset_seconds,
        "timezone_basis": ("device date +%z captured at collection（设备本地时间→UTC 换算；"
                           "历史 TZ/时钟变更不可追溯，raw 保留原始行）"),
        "device_utc_epoch": identity.get("device_utc_epoch", ""),
        "lines_total": len(capture["log_lines"]),
        "events_built": len(events),
        "year_missing_lines": year_missing,
        "unparseable_lines": unparseable,
        "skipped_samples": skipped_samples,
        "truncated": capture.get("truncated", False),
        "window_first": min(timestamps) if timestamps else "",
        "window_last": max(timestamps) if timestamps else "",
        "ring_loss_semantics": "unavailable（环形缓冲中已被覆盖的历史行不可知，非零丢失）",
    }
    return events, meta


def _record_sensor(db: Session, *, asset_id: int, sensor_id: str, meta: dict[str, Any],
                   stored_new: int, duplicates: int) -> None:
    """拉取式采集的心跳语义：一次性窗口完成即 stopped（非常驻探针）。

    dropped_events 不写数值（None→unavailable）：ring 覆盖丢失不可测，
    绝不虚构为零。能力快照记录本次窗口事实供 coverage / 智能体读取。
    """
    row = db.query(models.RuntimeSensor).filter_by(asset_id=asset_id, sensor_id=sensor_id).one_or_none()
    if row is None:
        row = models.RuntimeSensor(asset_id=asset_id, sensor_id=sensor_id)
        db.add(row)
    row.source = SENSOR_SOURCE
    row.status = "stopped"
    row.dropped_events = None
    row.detail = "logread 拉取式采集：窗口完成即止（非常驻探针）；ring 覆盖丢失不可测（unavailable）"
    row.capabilities_json = json.dumps({
        "driver": "logread",
        "mode": "pull",
        "transport": "ssh_readonly_pinned",
        "last_window": {
            "lines_total": meta["lines_total"], "events_built": meta["events_built"],
            "stored_new": stored_new, "duplicates": duplicates,
            "year_missing_lines": meta["year_missing_lines"],
            "unparseable_lines": meta["unparseable_lines"],
            "window_first": meta["window_first"], "window_last": meta["window_last"],
            "boot_id": meta["boot_id"], "truncated": meta["truncated"],
        },
        "note": "每次采集为全量窗口拉取（设备不留状态）；重复行由服务端指纹幂等去重",
    }, ensure_ascii=False)
    row.last_heartbeat_at = models.utcnow()
    db.commit()


def collect_runtime_logs(db: Session, connection, *, audit: dict[str, Any] | None = None) -> dict[str, Any]:
    """经既有 DeviceConnection 拉取 OpenWrt logread 日志并接入 P0 事件管线。

    全程只读：固定脚本（内容哈希入审计）、SSH 指纹钉扎、凭据仅经环境变量
    引用；对设备零写入、零配置改动、零软件包安装。
    """
    from app.services.ebpf_event_collector import append_events

    audit = audit if audit is not None else {}
    asset = db.get(models.LinuxAsset, connection.asset_id) if connection.asset_id else None
    if not asset or asset.distribution != "openwrt":
        raise device_access.DeviceOperationError("asset_binding_required", "日志采集必须先绑定已有 OpenWrt 资产")
    try:
        script = LOGREAD_COLLECTOR.read_text(encoding="utf-8")
    except OSError as exc:
        raise device_access.DeviceOperationError("collector_unavailable", "固定 logread Collector 不可用") from exc
    collector_sha256 = hashlib.sha256(script.encode()).hexdigest()
    audit.update(collector_type="openwrt_logread", collector_sha256=collector_sha256,
                 node=device_access.collector_node())
    client = device_access.open_connection(connection)
    audit.update(ssh_host_identity="verified", ssh_authentication="succeeded")
    try:
        text = device_access.run_fixed_script(client, script, timeout=60, max_bytes=4_000_000)
    finally:
        client.close()
    audit.update(collector_exit_status=0, remote_execution_status="exited",
                 output_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                 output_bytes=len(text.encode("utf-8")))

    capture = parse_capture_output(text)
    sensor_id = f"openwrt-logread-{connection.id}"
    events, meta = build_events(capture, asset_hostname=asset.hostname,
                                asset_id=asset.id, sensor_id=sensor_id)
    audit.update(log_window=meta)
    stored = append_events(events, db=db) if events else []
    stored_new = sum(1 for event in stored if not event.get("duplicate"))
    duplicates = sum(1 for event in stored if event.get("duplicate"))
    _record_sensor(db, asset_id=asset.id, sensor_id=sensor_id, meta=meta,
                   stored_new=stored_new, duplicates=duplicates)
    audit.update(asset_id=asset.id, events_stored_new=stored_new, events_duplicates=duplicates,
                 runtime_collection="succeeded")
    return {"audit": audit, "meta": meta, "stored": stored,
            "stored_new": stored_new, "duplicates": duplicates,
            "sensor_id": sensor_id, "asset_id": asset.id}
