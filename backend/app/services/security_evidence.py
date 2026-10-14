"""SecurityEvidence 统一证据层：eBPF / Falco / Tetragon → 三类真实监控证据。

职责：
- 把归一化后的运行时事件分类为 process / network / file 三类；
- 提取事件主体（进程、PID/PPID、用户、命令行）与类型化明细（目的 IP/端口、
  文件路径、操作），生成 evidence_id 并幂等落库；
- 构建进程树（pid/ppid 关联，还原 mosquitto → sh → wget 式父子链）；
- 供运行时 API 与四智能体证据包直接消费。

分类只依据事件自身字段（evt.type / file_path / destination / 规则名），
不依据来源标签，保证对 Falco、Tetragon、bpftrace 三种采集端一致。
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app import models

# 阶段二重点监控的文件/目录（文件类证据的优先级依据）
FILE_WATCH_PATHS = [
    "/etc/mosquitto/",
    "/etc/iotguard/",
    "/etc/passwd",
    "/etc/shadow",
    "/opt/firmware/",
]

NETWORK_EVENT_TYPES = {"connect", "connect_ex", "tcp_connect", "udp_sendto", "accept", "accept4"}
PROCESS_EVENT_TYPES = {"execve", "execveat", "spawned_process", "process_exec", "clone", "fork", "shell"}

# 文件操作严重度基线：写敏感凭证文件 > 写配置 > 读凭证 > 普通读
_FILE_SEVERITY = {
    ("write", "/etc/shadow"): ("critical", 86),
    ("read", "/etc/shadow"): ("warning", 58),
    ("write", "/etc/passwd"): ("critical", 86),
    ("read", "/etc/passwd"): ("notice", 36),
    ("write", "/etc/mosquitto/"): ("warning", 58),
    ("write", "/etc/iotguard/"): ("warning", 58),
    ("write", "/opt/firmware/"): ("error", 72),
}


def _watch_path_match(path: str) -> str | None:
    if not path:
        return None
    for watch in FILE_WATCH_PATHS:
        if watch.endswith("/"):
            if path.startswith(watch) or path + "/" == watch:
                return watch
        elif path == watch:
            return watch
    return None


def classify_evidence_type(event: dict[str, Any]) -> str:
    """依据事件字段判定 process / network / file。"""
    event_type = str(event.get("event_type") or "").lower()
    file_path = str(event.get("file_path") or "")
    destination = str(event.get("destination") or "")
    port = int(event.get("port") or 0)

    if event_type in NETWORK_EVENT_TYPES or (destination and port and not file_path):
        return "network"
    if file_path and (_watch_path_match(file_path) or event_type in {"open", "openat", "openat2", "file_open"}):
        return "file"
    if event_type in PROCESS_EVENT_TYPES or "execve" in event_type:
        return "process"
    # 类目兜底：沿用既有 category 的语义
    category = str(event.get("category") or "")
    if category == "network_activity":
        return "network"
    if category == "sensitive_file_access":
        return "file"
    if category == "process_execution":
        return "process"
    return "process"


def _detect_file_operation(event: dict[str, Any]) -> str:
    """从事件类型/原始报文中推断文件操作：read / write / open。"""
    text = " ".join([
        str(event.get("event_type") or ""),
        str(event.get("rule") or "").lower(),
        json.dumps(event.get("raw") or {}, ensure_ascii=False).lower(),
    ])
    if any(token in text for token in ("o_wronly", "o_rdwr", "write", "open_write", "truncate", "creat")):
        return "write"
    if any(token in text for token in ("o_rdonly", "read", "open_read")):
        return "read"
    return "open"


def _severity_for(event: dict[str, Any], evidence_type: str, operation: str, watch: str | None) -> tuple[str, int]:
    if evidence_type == "file" and watch:
        key = (operation, watch)
        if key in _FILE_SEVERITY:
            return _FILE_SEVERITY[key]
        if watch == "/opt/firmware/":
            return ("notice", 36)
        return ("info", 18)
    # 沿用事件自带的 Falco/bpftrace 严重度
    severity = str(event.get("severity") or "info").lower()
    score = int(event.get("severity_score") or 0)
    return (severity, score)


def event_to_evidence(event: dict[str, Any]) -> dict[str, Any]:
    """把 normalize_event 的输出转换为 SecurityEvidence 记录。"""
    evidence_type = classify_evidence_type(event)
    file_path = str(event.get("file_path") or "")
    watch = _watch_path_match(file_path)
    operation = _detect_file_operation(event) if evidence_type == "file" else str(event.get("event_type") or "").lower()

    raw = event.get("raw") or {}
    user = str(event.get("user") or raw.get("user") or "")
    if not user:
        user = str((raw.get("output_fields") or {}).get("user.name") or "")
    if not user and evidence_type == "file" and "/etc/shadow" in (watch or ""):
        user = "root"

    destination = str(event.get("destination") or "")
    port = int(event.get("port") or 0)
    # 文件事件的 destination 被复用过文件路径，此处还原语义
    if evidence_type == "file":
        destination, port = "", 0
    elif destination and not port:
        destination, _, port_text = destination.rpartition(":")
        if port_text.isdigit():
            port = int(port_text)

    severity, severity_score = _severity_for(event, evidence_type, operation, watch)
    pid = int(event.get("process_id") or 0)
    ppid = int(event.get("parent_process_id") or 0)
    process = str(event.get("process_name") or "")
    commandline = str(event.get("commandline") or "")

    if evidence_type == "process":
        description = f"进程 {process or 'unknown'} (pid={pid or '?'}) 由 {event.get('parent_process') or '?'} 启动：{commandline[:160]}"
    elif evidence_type == "network":
        description = f"进程 {process or 'unknown'} (pid={pid or '?'}) 连接 {destination or '?'}:{port or '?'}"
    elif watch:
        description = f"进程 {process or 'unknown'} (pid={pid or '?'}) {operation} 受控路径 {watch} 下文件 {file_path}"
    else:
        description = f"进程 {process or 'unknown'} (pid={pid or '?'}) {operation} {file_path}"

    basis = json.dumps({
        "device_id": event.get("hostname") or "",
        "type": evidence_type, "timestamp": event.get("timestamp") or "",
        "pid": pid, "ppid": ppid, "process": process,
        "destination": destination, "port": port,
        "file_path": file_path, "operation": operation,
        "raw": raw,
    }, sort_keys=True, ensure_ascii=False, default=str)
    evidence_hash = hashlib.sha256(basis.encode("utf-8")).hexdigest()

    return {
        "evidence_id": "SE-" + evidence_hash[:16],
        "evidence_hash": evidence_hash,
        "device_id": str(event.get("hostname") or ""),
        "asset_id": event.get("asset_id"),
        "source": str(event.get("source") or ""),
        "evidence_type": evidence_type,
        "timestamp": str(event.get("timestamp") or ""),
        "severity": severity,
        "severity_score": severity_score,
        "process": process,
        "pid": pid,
        "ppid": ppid,
        # P1-3 会话身份：随事件透传到证据层（不参与 evidence_hash 基准，
        # 保证升级前后同一事件的证据身份零漂移）。
        "process_exec_id": str(event.get("process_exec_id") or "")[:255],
        "parent_exec_id": str(event.get("parent_exec_id") or "")[:255],
        "user": user[:64],
        "commandline": commandline,
        "parent_process": str(event.get("parent_process") or ""),
        "operation": operation,
        "destination_ip": destination[:64],
        "destination_port": port,
        "file_path": file_path,
        "description": description,
        "raw_data": json.dumps(raw, ensure_ascii=False, default=str),
    }


def persist_evidence(db: Session, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """幂等写入：同一 evidence_hash 只保留一条，重复事件返回已有 evidence_id。"""
    stored: list[dict[str, Any]] = []
    for event in events:
        # P0：duplicate 事件跳过新建，但仍参与"缺绑补绑"检查（asset_rebound 语义）。
        record = event_to_evidence(event)
        existing = db.query(models.SecurityEvidence).filter_by(evidence_hash=record["evidence_hash"]).first()
        if existing:
            record["evidence_id"] = existing.evidence_id
            record["duplicate"] = True
            # 证据层回绑（修复审计 D1 后半）：既有证据缺资产归属而本次事件
            # 可解析到资产时补绑；先到先绑定，不改写既有非空归属。
            if existing.asset_id is None and record.get("asset_id"):
                existing.asset_id = record["asset_id"]
                db.commit()
                record["asset_rebound"] = True
            # P1-3 回填：升级前入库的证据行缺会话身份而本次重放事件可提供
            # 时补写（只填空值，不改写既有非空值）。
            backfilled = False
            for field in ("process_exec_id", "parent_exec_id"):
                if not getattr(existing, field) and record.get(field):
                    setattr(existing, field, record[field])
                    backfilled = True
            if backfilled:
                db.commit()
            stored.append(record)
            continue
        if event.get("duplicate"):
            # 同批内已被 RuntimeEvent 判重且库中无既有证据（异常场景）：
            # 不新建，保持与 RuntimeEvent 一致，避免双写漂移。
            stored.append(record)
            continue
        row = models.SecurityEvidence(**{key: value for key, value in record.items()})
        db.add(row)
        db.flush()
        record["id"] = row.id
        stored.append(record)
    db.commit()
    return stored


def serialize_evidence(row: models.SecurityEvidence, include_raw: bool = False) -> dict[str, Any]:
    data = {
        "evidence_id": row.evidence_id,
        "device_id": row.device_id,
        "asset_id": row.asset_id,
        "source": row.source,
        "type": row.evidence_type,
        "timestamp": row.timestamp,
        "severity": row.severity,
        "severity_score": row.severity_score,
        "process": row.process,
        "pid": row.pid,
        "ppid": row.ppid,
        "process_exec_id": row.process_exec_id or "",
        "parent_exec_id": row.parent_exec_id or "",
        "user": row.user,
        "commandline": row.commandline,
        "parent_process": row.parent_process,
        "operation": row.operation,
        "destination_ip": row.destination_ip,
        "destination_port": row.destination_port,
        "file_path": row.file_path,
        "description": row.description,
        "created_at": row.created_at,
    }
    if include_raw:
        try:
            data["raw_data"] = json.loads(row.raw_data or "{}")
        except json.JSONDecodeError:
            data["raw_data"] = {}
    return data


def query_evidence(
    db: Session,
    evidence_type: str | None = None,
    device_id: str | None = None,
    severity_min: int | None = None,
    limit: int = 200,
) -> list[models.SecurityEvidence]:
    """参数化查询（全部经 SQLAlchemy 绑定，不拼接 SQL）。"""
    query = db.query(models.SecurityEvidence).order_by(models.SecurityEvidence.id.desc())
    if evidence_type:
        query = query.filter(models.SecurityEvidence.evidence_type == evidence_type)
    if device_id:
        query = query.filter(models.SecurityEvidence.device_id == device_id)
    if severity_min is not None:
        query = query.filter(models.SecurityEvidence.severity_score >= severity_min)
    rows = query.limit(max(1, min(limit, 2000))).all()
    return list(reversed(rows))


def summarize_evidence(db: Session) -> dict[str, Any]:
    rows = db.query(models.SecurityEvidence).order_by(models.SecurityEvidence.id.desc()).limit(2000).all()
    by_type: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_device: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        by_type[row.evidence_type] += 1
        by_severity[row.severity] += 1
        by_device[row.device_id or "unknown"][row.evidence_type] += 1
    watched_file_events = sum(1 for row in rows if row.evidence_type == "file" and _watch_path_match(row.file_path or ""))
    return {
        "total": len(rows),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "by_device": {device: dict(types) for device, types in by_device.items()},
        "watched_file_events": watched_file_events,
        "watch_paths": FILE_WATCH_PATHS,
        "latest_timestamp": rows[-1].timestamp if rows else "",
    }


# ── 进程树：还原父子进程链（如 mosquitto → sh → wget） ────────────────────────

def build_process_tree(db: Session, device_id: str | None = None, limit: int = 1000) -> dict[str, Any]:
    """把进程类证据按 pid/ppid 组织成树，并输出可疑服务链。

    证据流中同一 pid 可能出现多次（exec 更换映像），按时间序保留最近命令行；
    树中只展示有证据的节点，未知父节点挂到 roots。
    """
    query = db.query(models.SecurityEvidence).filter(models.SecurityEvidence.evidence_type == "process")
    if device_id:
        query = query.filter(models.SecurityEvidence.device_id == device_id)
    rows = list(reversed(query.order_by(models.SecurityEvidence.id.desc()).limit(max(1, min(limit, 4000))).all()))

    # 按设备分组构建
    devices: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        node = devices[row.device_id or "unknown"].get(row.pid)
        if node is None:
            node = {
                "pid": row.pid, "ppid": row.ppid, "process": row.process or "unknown",
                "user": row.user, "commandline": row.commandline,
                "parent_process": row.parent_process,
                "first_seen": row.timestamp, "last_seen": row.timestamp,
                "evidence_ids": [], "children": [],
            }
            devices[row.device_id or "unknown"][row.pid] = node
        node["evidence_ids"].append(row.evidence_id)
        node["last_seen"] = row.timestamp
        # exec 会替换映像：同 pid 多次 exec 时以最终映像名为准（ps 语义）。
        if row.process:
            node["process"] = row.process
        if row.commandline:
            node["commandline"] = row.commandline
        if row.ppid:
            node["ppid"] = row.ppid

    trees = {}
    for device, nodes in devices.items():
        roots = []
        for pid, node in nodes.items():
            parent = nodes.get(node["ppid"])
            if parent is not None and parent is not node:
                parent["children"].append(node)
            else:
                roots.append(node)

        def depth(node: dict) -> int:
            return 1 + max((depth(child) for child in node["children"]), default=0)

        # 服务进程启动 shell 的链（mosquitto/nginx/sshd → sh/bash → wget/curl 等）
        chain_findings = []
        service_names = {"mosquitto", "nginx", "sshd", "httpd", "lighttpd", "uhttpd", "dropbear", "telnetd"}
        downloader_names = {"wget", "curl", "ftp", "tftp", "nc", "ncat", "socat", "python", "python3"}

        def walk(node: dict, path: list[str]) -> None:
            current = path + [node["process"]]
            if len(current) >= 3:
                if current[0] in service_names and current[1] in {"sh", "bash", "dash", "ash"} and current[-1] in downloader_names:
                    chain_findings.append({
                        "chain": current[:len(current) if len(current) <= 4 else 4],
                        "pids": [node["pid"]],
                        "description": f"服务进程 {current[0]} 启动 shell 后执行 {current[-1]}，疑似设备固件更新/回滚通道",
                    })
            for child in node["children"]:
                walk(child, current)

        for root in roots:
            walk(root, [])

        trees[device] = {
            "roots": sorted(roots, key=lambda item: item["pid"]),
            "process_count": len(nodes),
            "max_depth": max((depth(root) for root in roots), default=0),
            "service_shell_chains": chain_findings,
        }
    return {"devices": trees, "note": "进程树由 eBPF 进程类证据实时构建；仅包含有证据的进程节点。"}
