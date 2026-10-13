import json
import hashlib
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.runtime_telemetry import IDENTITY_FIELDS, identity_fields


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
EVENT_FILE = Path(os.getenv("LINUXGUARD_EVENT_FILE", str(DATA_DIR / "ebpf_events.jsonl")))
COLLECTOR_SCRIPT = Path(__file__).resolve().parents[2] / "collector" / "run_falco_capture.sh"

FALCO_TEXT_RE = re.compile(
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<severity>Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug)\s+"
    r"(?P<message>.*)",
    re.IGNORECASE,
)

SEVERITY_SCORE = {
    "emergency": 100,
    "alert": 92,
    "critical": 86,
    "error": 72,
    "warning": 58,
    "notice": 36,
    "informational": 18,
    "info": 18,
    "debug": 8,
}

CATEGORY_RULES = [
    {
        "category": "sensitive_file_access",
        "label": "敏感文件访问",
        "keywords": ["sensitive file", "/etc/shadow", "/etc/passwd", "credential", "ssh", "private key"],
        "tactic": "Credential Access",
        "technique": "T1555",
        "risk_signal": "Observed sensitive file access that can support credential theft or lateral movement.",
    },
    {
        "category": "privilege_activity",
        "label": "权限提升行为",
        "keywords": ["sudo", "setuid", "root", "privilege", "user=root"],
        "tactic": "Privilege Escalation",
        "technique": "T1548",
        "risk_signal": "Observed privileged execution context related to local escalation scenarios.",
    },
    {
        "category": "network_activity",
        "label": "网络连接行为",
        "keywords": ["connect", "accept", "fd.rip", "fd.sip", "network", "curl", "wget"],
        "tactic": "Command and Control",
        "technique": "T1105",
        "risk_signal": "Observed network activity indicating real service exposure or remote interaction.",
    },
    {
        "category": "process_execution",
        "label": "进程执行行为",
        "keywords": ["execve", "spawn", "command=", "proc.cmdline", "bash", "python", "sh -c"],
        "tactic": "Execution",
        "technique": "T1059",
        "risk_signal": "Observed process execution consistent with the attack chain execution stage.",
    },
    {
        "category": "package_or_service_change",
        "label": "服务或软件包变更",
        "keywords": ["apt", "dpkg", "systemctl", "service", "restart", "install", "upgrade"],
        "tactic": "Impact",
        "technique": "Service Modification",
        "risk_signal": "Observed package or service change suitable for remediation verification.",
    },
]


def _now_iso(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


def _first_value(payload: dict[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        value: Any = payload
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value is not None and value != "" and not isinstance(value, (dict, list)):
            return str(value)
    return default


def _score_for_severity(value: str) -> int:
    return SEVERITY_SCORE.get((value or "").lower(), 18)


def _extract_json_payloads(content: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        for key in ("events", "items", "records", "data", "results"):
            nested = parsed.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def classify_event(event: dict[str, Any]) -> dict[str, str]:
    text = " ".join(
        [
            str(event.get("rule") or ""),
            str(event.get("event_type") or ""),
            str(event.get("process_name") or ""),
            str(event.get("parent_process") or ""),
            str(event.get("commandline") or ""),
            str(event.get("file_path") or ""),
            str(event.get("destination") or ""),
            json.dumps(event.get("raw") or {}, ensure_ascii=False),
        ]
    ).lower()
    for rule in CATEGORY_RULES:
        if any(keyword.lower() in text for keyword in rule["keywords"]):
            return rule
    return {
        "category": "runtime_observation",
        "label": "运行时观察",
        "tactic": "Discovery",
        "technique": "Runtime Signal",
        "risk_signal": "Observed runtime context that supplements static CVE matching.",
    }


def normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize Falco, Tetragon, or simple JSON events into one runtime schema."""
    output_fields = payload.get("output_fields") or {}
    source_field = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    process_exec = next((payload[key] for key in ("process_exec", "process_kprobe", "process_tracepoint", "process_exit")
                         if isinstance(payload.get(key), dict)), {})
    process = process_exec.get("process") or payload.get("process") or {}
    parent = process_exec.get("parent") or payload.get("parent") or {}

    event_type = _first_value(
        payload,
        ["event_type", "evt.type", "process_exec.process_exec", "process_kprobe.function_name"],
        output_fields.get("evt.type") or payload.get("rule") or "runtime_event",
    )
    hostname = _first_value(
        payload,
        ["hostname", "host", "node_name", "node.name"],
        output_fields.get("host.name") or source_field.get("hostname", ""),
    )
    process_name = _first_value(
        payload,
        ["process_name", "proc.name", "process.name"],
        output_fields.get("proc.name") or Path(str(process.get("binary", ""))).name,
    )
    commandline = _first_value(
        payload,
        ["commandline", "proc.cmdline", "process.cmdline"],
        output_fields.get("proc.cmdline")
        or " ".join([str(process.get("binary", "")), str(process.get("arguments", ""))]).strip(),
    )
    file_path = output_fields.get("fd.name") or payload.get("file_path") or ""
    socket_arg = {}
    for argument in process_exec.get("args") or []:
        if isinstance(argument, dict):
            file_arg = argument.get("file_arg") or {}
            file_path = file_path or file_arg.get("path", "")
            socket_arg = argument.get("sock_arg") or socket_arg
    destination = _first_value(
        payload,
        ["destination", "fd.rip", "network.destination"],
        output_fields.get("fd.rip") or output_fields.get("fd.cip") or socket_arg.get("daddr") or file_path,
    )
    port_value = _first_value(
        payload,
        ["port", "fd.rport", "fd.sport", "network.port"],
        output_fields.get("fd.rport") or output_fields.get("fd.sport") or socket_arg.get("dport") or "",
    )
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        port = 0

    source_value = payload.get("source") if isinstance(payload.get("source"), str) else ""
    if not source_value and any(key in payload for key in ("process_exec", "process_kprobe", "process_tracepoint", "process_exit")):
        source_value = "tetragon"
    severity = _first_value(payload, ["severity", "priority"], payload.get("priority", "info"))
    event = {
        "timestamp": _first_value(payload, ["timestamp", "time"], _now_iso()),
        "hostname": hostname,
        "source": source_value or _first_value(payload, ["observer"], "falco_or_tetragon"),
        "event_type": event_type,
        "process_name": process_name,
        "commandline": commandline,
        "parent_process": payload.get("parent_process")
        or output_fields.get("proc.pname")
        or (parent.get("binary", "") if isinstance(parent, dict) else ""),
        "file_path": file_path,
        "destination": destination,
        "port": port,
        "severity": severity,
        "severity_score": _score_for_severity(severity),
        "rule": _first_value(payload, ["rule", "policy_name"], ""),
        "raw": payload,
    }
    event.update(identity_fields(payload))
    if isinstance(payload.get("asset_id"), int) and not isinstance(payload["asset_id"], bool):
        event["asset_id"] = payload["asset_id"]
    # Runtime probes already carry an intentional classification.  Reclassifying
    # their raw payload makes the transport name (for example
    # ``runtime_probe_ssh``) look like a credential-access signal and overwrites
    # an ordinary process-execution probe with ``sensitive_file_access``.
    explicit_category = str(payload.get("category") or "")
    explicit_rule = next(
        (rule for rule in CATEGORY_RULES if rule["category"] == explicit_category),
        None,
    )
    event.update(explicit_rule or classify_event(event))
    return event


def parse_event_lines(content: str) -> list[dict[str, Any]]:
    structured_payloads = _extract_json_payloads(content)
    if structured_payloads:
        return structured_payloads

    payloads: list[dict[str, Any]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                payloads.append(parsed)
            continue
        except json.JSONDecodeError:
            pass

        match = FALCO_TEXT_RE.search(line)
        if not match:
            continue
        message = match.group("message")
        process_match = re.search(r"(?:proc\.name|proc_exepath|proc\.exepath)=([^\s)]+)", message)
        command_match = re.search(r"(?:command|proc\.cmdline|proc\.args)=([^|)]+)", message)
        file_match = re.search(r"(?:file|fd\.name)=([^\s)]+)", message)
        user_match = re.search(r"user\.name=([^\s)]+)", message)
        payloads.append(
            {
                "timestamp": match.group("time"),
                "source": "falco_text",
                "event_type": "falco_rule_alert",
                "severity": match.group("severity").lower(),
                "rule": message.split("(", 1)[0].split("|", 1)[0].strip(),
                "process_name": Path(process_match.group(1)).name if process_match else "",
                "commandline": command_match.group(1).strip() if command_match else message,
                "file_path": file_match.group(1) if file_match else "",
                "destination": file_match.group(1) if file_match else "",
                "user": user_match.group(1) if user_match else "",
                "raw": {"line": line},
            }
        )
    return payloads


def _asset_for_event(db: Session, event: dict[str, Any]) -> models.LinuxAsset | None:
    hostname = (event.get("hostname") or "").strip()
    if event.get("asset_id"):
        asset = db.get(models.LinuxAsset, event["asset_id"])
        if not asset:
            raise ValueError("事件指定的资产不存在")
        names = {asset.hostname, asset.ip_address}
        if asset.mac_address:
            names.add(asset.hostname.rsplit("-", 1)[0])
        if hostname and hostname not in names:
            raise ValueError("事件资产 ID 与主机标识冲突")
        return asset
    if hostname:
        asset = db.query(models.LinuxAsset).filter_by(hostname=hostname).first()
        if asset:
            return asset
        asset = db.query(models.LinuxAsset).filter_by(ip_address=hostname).first()
        if asset:
            return asset
    return None


def _runtime_event_to_dict(row: models.RuntimeEvent) -> dict[str, Any]:
    raw = {}
    if row.raw_json:
        try:
            raw = json.loads(row.raw_json)
        except json.JSONDecodeError:
            raw = {"raw": row.raw_json}
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "timestamp": row.occurred_at,
        "hostname": row.hostname,
        "source": row.source,
        "event_type": row.event_type,
        "category": row.category,
        "severity": row.severity,
        "severity_score": row.severity_score,
        "rule": row.rule,
        "process_name": row.process_name,
        "parent_process": row.parent_process,
        "commandline": row.commandline,
        "file_path": row.file_path,
        "destination": row.destination,
        "port": row.port,
        "tactic": row.tactic,
        "technique": row.technique,
        "risk_signal": row.risk_signal,
        "raw": raw,
        **{name: getattr(row, name, "") for name in IDENTITY_FIELDS},
        "evidence_level": "runtime_observation",
        "event_fingerprint": row.event_fingerprint,
    }


def _observation_mode(source: str) -> str:
    value = (source or "").lower()
    if "demo" in value:
        return "simulation"
    if "tetragon" in value:
        return "ebpf"
    if "falco" in value:
        return "sensor"  # The event format does not establish the selected driver.
    if value.startswith("runtime_probe_"):
        return "probe"
    return "runtime"


def _persist_events(db: Session, events: list[dict[str, Any]]) -> None:
    # 阶段二：事件入库的同时生成统一 SecurityEvidence（process/network/file），
    # 形成 eBPF → Evidence → 数据库 → API → 智能体 的链路，而非独立日志。
    from app.services.security_evidence import persist_evidence

    for event in events:
        asset = _asset_for_event(db, event)
        if asset:
            event["asset_id"], event["hostname"] = asset.id, asset.hostname
        raw = event.get("raw", {})
        fingerprint = ""
        if raw.get("timestamp") or raw.get("time"):
            fingerprint = hashlib.sha256(json.dumps({"asset_id": event.get("asset_id"), "raw": raw}, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            prior = db.query(models.RuntimeEvent).filter_by(event_fingerprint=fingerprint).first()
            if prior:
                event["id"], event["duplicate"] = prior.id, True
                continue
        row = models.RuntimeEvent(
            asset_id=asset.id if asset else None,
            hostname=event.get("hostname", ""),
            source=event.get("source", ""),
            event_type=event.get("event_type", ""),
            category=event.get("category", "runtime_observation"),
            severity=event.get("severity", "info"),
            severity_score=event.get("severity_score", 0),
            rule=event.get("rule", ""),
            process_name=event.get("process_name", ""),
            parent_process=event.get("parent_process", ""),
            commandline=event.get("commandline", ""),
            file_path=event.get("file_path", ""),
            destination=event.get("destination", ""),
            port=event.get("port", 0),
            tactic=event.get("tactic", ""),
            technique=event.get("technique", ""),
            risk_signal=event.get("risk_signal", ""),
            raw_json=json.dumps(event.get("raw", {}), ensure_ascii=False),
            occurred_at=event.get("timestamp", ""),
            event_fingerprint=fingerprint,
            **{name: event.get(name, 0 if name in {"process_id", "parent_process_id"} else "") for name in IDENTITY_FIELDS},
        )
        db.add(row)
        db.flush()
        event["id"] = row.id
    db.commit()
    persist_evidence(db, events)


def append_events(payloads: list[dict[str, Any]], db: Session | None = None) -> list[dict[str, Any]]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    normalized = [normalize_event(payload) for payload in payloads]
    if db is not None and normalized:
        _persist_events(db, normalized)
    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_FILE.open("a", encoding="utf-8") as handle:
        for event in normalized:
            if event.get("duplicate"):
                continue
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    return normalized


def load_events(limit: int = 500) -> list[dict[str, Any]]:
    if not EVENT_FILE.exists():
        return []
    rows: list[dict[str, Any]] = []
    with EVENT_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def _apply_runtime_filters(
    rows: list[dict[str, Any]],
    hostname: str | None = None,
    category: str | None = None,
    source: str | None = None,
    severity_min: int | None = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    filtered = rows
    if hostname:
        filtered = [row for row in filtered if row.get("hostname") == hostname]
    if category:
        filtered = [row for row in filtered if row.get("category") == category]
    if source:
        filtered = [row for row in filtered if row.get("source") == source]
    if severity_min is not None:
        filtered = [row for row in filtered if int(row.get("severity_score") or 0) >= severity_min]
    if mode:
        filtered = [row for row in filtered if _observation_mode(row.get("source", "")) == mode]
    return filtered


def load_runtime_events(
    db: Session | None = None,
    limit: int = 500,
    hostname: str | None = None,
    category: str | None = None,
    source: str | None = None,
    severity_min: int | None = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    if db is None:
        rows = load_events(limit=100000)
        rows = _apply_runtime_filters(rows, hostname=hostname, category=category, source=source, severity_min=severity_min, mode=mode)
        return rows[-limit:]

    query = db.query(models.RuntimeEvent).order_by(models.RuntimeEvent.id.desc())
    if hostname:
        query = query.filter(models.RuntimeEvent.hostname == hostname)
    if category:
        query = query.filter(models.RuntimeEvent.category == category)
    if source:
        query = query.filter(models.RuntimeEvent.source == source)
    if severity_min is not None:
        query = query.filter(models.RuntimeEvent.severity_score >= severity_min)
    rows = [_runtime_event_to_dict(row) for row in query.limit(max(limit * 4, limit)).all()]
    rows.reverse()
    rows = _apply_runtime_filters(rows, hostname=hostname, category=category, source=source, severity_min=severity_min, mode=mode)
    return rows[-limit:]


def summarize_runtime_events(db: Session) -> dict[str, Any]:
    events = load_runtime_events(db=db, limit=2000)
    category_counts = Counter(event.get("category", "runtime_observation") for event in events)
    severity_counts = Counter(event.get("severity", "info") for event in events)
    process_counts = Counter(event.get("process_name", "") or "unknown" for event in events)
    host_counts = Counter(event.get("hostname", "") or "unknown" for event in events)
    source_counts = Counter(event.get("source", "") or "unknown" for event in events)
    observation_mode_counts = Counter(_observation_mode(event.get("source", "")) for event in events)
    host_source_counts: dict[str, Counter] = {}
    host_observation_modes: dict[str, Counter] = {}
    for event in events:
        hostname = event.get("hostname", "") or "unknown"
        host_source_counts.setdefault(hostname, Counter())[event.get("source", "") or "unknown"] += 1
        host_observation_modes.setdefault(hostname, Counter())[_observation_mode(event.get("source", ""))] += 1
    high_value = [
        event
        for event in events
        if event.get("severity_score", 0) >= 50 or event.get("category") in {"sensitive_file_access", "privilege_activity"}
    ]
    return {
        "total": len(events),
        "category_counts": dict(category_counts),
        "severity_counts": dict(severity_counts),
        "top_processes": [{"name": name, "count": count} for name, count in process_counts.most_common(8)],
        "host_counts": dict(host_counts),
        "source_counts": dict(source_counts),
        "observation_mode_counts": dict(observation_mode_counts),
        "host_source_counts": {hostname: dict(counts) for hostname, counts in host_source_counts.items()},
        "host_observation_modes": {hostname: dict(counts) for hostname, counts in host_observation_modes.items()},
        "high_value_count": len(high_value),
        "latest_event_at": events[-1]["timestamp"] if events else "",
        "latest_events": events[-10:],
    }


def correlate_runtime_events(db: Session) -> list[dict[str, Any]]:
    events = load_runtime_events(db=db, limit=2000)
    assets = db.query(models.LinuxAsset).all()
    results = []
    for asset in assets:
        asset_events = [
            event
            for event in events
            if event.get("asset_id") == asset.id or event.get("hostname") == asset.hostname or event.get("hostname") == asset.ip_address
        ]
        service_names = {svc.service_name or svc.process_name for svc in asset.services if svc.service_name or svc.process_name}
        package_names = {pkg.package_name for pkg in asset.packages}
        matched_services = []
        matched_packages = []
        for event in asset_events:
            text = " ".join(
                [
                    event.get("process_name", ""),
                    event.get("parent_process", ""),
                    event.get("commandline", ""),
                    event.get("rule", ""),
                    json.dumps(event.get("raw") or {}, ensure_ascii=False),
                ]
            ).lower()
            matched_services.extend([name for name in service_names if name and name.lower() in text])
            matched_packages.extend([name for name in package_names if name and name.lower() in text])

        category_counts = Counter(event.get("category", "runtime_observation") for event in asset_events)
        source_counts = Counter(event.get("source", "") or "unknown" for event in asset_events)
        observation_modes = Counter(_observation_mode(event.get("source", "")) for event in asset_events)
        score = min(
            100,
            sum(max(int(event.get("severity_score", 0)), 10) for event in asset_events[:50])
            + len(set(matched_services)) * 8
            + len(set(matched_packages)) * 4,
        )
        results.append(
            {
                "asset": {
                    "id": asset.id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "os": f"{asset.os_name} {asset.os_version}".strip(),
                },
                "event_count": len(asset_events),
                "evidence_score": score,
                "category_counts": dict(category_counts),
                "source_counts": dict(source_counts),
                "observation_modes": dict(observation_modes),
                "matched_services": sorted(set(matched_services))[:8],
                "matched_packages": sorted(set(matched_packages))[:8],
                "latest_events": asset_events[-5:],
            }
        )
    return results


def build_collector_command(api_base: str, duration: int = 60) -> str:
    script_path = COLLECTOR_SCRIPT.as_posix()
    return "\n".join(
        [
            f"chmod +x {script_path}",
            f"{script_path} {api_base} {duration}",
        ]
    )


def runtime_status(db: Session, api_base: str) -> dict[str, Any]:
    file_events = load_events(limit=100000)
    db_events = load_runtime_events(db=db, limit=5000)
    assets = db.query(models.LinuxAsset).all()
    known_hostnames = {asset.hostname for asset in assets if asset.hostname}
    known_hostnames.update({asset.ip_address for asset in assets if asset.ip_address})
    unmatched_hosts = sorted(
        {
            event.get("hostname", "")
            for event in db_events
            if event.get("hostname") and event.get("hostname") not in known_hostnames
        }
    )
    matched_asset_ids = {event.get("asset_id") for event in db_events if event.get("asset_id")}
    source_counts = Counter(event.get("source", "") or "unknown" for event in db_events)
    category_counts = Counter(event.get("category", "runtime_observation") for event in db_events)
    observation_mode_counts = Counter(_observation_mode(event.get("source", "")) for event in db_events)
    recommendations = []
    if not assets:
        recommendations.append("Upload Linux assets first so runtime events can map to real hosts.")
    if not db_events:
        recommendations.append("Upload a Falco/Tetragon event file or generate demo runtime evidence from the Runtime page.")
    if db_events and not matched_asset_ids:
        recommendations.append("Runtime events are not mapped to assets. Verify hostname or IP alignment between assets and events.")
    if observation_mode_counts.get("probe", 0) and not observation_mode_counts.get("ebpf", 0):
        recommendations.append("Current runtime evidence is demo probe data. Replace it with real Falco/Tetragon capture before final delivery.")
    if db_events and not recommendations:
        recommendations.append("Runtime evidence is healthy. You can proceed with attack-chain verification and report export.")

    latest_event_at = db_events[-1]["timestamp"] if db_events else ""
    return {
        "db_event_count": len(db_events),
        "file_event_count": len(file_events),
        "asset_count": len(assets),
        "matched_asset_count": len(matched_asset_ids),
        "matched_asset_ratio": round((len(matched_asset_ids) / len(assets)) * 100, 2) if assets else 0,
        "latest_event_at": latest_event_at,
        "unmatched_hosts": unmatched_hosts,
        "available_hosts": sorted({event.get("hostname", "") for event in db_events if event.get("hostname")}),
        "available_categories": sorted(category_counts.keys()),
        "available_sources": sorted(source_counts.keys()),
        "source_counts": dict(source_counts),
        "category_counts": dict(category_counts),
        "observation_mode_counts": dict(observation_mode_counts),
        "collector_script": COLLECTOR_SCRIPT.as_posix(),
        "event_file": EVENT_FILE.as_posix(),
        "collector_command": build_collector_command(api_base),
        "recommendations": recommendations,
    }


def _pick_primary_service(asset: models.LinuxAsset) -> models.AssetService | None:
    exposed = [service for service in asset.services if service.is_public_exposed or service.listen_address in {"0.0.0.0", "::", "*"}]
    if exposed:
        return exposed[0]
    return asset.services[0] if asset.services else None


def _pick_package(asset: models.LinuxAsset, preferred: tuple[str, ...]) -> str:
    package_names = {package.package_name for package in asset.packages}
    for name in preferred:
        if name in package_names:
            return name
    return next(iter(package_names), "openssl")


def generate_demo_runtime_events(db: Session, per_asset: int = 4) -> list[dict[str, Any]]:
    assets = db.query(models.LinuxAsset).all()
    payloads: list[dict[str, Any]] = []
    for asset in assets:
        primary_service = _pick_primary_service(asset)
        service_name = (primary_service.service_name or primary_service.process_name) if primary_service else ""
        port = primary_service.port if primary_service else 0
        network_package = _pick_package(asset, ("nginx", "apache2", "openssl", "openssh-server", "curl"))
        privileged_package = _pick_package(asset, ("sudo", "bash", "openssh-server", "ssh"))
        packages_changed = _pick_package(asset, ("openssl", "nginx", "bash", "curl", "systemd"))
        host = asset.hostname or asset.ip_address or f"asset-{asset.id}"

        scenarios = [
            {
                "timestamp": _now_iso(5),
                "hostname": host,
                "source": "runtime_probe_exec",
                "event_type": "execve",
                "process_name": service_name or network_package,
                "parent_process": "systemd",
                "commandline": f"{service_name or network_package} --worker-process",
                "port": port,
                "severity": "warning",
                "rule": "Synthetic service execution evidence",
                "raw": {"generator": "linuxguard-demo", "scenario": "service_exec"},
            },
            {
                "timestamp": _now_iso(4),
                "hostname": host,
                "source": "runtime_probe_network",
                "event_type": "connect",
                "process_name": service_name or network_package,
                "parent_process": "systemd",
                "commandline": f"{service_name or network_package} --tls-proxy",
                "destination": "198.51.100.10",
                "port": port or 443,
                "severity": "critical",
                "rule": "Synthetic network path evidence",
                "raw": {"generator": "linuxguard-demo", "scenario": "network_activity", "package": network_package},
            },
            {
                "timestamp": _now_iso(3),
                "hostname": host,
                "source": "runtime_probe_privilege",
                "event_type": "execve",
                "process_name": privileged_package,
                "parent_process": "sshd",
                "commandline": f"sudo -n /usr/bin/{privileged_package}",
                "file_path": "/etc/shadow",
                "severity": "alert",
                "rule": "Synthetic privilege activity evidence",
                "raw": {"generator": "linuxguard-demo", "scenario": "privilege_activity"},
            },
            {
                "timestamp": _now_iso(2),
                "hostname": host,
                "source": "runtime_probe_patch",
                "event_type": "execve",
                "process_name": "apt",
                "parent_process": "bash",
                "commandline": f"apt install --only-upgrade {packages_changed}",
                "severity": "notice",
                "rule": "Synthetic remediation verification evidence",
                "raw": {"generator": "linuxguard-demo", "scenario": "package_change", "package": packages_changed},
            },
        ]
        payloads.extend(scenarios[: max(1, min(per_asset, len(scenarios)))])

    if not payloads:
        return []
    return append_events(payloads, db=db)


def clear_events(db: Session | None = None) -> int:
    count = len(load_events(limit=100000))
    if EVENT_FILE.exists():
        EVENT_FILE.unlink()
    if db is not None:
        db_count = db.query(models.RuntimeEvent).count()
        db.query(models.RuntimeEvent).delete()
        db.commit()
        count = max(count, db_count)
    return count
