import json
from pathlib import PurePosixPath
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app import models
from app.services.runtime_context import (
    SERVICE_DEPENDENCIES,
    package_related_to_service,
    service_name,
)


CATEGORY_WEIGHTS = {
    "sensitive_file_access": 1.0,
    "privilege_activity": 0.95,
    "process_execution": 0.82,
    "network_activity": 0.76,
    "package_or_service_change": 0.5,
    "runtime_observation": 0.35,
}

FRESHNESS_LABELS = {
    "unknown": "时间未知",
    "last_hour": "最近一小时",
    "last_day": "最近一天",
    "last_week": "最近一周",
    "stale": "较早事件",
}

CATEGORY_LABELS = {
    "sensitive_file_access": "敏感文件访问",
    "privilege_activity": "权限提升行为",
    "process_execution": "进程执行行为",
    "network_activity": "网络活动",
    "package_or_service_change": "软件包或服务变更",
    "runtime_observation": "运行时观察",
}


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _freshness(timestamp: str) -> tuple[float, str]:
    dt = _parse_timestamp(timestamp)
    if not dt:
        return 0.45, "unknown"
    age_hours = max(0.0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds() / 3600)
    if age_hours <= 1:
        return 1.0, "last_hour"
    if age_hours <= 24:
        return 0.82, "last_day"
    if age_hours <= 24 * 7:
        return 0.6, "last_week"
    return 0.28, "stale"


def _annotate_event(event: dict[str, Any], match_type: str, reasons: list[str]) -> dict[str, Any]:
    severity = max(0.0, min(1.0, float(event.get("severity_score", 0)) / 100))
    category = CATEGORY_WEIGHTS.get(event.get("category", "runtime_observation"), 0.35)
    freshness, freshness_bucket = _freshness(str(event.get("timestamp") or ""))
    relation = 1.0 if match_type == "direct" else 0.65
    evidence_weight = round(category * 38 + severity * 32 + freshness * 20 + relation * 10, 2)

    annotated = dict(event)
    annotated["match_type"] = match_type
    annotated["match_reasons"] = reasons
    annotated["freshness"] = freshness_bucket
    annotated["evidence_weight"] = evidence_weight
    return annotated


def _localized_counter(data: Counter, labels: dict[str, str]) -> dict[str, int]:
    return {labels.get(key, key): value for key, value in data.items()}


def evaluate_runtime_evidence(
    asset: models.LinuxAsset,
    package_name: str,
    services: list[models.AssetService],
    events: list[dict[str, Any]],
    scenario_id: str = "",
) -> dict[str, Any]:
    asset_keys = {key.lower() for key in [asset.hostname, asset.ip_address] if key}
    asset_events = [
        event
        for event in events
        if event.get("asset_id") == asset.id or (asset_keys and (event.get("hostname") or "").lower() in asset_keys)
    ]
    if not asset_events:
        return {
            "status": "waiting",
            "evidence_level": "unavailable",
            "exploitation_confirmed": False,
            "absence_proves_safe": False,
            "adjustment_score": 0,
            "strength_score": 0.0,
            "confidence": 0.28,
            "matched_events": [],
            "conclusion": "该资产暂未接入 Falco/Tetragon 运行时证据。",
            "signals": {
                "direct_count": 0,
                "contextual_count": 0,
                "recent_count": 0,
                "freshness_mix": {},
                "top_categories": {},
                "max_weight": 0,
            },
        }

    related_services = [service for service in services if package_related_to_service(package_name, service_name(service))]
    service_names = {service_name(service).lower() for service in related_services if service_name(service)}
    service_ports = {service.port for service in related_services if service.port}
    package_token = (package_name or "").lower()
    direct_hits: list[dict[str, Any]] = []
    contextual_hits: list[dict[str, Any]] = []

    for event in asset_events:
        process = (event.get("process_name") or "").lower()
        commandline = (event.get("commandline") or "").lower()
        parent_process = (event.get("parent_process") or "").lower()
        category = (event.get("category") or "").lower()
        raw_text = json.dumps(event.get("raw") or {}, ensure_ascii=False).lower()
        file_path = (event.get("file_path") or "").lower()
        event_port = int(event.get("port") or 0)
        direct_reasons = []
        contextual_reasons = []

        aliases = {package_token}
        aliases.update({"openssh-server": {"sshd"}, "redis-server": {"redis-server"}, "mosquitto": {"mosquitto"},
                        "dropbear": {"dropbear"}}.get(package_token, set()))
        if package_token and PurePosixPath(process).name in aliases:
            direct_reasons.append("process")
        if package_token and package_token in commandline:
            contextual_reasons.append("commandline_text")
        if package_token and package_token in parent_process:
            contextual_reasons.append("parent_process_text")
        if package_token and package_token in raw_text:
            contextual_reasons.append("raw_payload_text")
        if package_token and package_token in file_path:
            contextual_reasons.append("file_path_text")

        privileged_context = category in {"sensitive_file_access", "privilege_activity"} and (
            scenario_id in {"lpe", "data_leak"} or package_name in {"sudo", "bash", "openssh-server", "ssh", "pam", "passwd", "shadow"}
        )
        if privileged_context:
            contextual_reasons.append("privileged_context")

        if any(name and name in process for name in service_names):
            contextual_reasons.append("service_process")
        if any(name and name in commandline for name in service_names):
            contextual_reasons.append("service_command")
        if any(name and name in parent_process for name in service_names):
            contextual_reasons.append("service_parent")
        if any(name and name in raw_text for name in service_names):
            contextual_reasons.append("service_raw")
        if event_port in service_ports:
            contextual_reasons.append("service_port")

        if direct_reasons:
            direct_hits.append(_annotate_event(event, "direct", direct_reasons))
        elif contextual_reasons:
            contextual_hits.append(_annotate_event(event, "contextual", contextual_reasons))

    direct_hits.sort(key=lambda item: item["evidence_weight"], reverse=True)
    contextual_hits.sort(key=lambda item: item["evidence_weight"], reverse=True)
    top_direct = direct_hits[:5]
    top_contextual = contextual_hits[:5]
    top_hits = top_direct if top_direct else top_contextual
    category_counts = Counter(event.get("category", "runtime_observation") for event in top_hits)
    freshness_counts = Counter(event.get("freshness", "unknown") for event in top_hits)
    recent_count = sum(1 for event in top_hits if event.get("freshness") in {"last_hour", "last_day"})
    strength = round(
        sum(event.get("evidence_weight", 0) for event in top_hits) / len(top_hits),
        2,
    ) if top_hits else 0.0

    if top_direct:
        adjustment = min(24, round(8 + strength / 5 + min(len(top_direct), 4)))
        confidence = min(0.97, round(0.55 + strength / 200 + recent_count * 0.03, 2))
        localized_categories = _localized_counter(category_counts, CATEGORY_LABELS)
        localized_freshness = _localized_counter(freshness_counts, FRESHNESS_LABELS)
        conclusion = (
            f"已观察到 {len(direct_hits)} 条与 {package_name} 直接相关的运行时证据；"
            f"主要类型={localized_categories}，时间分布={localized_freshness}，"
            f"最高证据权重={top_direct[0]['evidence_weight']}。"
        )
        status = "verified"
    elif top_contextual:
        adjustment = min(14, round(3 + strength / 8 + min(len(top_contextual), 3)))
        confidence = min(0.86, round(0.42 + strength / 220 + recent_count * 0.02, 2))
        localized_categories = _localized_counter(category_counts, CATEGORY_LABELS)
        localized_freshness = _localized_counter(freshness_counts, FRESHNESS_LABELS)
        conclusion = (
            f"已观察到 {len(contextual_hits)} 条围绕关联服务路径的上下文运行时证据；"
            f"主要类型={localized_categories}，时间分布={localized_freshness}，"
            f"最高证据权重={top_contextual[0]['evidence_weight']}。"
        )
        status = "contextual"
    else:
        adjustment = 0
        confidence = 0.38
        conclusion = "虽然该资产已有运行时事件，但暂未观察到与该软件包或关联服务直接相关的活动。"
        status = "not_observed"

    return {
        "status": status,
        "evidence_level": "component_activity" if top_direct else "contextual_activity" if top_contextual else "not_observed",
        "exploitation_confirmed": False,
        "absence_proves_safe": False,
        "adjustment_score": adjustment,
        "strength_score": strength,
        "confidence": confidence,
        "matched_events": top_hits,
        "conclusion": conclusion,
        "signals": {
            "direct_count": len(direct_hits),
            "contextual_count": len(contextual_hits),
            "recent_count": recent_count,
            "freshness_mix": dict(freshness_counts),
            "top_categories": dict(category_counts),
            "max_weight": top_hits[0]["evidence_weight"] if top_hits else 0,
        },
    }
