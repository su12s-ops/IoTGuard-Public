"""Compact, human-readable result snapshots for the experiment lifecycle.

The runtime event table can contain hundreds of thousands of rows, so a full
database dump is not a useful "final result". This module archives the parts an
operator needs to review or hand over: assets/devices, risks, matches, CVE
context, agent decisions, repair tasks/runs, report records and runtime summary
counts. Raw runtime events and the global CVE cache stay out of the snapshot.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.config import DATA_DIR

RESULT_ARCHIVE_SCHEMA_VERSION = 1
TEXT_LIMIT = 200_000

KEPT_MODELS = (
    models.LinuxAsset,
    models.AssetPackage,
    models.AssetService,
    models.DemoTarget,
    models.DeviceConnection,
    models.DeviceObservation,
    models.OpenWrtAdvisory,
    models.RuntimeSensor,
    models.IotDevice,
    models.IotDeviceService,
    models.IotDeviceComponent,
    models.IotOfficialAdvisory,
    models.IotDeviceAdvisory,
    models.LsmPolicy,
    models.ScanTarget,
)

DERIVED_MODELS = (
    models.AnalysisBudget,
    models.AnalysisTask,
    models.TraceEvent,
    models.TraceRun,
    models.ScanRun,
    models.DeviceVulnerabilityMatch,
    models.RemediationWorkflowRun,
    models.ApplicabilityCorrection,
    models.RiskGovernanceEvent,
    models.SecurityEvidence,
    models.CollectionEvidence,
    models.InvestigationRequest,
    models.OfficialCveRecord,
    models.UnifiedAnalysisRun,
    models.AgentOrchestrationRun,
    models.HarnessAssetLock,
    models.HarnessToolCall,
    models.HarnessRun,
    models.AgentAuditRecord,
    models.AnalysisReport,
    models.RemediationTask,
    models.RiskAssessment,
    models.VulnerabilityMatch,
    models.RuntimeEvidenceJob,
    models.RuntimeEvent,
    models.VulnerabilityInfo,
    models.ThreatIntelSource,
)


def archive_dir() -> Path:
    path = Path(os.getenv("REPORT_ARCHIVE_DIR", str(Path(DATA_DIR) / "archives")))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _iso(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (TypeError, ValueError):
            return str(value)
    return value


def _row_dict(row: Any, fields: tuple[str, ...] | None = None, text_limit: int = TEXT_LIMIT) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for column in row.__table__.columns:
        if fields is not None and column.name not in fields:
            continue
        value = _iso(getattr(row, column.name))
        if isinstance(value, str) and len(value) > text_limit:
            value = value[:text_limit] + f"…[truncated {len(value) - text_limit} chars]"
        data[column.name] = value
    return data


def _query_dicts(rows, fields: tuple[str, ...] | None = None, text_limit: int = TEXT_LIMIT) -> list[dict[str, Any]]:
    return [_row_dict(row, fields, text_limit) for row in rows]


def _chunks(values: list[str], size: int = 500):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def effective_level(risk: models.RiskAssessment) -> str:
    final_states = {
        "auto_confirmed", "human_confirmed", "remediation_ready",
        "remediation_in_progress", "verification", "resolved",
    }
    return (risk.risk_level if risk.review_status in final_states and risk.final_score is not None else risk.preliminary_level) or "Low"


def build_summary(db: Session) -> dict[str, Any]:
    risks = db.query(models.RiskAssessment).all()
    levels = Counter(effective_level(risk) for risk in risks)
    high = levels.get("Critical", 0) + levels.get("High", 0)
    tasks = db.query(models.RemediationTask).all()
    pending = sum(1 for task in tasks if task.status == "pending")
    blocked = sum(1 for task in tasks if task.status == "blocked")
    return {
        "assets": db.query(models.LinuxAsset).count(),
        "iot_devices": db.query(models.IotDevice).count(),
        "vulnerabilities": db.query(models.VulnerabilityInfo).count(),
        "matches": db.query(models.VulnerabilityMatch).count(),
        "risks": len(risks),
        "risk_levels": {key: levels.get(key, 0) for key in ("Critical", "High", "Medium", "Low")},
        "high_risks": high,
        "runtime_events": db.query(models.RuntimeEvent).count(),
        "unified_runs": db.query(models.UnifiedAnalysisRun).count(),
        "harness_runs": db.query(models.HarnessRun).count(),
        "remediation_tasks": len(tasks),
        "pending_tasks": pending,
        "blocked_tasks": blocked,
        "analysis_reports": db.query(models.AnalysisReport).count(),
        "archived_at": datetime.now(timezone.utc).isoformat(),
    }


def _runtime_summary(db: Session) -> dict[str, Any]:
    by_category = db.query(models.RuntimeEvent.category, func.count(models.RuntimeEvent.id)).group_by(models.RuntimeEvent.category).all()
    by_host = db.query(models.RuntimeEvent.hostname, func.count(models.RuntimeEvent.id)).group_by(models.RuntimeEvent.hostname).all()
    latest = db.query(func.max(models.RuntimeEvent.created_at)).scalar()
    return {
        "event_count": db.query(models.RuntimeEvent).count(),
        "by_category": {str(key or "unknown"): int(value) for key, value in by_category},
        "by_host": {str(key or "unknown"): int(value) for key, value in by_host},
        "latest_event_at": _iso(latest),
    }


def build_result_snapshot(db: Session, label: str = "当前结果", kind: str = "manual") -> dict[str, Any]:
    summary = build_summary(db)
    assets = db.query(models.LinuxAsset).all()
    asset_rows = []
    for asset in assets:
        item = _row_dict(asset)
        item["package_count"] = db.query(models.AssetPackage).filter_by(asset_id=asset.id).count()
        item["service_count"] = db.query(models.AssetService).filter_by(asset_id=asset.id).count()
        asset_rows.append(item)

    iot_devices = []
    for device in db.query(models.IotDevice).all():
        item = _row_dict(device)
        item["services"] = _query_dicts(
            db.query(models.IotDeviceService).filter_by(device_row_id=device.id).all(),
            fields=("port", "transport", "service_type", "product", "version", "auth_state", "status"),
            text_limit=20_000,
        )
        item["components"] = _query_dicts(
            db.query(models.IotDeviceComponent).filter_by(device_row_id=device.id).all(),
            fields=("component_name", "component_type", "version", "cpe", "source"),
            text_limit=20_000,
        )
        iot_devices.append(item)

    risks = db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all()
    cve_ids = sorted({risk.cve_id for risk in risks if risk.cve_id})
    vulnerabilities = []
    for chunk in _chunks(cve_ids):
        rows = db.query(models.VulnerabilityInfo).filter(models.VulnerabilityInfo.cve_id.in_(chunk)).all()
        vulnerabilities.extend(
            _row_dict(row, fields=("cve_id", "title", "description", "cvss_score", "severity", "published_at", "affected_package"), text_limit=50_000)
            for row in rows
        )

    matches = _query_dicts(
        db.query(models.VulnerabilityMatch).all(),
        fields=(
            "asset_id", "cve_id", "package_name", "installed_version", "fixed_version",
            "affected", "match_status", "reason_code", "match_reason", "confidence",
            "applicability_source", "active", "created_at",
        ),
        text_limit=20_000,
    )

    unified_runs = _query_dicts(
        db.query(models.UnifiedAnalysisRun).order_by(models.UnifiedAnalysisRun.created_at.desc()).all(),
        fields=(
            "run_id", "task_type", "target_type", "target_ref", "mode", "status",
            "pipeline_version", "routing_json", "decision_json", "plan_json",
            "usage_json", "risk_id", "error", "trace_id", "created_at", "completed_at",
        ),
        text_limit=50_000,
    )

    harness_rows = db.query(models.HarnessRun).order_by(models.HarnessRun.created_at.desc()).all()
    harness_runs = _query_dicts(
        harness_rows,
        fields=(
            "id", "asset_id", "risk_id", "connection_id", "status", "current_step",
            "plan_hash", "approved_by", "approval_reason", "error", "attempts",
            "trace_id", "created_at", "updated_at", "completed_at",
        ),
    )
    # Plans/results for thousands of interrupted collector runs dominate the
    # snapshot. Keep the final outcome payload only for runs that actually
    # finished, newest first, and cap the set.
    harness_final_plans = _query_dicts(
        [row for row in harness_rows if row.status in {"completed", "verified", "failed", "rolled_back"}][:200],
        fields=("id", "status", "plan_json", "result_json", "error", "completed_at"),
        text_limit=30_000,
    )

    analysis_reports = _query_dicts(
        db.query(models.AnalysisReport).order_by(models.AnalysisReport.created_at.desc()).all(),
        text_limit=100_000,
    )
    remediation_tasks = _query_dicts(db.query(models.RemediationTask).all(), text_limit=20_000)

    return {
        "schema_version": RESULT_ARCHIVE_SCHEMA_VERSION,
        "kind": kind,
        "label": label.strip()[:80] or "当前结果",
        "archived_at": summary["archived_at"],
        "summary": summary,
        "assets": asset_rows,
        "iot_devices": iot_devices,
        "risks": [_row_dict(risk) for risk in risks],
        "vulnerabilities": vulnerabilities,
        "matches": matches,
        "unified_runs": unified_runs,
        "harness_runs": harness_runs,
        "harness_final_plans": harness_final_plans,
        "analysis_reports": analysis_reports,
        "remediation_tasks": remediation_tasks,
        "runtime": _runtime_summary(db),
        "kept_counts": {model.__tablename__: db.query(model).count() for model in KEPT_MODELS},
        "derived_counts": {model.__tablename__: db.query(model).count() for model in DERIVED_MODELS},
    }


def _safe_stem(label: str, kind: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^0-9A-Za-z_-]+", "-", label).strip("-")[:36]
    slug = slug or kind or "snapshot"
    return f"exp-{stamp}-{slug}"


def write_result_archive(db: Session, label: str = "当前结果", kind: str = "manual") -> dict[str, Any]:
    payload = build_result_snapshot(db, label=label, kind=kind)
    directory = archive_dir()
    stem = _safe_stem(label, kind)
    candidate = directory / f"{stem}.json"
    suffix = 2
    while candidate.exists():
        candidate = directory / f"{stem}-{suffix}.json"
        suffix += 1
    with candidate.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
    size = candidate.stat().st_size
    meta = {
        "filename": candidate.name,
        "label": payload["label"],
        "kind": kind,
        "archived_at": payload["archived_at"],
        "summary": payload["summary"],
        "size_bytes": size,
    }
    meta_path = candidate.with_name(candidate.stem + ".meta.json")
    with meta_path.open("w", encoding="utf-8") as handle:
        json.dump(meta, handle, ensure_ascii=False, indent=2, default=str)
    return meta


def list_result_archives(limit: int = 20) -> list[dict[str, Any]]:
    directory = archive_dir()
    items: list[dict[str, Any]] = []
    for meta_path in directory.glob("exp-*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        main_path = directory / str(meta.get("filename") or "")
        if not main_path.is_file():
            continue
        if not meta.get("archived_at"):
            meta["archived_at"] = datetime.fromtimestamp(main_path.stat().st_mtime, timezone.utc).isoformat()
        meta["size_bytes"] = int(meta.get("size_bytes") or main_path.stat().st_size)
        items.append(meta)
    items.sort(key=lambda item: (item.get("archived_at") or "", item.get("filename") or ""), reverse=True)
    return items[:limit]


def archive_path(filename: str) -> Path:
    name = Path(filename).name
    if name != filename or not name.startswith("exp-") or not name.endswith(".json"):
        raise FileNotFoundError(filename)
    path = (archive_dir() / name).resolve()
    if not path.is_relative_to(archive_dir().resolve()) or not path.is_file():
        raise FileNotFoundError(filename)
    return path


def read_result_archive(filename: str) -> dict[str, Any]:
    path = archive_path(filename)
    return json.loads(path.read_text(encoding="utf-8"))


def active_runs(db: Session) -> dict[str, int]:
    """Count work that is actually executing.

    ``queued_remote`` HarnessRun rows are waiting for a collection node; they do
    not hold a device lock or an open worker. They are archived with the round
    and removed by a reset. Only a running task blocks the next round.
    """
    return {
        "unified": db.query(models.UnifiedAnalysisRun).filter(models.UnifiedAnalysisRun.status == "running").count(),
        "harness": db.query(models.HarnessRun).filter(models.HarnessRun.status == "running").count(),
        "orchestration": db.query(models.AgentOrchestrationRun).filter(models.AgentOrchestrationRun.status == "running").count(),
    }


def lifecycle_state(db: Session) -> dict[str, Any]:
    return {
        "summary": build_summary(db),
        "kept": {model.__tablename__: db.query(model).count() for model in KEPT_MODELS},
        "cache": {models.VulnerabilityIntelligenceSource.__tablename__: db.query(models.VulnerabilityIntelligenceSource).count()},
        "derived": {model.__tablename__: db.query(model).count() for model in DERIVED_MODELS},
        "active_runs": active_runs(db),
        "archives": list_result_archives(8),
    }
