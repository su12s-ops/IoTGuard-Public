"""Archive and reset one LinuxGuard experiment as a consistent unit.

Asset inventory and configured targets survive a normal experiment reset. All
derived records are archived and deleted in dependency-safe order so that a
RiskAssessment, its AgentAuditRecord rows, and the AnalysisReport that owns the
run always have the same lifecycle.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app import models


ARCHIVE_SCHEMA_VERSION = 3

# Restore parents before children. The table-name form is intentionally public
# so the standalone SQLite restore utility can share the exact same contract.
ARCHIVE_TABLE_MAPPINGS = (
    ("assets", "linux_asset"),
    ("packages", "asset_package"),
    ("services", "asset_service"),
    ("targets", "demo_target"),
    ("device_connections", "device_connection"),
    ("device_observations", "device_observation"),
    ("openwrt_advisories", "openwrt_advisory"),
    ("runtime_sensors", "runtime_sensor"),
    ("vulnerabilities", "vulnerability_info"),
    ("intel", "threat_intel_source"),
    ("matches", "vulnerability_match"),
    ("risks", "risk_assessment"),
    ("analysis_reports", "analysis_report"),
    ("agent_audit_records", "agent_audit_record"),
    ("tasks", "remediation_task"),
    ("events", "runtime_event"),
    ("runtime_evidence_jobs", "runtime_evidence_job"),
    ("harness_runs", "harness_run"),
    ("harness_tool_calls", "harness_tool_call"),
)

_MODEL_BY_TABLE = {
    model.__tablename__: model
    for model in (
        models.LinuxAsset,
        models.AssetPackage,
        models.AssetService,
        models.DemoTarget,
        models.VulnerabilityInfo,
        models.ThreatIntelSource,
        models.VulnerabilityMatch,
        models.RiskAssessment,
        models.AnalysisReport,
        models.AgentAuditRecord,
        models.RemediationTask,
        models.RuntimeEvent,
        models.RuntimeEvidenceJob,
        models.DeviceConnection,
        models.DeviceObservation,
        models.OpenWrtAdvisory,
        models.RuntimeSensor,
        models.HarnessRun,
        models.HarnessToolCall,
    )
}

# Children must be removed before their RiskAssessment / vulnerability parent.
DERIVED_DELETE_ORDER = (
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
    models.ThreatIntelSource,
    models.VulnerabilityInfo,
)


def serialize_rows(rows) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {}
        for column in row.__table__.columns:
            if isinstance(row, models.DemoTarget) and column.name == "password":
                continue
            value = getattr(row, column.name)
            item[column.name] = value.isoformat() if hasattr(value, "isoformat") else value
        serialized.append(item)
    return serialized


def lifecycle_counts(db: Session) -> dict[str, int]:
    return {
        archive_key: db.query(_MODEL_BY_TABLE[table_name]).count()
        for archive_key, table_name in ARCHIVE_TABLE_MAPPINGS
    }


def build_archive_payload(db: Session) -> dict[str, Any]:
    counts = lifecycle_counts(db)
    payload: dict[str, Any] = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "archived_at": datetime.now(timezone.utc).isoformat(),
        "summary": counts.copy(),
    }
    for archive_key, table_name in ARCHIVE_TABLE_MAPPINGS:
        payload[archive_key] = serialize_rows(db.query(_MODEL_BY_TABLE[table_name]).all())
    return payload


def clear_derived_data(db: Session) -> dict[str, int]:
    """Delete the complete derived experiment graph and retain inventory."""
    if db.query(models.HarnessRun).filter_by(status="running").first():
        raise ValueError("设备任务正在运行，暂不能重置实验数据")
    counts = {
        model.__tablename__: db.query(model).count()
        for model in DERIVED_DELETE_ORDER
    }
    for model in DERIVED_DELETE_ORDER:
        db.query(model).delete(synchronize_session=False)
    db.commit()
    return counts
