"""Archive and reset one LinuxGuard experiment as a consistent unit.

Asset inventory and configured targets survive a normal experiment reset. All
derived records are archived and deleted in dependency-safe order so that a
RiskAssessment, its AgentAuditRecord rows, and the AnalysisReport that owns the
run always have the same lifecycle.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
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
# Keep only device inventory, connection/collection configuration, sensors,
# policy and reference advisories. Everything produced by a run is listed here.
DERIVED_DELETE_ORDER = (
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


def clear_derived_data(db: Session, *, full_console: bool = False) -> dict[str, int]:
    """Delete the complete derived experiment graph and retain inventory."""
    if db.query(models.HarnessRun).filter_by(status="running").first():
        raise ValueError("设备任务正在运行，暂不能重置实验数据")
    if db.query(models.UnifiedAnalysisRun).filter(
        models.UnifiedAnalysisRun.status.in_(("running", "queued_remote"))
    ).first():
        raise ValueError("智能研判正在运行，暂不能重置实验数据")
    delete_order = DERIVED_DELETE_ORDER
    if full_console:
        delete_order = (models.ConsoleWorkflow, models.AnalysisRound) + delete_order + (
            models.VulnerabilityIntelligenceSource, models.OpenWrtAdvisory,
            models.IotDeviceAdvisory, models.IotOfficialAdvisory,
        )
    # The retained inventory's metadata points at raw collection receipts.
    # Removing those receipts leaves a seemingly complete inventory with broken
    # evidence IDs, causing every later review to fail reference validation.
    current_receipts = set()
    for asset_id, raw_metadata in db.query(models.LinuxAsset.id, models.LinuxAsset.inventory_metadata_json):
        try:
            metadata = json.loads(raw_metadata or "{}")
        except (ValueError, TypeError):
            continue
        reference = metadata.get("inventory_evidence_id") if isinstance(metadata, dict) else None
        if isinstance(reference, str) and reference:
            current_receipts.add((asset_id, reference))
    retained_ids = [item.id for item in db.query(models.CollectionEvidence.id,
                    models.CollectionEvidence.asset_id, models.CollectionEvidence.evidence_id)
                    if (item.asset_id, item.evidence_id) in current_receipts]
    def delete_query(model):
        query = db.query(model)
        if model is models.CollectionEvidence and retained_ids:
            query = query.filter(models.CollectionEvidence.id.notin_(retained_ids))
        return query
    counts = {
        model.__tablename__: delete_query(model).count()
        for model in delete_order
    }
    for model in delete_order:
        delete_query(model).delete(synchronize_session=False)
    # Device rows stay, but the last run's assessment fields must not leak into
    # the next round as if they were current results.
    db.query(models.IotDevice).update(
        {
            models.IotDevice.risk_score: 0,
            models.IotDevice.risk_score_basis: "none",
            models.IotDevice.security_status: "unassessed",
        },
        synchronize_session=False,
    )
    db.query(models.ScanTarget).update(
        {models.ScanTarget.last_run_id: None},
        synchronize_session=False,
    )
    db.commit()
    return counts
