"""Read-only migration and rollback planning. Never promotes a shadow verdict."""
from __future__ import annotations

import json
from app import config, models
from app.services.unified.investigation import fingerprint


def snapshot(db):
    rows = [{c.name: getattr(row, c.name) for c in models.RiskAssessment.__table__.columns}
            for row in db.query(models.RiskAssessment).order_by(models.RiskAssessment.id)]
    # JSON normalized types make a saved and reopened manifest equivalent.
    rows = json.loads(json.dumps(rows, default=str))
    return {"version": "formal-migration-v1", "mode": config.UNIFIED_PIPELINE_MODE,
        "formal_entry": "/api/analysis", "current_writer": "unified" if config.UNIFIED_PIPELINE_MODE == "on" else "system_b",
        "risk_rows": rows, "snapshot_hash": fingerprint(rows),
        "shadow_promotion_allowed": False,
        "prerequisites": ["独立正式迁移审批", "完成 Mimosa 安全验收", "停止接收新正式任务并排空旧 worker",
            "保存一致性数据库备份及本清单", "确认只启动一种模式的正式 worker"],
        "rollback": "停止统一正式任务并排空 worker；审核本快照的逐字段差异，人工授权恢复正式字段；保留所有新旧审计及 Trace，再以 off 重启 System B。仅改 flag 不会还原已写结论。"}


def rollback_plan(db, manifest):
    if manifest.get("version") != "formal-migration-v1" or fingerprint(manifest.get("risk_rows")) != manifest.get("snapshot_hash"):
        raise ValueError("migration_snapshot_corrupt")
    columns = {c.name for c in models.RiskAssessment.__table__.columns}
    differences = []
    for before in manifest["risk_rows"]:
        if set(before) != columns:
            raise ValueError("migration_schema_changed")
        row = db.get(models.RiskAssessment, before["id"])
        if row is None:
            raise ValueError("migration_risk_missing")
        now = json.loads(json.dumps({c: getattr(row, c) for c in columns}, default=str))
        changed = {c: {"current": now[c], "restore_to": before[c]} for c in columns if now[c] != before[c]}
        if changed:
            differences.append({"risk_id": row.id, "changes": changed})
    original_ids = {r["id"] for r in manifest["risk_rows"]}
    return {"read_only": True, "requires_separate_approval": True, "differences": differences,
        "new_risk_ids_preserved": [r.id for r in db.query(models.RiskAssessment) if r.id not in original_ids],
        "audit_records_preserved": True, "shadow_records_preserved": True}
