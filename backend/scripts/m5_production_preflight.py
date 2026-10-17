"""Consistent backup and isolated field-restoration rehearsal; no device writes."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import create_engine, DateTime
from sqlalchemy.orm import Session
from app import config, models
from app.database import SessionLocal
from app.services.unified.migration import snapshot, rollback_plan


def run():
    root = Path(__file__).resolve().parents[2]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = root / "local-archive" / "m5-final-switch" / stamp
    destination.mkdir(parents=True, exist_ok=False)
    with SessionLocal() as db:
        busy = {
            "risks": db.query(models.RiskAssessment).filter(models.RiskAssessment.review_status.in_(
                ["running", "evidence_preparing", "agent_reviewing", "conflict_review", "coordinator_review"])).count(),
            "reports": db.query(models.AnalysisReport).filter_by(status="running").count(),
            "unified": db.query(models.UnifiedAnalysisRun).filter_by(status="running").count(),
            "harness": db.query(models.HarnessRun).filter(models.HarnessRun.status.in_(
                ["running", "executing", "collecting", "queued", "ubuntu_executing"])).count()}
        if any(busy.values()):
            raise RuntimeError("workers_not_drained:" + json.dumps(busy))
        manifest = snapshot(db)
    from sqlalchemy.engine import make_url
    url = make_url(config.DATABASE_URL)
    if url.drivername != "sqlite":
        raise RuntimeError("sqlite_backup_only")
    source = Path(url.database).resolve()
    saved = destination / "production.db"
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as original, sqlite3.connect(saved) as backup:
        original.backup(backup)
        if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("backup_integrity_failed")
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    rehearsal = destination / "rehearsal.db"
    with sqlite3.connect(saved) as backup, sqlite3.connect(rehearsal) as test:
        backup.backup(test)
    engine = create_engine("sqlite:///" + str(rehearsal))
    with Session(engine) as db:
        row = db.query(models.RiskAssessment).first()
        row.review_reason = "isolated_recovery_probe"
        db.commit()
        assert rollback_plan(db, manifest)["differences"]
        for before in manifest["risk_rows"]:
            target = db.get(models.RiskAssessment, before["id"])
            for column in models.RiskAssessment.__table__.columns:
                value = before[column.name]
                if isinstance(column.type, DateTime) and isinstance(value, str):
                    value = datetime.fromisoformat(value)
                setattr(target, column.name, value)
        db.commit()
        assert rollback_plan(db, manifest)["differences"] == []
        assert snapshot(db)["snapshot_hash"] == manifest["snapshot_hash"]
    engine.dispose()
    result = {"backup": str(saved), "sha256": hashlib.sha256(saved.read_bytes()).hexdigest(),
        "bytes": saved.stat().st_size, "integrity_check": "ok", "busy": busy,
        "snapshot_hash": manifest["snapshot_hash"], "risk_rows": len(manifest["risk_rows"]),
        "isolated_restore_differences": 0, "device_write": False}
    (destination / "verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    run()
