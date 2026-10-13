import os

from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DATABASE_URL


_SQLITE_KWARGS = {"check_same_thread": False, "timeout": 30}
engine = create_engine(
    DATABASE_URL,
    connect_args=_SQLITE_KWARGS if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

if DATABASE_URL.startswith("sqlite") and os.getenv("LINUXGUARD_DEPLOYMENT_MODE") == "collection_only":
    @event.listens_for(engine, "connect")
    def _integration_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

# ── SQLite WAL 模式，提升并发写入能力 ──
if DATABASE_URL.startswith("sqlite"):
    try:
        with engine.connect() as _wal_conn:
            _wal_conn.execute(text("PRAGMA journal_mode=WAL"))
    except Exception:
        pass
Base = declarative_base()


RISK_ASSESSMENT_COLUMN_MIGRATIONS = {
    "match_id": "INTEGER REFERENCES vulnerability_match(id)",
    "package_name": "VARCHAR(128) DEFAULT ''",
    "candidate_fingerprint": "VARCHAR(64) DEFAULT ''",
    "active": "BOOLEAN DEFAULT 1",
    "static_score": "FLOAT DEFAULT 0",
    "runtime_score": "FLOAT DEFAULT 0",
    "environment_score": "FLOAT DEFAULT 0",
    "actionability_score": "FLOAT DEFAULT 0",
    "reachability_score": "FLOAT DEFAULT 0",
    "path_count": "INTEGER DEFAULT 0",
    "exposed_service_count": "INTEGER DEFAULT 0",
    "affected_status": "VARCHAR(32) DEFAULT 'unknown'",
    "reachable_status": "VARCHAR(32) DEFAULT 'none'",
    "runtime_status": "VARCHAR(32) DEFAULT 'waiting'",
    "exploitability_status": "VARCHAR(32) DEFAULT 'unlikely'",
    "decision": "VARCHAR(32) DEFAULT 'monitor'",
    "decision_confidence": "FLOAT DEFAULT 0",
    "reachability_reason": "TEXT DEFAULT ''",
    "decision_reason": "TEXT DEFAULT ''",
    # ── 初步研判（确定性引擎） ──
    "preliminary_score": "FLOAT DEFAULT 0",
    "preliminary_level": "VARCHAR(32) DEFAULT 'Low'",
    "preliminary_decision": "VARCHAR(32) DEFAULT 'monitor'",
    "preliminary_reason": "TEXT DEFAULT ''",
    # ── 智能体协同复核 ──
    "review_status": "VARCHAR(32) DEFAULT 'pending'",
    "review_verdict": "VARCHAR(32) DEFAULT ''",
    "review_confidence": "FLOAT DEFAULT 0",
    "review_adjustment": "FLOAT DEFAULT 0",
    "review_evidence_ids": "TEXT DEFAULT '[]'",
    "review_conflicts": "TEXT DEFAULT '[]'",
    "review_missing_evidence": "TEXT DEFAULT '[]'",
    "review_reason": "TEXT DEFAULT ''",
    "review_completed_at": "DATETIME",
    "human_review_required": "BOOLEAN DEFAULT 0",
    "review_failed_agents": "TEXT DEFAULT '[]'",
    "evidence_packet_json": "TEXT DEFAULT '{}'",
    "agent_results_json": "TEXT DEFAULT '{}'",
    "conflict_result_json": "TEXT DEFAULT '{}'",
    "audit_policy_reasons": "TEXT DEFAULT '[]'",
    "recommended_priority": "VARCHAR(32) DEFAULT ''",
    "recommended_action": "VARCHAR(64) DEFAULT ''",
    "risk_direction": "VARCHAR(32) DEFAULT 'maintain'",
    "reanalysis_count": "INTEGER DEFAULT 0",
    "updated_at": "DATETIME",
    "applicability_source": "VARCHAR(32) DEFAULT 'unknown'",
    "ubuntu_priority": "VARCHAR(32) DEFAULT 'unknown'",
    "technical_severity": "VARCHAR(32) DEFAULT 'unknown'",
    "likelihood_level": "VARCHAR(32) DEFAULT 'unknown'",
    "known_exploited": "BOOLEAN DEFAULT 0",
    "risk_factors_json": "TEXT DEFAULT '{}'",
}

ASSET_COLUMN_MIGRATIONS = {
    "device_type": "VARCHAR(32) DEFAULT 'linux_server'",
    "device_model": "VARCHAR(128) DEFAULT ''",
    "mac_address": "VARCHAR(32) DEFAULT ''",
    "firmware_version": "VARCHAR(128) DEFAULT ''",
    "identity_source": "VARCHAR(64) DEFAULT 'uploaded_inventory'",
    "identity_confidence": "FLOAT DEFAULT 0",
    "capabilities_json": "TEXT DEFAULT '{}'",
    "inventory_complete": "BOOLEAN DEFAULT 0",
    "inventory_collected_at": "DATETIME",
    "inventory_sha256": "VARCHAR(64) DEFAULT ''",
    "inventory_metadata_json": "TEXT DEFAULT '{}'",
    "inventory_external_id": "VARCHAR(128)",
    "last_seen_at": "DATETIME",
}

DEVICE_CONNECTION_COLUMN_MIGRATIONS = {
    "auth_type": "VARCHAR(16) NOT NULL DEFAULT 'password'",
    "key_path_env": "VARCHAR(128) NOT NULL DEFAULT ''",
    "key_passphrase_env": "VARCHAR(128) NOT NULL DEFAULT ''",
}

RUNTIME_COLUMN_MIGRATIONS = {
    "process_id": "INTEGER DEFAULT 0", "parent_process_id": "INTEGER DEFAULT 0",
    "process_exec_id": "VARCHAR(255) DEFAULT ''", "parent_exec_id": "VARCHAR(255) DEFAULT ''",
    "process_start_time": "VARCHAR(64) DEFAULT ''", "boot_id": "VARCHAR(64) DEFAULT ''",
    "sensor_id": "VARCHAR(128) DEFAULT ''", "executable": "TEXT DEFAULT ''",
    "container_id": "VARCHAR(128) DEFAULT ''", "event_fingerprint": "VARCHAR(64) DEFAULT ''",
}

VULNERABILITY_MATCH_COLUMN_MIGRATIONS = {
    "match_status": "VARCHAR(32) DEFAULT 'unknown'",
    "reason_code": "VARCHAR(64) DEFAULT 'unknown'",
    "evidence_fingerprint": "VARCHAR(64) DEFAULT ''",
    "active": "BOOLEAN DEFAULT 1",
    "updated_at": "DATETIME",
}

REMEDIATION_TASK_COLUMN_MIGRATIONS = {
    "risk_id": "INTEGER REFERENCES risk_assessment(id)",
}

# device_observation 表的发现闭环列（阶段五：观察 → 识别 → 建档 → CVE）
DEVICE_OBSERVATION_COLUMN_MIGRATIONS = {
    "review_status": "VARCHAR(32) DEFAULT 'pending' NOT NULL",
    "review_note": "TEXT DEFAULT ''",
    "review_attempts": "INTEGER DEFAULT 0",
    "reviewed_at": "DATETIME",
    "promoted_device_id": "VARCHAR(64) DEFAULT ''",
}

# analysis_report 表的新增列（旧库可能只有 answer/transcript_json）
ANALYSIS_REPORT_COLUMN_MIGRATIONS = {
    "verdict_json": "TEXT DEFAULT ''",
    "opinions_json": "TEXT DEFAULT ''",
    "review_run_id": "VARCHAR(32) DEFAULT ''",
    "termination_reason": "VARCHAR(64) DEFAULT ''",
    "verdict_hit": "BOOLEAN DEFAULT 0",
    "verdict_parse_ok": "BOOLEAN DEFAULT 0",
    "turn_count": "INTEGER DEFAULT 0",
    "candidate_count": "INTEGER DEFAULT 0",
    "object_verdict_count": "INTEGER DEFAULT 0",
    "agent_executions_json": "TEXT DEFAULT '{}'",
    "pipeline_version": "VARCHAR(64) DEFAULT ''",
    "current_stage": "VARCHAR(64) DEFAULT ''",
    "selected_object_count": "INTEGER DEFAULT 0",
    "processed_object_count": "INTEGER DEFAULT 0",
    "completed_object_count": "INTEGER DEFAULT 0",
    "human_review_object_count": "INTEGER DEFAULT 0",
    "selected_object_ids_json": "TEXT DEFAULT '[]'",
    "skipped_objects_json": "TEXT DEFAULT '[]'",
    "progress_percent": "INTEGER DEFAULT 0",
    "current_object_id": "VARCHAR(64) DEFAULT ''",
    "progress_message": "TEXT DEFAULT ''",
    "progress_sequence": "INTEGER DEFAULT 0",
    "progress_updated_at": "DATETIME",
}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def recover_stale_running(max_minutes: int = 30) -> int:
    """恢复超时的 running 状态风险记录。

    当 review_status='running' 且 review_completed_at 为 None 或距今超过
    max_minutes 分钟时，标记为 interrupted 并恢复到 candidate 状态。
    返回恢复的记录数。
    """
    from datetime import datetime, timedelta, timezone

    from app import models

    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_minutes)
        stale = (
            db.query(models.RiskAssessment)
            .filter(
                models.RiskAssessment.review_status.in_([
                    "running", "evidence_preparing", "agent_reviewing", "conflict_review", "coordinator_review"
                ]),
                (
                    models.RiskAssessment.review_completed_at.is_(None)
                    | (models.RiskAssessment.review_completed_at < cutoff)
                ),
            )
            .all()
        )
        count = 0
        for risk in stale:
            # 检查是否有对应的 AnalysisReport 仍在运行
            active_report = (
                db.query(models.AnalysisReport)
                .filter(
                    models.AnalysisReport.status == "running",
                    models.AnalysisReport.created_at > cutoff,
                )
                .first()
            )
            if active_report is None:
                risk.review_status = "reanalysis_required"
                risk.human_review_required = False
                # 记录恢复原因
                risk.review_reason = (risk.review_reason or "") + " [stale_running_recovered]"
                if risk.decision_reason:
                    risk.decision_reason = risk.decision_reason + " [stale_running_recovered]"
                count += 1
        if count:
            db.commit()
        return count
    finally:
        db.close()


def init_db():
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    return _migrate_sqlite_schema()


def _migrate_sqlite_schema():
    added_columns: list[str] = []
    if engine.dialect.name != "sqlite":
        return added_columns
    with engine.begin() as conn:
        for table_name, migrations in [
            ("linux_asset", ASSET_COLUMN_MIGRATIONS),
            ("device_connection", DEVICE_CONNECTION_COLUMN_MIGRATIONS),
            ("runtime_event", RUNTIME_COLUMN_MIGRATIONS),
            ("vulnerability_match", VULNERABILITY_MATCH_COLUMN_MIGRATIONS),
            ("risk_assessment", RISK_ASSESSMENT_COLUMN_MIGRATIONS),
            ("remediation_task", REMEDIATION_TASK_COLUMN_MIGRATIONS),
            ("analysis_report", ANALYSIS_REPORT_COLUMN_MIGRATIONS),
            ("device_observation", DEVICE_OBSERVATION_COLUMN_MIGRATIONS),
        ]:
            if not _sqlite_table_exists(conn, table_name):
                continue
            existing_columns = {
                row[1]
                for row in conn.execute(text(f"PRAGMA table_info('{table_name}')")).fetchall()
            }
            for column_name, ddl in migrations.items():
                if column_name in existing_columns:
                    continue
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"))
                added_columns.append(f"{table_name}.{column_name}")
        if _sqlite_table_exists(conn, "linux_asset"):
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_linux_asset_inventory_external_id "
                              "ON linux_asset(inventory_external_id) WHERE inventory_external_id IS NOT NULL"))
        _backfill_targeted_refactor(conn)
    return added_columns


def _backfill_targeted_refactor(conn) -> None:
    """Backfill exact event links without deleting historical rows."""
    if not _sqlite_table_exists(conn, "vulnerability_match") or not _sqlite_table_exists(conn, "risk_assessment"):
        return

    conn.execute(text("""
        UPDATE vulnerability_match
        SET package_name = COALESCE(package_name, ''),
            match_status = CASE
                WHEN affected = 1 THEN 'potentially_affected'
                WHEN COALESCE(installed_version, '') = '' THEN 'not_applicable'
                ELSE 'fixed'
            END,
            reason_code = CASE
                WHEN affected = 1 THEN 'installed_version_below_fixed'
                WHEN COALESCE(installed_version, '') = '' THEN 'package_not_installed'
                ELSE 'installed_version_fixed'
            END,
            active = COALESCE(active, 1),
            updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
        WHERE match_status IS NULL OR match_status = '' OR reason_code IS NULL OR reason_code = '' OR updated_at IS NULL
    """))

    # A legacy risk can be linked automatically only when asset+CVE identifies
    # exactly one match. Ambiguous historical rows remain unlinked and are
    # explicitly queued for reanalysis instead of choosing `.first()`.
    conn.execute(text("""
        UPDATE risk_assessment
        SET match_id = (
                SELECT MIN(vm.id) FROM vulnerability_match vm
                WHERE vm.asset_id = risk_assessment.asset_id
                  AND vm.cve_id = risk_assessment.cve_id
            ),
            package_name = COALESCE((
                SELECT MIN(vm.package_name) FROM vulnerability_match vm
                WHERE vm.asset_id = risk_assessment.asset_id
                  AND vm.cve_id = risk_assessment.cve_id
            ), package_name, ''),
            active = COALESCE(active, 1),
            updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
        WHERE match_id IS NULL
          AND 1 = (
              SELECT COUNT(*) FROM vulnerability_match vm
              WHERE vm.asset_id = risk_assessment.asset_id
                AND vm.cve_id = risk_assessment.cve_id
          )
    """))
    conn.execute(text("""
        UPDATE risk_assessment
        SET review_status = 'reanalysis_required',
            review_reason = CASE
                WHEN COALESCE(review_reason, '') = '' THEN 'legacy_match_link_ambiguous'
                ELSE review_reason || ' [legacy_match_link_ambiguous]'
            END,
            human_review_required = 1
        WHERE match_id IS NULL
          AND 1 < (
              SELECT COUNT(*) FROM vulnerability_match vm
              WHERE vm.asset_id = risk_assessment.asset_id
                AND vm.cve_id = risk_assessment.cve_id
          )
    """))
    conn.execute(text("""
        UPDATE remediation_task
        SET risk_id = (
            SELECT ra.id FROM risk_assessment ra
            WHERE ra.asset_id = remediation_task.asset_id
              AND ra.cve_id = remediation_task.cve_id
              AND ra.package_name = remediation_task.package_name
            ORDER BY ra.id LIMIT 1
        )
        WHERE risk_id IS NULL
    """))
    conn.execute(text("""
        UPDATE risk_assessment
        SET review_status = CASE
            WHEN review_status = 'completed' AND COALESCE(human_review_required, 0) = 0 THEN 'auto_confirmed'
            WHEN review_status = 'human_review' THEN 'pending_human_review'
            WHEN review_status = 'running' THEN 'reanalysis_required'
            ELSE review_status
        END
        WHERE review_status IN ('completed', 'human_review', 'running')
    """))

    # Enforce the current audit-policy invariant on migrated conclusions too.
    # A historical automatic conclusion must not retain final authority when
    # the event is High/Critical (or belongs to a critical/core asset).
    risk_columns = {
        row[1] for row in conn.execute(text("PRAGMA table_info('risk_assessment')")).fetchall()
    }
    high_risk_predicates: list[str] = []
    if "risk_level" in risk_columns:
        high_risk_predicates.append("UPPER(COALESCE(risk_level, '')) IN ('HIGH', 'CRITICAL')")
    if "preliminary_level" in risk_columns:
        high_risk_predicates.append("UPPER(COALESCE(preliminary_level, '')) IN ('HIGH', 'CRITICAL')")
    if _sqlite_table_exists(conn, "linux_asset"):
        asset_columns = {
            row[1] for row in conn.execute(text("PRAGMA table_info('linux_asset')")).fetchall()
        }
        if "asset_id" in risk_columns and "business_level" in asset_columns:
            high_risk_predicates.append(
                "asset_id IN (SELECT id FROM linux_asset "
                "WHERE LOWER(COALESCE(business_level, '')) IN ('core', 'critical'))"
            )
    if high_risk_predicates:
        high_condition = " OR ".join(f"({item})" for item in high_risk_predicates)
        conn.execute(text(f"""
            UPDATE risk_assessment
            SET review_status = 'pending_human_review',
                human_review_required = 1,
                review_reason = CASE
                    WHEN COALESCE(review_reason, '') = '' THEN 'migrated_auto_confirmation_requires_human_review'
                    WHEN INSTR(review_reason, 'migrated_auto_confirmation_requires_human_review') = 0
                        THEN review_reason || ' [migrated_auto_confirmation_requires_human_review]'
                    ELSE review_reason
                END,
                audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
            WHERE review_status = 'auto_confirmed'
              AND ({high_condition})
        """))
        if "final_score" in risk_columns:
            conn.execute(text("""
                UPDATE risk_assessment SET final_score = NULL
                WHERE review_status = 'pending_human_review'
                  AND audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
            """))
        if "risk_level" in risk_columns:
            conn.execute(text("""
                UPDATE risk_assessment SET risk_level = NULL
                WHERE review_status = 'pending_human_review'
                  AND audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
            """))
        if "decision" in risk_columns:
            conn.execute(text("""
                UPDATE risk_assessment SET decision = NULL
                WHERE review_status = 'pending_human_review'
                  AND audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
            """))
        if _sqlite_table_exists(conn, "remediation_task"):
            remediation_columns = {
                row[1] for row in conn.execute(text("PRAGMA table_info('remediation_task')")).fetchall()
            }
            if {"risk_id", "status"}.issubset(remediation_columns):
                conn.execute(text("""
                    UPDATE remediation_task SET status = 'blocked'
                    WHERE risk_id IN (
                        SELECT id FROM risk_assessment
                        WHERE review_status = 'pending_human_review'
                          AND audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
                    )
                      AND status NOT IN ('verified', 'resolved')
                """))
    conn.execute(text("""
        UPDATE vulnerability_match
        SET active = 0,
            reason_code = 'duplicate_historical_record',
            match_reason = CASE
                WHEN COALESCE(match_reason, '') = '' THEN '历史重复匹配已停用，保留用于审计。'
                ELSE match_reason || ' [历史重复匹配已停用]'
            END
        WHERE id NOT IN (
            SELECT MIN(id) FROM vulnerability_match
            GROUP BY asset_id, cve_id, package_name
        )
    """))
    conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerability_match_active_event
        ON vulnerability_match(asset_id, cve_id, package_name)
        WHERE active = 1
    """))
    conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_assessment_active_match
        ON risk_assessment(match_id)
        WHERE active = 1 AND match_id IS NOT NULL
    """))


def schema_health_report() -> dict:
    from app import models

    report = {
        "database_url": DATABASE_URL,
        "dialect": engine.dialect.name,
        "ok": True,
        "tables": {},
    }

    if engine.dialect.name != "sqlite":
        return report

    expected = {
        "vulnerability_intelligence_source": [column.name for column in models.VulnerabilityIntelligenceSource.__table__.columns],
        "vulnerability_match": [column.name for column in models.VulnerabilityMatch.__table__.columns],
        "risk_assessment": [column.name for column in models.RiskAssessment.__table__.columns],
        "remediation_task": [column.name for column in models.RemediationTask.__table__.columns],
        "analysis_report": [column.name for column in models.AnalysisReport.__table__.columns],
        "agent_audit_record": [column.name for column in models.AgentAuditRecord.__table__.columns],
    }

    with engine.begin() as conn:
        for table_name, expected_columns in expected.items():
            table_exists = _sqlite_table_exists(conn, table_name)
            if not table_exists:
                report["ok"] = False
                report["tables"][table_name] = {
                    "exists": False,
                    "missing_columns": expected_columns,
                    "actual_columns": [],
                }
                continue

            actual_columns = [row[1] for row in conn.execute(text(f"PRAGMA table_info('{table_name}')")).fetchall()]
            missing_columns = [column for column in expected_columns if column not in actual_columns]
            if missing_columns:
                report["ok"] = False
            report["tables"][table_name] = {
                "exists": True,
                "missing_columns": missing_columns,
                "actual_columns": actual_columns,
            }

    return report


def _sqlite_table_exists(conn, table_name: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"),
            {"name": table_name},
        ).scalar()
    )
