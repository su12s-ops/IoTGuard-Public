import sqlite3

from scripts.restore_archive_snapshot import TABLE_MAPPINGS, _restore_table


def test_restore_contract_contains_risk_report_and_audit_in_parent_first_order(tmp_path):
    keys = [key for key, _ in TABLE_MAPPINGS]
    assert keys.index("risks") < keys.index("analysis_reports")
    assert keys.index("risks") < keys.index("agent_audit_records")

    conn = sqlite3.connect(tmp_path / "restore.db")
    try:
        conn.executescript(
            """
            CREATE TABLE risk_assessment (id INTEGER PRIMARY KEY, cve_id TEXT);
            CREATE TABLE analysis_report (id INTEGER PRIMARY KEY, review_run_id TEXT, status TEXT);
            CREATE TABLE agent_audit_record (
                id INTEGER PRIMARY KEY, run_id TEXT, risk_id INTEGER,
                object_id TEXT, agent_name TEXT, parse_status TEXT
            );
            """
        )
        assert _restore_table(conn, "risk_assessment", [{"id": 9, "cve_id": "CVE-TEST-9"}]) == 1
        assert _restore_table(conn, "analysis_report", [{
            "id": 3, "review_run_id": "restore-run", "status": "completed",
            "newer_unknown_column": "ignored",
        }]) == 1
        assert _restore_table(conn, "agent_audit_record", [{
            "id": 4, "run_id": "restore-run", "risk_id": 9,
            "object_id": "risk-9", "agent_name": "evidence_audit_agent", "parse_status": "valid",
        }]) == 1
        conn.commit()

        assert conn.execute("SELECT cve_id FROM risk_assessment WHERE id=9").fetchone()[0] == "CVE-TEST-9"
        assert conn.execute("SELECT review_run_id FROM analysis_report WHERE id=3").fetchone()[0] == "restore-run"
        assert conn.execute("SELECT risk_id FROM agent_audit_record WHERE id=4").fetchone()[0] == 9
    finally:
        conn.close()


def test_restore_does_not_resurrect_task_leases_or_running_writes(tmp_path):
    conn = sqlite3.connect(tmp_path / "leases.db")
    conn.executescript("CREATE TABLE harness_run(id TEXT, status TEXT, error TEXT); CREATE TABLE harness_asset_lock(asset_id INTEGER, run_id TEXT);")
    try:
        assert _restore_table(conn, "harness_asset_lock", [{"asset_id": 1, "run_id": "test"}]) == 0
        _restore_table(conn, "harness_run", [{"id": "test", "status": "running"}])
        assert conn.execute("SELECT status FROM harness_run").fetchone()[0] == "interrupted"
    finally:
        conn.close()
