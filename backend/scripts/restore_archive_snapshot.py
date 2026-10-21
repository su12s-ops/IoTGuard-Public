import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.config import DATA_DIR, DATABASE_URL  # noqa: E402
from app.services.experiment_lifecycle import ARCHIVE_TABLE_MAPPINGS  # noqa: E402


TABLE_MAPPINGS = list(ARCHIVE_TABLE_MAPPINGS)

# 表/列标识符只允许小写字母与下划线；任何外部值先经此校验才能进入 SQL 标识位。
_IDENTIFIER_RE = re.compile(r"[a-z_]{1,64}")


def _safe_identifier(identifier: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(identifier):
        raise SystemExit(f"非法表/列名: {identifier!r}")
    return identifier


def _quote(identifier: str) -> str:
    return '"' + _safe_identifier(identifier).replace('"', '""') + '"'


# 固定表白名单：每个可调用体内仅出现字面量 SQL；表名绝不拼接进语句。
_TABLE_PRAGMA = {
    "runtime_evidence_job": lambda conn: conn.execute("PRAGMA table_info(runtime_evidence_job)").fetchall(),
    "linux_asset": lambda conn: conn.execute("PRAGMA table_info(linux_asset)").fetchall(),
    "asset_package": lambda conn: conn.execute("PRAGMA table_info(asset_package)").fetchall(),
    "asset_service": lambda conn: conn.execute("PRAGMA table_info(asset_service)").fetchall(),
    "demo_target": lambda conn: conn.execute("PRAGMA table_info(demo_target)").fetchall(),
    "device_connection": lambda conn: conn.execute("PRAGMA table_info(device_connection)").fetchall(),
    "device_observation": lambda conn: conn.execute("PRAGMA table_info(device_observation)").fetchall(),
    "openwrt_advisory": lambda conn: conn.execute("PRAGMA table_info(openwrt_advisory)").fetchall(),
    "runtime_sensor": lambda conn: conn.execute("PRAGMA table_info(runtime_sensor)").fetchall(),
    "vulnerability_info": lambda conn: conn.execute("PRAGMA table_info(vulnerability_info)").fetchall(),
    "threat_intel_source": lambda conn: conn.execute("PRAGMA table_info(threat_intel_source)").fetchall(),
    "vulnerability_match": lambda conn: conn.execute("PRAGMA table_info(vulnerability_match)").fetchall(),
    "risk_assessment": lambda conn: conn.execute("PRAGMA table_info(risk_assessment)").fetchall(),
    "analysis_report": lambda conn: conn.execute("PRAGMA table_info(analysis_report)").fetchall(),
    "agent_audit_record": lambda conn: conn.execute("PRAGMA table_info(agent_audit_record)").fetchall(),
    "remediation_task": lambda conn: conn.execute("PRAGMA table_info(remediation_task)").fetchall(),
    "runtime_event": lambda conn: conn.execute("PRAGMA table_info(runtime_event)").fetchall(),
    "harness_run": lambda conn: conn.execute("PRAGMA table_info(harness_run)").fetchall(),
    "harness_tool_call": lambda conn: conn.execute("PRAGMA table_info(harness_tool_call)").fetchall(),
    "harness_asset_lock": lambda conn: conn.execute("PRAGMA table_info(harness_asset_lock)").fetchall(),
}
_TABLE_DELETE = {
    "runtime_evidence_job": lambda conn: conn.execute("DELETE FROM runtime_evidence_job"),
    "linux_asset": lambda conn: conn.execute("DELETE FROM linux_asset"),
    "asset_package": lambda conn: conn.execute("DELETE FROM asset_package"),
    "asset_service": lambda conn: conn.execute("DELETE FROM asset_service"),
    "demo_target": lambda conn: conn.execute("DELETE FROM demo_target"),
    "device_connection": lambda conn: conn.execute("DELETE FROM device_connection"),
    "device_observation": lambda conn: conn.execute("DELETE FROM device_observation"),
    "openwrt_advisory": lambda conn: conn.execute("DELETE FROM openwrt_advisory"),
    "runtime_sensor": lambda conn: conn.execute("DELETE FROM runtime_sensor"),
    "vulnerability_info": lambda conn: conn.execute("DELETE FROM vulnerability_info"),
    "threat_intel_source": lambda conn: conn.execute("DELETE FROM threat_intel_source"),
    "vulnerability_match": lambda conn: conn.execute("DELETE FROM vulnerability_match"),
    "risk_assessment": lambda conn: conn.execute("DELETE FROM risk_assessment"),
    "analysis_report": lambda conn: conn.execute("DELETE FROM analysis_report"),
    "agent_audit_record": lambda conn: conn.execute("DELETE FROM agent_audit_record"),
    "remediation_task": lambda conn: conn.execute("DELETE FROM remediation_task"),
    "runtime_event": lambda conn: conn.execute("DELETE FROM runtime_event"),
    "harness_run": lambda conn: conn.execute("DELETE FROM harness_run"),
    "harness_tool_call": lambda conn: conn.execute("DELETE FROM harness_tool_call"),
}
# 白名单与业务映射漂移时立即失败，而不是静默漏恢复。
assert set(_TABLE_DELETE) == {table for _, table in TABLE_MAPPINGS}, \
    "字面量 SQL 白名单与 TABLE_MAPPINGS 不同步"


def _sqlite_path() -> Path:
    prefix = "sqlite:///"
    if not DATABASE_URL.startswith(prefix):
        raise SystemExit(f"Only sqlite databases are supported, got: {DATABASE_URL}")
    return Path(DATABASE_URL[len(prefix) :])


def _default_archive() -> Path:
    archive_dir = DATA_DIR / "archives"
    candidates = sorted(archive_dir.glob("exp-*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not candidates:
        raise SystemExit(f"No archive found under {archive_dir}")
    return candidates[0]


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = _TABLE_PRAGMA[_safe_identifier(table_name)](conn)
    return {row[1] for row in rows}


def _restore_table(conn: sqlite3.Connection, table_name: str, rows: list[dict]) -> int:
    if table_name == "harness_asset_lock":
        return 0  # Leases belong to live processes, never to an archive.
    available = _table_columns(conn, table_name)
    restored = 0
    for row in rows:
        payload = {key: value for key, value in row.items() if key in available}
        if table_name in {"harness_run", "harness_tool_call"} and payload.get("status") == "running":
            payload["status"] = "interrupted"
            if "error" in available:
                payload["error"] = "从归档恢复的中断任务；须重新检查设备状态，不自动重放写操作。"
        if not payload:
            continue
        columns = [_safe_identifier(column) for column in payload]
        placeholders = ", ".join("?" for _ in columns)
        quoted_columns = ", ".join(_quote(column) for column in columns)
        sql = f"INSERT INTO {_quote(table_name)} ({quoted_columns}) VALUES ({placeholders})"
        conn.execute(sql, [payload[column] for column in columns])
        restored += 1
    return restored


def main() -> None:
    parser = argparse.ArgumentParser(description="Restore LinuxGuard database snapshot from an archived experiment JSON.")
    parser.add_argument("--archive", help="Path to archive JSON file. Defaults to the latest archive in backend/data/archives.")
    args = parser.parse_args()

    archive_path = Path(args.archive) if args.archive else _default_archive()
    payload = json.loads(archive_path.read_text(encoding="utf-8"))
    db_path = _sqlite_path()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        for _, table_name in reversed(TABLE_MAPPINGS):
            _TABLE_DELETE[_safe_identifier(table_name)](conn)
        if _table_columns(conn, "harness_asset_lock"):
            conn.execute("DELETE FROM harness_asset_lock")

        restored_counts = {}
        for archive_key, table_name in TABLE_MAPPINGS:
            restored_counts[table_name] = _restore_table(conn, table_name, payload.get(archive_key, []) or [])

        conn.commit()
    finally:
        conn.close()

    print(f"restored archive: {archive_path}")
    for _, table_name in TABLE_MAPPINGS:
        print(f"{table_name}: {restored_counts[table_name]}")


if __name__ == "__main__":
    main()
