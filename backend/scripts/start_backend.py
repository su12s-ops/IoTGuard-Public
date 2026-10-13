import sys
import os
from pathlib import Path

import uvicorn

# ── Windows 控制台 UTF-8 修复（不影响业务数据编码） ──
if os.name == "nt":
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.archive_on_startup import main as archive_on_startup  # noqa: E402
from app.config import DATABASE_URL  # noqa: E402
from app.database import init_db, schema_health_report  # noqa: E402
from scripts.cleanup_sample_assets import cleanup_sample_assets  # noqa: E402


def _env_enabled(name: str, default: str = "0") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _print_schema_report(report: dict, added_columns: list[str]) -> None:
    print(f"[startup] database={DATABASE_URL}")
    if added_columns:
        print(f"[startup] migrated risk_assessment columns: {', '.join(added_columns)}")
    elif report["dialect"] == "sqlite":
        print("[startup] schema migration: no pending sqlite columns")

    if report["ok"]:
        print("[startup] schema check: ok")
        return

    print("[startup] schema check: failed")
    for table_name, table in report["tables"].items():
        if table["exists"] and not table["missing_columns"]:
            continue
        if not table["exists"]:
            print(f"[startup] table missing: {table_name}")
            continue
        print(f"[startup] table {table_name} missing columns: {', '.join(table['missing_columns'])}")

    print("[startup] suggested recovery:")
    print("[startup]   1. docker compose down")
    print("[startup]   2. docker compose up --build")
    print("[startup]   3. if the old sqlite volume is still incompatible: docker compose down -v")


def main() -> None:
    print("[startup] initializing database schema")
    added_columns = init_db()
    report = schema_health_report()
    _print_schema_report(report, added_columns)
    if not report["ok"]:
        raise SystemExit(1)

    if _env_enabled("LINUXGUARD_ARCHIVE_ON_STARTUP", "0"):
        print("[startup] archiving previous experiment data if present")
        archive_on_startup()
    else:
        print("[startup] LINUXGUARD_ARCHIVE_ON_STARTUP=0, preserving current experiment data")

    print("[startup] removing legacy sample assets if present")
    removed = cleanup_sample_assets()
    print(f"[startup] legacy sample assets removed: {removed}")

    print("[startup] starting uvicorn on 0.0.0.0:8000")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
