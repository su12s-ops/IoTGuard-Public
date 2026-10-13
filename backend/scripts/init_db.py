import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.database import init_db, schema_health_report


if __name__ == "__main__":
    added_columns = init_db()
    report = schema_health_report()
    if added_columns:
        print("LinuxGuard database initialized. Added columns:", ", ".join(added_columns))
    else:
        print("LinuxGuard database initialized.")
    if report["ok"]:
        print("Schema health: ok")
    else:
        print("Schema health: failed", report)
        raise SystemExit(1)
