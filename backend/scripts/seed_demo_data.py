import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.database import SessionLocal, init_db
from app.services.matching_engine import run_matching
from app.services.remediation_engine import generate_remediation_tasks
from app.services.risk_engine import calculate_risk


def main():
    init_db()
    db = SessionLocal()
    try:
        match_count = run_matching(db)
        risk_count = calculate_risk(db)
        task_count = generate_remediation_tasks(db)
        print(
            "Real-data analysis completed: "
            f"matches={match_count}, risks={risk_count}, tasks={task_count}. "
            "No sample assets were imported."
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
