import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.database import SessionLocal, init_db
from app.services.matching_engine import run_matching
from app.services.real_intel_collector import sync_real_vulnerabilities
from app.services.remediation_engine import generate_remediation_tasks
from app.services.risk_engine import calculate_risk


def main():
    parser = argparse.ArgumentParser(description="Sync real vulnerability intelligence from NVD, CISA KEV, and EPSS.")
    parser.add_argument("--keyword", default="linux", help="NVD keywordSearch value, for example linux, openssl, nginx")
    parser.add_argument("--days", type=int, default=30, help="Published date window in days, 1-120")
    parser.add_argument("--limit", type=int, default=100, help="Maximum NVD CVEs to import, 1-500")
    parser.add_argument("--append", action="store_true", help="Append/update instead of replacing existing vulnerabilities")
    parser.add_argument("--no-analysis", action="store_true", help="Do not run matching, risk scoring, and remediation generation")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        result = sync_real_vulnerabilities(
            db,
            keyword=args.keyword,
            days=args.days,
            limit=args.limit,
            replace=not args.append,
        )
        print(
            "Real intel synced: "
            f"nvd={result.total_from_nvd}, saved={result.saved}, "
            f"kev={result.kev_marked}, epss={result.epss_enriched}"
        )
        if not args.no_analysis:
            matches = run_matching(db)
            risks = calculate_risk(db)
            tasks = generate_remediation_tasks(db)
            print(f"Analysis completed: matches={matches}, risks={risks}, tasks={tasks}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

