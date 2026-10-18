"""Import a preserved official GHSA snapshot and export a version assessment.

Run from backend: python scripts/import_iot_official.py --help
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import SessionLocal, engine
from app import models
from app.services.iot_official import import_snapshot, assess_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--ecosystem", choices=["zephyr", "openwrt"], required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.snapshot.read_text(encoding="utf-8-sig"))
    rows = data if isinstance(data, list) else data["rows"]
    models.IotOfficialAdvisory.__table__.create(engine, checkfirst=True)
    with SessionLocal() as db:
        import_snapshot(db, args.ecosystem, rows)
        result = assess_snapshot(db, args.ecosystem, args.version)
        db.commit()
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Imported {result['count']} official advisories; coverage remains partial.")


if __name__ == "__main__":
    main()
