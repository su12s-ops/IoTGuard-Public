"""Refresh both official repositories atomically; suitable for a service timer.

No matching, risk changes, model calls or device writes are performed.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import SessionLocal, init_db
from app.services.iot_official import import_snapshot
from app.services.openwrt_intel import fetch_advisory_rows, sync_openwrt_advisories


def main():
    batches = {ecosystem: fetch_advisory_rows(os.getenv("GITHUB_TOKEN"), ecosystem=ecosystem)
               for ecosystem in ("openwrt", "zephyr")}
    init_db()
    with SessionLocal() as db:
        for ecosystem, rows in batches.items():
            import_snapshot(db, ecosystem, rows)
        sync_openwrt_advisories(db, batches["openwrt"])
        db.commit()
    print("Official snapshots refreshed: " + ", ".join(f"{key}={len(rows)}" for key, rows in batches.items()))


if __name__ == "__main__":
    main()
