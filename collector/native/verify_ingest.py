#!/usr/bin/env python3
"""Replay freshly captured C records through real isolated FastAPI + worker."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture")
    parser.add_argument("report")
    args = parser.parse_args()
    records = [json.loads(line) for line in Path(args.capture).read_text().splitlines()]
    assert records and all(e["source"] == "c_ebpf" for e in records)
    with tempfile.TemporaryDirectory(prefix="native-ingest-", ignore_cleanup_errors=True) as directory:
        work = Path(directory)
        os.environ.update(PYTHON_DOTENV_DISABLED="1", LINUXGUARD_ARCHIVE_ON_STARTUP="0",
                          LINUXGUARD_DATABASE_URL="sqlite:///" + str(work / "isolated.db"),
                          LINUXGUARD_EVENT_FILE=str(work / "events.jsonl"),
                          LINUXGUARD_DATA_DIR=str(work), LINUXGUARD_CONTROL_TOKEN="native-isolated",
                          LINUXGUARD_DEPLOYMENT_MODE="standard", DEEPSEEK_API_KEY="")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import SessionLocal
        from app import models
        with TestClient(app) as client:
            headers = {"X-Control-Token": "native-isolated"}
            url = "/api/runtime/ebpf/events/batch"
            reply = client.post(url, headers=headers, json={"events": records})
            assert reply.status_code == 200, reply.text
            assert reply.json()["accepted"] == len(records)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                status = client.get("/api/runtime/ebpf/reliability").json()
                if status["evidence_processing"]["pending"] == 0: break
                time.sleep(.1)
            else: raise AssertionError(status)
            with SessionLocal() as db:
                assert db.query(models.RuntimeEvent).count() == db.query(models.SecurityEvidence).count() == len(records)
            exposed = client.get("/api/runtime/evidence", params={"limit": 200}).json()["events"]
            assert any(e.get("result") == "failure" for e in exposed)
            assert any(e.get("result") == "pending" for e in exposed)
            again = client.post(url, headers=headers, json={"events": records}).json()
            assert again["duplicates"] == len(records) and again["accepted"] == 0
        report = {"passed": True, "captured_records": len(records), "ack": reply.json(),
                  "replay_duplicates": again["duplicates"], "evidence_processing": status["evidence_processing"],
                  "checks": ["real-C-records", "FastAPI-batch-ack", "lifespan-worker", "outcomes-exposed", "idempotent-replay"]}
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
        print(json.dumps({"passed": True, "records": len(records)}))


if __name__ == "__main__":
    main()
