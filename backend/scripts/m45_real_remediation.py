#!/usr/bin/env python3
"""Read-only M4.5 real acceptance. Never approves or executes device repairs.

Runs the product backend on loopback and existing Linux pull node over pinned
SSH. Only collection and Ubuntu dry-run requests are issued. Local evidence is
gitignored. Existing M4.4 development processes can be replaced with --replace.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import models
from app.database import SessionLocal
from app.services import canonical_official, ubuntu_repair

OUT = ROOT / "reports" / "m45-work"
OUT.mkdir(parents=True, exist_ok=True)


def save(name, value):
    (OUT / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def api(method, path, body=None, expected=200):
    if not path.startswith("/api/") or ".." in path or ":" in path:
        raise ValueError("invalid_product_path")
    conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=240)
    try:
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "X-Control-Token": os.environ.get("LINUXGUARD_CONTROL_TOKEN", "")})
        response = conn.getresponse()
        data = json.loads(response.read())
        if response.status != expected:
            raise RuntimeError(f"product_status_{response.status}:" + str(data)[:250])
        return data
    finally:
        conn.close()


def history(db):
    return {cls.__tablename__: hashlib.sha256(json.dumps([{c.name: getattr(r, c.name) for c in cls.__table__.columns}
        for r in db.query(cls).order_by(cls.id).all()], sort_keys=True, default=str).encode()).hexdigest()
        for cls in (models.RiskAssessment, models.UnifiedAnalysisRun)}


def poll(path, terminal):
    for _ in range(100):
        value = api("GET", path)
        if value["status"] in terminal:
            return value
        time.sleep(2)
    raise RuntimeError("product_task_timeout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    with SessionLocal() as db:
        before = history(db)
        asset = db.query(models.LinuxAsset).filter_by(distribution="ubuntu").one()
        conn = db.query(models.DeviceConnection).filter_by(asset_id=asset.id, enabled=True).one()
        risk = db.query(models.RiskAssessment).filter_by(asset_id=asset.id, active=True, package_name="curl").filter(
            models.RiskAssessment.cve_id.like("CVE-2026-94266%" )).one()
        asset_id, conn_id, risk_id = asset.id, conn.id, risk.id
        node_host, node_user = conn.host, conn.username
        allowed = ",".join(c.host + ("/128" if ":" in c.host else "/32") for c in db.query(models.DeviceConnection).filter_by(enabled=True))
        save("official-refresh", canonical_official.import_official_records(db, ["CVE-2026-94266"]))
        db.commit()
        save("official-proof", ubuntu_repair.official(db, "CVE-2026-94266"))
    save("history-before", before)
    if args.replace:
        # Only the recorded, project-owned development backend/worker PIDs.
        for folder in ("m44-work", "m45-work"):
            for name in ("collection-node.pid", "backend.pid"):
                p = ROOT / "reports" / folder / name
                if p.exists():
                    pid = int(p.read_text())
                    try:
                        import psutil
                        proc = psutil.Process(pid)
                        cmd = proc.cmdline()
                        expected = "uvicorn" if name == "backend.pid" else "ssh"
                        if any(expected in part.lower() for part in cmd):
                            proc.terminate()
                            proc.wait(timeout=10)
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        pass
    node_id = "m45-linux-node"
    node_token = secrets.token_urlsafe(36)
    env = os.environ.copy()
    env.update(LINUXGUARD_UNIFIED_PIPELINE="off", LINUXGUARD_ENABLE_DEVICE_REPAIR="0",
        LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR="0", LINUXGUARD_ARCHIVE_ON_STARTUP="0",
        LINUXGUARD_COLLECTION_NODE_ID=node_id, LINUXGUARD_COLLECTION_NODE_TOKEN=node_token,
        LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID=str(asset_id), LINUXGUARD_DISCOVERY_CIDRS=allowed)
    with (OUT / "backend.log").open("ab") as log:
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=ROOT / "backend", env=env, stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    (OUT / "backend.pid").write_text(str(server.pid))
    for _ in range(60):
        if server.poll() is not None:
            raise RuntimeError("backend_start_failed")
        try:
            api("GET", "/api/iot/capabilities")
            break
        except OSError:
            time.sleep(.5)
    node_env = {"LINUXGUARD_COLLECTION_NODE_ID": node_id, "LINUXGUARD_NODE_TOKEN": node_token,
        "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18445", "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
        "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0"}
    runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    bootstrap = "import os,sys\nos.environ.update(" + repr(node_env) + ")\nsys.argv=['collection_node_runner.py','--serve','--interval','3']\n"
    key = Path(os.getenv("M45_NODE_KEY", str(Path.home() / ".ssh/id_ed25519_vms"))).resolve()
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15", "-i", str(key), "-R", "18445:127.0.0.1:8000", f"{node_user}@{node_host}", "python3 -"]
    with (OUT / "collection-node.log").open("ab") as log:
        worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        worker.stdin.write((bootstrap + runner.replace("from __future__ import annotations", "")).encode())
        worker.stdin.close()
    (OUT / "collection-node.pid").write_text(str(worker.pid))
    run = api("POST", f"/api/iot/connections/{conn_id}/collection-runs", {"request_id": "m45-" + uuid.uuid4().hex})
    api("POST", f"/api/iot/collection-runs/{run['id']}/execute")
    collection = poll(f"/api/iot/collection-runs/{run['id']}", {"completed", "failed", "interrupted"})
    save("fresh-collection", collection)
    if collection["status"] != "completed":
        raise RuntimeError("fresh_collection_failed")
    repair = api("POST", "/api/harness/runs", {"asset_id": asset_id, "risk_id": risk_id, "goal": "repair", "shadow_run_id": "m44-real-841d76e9aa"})
    save("candidate-plan", repair)
    if repair["status"] != "awaiting_preflight":
        raise RuntimeError("candidate_blocked:" + str(repair["plan"]["blocked_reasons"]))
    api("POST", f"/api/harness/runs/{repair['id']}/dry-run")
    dry = poll(f"/api/harness/runs/{repair['id']}", {"awaiting_approval", "preflight_failed", "failed"})
    save("real-dry-run", dry)
    rejected = api("POST", f"/api/harness/runs/{repair['id']}/approve", {"plan_hash": "f" * 64, "actor": "M4.5-readonly-acceptance", "reason": "wrong hash rejection test"}, expected=409)
    refused = api("POST", f"/api/harness/runs/{repair['id']}/execute", expected=409)
    save("gate-rejections", {"wrong_approval": rejected, "unapproved_execute": refused})
    with SessionLocal() as db:
        after = history(db)
        assert before == after, "original risk or historical analysis changed"
        assert db.query(models.HarnessToolCall).filter_by(run_id=repair["id"], side_effect=True).count() == 0
        save("acceptance", {"history_unchanged": before == after, "history": after, "risk_id": risk_id,
            "harness_run_id": repair["id"], "trace_id": dry["trace_id"], "status": dry["status"],
            "device_writes": 0, "unified_pipeline": "off", "repair_switch": "0", "lab_repair_switch": "0"})
    print(json.dumps({"run_id": repair["id"], "status": dry["status"], "device_writes": 0}))


if __name__ == "__main__":
    main()
