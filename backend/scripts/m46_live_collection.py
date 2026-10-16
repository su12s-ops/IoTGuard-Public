"""Authorize one real agent inventory proposal under the user's M4.6 read-only scope."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import models, config
from app.database import SessionLocal
from app.services.unified.investigation import serialize
from m46_production_readiness import formal_snapshot

OUT = ROOT / "reports/m46-work"


def save(name, value):
    (OUT / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def api(method, path, payload=None, token=True):
    if not path.startswith("/api/") or ":" in path or ".." in path:
        raise ValueError("invalid_path")
    connection = http.client.HTTPConnection("127.0.0.1", 18460, timeout=60)
    try:
        connection.request(method, path, body=json.dumps(payload).encode() if payload is not None else None,
            headers={"Content-Type": "application/json", "X-Control-Token": os.getenv("LINUXGUARD_CONTROL_TOKEN", "") if token else ""})
        response = connection.getresponse()
        data = json.loads(response.read())
        return response.status, data
    finally:
        connection.close()


def main():
    assert config.UNIFIED_PIPELINE_MODE == "off"
    with SessionLocal() as db:
        source = json.loads((OUT / "curl.json").read_text(encoding="utf-8"))["run_id"]
        item = db.query(models.InvestigationRequest).filter_by(source_run_id=source, status="awaiting_authorization").first()
        if not item:
            raise RuntimeError("no_real_agent_collection_proposal")
        conn = db.query(models.DeviceConnection).filter_by(asset_id=item.asset_id, enabled=True).one()
        before = formal_snapshot(db)
        rid, request_hash, connection_id, asset_id = item.id, item.request_hash, conn.id, conn.asset_id
        host, user = conn.host, conn.username
        allowed = ",".join(c.host + ("/128" if ":" in c.host else "/32") for c in db.query(models.DeviceConnection).filter_by(enabled=True))
    node_id, node_token = "m46-linux-node", secrets.token_urlsafe(36)
    env = os.environ.copy()
    env.update(LINUXGUARD_UNIFIED_PIPELINE="off", LINUXGUARD_ENABLE_DEVICE_REPAIR="0", LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR="0",
        LINUXGUARD_ARCHIVE_ON_STARTUP="0", LINUXGUARD_COLLECTION_NODE_ID=node_id, LINUXGUARD_COLLECTION_NODE_TOKEN=node_token,
        LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID=str(asset_id), LINUXGUARD_DISCOVERY_CIDRS=allowed)
    with (OUT / "backend.log").open("ab") as log:
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "18460"],
            cwd=ROOT / "backend", env=env, stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    (OUT / "backend.pid").write_text(str(server.pid))
    for _ in range(60):
        if server.poll() is not None: raise RuntimeError("backend_failed")
        try:
            if api("GET", "/api/unified/specs")[0] == 200: break
        except OSError: pass
        time.sleep(.5)
    runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    node_env = {"LINUXGUARD_COLLECTION_NODE_ID": node_id, "LINUXGUARD_NODE_TOKEN": node_token,
        "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18460", "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
        "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0"}
    bootstrap = "import os,sys\nos.environ.update(" + repr(node_env) + ")\nsys.argv=['collection_node_runner.py','--serve','--interval','3']\n"
    key = Path(os.getenv("M46_NODE_KEY", str(Path.home() / ".ssh/id_ed25519_vms"))).resolve()
    with (OUT / "collection-node.log").open("ab") as log:
        worker = subprocess.Popen(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15", "-i", str(key), "-R", "18460:127.0.0.1:18460", f"{user}@{host}", "python3 -"],
            stdin=subprocess.PIPE, stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        worker.stdin.write((bootstrap + runner.replace("from __future__ import annotations", "")).encode())
        worker.stdin.close()
    (OUT / "collection-node.pid").write_text(str(worker.pid))
    payload = {"request_hash": request_hash, "connection_id": connection_id, "actor": "codex:m46-user-readonly-request",
        "reason": "用户本轮明确授权真实主动补证验收；仅复用已登记资产与固定只读 Collector，不执行索引刷新或修复"}
    denied = api("POST", f"/api/unified/investigations/{rid}/authorize", payload, token=False)
    assert denied[0] == 401
    wrong = api("POST", f"/api/unified/investigations/{rid}/authorize", {**payload, "request_hash": "f" * 64})
    assert wrong[0] == 409
    approved = api("POST", f"/api/unified/investigations/{rid}/authorize", payload)
    save("readonly-authorization", {"missing_control": denied, "wrong_hash": wrong, "authorized": approved})
    if approved[0] != 200: raise RuntimeError("authorization_failed")
    collection_id = approved[1]["collection_run_id"]
    for _ in range(150):
        status, collection = api("GET", f"/api/iot/collection-runs/{collection_id}")
        if collection["status"] in {"completed", "failed", "interrupted"}: break
        time.sleep(2)
    save("fresh-collection", collection)
    if collection["status"] != "completed": raise RuntimeError("real_collection_failed")
    status, resumed = api("POST", f"/api/unified/investigations/{rid}/resume")
    save("resume-request", {"status": status, "result": resumed})
    assert status == 200
    for _ in range(600):
        with SessionLocal() as db:
            current = db.get(models.InvestigationRequest, rid)
            if current.status in {"completed", "reanalysis_failed"}:
                save("real-investigation", serialize(current))
                child = db.query(models.UnifiedAnalysisRun).filter_by(run_id=current.reanalysis_run_id).one()
                save("reanalysis", {"run_id": child.run_id, "trace_id": child.trace_id, "state": json.loads(child.state_json), "status": child.status, "agents": json.loads(child.agents_json)})
                assert formal_snapshot(db) == before
                save("loop-isolation", {"formal_unchanged": True, "digest": before, "flag": "off", "repair": "0", "lab_repair": "0"})
                print(current.id, current.status, child.run_id, flush=True)
                break
        time.sleep(2)
    else: raise RuntimeError("reanalysis_timeout")


if __name__ == "__main__": main()
