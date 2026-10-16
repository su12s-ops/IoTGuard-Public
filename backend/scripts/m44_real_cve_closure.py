#!/usr/bin/env python3
"""Real M4.4 acceptance. No device repair, no fabricated CVEs, no flag change.

Run from the repository root. SSH node host/user/key are operator environment
references (M44_NODE_HOST/USER/KEY); the host must already be in known_hosts.
The registered Linux node runs the existing fixed collectors and submits through
the product API over a pinned SSH reverse tunnel. No keys leave either node.
Evidence is saved under gitignored reports/m44-work; phase logs contain no token.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time
import uuid
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import config, models
from app.database import Base, engine, SessionLocal

OUT = ROOT / "reports" / "m44-work"
OUT.mkdir(parents=True, exist_ok=True)


def save(name, value):
    (OUT / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def api(method, path, body=None):
    # Fixed loopback backend; caller only supplies a relative product path.
    if not path.startswith("/api/") or ".." in path or ":" in path:
        raise ValueError("invalid product API path")
    conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=240)
    try:
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json", "X-Control-Token": os.getenv("LINUXGUARD_CONTROL_TOKEN", "")})
        response = conn.getresponse()
        raw = response.read()
        if response.status >= 300:
            raise urllib.error.HTTPError(path, response.status, response.reason, response.headers, io.BytesIO(raw))
        return json.loads(raw)
    finally:
        conn.close()


def collect():
    import paramiko
    with SessionLocal() as db:
        ubuntu = db.query(models.LinuxAsset).filter_by(distribution="ubuntu").one()
        host = os.environ.get("M44_NODE_HOST") or ubuntu.ip_address
        user = os.environ["M44_NODE_USER"]
        key = Path(os.environ["M44_NODE_KEY"]).expanduser().resolve()
        keys = paramiko.HostKeys(str(Path.home() / ".ssh" / "known_hosts"))
        host_key = keys.lookup(host)["ssh-ed25519"]
        import base64
        pin = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
        conn = db.query(models.DeviceConnection).filter_by(asset_id=ubuntu.id).first()
        if conn is None:
            conn = models.DeviceConnection(asset_id=ubuntu.id, host=host, username=user,
                port=22, adapter="openwrt_ssh", auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_UBUNTU_KEY",
                host_key_sha256=pin, enabled=True, label="Ubuntu Linux collector (node local)")
            db.add(conn)
            db.commit()
        connections = db.query(models.DeviceConnection).filter_by(enabled=True).all()
        asset_id = ubuntu.id
        ids = [c.id for c in connections]
        allowed = ",".join(c.host + ("/128" if ":" in c.host else "/32") for c in connections)
    node_id = "m44-linux-node"
    node_token = secrets.token_urlsafe(36)
    env = os.environ.copy()
    env.update(LINUXGUARD_UNIFIED_PIPELINE="off", LINUXGUARD_ENABLE_DEVICE_REPAIR="0",
        LINUXGUARD_ARCHIVE_ON_STARTUP="0", LINUXGUARD_DISCOVERY_CIDRS=allowed, LINUXGUARD_COLLECTION_NODE_ID=node_id,
        LINUXGUARD_COLLECTION_NODE_TOKEN=node_token, LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID=str(asset_id))
    # Keep this local test backend available for frontend inspection after collection.
    with (OUT / "backend.log").open("ab") as log:
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=ROOT / "backend", env=env, stdout=log, stderr=log)
    (OUT / "backend.pid").write_text(str(server.pid))
    for _ in range(60):
        if server.poll() is not None:
            raise RuntimeError("acceptance backend failed to start; inspect local backend.log")
        try:
            api("GET", "/api/iot/capabilities")
            break
        except Exception:
            time.sleep(.5)
    outcomes = []
    runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    remote_env = {"LINUXGUARD_COLLECTION_NODE_ID": node_id,
        "LINUXGUARD_NODE_TOKEN": node_token, "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18444",
        "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32"}
    # Node-local key reference: only the filename is provided, never key material.
    bootstrap = "import os,sys\nos.environ.update(" + repr(remote_env) + ")\nos.environ['LINUXGUARD_DEVICE_OPENWRT_KEY']=os.path.expanduser('~/.ssh/iotguard_ed25519')\nsys.argv=['collection_node_runner.py','--serve','--interval','3']\n"
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15", "-i", str(key), "-R", "18444:127.0.0.1:8000", f"{user}@{host}", "python3 -"]
    with (OUT / "collection-node.log").open("ab") as log:
        worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log)
        worker.stdin.write((bootstrap + runner.replace('from __future__ import annotations', '')).encode())
        worker.stdin.close()
    (OUT / "collection-node.pid").write_text(str(worker.pid))
    for cid in ids:
        pending = [r for r in api("GET", f"/api/iot/collection-runs?connection_id={cid}") if r["status"] == "queued_remote"]
        run = pending[0] if pending else api("POST", f"/api/iot/connections/{cid}/collection-runs", {"request_id": "m44-" + uuid.uuid4().hex})
        run = api("POST", f"/api/iot/collection-runs/{run['id']}/execute")
        if run["status"] != "queued_remote":
            raise RuntimeError("collection was not delegated")
        # Same --serve worker handles normal product requests; there is no
        # per-task operator SSH collection or manual inventory upload.
        deadline = time.monotonic() + 240
        while True:
            done = api("GET", f"/api/iot/collection-runs/{run['id']}")
            if done["status"] in {"completed", "failed", "interrupted"} or worker.poll() is not None or time.monotonic() > deadline:
                break
            time.sleep(1)
        outcomes.append(done)
        save("collection-results", outcomes)
        print("COLLECTION", done["id"], done["status"], done["result"].get("package_count"), done.get("error"), flush=True)
        if done["status"] != "completed":
            raise RuntimeError("real collection failed; existing inventory is not a new result")


def verify():
    with SessionLocal() as db:
        candidates = sorted({r.cve_id.split(":")[0] for r in db.query(models.RiskAssessment).filter_by(active=True).all()})
        candidates = sorted(set(candidates) | {"CVE-2026-63073", "CVE-2026-94266"})
        imported = {r.cve_id for r in db.query(models.OfficialCveRecord).filter_by(evidence_status="available").all()}
        candidates = [c for c in candidates if c not in imported]
        historical = {r.run_id: {k: getattr(r, k) for k in ("decision_json", "state_json", "agents_json", "plan_json")}
            for r in db.query(models.UnifiedAnalysisRun).all()}
    if not (OUT / "historical-shadow-before.json").exists():
        save("historical-shadow-before", historical)
    results = json.loads((OUT / "official-verification.json").read_text(encoding="utf-8")) if (OUT / "official-verification.json").exists() else []
    # Small batches make source timeouts observable without hiding partial work.
    for offset in range(0, len(candidates), 5):
        result = api("POST", "/api/vulnerabilities/official/verify", {"cve_ids": candidates[offset:offset + 5]})
        results.append(result)
        save("official-verification", results)
        print("OFFICIAL", offset + len(result["records"]), "/", len(candidates), "corrections", len(result["correction_ids"]), flush=True)
    with SessionLocal() as db:
        now = {r.run_id: {k: getattr(r, k) for k in ("decision_json", "state_json", "agents_json", "plan_json")}
            for r in db.query(models.UnifiedAnalysisRun).all()}
        assert all(now[k] == v for k, v in historical.items())
        matches = [{k: getattr(r, k) for k in ("id", "asset_id", "cve_id", "package_name", "installed_version", "fixed_version", "match_status", "reason_code", "active")}
            for r in db.query(models.VulnerabilityMatch).filter_by(active=True).all()]
        save("matches-after", matches)
        save("history-preserved", {"unchanged_runs": len(historical)})


def shadow():
    from app.services import trace_service as tracing
    from app.services.unified.runner import run_unified_sync
    from app.services.unified.schemas import ALL_AGENT_IDS
    assert config.UNIFIED_PIPELINE_MODE == "off"
    with SessionLocal() as db:
        risk = db.query(models.RiskAssessment).filter_by(cve_id="CVE-2026-94266:noble:curl", active=True).one()
        asset = db.get(models.LinuxAsset, risk.asset_id)
        # Snapshot ALL formal risk columns; the isolated runner must change none.
        before = {str(r.id): {c.name: getattr(r, c.name) for c in r.__table__.columns} for r in db.query(models.RiskAssessment).all()}
        run_id = "m44-real-" + uuid.uuid4().hex[:10]
        trace = tracing.start_trace(db, task_type="unified_four_agent", target_type="linux_host", target_ref=asset.hostname,
            run_ref_type="unified_analysis", run_ref_id=run_id, metadata={"mode": "shadow", "entry": "m44_isolated_real"})
        row = models.UnifiedAnalysisRun(run_id=run_id, risk_id=risk.id, task_type="risk_review", target_type="linux_host",
            target_ref=asset.hostname, mode="shadow", status="running", trace_id=trace.trace_id,
            routing_json=json.dumps({"tier": "standard", "include_runtime": True, "reason": "real_candidate_full_chain_acceptance"}))
        db.add(row)
        db.commit()
        run_unified_sync(db, row, sink=None, force_full_review=True)
        db.expire_all()
        after = {str(r.id): {c.name: getattr(r, c.name) for c in r.__table__.columns} for r in db.query(models.RiskAssessment).all()}
        assert before == after, "shadow changed formal RiskAssessment"
        state = json.loads(row.state_json)
        agents = json.loads(row.agents_json)
        save("real-shadow", {"run_id": row.run_id, "risk_id": risk.id, "trace_id": row.trace_id, "status": row.status,
            "state": state, "agents": agents, "plan": json.loads(row.plan_json), "formal_risks_unchanged": len(before)})
        print("SHADOW", row.run_id, row.status, "roles", list(agents), "formal_unchanged", before == after, flush=True)
        assert row.status == "completed" and all(role in agents for role in ALL_AGENT_IDS)


def harness():
    real = json.loads((OUT / "real-shadow.json").read_text(encoding="utf-8"))
    with SessionLocal() as db:
        risk = db.get(models.RiskAssessment, real["risk_id"])
        asset_id = risk.asset_id
        before = db.get(models.LinuxAsset, asset_id).inventory_sha256
    checks = []
    for goal in ("investigate", "repair"):
        run = api("POST", "/api/harness/runs", {"asset_id": asset_id, "risk_id": real["risk_id"],
            "goal": goal, "shadow_run_id": real["run_id"]})
        item = {"created": run, "rejections": []}
        for label, path, payload in [
            ("wrong_plan_hash", f"/api/harness/runs/{run['id']}/approve", {"plan_hash": "0" * 64, "actor": "m44-readonly-check", "reason": "validate rejection only"}),
            ("no_authorization_from_shadow", f"/api/harness/runs/{run['id']}/approve", {"plan_hash": run["plan_hash"], "actor": "m44-readonly-check", "reason": "validate rejection only"})]:
            try:
                api("POST", path, payload)
                raise AssertionError("Harness must reject this approval")
            except urllib.error.HTTPError as exc:
                assert exc.code == 409
                item["rejections"].append({"check": label, "http_status": exc.code, "body": exc.read().decode()})
        if goal == "investigate":
            item["result"] = api("POST", f"/api/harness/runs/{run['id']}/execute")
            assert item["result"]["status"] in {"completed", "needs_evidence"}
            assert all(not call["side_effect"] for call in item["result"]["tool_calls"])
        else:
            assert run["status"] == "blocked"
            try:
                api("POST", f"/api/harness/runs/{run['id']}/execute")
                raise AssertionError("blocked repair executed")
            except urllib.error.HTTPError as exc:
                assert exc.code == 409
                item["execution_refused"] = exc.read().decode()
        checks.append(item)
        save("harness-checks", checks)
        print("HARNESS", goal, run["id"], (item.get("result") or run)["status"], flush=True)
    with SessionLocal() as db:
        assert db.get(models.LinuxAsset, asset_id).inventory_sha256 == before
    save("harness-boundaries", {"inventory_unchanged": True, "device_writes": 0,
        "repair_approvals_granted": 0, "shadow_run_id": real["run_id"]})


def validate():
    from app.services import trace_service as tracing
    real = json.loads((OUT / "real-shadow.json").read_text(encoding="utf-8"))
    checks = {}
    with SessionLocal() as db:
        run = db.query(models.UnifiedAnalysisRun).filter_by(run_id=real["run_id"]).one()
        state = json.loads(run.state_json)
        plan = json.loads(run.plan_json)
        checks["shadow_mode_off"] = run.mode == "shadow" and config.UNIFIED_PIPELINE_MODE == "off"
        checks["four_real_roles"] = set(json.loads(run.agents_json)) == {"asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"}
        checks["no_degraded_roles"] = not state.get("degraded_roles")
        refs = plan.get("original_evidence_ids") or []
        resolved = {}
        for ref in refs:
            model = models.OfficialCveRecord if ref.startswith("ADV-") else models.CollectionEvidence if ref.startswith("INV-") else models.SecurityEvidence
            resolved[ref] = db.query(model).filter_by(evidence_id=ref).count() == 1
        checks["all_original_refs_resolve"] = bool(resolved) and all(resolved.values())
        checks["plan_pending_approval"] = plan["requires_approval"] is True and plan["technical_gate"]["executed"] is False
        checks["correct_fix_component_release"] = plan["affected_source_package"] == "curl" and plan["vendor_release_fixed_version"] == "8.5.0-2ubuntu10.16"
        checks["runtime_honest"] = bool((state.get("runtime") or {}).get("findings")) and (state.get("runtime") or {}).get("exploitation_relation") != "confirmed_exploitation"
        old_risk = db.get(models.RiskAssessment, 12)
        checks["old_risk_corrected_not_deleted"] = old_risk is not None and not old_risk.active
        original = json.loads((OUT / "historical-shadow-before.json").read_text(encoding="utf-8"))
        checks["all_historical_shadow_unchanged"] = all(
            (row := db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id).one()) and all(getattr(row, k) == v for k, v in snapshot.items())
            for run_id, snapshot in original.items())
        checks["current_shadow_formal_snapshot_unchanged"] = real["formal_risks_unchanged"] > 0
        trace_refs = tracing.evidence_for_trace(db, run.trace_id)
        save("trace-evidence", trace_refs)
        checks["trace_refs_resolve"] = all(item["resolved"] for item in trace_refs["evidence"])
        save("acceptance-validation", {"run_id": run.run_id, "risk_id": run.risk_id, "trace_id": run.trace_id,
            "checks": checks, "original_evidence_resolution": resolved,
            "formal_risks_unchanged": real["formal_risks_unchanged"]})
    print("ACCEPTANCE", sum(checks.values()), "/", len(checks), flush=True)
    assert all(checks.values()), checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["collect", "verify", "shadow", "harness", "validate"])
    args = parser.parse_args()
    assert config.UNIFIED_PIPELINE_MODE == "off"
    assert os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") != "1"
    Base.metadata.create_all(engine)
    if not (OUT / "pre-m44.db").exists():
        with sqlite3.connect(ROOT / "backend/data/linuxguard.db") as source, sqlite3.connect(OUT / "pre-m44.db") as dest:
            source.backup(dest)
    {"collect": collect, "verify": verify, "shadow": shadow, "harness": harness, "validate": validate}[args.phase]()


if __name__ == "__main__":
    main()
