"""Restore the existing M4.5 Linux Pull Runner, never a repair executor.

Requires the local M4.4/M4.5 successful collection receipts. Credentials are
passed only through existing SSH/environment references, never command lines.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from dotenv import dotenv_values, set_key
from app import models
from app.database import SessionLocal


def registered_scope():
    receipts = json.loads((ROOT / "reports/m44-work/collection-results.json").read_text(encoding="utf-8"))
    receipts += [json.loads((ROOT / "reports/m45-work/fresh-collection.json").read_text(encoding="utf-8"))]
    approved = {r["connection_id"] for r in receipts if r["status"] == "completed"}
    with SessionLocal() as db:
        connections = db.query(models.DeviceConnection).filter(models.DeviceConnection.id.in_(approved),
                                                              models.DeviceConnection.enabled.is_(True)).all()
        ubuntu = [(c, db.get(models.LinuxAsset, c.asset_id)) for c in connections
                  if db.get(models.LinuxAsset, c.asset_id).distribution == "ubuntu"]
        if len(ubuntu) != 1 or len(connections) != len(approved):
            raise RuntimeError("previously_approved_connection_scope_changed")
        connection, asset = ubuntu[0]
        from app.services.agent_harness import connection_signature, digest
        for c in connections:
            proven = [r for r in receipts if r["connection_id"] == c.id and r["status"] == "completed"]
            valid = False
            for receipt in proven:
                old = db.get(models.HarnessRun, receipt["id"])
                if not old or old.status != "completed" or old.connection_id != c.id:
                    continue
                plan = json.loads(old.plan_json)
                valid |= (digest(plan) == old.plan_hash and plan.get("connection_hash") == connection_signature(c))
            if not valid:
                raise RuntimeError("registered_connection_differs_from_successful_receipt")
        return {"id": connection.id, "asset_id": asset.id, "host": connection.host,
                "username": connection.username, "port": connection.port,
                "scope": sorted(c.host + ("/128" if ":" in c.host else "/32") for c in connections)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["configure", "start"])
    parser.add_argument("--supervise", action="store_true", help="Keep the existing SSH runner connected while this host is running")
    parser.add_argument("--watch", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    scope = registered_scope()
    environment = ROOT / "backend/.env"
    if args.operation == "configure":
        values = {"LINUXGUARD_COLLECTION_NODE_ID": "m45-linux-node",
            "LINUXGUARD_COLLECTION_NODE_TOKEN": secrets.token_urlsafe(36),
            "LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID": str(scope["asset_id"]),
            "LINUXGUARD_DISCOVERY_CIDRS": ",".join(scope["scope"]),
            "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0"}
        for key, value in values.items():
            set_key(environment, key, value)
        print(json.dumps({"node_id": "m45-linux-node", "connection_id": scope["id"],
            "restored_previously_approved_targets": len(scope["scope"]), "repair_switches": [0, 0]}))
        return
    values = dotenv_values(environment)
    if values.get("LINUXGUARD_COLLECTION_NODE_ID") != "m45-linux-node" or not values.get("LINUXGUARD_COLLECTION_NODE_TOKEN"):
        raise RuntimeError("existing_node_configuration_required")
    remote_env = {"LINUXGUARD_COLLECTION_NODE_ID": "m45-linux-node",
        "LINUXGUARD_NODE_TOKEN": values["LINUXGUARD_COLLECTION_NODE_TOKEN"],
        "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18445",
        "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
        "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0"}
    runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    bootstrap = "import os,sys\nos.environ.update(" + repr(remote_env) + ")\n"
    bootstrap += "os.environ['LINUXGUARD_DEVICE_OPENWRT_KEY']=os.path.expanduser('~/.ssh/iotguard_ed25519')\n"
    bootstrap += "sys.argv=['collection_node_runner.py','--serve','--interval','3']\n"
    key = Path.home() / ".ssh/id_ed25519_vms"
    if not key.is_file():
        raise RuntimeError("existing_ssh_key_reference_unavailable")
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-i", str(key), "-p", str(scope["port"]),
        "-R", "18445:127.0.0.1:8000", f"{scope['username']}@{scope['host']}", "python3 -"]
    output = ROOT / "reports/m5-final"
    output.mkdir(parents=True, exist_ok=True)
    if args.supervise:
        with (output / "collection-node-supervisor.log").open("ab") as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "start", "--watch"],
                stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        (output / "collection-node-supervisor.pid").write_text(str(process.pid))
    else:
        delay = 5
        while True:
            # Re-read the fixed runner on reconnect, without rotating node credentials.
            runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
            with (output / "collection-node.log").open("ab") as log:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                try:
                    process.stdin.write((bootstrap + runner.replace("from __future__ import annotations", "")).encode())
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    process.terminate()
            (output / "collection-node.pid").write_text(str(process.pid))
            if not args.watch:
                break
            started = time.monotonic()
            process.wait()
            delay = 5 if time.monotonic() - started > 60 else min(60, delay * 2)
            print(json.dumps({"event": "runner_disconnected", "retry_after_s": delay}), flush=True)
            time.sleep(delay)
    print(json.dumps({"node_id": "m45-linux-node", "ssh_pid": process.pid, "existing_runner_reused": True,
                      "private_key_contents_exposed": False, "repair_switches": [0, 0]}))


if __name__ == "__main__":
    main()
