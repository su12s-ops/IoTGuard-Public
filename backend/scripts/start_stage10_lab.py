"""Prepare an independent Stage 10 backend and publish its clone-only runner.

Never edits production configuration, grants a human verdict, approves a plan,
or starts a privileged process in the VM. The operator starts the published
runner at the VM console; subsequent work uses the existing Harness API.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "local-archive" / "stage10-continuation" / "lab"
PORT = 18001
TUNNEL = 18447
NODE = "stage10-lab-clone-node"
REMOTE = "/home/wyh/.local/share/iotguard-stage10-lab"
KEY = ROOT / "local-archive" / "stage10-work" / "clone_node_ed25519"


def private(path):
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        getpass.getuser() + ":(F)", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"],
                       check=True, capture_output=True)
    else:
        path.chmod(0o600)


def prepare():
    LAB.mkdir(parents=True, exist_ok=True)
    if (LAB / "backend.env").exists() or (LAB / "lab.db").exists():
        raise SystemExit("Existing lab retained; use start/publish-node without recreating it.")
    source = ROOT / "backend" / "data" / "linuxguard.db"
    target = LAB / "lab.db"
    if target.resolve() == source.resolve():
        raise SystemExit("Isolated database required")
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(target) as dst:
            src.backup(dst)
            row = dst.execute("SELECT asset_id,host FROM device_connection WHERE id=?", (3,)).fetchone()
            if row != (3, "192.168.183.110"):
                raise SystemExit("Clone connection binding changed; no lab credentials generated")
            # Only the clone's registered connection is enabled in this copy.
            dst.execute("UPDATE device_connection SET enabled=0 WHERE id<>?", (3,))
            dst.commit()
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SystemExit("Lab copy integrity check failed")
    values = {
        "PYTHON_DOTENV_DISABLED": "1",
        "LINUXGUARD_DATABASE_URL": "sqlite:///" + target.as_posix(),
        "LINUXGUARD_DATA_DIR": str(LAB / "data"),
        "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
        "LINUXGUARD_CONTROL_TOKEN": secrets.token_urlsafe(36),
        "LINUXGUARD_COLLECTION_NODE_ID": NODE,
        "LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID": "3",
        "LINUXGUARD_COLLECTION_NODE_TOKEN": secrets.token_urlsafe(36),
        "LINUXGUARD_COLLECTION_NODES_JSON": "[]",
        "LINUXGUARD_DISCOVERY_CIDRS": "192.168.183.110/32",
        "LINUXGUARD_DEVICE_STAGE10_CLONE_KEY": str(KEY),
        "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
        "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0",
        "LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE": "3",
        "LINUXGUARD_UBUNTU_LAB_PERMIT": str(LAB / "permit.json"),
        "LINUXGUARD_UNIFIED_PIPELINE": "on",
    }
    envfile = LAB / "backend.env"
    envfile.touch()
    private(envfile)
    envfile.write_text("".join(k + "=" + json.dumps(v) + "\n" for k, v in values.items()), encoding="utf-8")
    info = {"port": PORT, "tunnel": TUNNEL, "node": NODE, "asset_id": 3,
            "database": str(target), "database_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "production_configuration_edited": False, "write_switches": [0, 0]}
    (LAB / "manifest.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(json.dumps(info))


def values():
    result = dotenv_values(LAB / "backend.env")
    if not result.get("LINUXGUARD_CONTROL_TOKEN"):
        raise SystemExit("Run prepare first")
    required = {"PYTHON_DOTENV_DISABLED": "1",
                "LINUXGUARD_DATABASE_URL": "sqlite:///" + (LAB / "lab.db").as_posix(),
                "LINUXGUARD_COLLECTION_NODE_ID": NODE,
                "LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID": "3",
                "LINUXGUARD_COLLECTION_NODES_JSON": "[]",
                "LINUXGUARD_DISCOVERY_CIDRS": "192.168.183.110/32",
                "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
                "LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE": "3"}
    if any(result.get(k) != v for k, v in required.items()):
        raise SystemExit("Lab isolation settings changed; refusing to start or publish a runner")
    return result


def start():
    settings = values()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", PORT))
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("LINUXGUARD_", "DEEPSEEK_", "OPENAI_", "ANTHROPIC_", "NVD_"))}
    env.update(settings)
    with (LAB / "backend.log").open("ab") as log:
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                    "--host", "127.0.0.1", "--port", str(PORT)],
                                   cwd=ROOT / "backend", env=env, stdout=log, stderr=log,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    (LAB / "backend.pid").write_text(str(process.pid))
    print(json.dumps({"lab_backend_pid": process.pid, "port": PORT, "write_switches": [
        settings["LINUXGUARD_ENABLE_DEVICE_REPAIR"], settings["LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR"]]}))


def ssh_args():
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-i", str(KEY)]


def publish_node():
    settings = values()
    remote_env = {"LINUXGUARD_COLLECTION_NODE_ID": NODE,
                  "LINUXGUARD_NODE_TOKEN": settings["LINUXGUARD_COLLECTION_NODE_TOKEN"],
                  "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:" + str(TUNNEL),
                  "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
                  "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
                  "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "1",
                  "LINUXGUARD_UBUNTU_LAB_PERMIT": REMOTE + "/permit.json"}
    runner = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    script = "import os,sys\nif os.geteuid()!=0: raise SystemExit('root_execution_node_required')\n"
    script += "os.environ.update(" + repr(remote_env) + ")\n"
    script += runner.replace("from __future__ import annotations", "")
    payload = "from pathlib import Path\nimport os\np=Path(" + repr(REMOTE) + ")\np.mkdir(parents=True,exist_ok=True)\np.chmod(0o700)\n"
    payload += "f=p/'node.py'\nf.touch(mode=0o600,exist_ok=True)\nf.chmod(0o600)\nf.write_text(" + repr(script) + ",encoding='utf-8')\n"
    subprocess.run(ssh_args() + ["wyh@192.168.183.110", "python3 -"], input=payload.encode(), check=True,
                   capture_output=True, timeout=25)
    (LAB / "node-sha256.txt").write_text(hashlib.sha256(script.encode()).hexdigest())
    print(json.dumps({"node": NODE, "root_started": False, "node_lab_switch": 1,
                      "permit_present": False, "console_command": "sudo python3 " + REMOTE + "/node.py --serve --interval 3"}))


def tunnel():
    with (LAB / "tunnel.log").open("ab") as log:
        process = subprocess.Popen(ssh_args() + ["-o", "ExitOnForwardFailure=yes", "-N", "-R",
                                    f"{TUNNEL}:127.0.0.1:{PORT}", "wyh@192.168.183.110"],
                                   stdout=log, stderr=log, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    (LAB / "tunnel.pid").write_text(str(process.pid))
    print(json.dumps({"tunnel_pid": process.pid, "tunnel": TUNNEL, "backend_port": PORT}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "start", "publish-node", "tunnel"])
    operation = parser.parse_args().operation
    {"prepare": prepare, "start": start, "publish-node": publish_node, "tunnel": tunnel}[operation]()
