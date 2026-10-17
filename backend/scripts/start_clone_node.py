"""Start the stage10-clone-node pull runner (Stage 10 round 3, authorized).

Modeled on restore_collection_node.py start, with clone-scoped parameters only:
- reverse tunnel 18446 into the CLONE VM (never shares 18445)
- node id stage10-clone-node with its own token
- device key env points at the clone-local key; no OpenWrt key on this node
- both repair switches pinned to 0
Credentials travel via existing SSH key references only; nothing is printed.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from dotenv import dotenv_values

values = dotenv_values(ROOT / "backend" / ".env")
node_id = "stage10-clone-node"
token = values.get("LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE", "")
if not token:
    raise SystemExit("clone node token missing from backend/.env")

remote_env = {
    "LINUXGUARD_COLLECTION_NODE_ID": node_id,
    "LINUXGUARD_NODE_TOKEN": token,
    "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18446",
    "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
    "LINUXGUARD_DEVICE_STAGE10_CLONE_KEY": "/home/wyh/.ssh/iotguard_clone_key",
    "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
    "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0",
}
runner = (ROOT / "backend" / "scripts" / "collection_node_runner.py").read_text(encoding="utf-8")
bootstrap = "import os,sys\nos.environ.update(" + repr(remote_env) + ")\n"
bootstrap += "sys.argv=['collection_node_runner.py','--serve','--interval','3']\n"
key = Path(r"E:\IoTGuard-Public\local-archive\stage10-work\clone_node_ed25519")
command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=10",
           "-o", "ServerAliveInterval=15", "-i", str(key),
           "-R", "18446:127.0.0.1:8000", "wyh@192.168.183.110", "python3 -"]
output = ROOT / "local-archive" / "stage10-work"
with (output / "clone-node.log").open("ab") as log:
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    process.stdin.write((bootstrap + runner.replace("from __future__ import annotations", "")).encode())
    process.stdin.close()
(output / "clone-node.pid").write_text(str(process.pid))
print(json.dumps({"node_id": node_id, "ssh_pid": process.pid,
                  "repair_switches": [0, 0], "tunnel": "18446"}))
