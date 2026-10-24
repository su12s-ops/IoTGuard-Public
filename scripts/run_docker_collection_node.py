"""Run the registered Ubuntu pull collector over a pinned, temporary SSH tunnel.
No remote service/config files are changed; device repair assignments are refused.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.request

import paramiko
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:18000"


def main():
    env = dotenv_values(ROOT / "backend/.env.docker")
    with urllib.request.urlopen(BASE + "/api/iot/connections", timeout=15) as response:
        connections = json.load(response)
    connection = next(c for c in connections if c["id"] == 2)
    expected = {"asset_id": 1, "host": "192.168.183.129", "port": 22,
                "username": "wyh", "auth_type": "ssh_key",
                "host_key_sha256": "SHA256:9iQisJ+wzFGKcY1RW3UOW/SYEIqW33selbbK8mW8N8s"}
    if any(connection.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Current registered Ubuntu connection differs from authorized identity")
    headers = {"X-Control-Token": env["LINUXGUARD_CONTROL_TOKEN"]}
    request = urllib.request.Request(BASE + "/api/iot/connections/2/preflight", headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        preflight = json.load(response)
    if not preflight.get("ready"):
        raise RuntimeError("Collection preflight not ready: " + json.dumps(preflight))

    class Pinned(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            actual = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
            if actual != expected["host_key_sha256"]:
                raise RuntimeError("Ubuntu SSH host fingerprint mismatch")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(Pinned())
    client.connect(expected["host"], port=22, username="wyh",
                   key_filename=str(Path.home() / ".ssh/id_ed25519_vms"),
                   allow_agent=False, look_for_keys=False, timeout=15)
    # Paramiko forwards accepted remote TCP channels back to this Docker API.
    import socket
    import threading
    import select

    def forward(channel):
        sock = socket.create_connection(("127.0.0.1", 18000), timeout=15)
        try:
            while True:
                ready, _, _ = select.select([sock, channel], [], [], 1)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (channel if source is sock else sock).sendall(data)
        finally:
            sock.close()
            channel.close()

    def handler(channel, origin, server):
        threading.Thread(target=forward, args=(channel,), daemon=True).start()

    transport = client.get_transport()
    transport.set_keepalive(15)
    transport.request_port_forward("127.0.0.1", 18445, handler=handler)
    remote_env = {
        "LINUXGUARD_COLLECTION_NODE_ID": env["LINUXGUARD_COLLECTION_NODE_ID"],
        "LINUXGUARD_NODE_TOKEN": env["LINUXGUARD_COLLECTION_NODE_TOKEN"],
        "LINUXGUARD_NODE_BACKEND_URL": "http://127.0.0.1:18445",
        "LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS": "127.0.0.1/32",
        "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
        "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": "0",
        "LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR": "0",
    }
    source = (ROOT / "backend/scripts/collection_node_runner.py").read_text(encoding="utf-8")
    # Load the unmodified collector functions without invoking its general queue loop.
    bootstrap = "import os,sys\nos.environ.update(" + repr(remote_env) + ")\n"
    bootstrap += "os.environ['LINUXGUARD_DEVICE_OPENWRT_KEY']=os.path.expanduser('~/.ssh/iotguard_ed25519')\n"
    bootstrap += "os.environ['LINUXGUARD_DEVICE_OPENWRT_LAB_KEY']=os.path.expanduser('~/.ssh/iotguard_lab_ed25519')\n"
    bootstrap += source.replace("from __future__ import annotations", "").replace('if __name__ == "__main__":', 'if False:')
    bootstrap += '''
backend = Backend(env_required("LINUXGUARD_NODE_BACKEND_URL"), env_required("LINUXGUARD_NODE_TOKEN"))
for _ in range(1200):
    status, payload = backend.request("GET", "/api/iot/collection-node/claim?node_id=" + env_required("LINUXGUARD_COLLECTION_NODE_ID") + "&node_platform=Linux")
    if status != 200:
        raise SystemExit("Claim rejected HTTP " + str(status))
    assignment = (payload or {}).get("assignment")
    if assignment:
        target = assignment.get("connection", {})
        asset_id = assignment.get("asset", {}).get("id")
        allowed = {1: ("192.168.183.129", "SHA256:9iQisJ+wzFGKcY1RW3UOW/SYEIqW33selbbK8mW8N8s"), 2: ("192.168.100.1", "SHA256:+CaFHIb60hY7jtvKJNU0uZnnJ0rHyiBCzFLsfqNMKAU"), 4: ("192.168.206.2", "SHA256:+ptdJBsAAHu7hJ9j0Oytyaw4XI7IMVTW/DHnVybqevU")}
        identity = allowed.get(asset_id)
        if assignment.get("harness_adapter") or not identity or (target.get("host"), target.get("host_key_sha256")) != identity or assignment.get("collector_type") not in ("linux_ssh", "openwrt_ssh", "openwrt_logread"):
            raise SystemExit("Refusing assignment outside authorized read-only inventory/log scope")
        execute_assignment(backend, assignment)
    time.sleep(3)
'''
    channel = transport.open_session()
    channel.exec_command("python3 -u -")
    channel.sendall(bootstrap.encode())
    channel.shutdown_write()
    print("Pinned Ubuntu identity verified; temporary Docker tunnel and read-only collector started", flush=True)
    try:
        while not channel.exit_status_ready():
            if channel.recv_ready():
                print(channel.recv(65536).decode("utf-8", errors="replace"), end="", flush=True)
            if channel.recv_stderr_ready():
                print(channel.recv_stderr(65536).decode("utf-8", errors="replace"), end="", file=sys.stderr, flush=True)
            time.sleep(0.2)
        code = channel.recv_exit_status()
        if code:
            raise RuntimeError("Remote collector exited " + str(code))
    finally:
        channel.close()
        client.close()


if __name__ == "__main__":
    main()
