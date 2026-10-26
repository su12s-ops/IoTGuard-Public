"""Run the registered Ubuntu pull collector over a pinned, temporary SSH tunnel.
No remote service/config files are changed; device repair assignments are refused.

Reconnect contract (2026-10-24): the collector session is deliberately long-lived
but a single SSH session can still die (VM reboot, network blip, backend restart).
The script therefore loops: every session re-verifies the pinned host key, tears
down cleanly, and reconnects with capped backoff. The remote claim loop never
exits on transient claim failures (HTTP 0/5xx are retried in-loop); only explicit
authorization rejections (401/403) abort, because retrying those cannot succeed.

Every outbound HTTP request goes through `fetch_json`, which accepts http/https
only, refuses URLs with embedded credentials or redirects, and requires the host
to be inside the operator-declared local backend allowlist (mirrors the remote
runner's LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS pattern). No dynamic/remote URL
is ever requested.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import paramiko
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:18080"
# Operator-declared backend allowlist for this local lab script: the Docker API
# is loopback-only by design (the frontend proxies /api on 127.0.0.1:18080). Any other
# host — private, public or otherwise — is refused before a request is made.
ALLOWED_BACKEND_HOSTS = {"127.0.0.1"}

# Reconnect backoff bounds: start fast (VM/network blips), cap at 60s so the
# node never looks permanently online-offline-flapping to the backend window.
RECONNECT_BACKOFF_S = 5.0
RECONNECT_BACKOFF_MAX_S = 60.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def fetch_json(path: str, headers: dict | None = None, timeout: int = 15):
    """Validated request to the pinned local backend; returns parsed JSON.

    Security gate before any socket is opened: scheme must be http/https, the
    URL must not embed credentials, the parsed host must be exactly the
    operator-declared loopback backend, and redirects are refused.
    """
    url = BASE + path
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RuntimeError("Backend request only allows http/https URLs")
    if parsed.username or parsed.password:
        raise RuntimeError("Backend URL must not embed credentials")
    if parsed.hostname not in ALLOWED_BACKEND_HOSTS:
        raise RuntimeError(f"Backend host not in operator allowlist: {parsed.hostname}")
    addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    for address in addresses:
        if address not in ALLOWED_BACKEND_HOSTS:
            raise RuntimeError(f"Resolved backend address outside allowlist: {address}")
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        return json.load(response)


def open_pinned_session(env):
    """Verify pinned identity, open the reverse tunnel and the remote collector.

    Returns the (client, channel) pair; raises on any failure so the caller can
    tear down and reconnect. The remote collector loop itself is unbounded and
    tolerates transient claim failures.
    """
    connections = fetch_json("/api/iot/connections")
    connection = next(c for c in connections if c["id"] == 2)
    expected = {"asset_id": 1, "host": "192.168.183.129", "port": 22,
                "username": "wyh", "auth_type": "ssh_key",
                "host_key_sha256": "SHA256:9iQisJ+wzFGKcY1RW3UOW/SYEIqW33selbbK8mW8N8s"}
    if any(connection.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Current registered Ubuntu connection differs from authorized identity")
    preflight = fetch_json("/api/iot/connections/2/preflight",
                           headers={"X-Control-Token": env["LINUXGUARD_CONTROL_TOKEN"]})
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
    import threading
    import select

    def forward(channel):
        import socket as socket_module
        backend_url = urlparse(BASE)
        sock = socket_module.create_connection((backend_url.hostname, backend_url.port or 80), timeout=15)
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
    bootstrap += source.replace("from __future__ import annotations", "").replace('if __name__ == "__main__":', 'if False:')
    # Unbounded claim loop: transient claim failures (status 0 = tunnel/backend
    # hiccup, 5xx) back off in-loop instead of exiting; only authorization
    # rejections (401/403) abort the remote loop so the outer session loop can
    # re-verify identity. A bounded loop was the old ~1h tunnel-expiry bug.
    bootstrap += '''
backend = Backend(env_required("LINUXGUARD_NODE_BACKEND_URL"), env_required("LINUXGUARD_NODE_TOKEN"))
claim_failures = 0
while True:
    status, payload = backend.request("GET", "/api/iot/collection-node/claim?node_id=" + env_required("LINUXGUARD_COLLECTION_NODE_ID") + "&node_platform=Linux")
    if status in (401, 403):
        raise SystemExit("Claim rejected HTTP " + str(status) + ": authorization; not retrying")
    if status != 200:
        claim_failures += 1
        time.sleep(min(60, 3 * claim_failures))
        continue
    claim_failures = 0
    assignment = (payload or {}).get("assignment")
    if assignment:
        target = assignment.get("connection", {})
        asset_id = assignment.get("asset", {}).get("id")
        allowed = {1: ("192.168.183.129", "SHA256:9iQisJ+wzFGKcY1RW3UOW/SYEIqW33selbbK8mW8N8s"), 2: ("192.168.100.1", "SHA256:+CaFHIb60hY7jtvKJNU0uZnnJ0rHyiBCzFLsfqNMKAU")}
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
    return client, channel


def main():
    # Keep the handle alive for the entire supervisor lifetime. A second logon
    # launcher must not contend for the pinned remote forwarding port.
    lock_dir = ROOT / "reports/collection-node"
    lock_dir.mkdir(parents=True, exist_ok=True)
    if sys.stdout is None or sys.stderr is None:
        stream = (lock_dir / "supervisor.log").open("a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = stream
    singleton = (lock_dir / "collection-supervisor.lock").open("a+b")
    if os.name == "nt":
        import msvcrt
        if singleton.seek(0, 2) == 0:
            singleton.write(b"0")
            singleton.flush()
        singleton.seek(0)
        try:
            msvcrt.locking(singleton.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            print("Existing collection supervisor holds the runtime lock; exiting.", flush=True)
            singleton.close()
            return
    env = dotenv_values(ROOT / "backend/.env.docker")
    session_no = 0
    backoff = RECONNECT_BACKOFF_S
    session_started = 0.0
    while True:
        session_no += 1
        client = None
        channel = None
        try:
            client, channel = open_pinned_session(env)
            backoff = RECONNECT_BACKOFF_S
            session_started = time.time()
            print(f"[session {session_no}] Pinned Ubuntu identity verified; temporary Docker tunnel "
                  f"and read-only collector started at {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
            while not channel.exit_status_ready():
                if channel.recv_ready():
                    print(channel.recv(65536).decode("utf-8", errors="replace"), end="", flush=True)
                if channel.recv_stderr_ready():
                    print(channel.recv_stderr(65536).decode("utf-8", errors="replace"), end="", file=sys.stderr, flush=True)
                time.sleep(0.2)
            code = channel.recv_exit_status()
            raise RuntimeError(f"Remote collector exited {code} after {time.time() - session_started:.0f}s")
        except KeyboardInterrupt:
            print("Interrupted by operator; closing session.", flush=True)
            return
        except Exception as exc:
            duration = time.time() - session_started if session_started else 0.0
            print(f"[session {session_no}] session ended after {duration:.0f}s: {exc}; "
                  f"reconnecting in {backoff:.0f}s", flush=True, file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX_S)
        finally:
            for closer in (channel, client):
                try:
                    if closer is not None:
                        closer.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
