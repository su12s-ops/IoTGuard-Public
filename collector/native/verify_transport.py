#!/usr/bin/env python3
"""Real C sensor + production WAL + loopback HTTP durable acknowledgement stub.

Validates transport faults without contacting the user's backend or asset DB.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time


def until(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(.2)
    raise AssertionError("Condition timeout")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    supervisor = Path(__file__).resolve().parent / "supervise.py"
    with tempfile.TemporaryDirectory(prefix="ig-transport-") as directory:
        work = Path(directory)
        state = work / "state"
        state.mkdir()
        hp = state / "health.json"
        wal = state / "wal.jsonl"
        online = threading.Event()
        seen = set()
        counts = {"accepted": 0, "duplicates": 0, "heartbeats": 0, "outages": 0}
        lock = threading.Lock()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert self.headers.get("X-Control-Token") == "isolated-native-test"
                if not online.is_set():
                    counts["outages"] += 1
                    self.send_response(503); self.end_headers(); return
                if self.path.endswith("heartbeat"):
                    counts["heartbeats"] += 1
                    answer = {}
                else:
                    batch = data["events"]
                    fresh = duplicate = 0
                    with lock, (work / "acknowledged.jsonl").open("a") as f:
                        for event in batch:
                            assert event["source"] == "c_ebpf"
                            key = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
                            if key in seen: duplicate += 1
                            else:
                                f.write(json.dumps(event) + "\n")
                                seen.add(key); fresh += 1
                        f.flush(); os.fsync(f.fileno())
                        counts["accepted"] += fresh; counts["duplicates"] += duplicate
                    answer = {"ack": True, "received": len(batch), "accepted": fresh, "duplicates": duplicate, "rejected": []}
                body = json.dumps(answer).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env = dict(os.environ, API_BASE=f"http://127.0.0.1:{server.server_port}/api", ASSET_ID="1",
                   LINUXGUARD_CONTROL_TOKEN="isolated-native-test", IOTGUARD_SENSOR_STATE=str(state))
        processes = []
        def start(log):
            p = subprocess.Popen([sys.executable, str(supervisor)], env=env, stdout=log, stderr=log)
            processes.append(p)
            return p
        try:
            with (work / "service.log").open("w") as log:
                process = start(log)
                until(lambda: hp.exists() and json.loads(hp.read_text()).get("phase") == "running")
                for _ in range(15): subprocess.run(["/bin/true"], check=True)
                until(lambda: wal.exists() and wal.stat().st_size > 0)
                assert process.poll() is None
                pending_during_outage = wal.stat().st_size
                online.set()
                until(lambda: counts["accepted"] > 0, 50)
                time.sleep(3)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=100) == 0, (work / "service.log").read_text()
                assert not wal.read_text().strip()
                assert json.loads(hp.read_text())["phase"] == "stopped"
                # Crash the C child. Supervisor must fail as a unit, not stay healthy.
                process = start(log)
                until(lambda: json.loads(hp.read_text()).get("phase") == "running")
                os.kill(json.loads(hp.read_text())["pid"], signal.SIGKILL)
                assert process.wait(timeout=100) != 0
                assert json.loads(hp.read_text())["phase"] == "failed"
                # Service-manager equivalent restart attaches and forwards again.
                before = counts["accepted"]
                process = start(log)
                until(lambda: json.loads(hp.read_text()).get("phase") == "running")
                for _ in range(10): subprocess.run(["/bin/true"], check=True)
                until(lambda: counts["accepted"] > before)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=100) == 0
                assert not wal.read_text().strip()
            report = {"passed": True, "pending_bytes_during_outage": pending_during_outage,
                      "counts": counts, "checks": ["real-sensor-to-production-forwarder", "offline-WAL",
                      "reconnect-without-restart", "graceful-pipe-drain", "sensor-crash-fails-unit", "unit-restart"],
                      "backend": "isolated loopback durable HTTP stub, not production FastAPI"}
            Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))
        finally:
            for p in processes:
                if p.poll() is None:
                    p.send_signal(signal.SIGTERM)
                    try: p.wait(timeout=100)
                    except subprocess.TimeoutExpired: p.kill(); p.wait()
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    main()
