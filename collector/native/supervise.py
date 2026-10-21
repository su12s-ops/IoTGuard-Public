#!/usr/bin/env python3
"""Own both processes; drain on stop, fail as a unit, systemd restarts the unit."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    here = Path(__file__).resolve().parent
    state = Path(os.environ.get("IOTGUARD_SENSOR_STATE", "/var/lib/iotguard/sensor"))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    health = state / "health.json"
    for name in ("API_BASE", "ASSET_ID", "LINUXGUARD_CONTROL_TOKEN"):
        if not os.environ.get(name):
            raise SystemExit(f"Required environment: {name}")
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    sensor = forwarder = None
    def failed():
        # Crash status must not keep claiming a previously healthy probe.
        payload = {"status": "degraded", "phase": "failed", "dropped_events": None,
                   "capabilities": {"driver": "libbpf_core", "phase": "failed"},
                   "detail": "Sensor pipeline exited unexpectedly; inspect service log and persistent WAL"}
        fd, temp = tempfile.mkstemp(dir=state, prefix="health-")
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.replace(temp, health)
    try:
        sensor = subprocess.Popen([str(here / "build/iotguard-sensor"), str(health)], stdout=subprocess.PIPE)
        forwarder = subprocess.Popen([sys.executable, str(here.parent / "ebpf_event_collector.py"),
            "--api", os.environ["API_BASE"], "--asset-id", os.environ["ASSET_ID"],
            "--source", "c_ebpf", "--sensor-id", os.environ.get("SENSOR_ID", socket.gethostname() + ":c_ebpf"),
            "--heartbeat", "--heartbeat-seconds", "5", "--health-file", str(health),
            "--spool-file", str(state / "wal.jsonl")], stdin=sensor.stdout)
        sensor.stdout.close()
        while not stopping and sensor.poll() is None and forwarder.poll() is None:
            time.sleep(0.2)
        expected = stopping
        if sensor.poll() is None:
            sensor.send_signal(signal.SIGINT)
        sensor.wait(timeout=10)
        # EOF drains remaining pipe data to WAL before final acknowledgement.
        try:
            forwarder.wait(timeout=70)
        except subprocess.TimeoutExpired:
            forwarder.send_signal(signal.SIGINT)
            forwarder.wait(timeout=20)
        if not expected or sensor.returncode or forwarder.returncode:
            failed()
            return 1
        return 0
    except Exception:
        failed()
        raise
    finally:
        for process in (sensor, forwarder):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
