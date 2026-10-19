"""Bounded read-only availability sampling; never reports unknown loss as zero."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from urllib.request import Request, urlopen


def sample(base, token=""):
    headers = {"X-Control-Token": token} if token else {}
    with urlopen(Request(base.rstrip("/") + "/api/health", headers=headers), timeout=5) as response:
        data = json.load(response)
    layers = data.get("layers", {})
    sensors = layers.get("sensors", {})
    failures = []
    if data.get("status") != "ok":
        failures.append("api_unhealthy")
    if not layers.get("collection_node", {}).get("online"):
        failures.append("node_offline_or_unknown")
    if not sensors.get("total") or sensors.get("healthy") != sensors.get("total"):
        failures.append("sensor_unhealthy_or_absent")
    if not layers.get("runtime_evidence", {}).get("fresh"):
        failures.append("evidence_stale_or_absent")
    return {"at": datetime.now(timezone.utc).isoformat(), "failures": failures,
            "sensors_healthy": sensors.get("healthy"), "sensors_total": sensors.get("total"),
            "loss_measurement": "not_measured_by_health_endpoint", "dropped_events": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.seconds < 1 or args.interval < 1:
        parser.error("seconds and interval must be positive")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    samples = failures = 0
    # Exclusive creation prevents accidental overwriting of previous evidence.
    with args.output.open("x", encoding="utf-8") as output:
        while True:
            try:
                row = sample(args.base, os.getenv("LINUXGUARD_CONTROL_TOKEN", ""))
            except Exception as exc:
                row = {"at": datetime.now(timezone.utc).isoformat(), "failures": [type(exc).__name__]}
            samples += 1
            failures += bool(row["failures"])
            output.write(json.dumps(row) + "\n"); output.flush()
            remaining = args.seconds - (time.monotonic() - start)
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))
    print(json.dumps({"samples": samples, "failed_samples": failures,
                      "observed_seconds": round(time.monotonic() - start, 2),
                      "reboot_recovery_verified": False, "zero_loss_verified": False}))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
