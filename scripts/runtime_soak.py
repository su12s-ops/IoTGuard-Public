"""Read-only backend/transport observation. Never substitutes for controlled probe evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time
from urllib.parse import urlsplit
from urllib.request import urlopen


COUNTERS = ("received", "parsed", "uploaded", "duplicates", "rejected", "retries", "failed_batches")


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def assess(samples, expected, duration, *, max_heartbeat_age=90):
    """Fail closed on missing data; compare counters within the same asset/sensor."""
    issues, missing = set(), set()
    previous, first, last = {}, {}, {}
    queue_sizes = []
    if duration < 86400:
        missing.add("less_than_24_hours")
    if len(samples) < 2:
        missing.add("insufficient_samples")
    elif (not number(samples[-1].get("elapsed_seconds")) or
          not number(samples[0].get("elapsed_seconds")) or
          samples[-1]["elapsed_seconds"] - samples[0]["elapsed_seconds"] < 86400):
        missing.add("observed_sample_span_less_than_24_hours")
    previous_elapsed = None
    for sample in samples:
        elapsed = sample.get("elapsed_seconds")
        if not number(elapsed):
            issues.add("invalid_sample_time")
        elif previous_elapsed is not None and elapsed - previous_elapsed > max_heartbeat_age:
            issues.add("sampling_gap")
        previous_elapsed = elapsed
        if sample.get("error"):
            issues.add("endpoint_error")
            continue
        health, reliability = sample.get("health", {}), sample.get("reliability", {})
        if health.get("status") != "ok" or health.get("database") != "ok":
            issues.add("backend_or_database_unhealthy")
        if health.get("layers", {}).get("collection_node", {}).get("online") is not True:
            issues.add("collection_node_offline_or_unknown")
        processing = reliability.get("evidence_processing", {})
        if not number(processing.get("pending")) or not number(processing.get("retrying")):
            missing.add("evidence_queue_metrics_unavailable")
        else:
            queue_sizes.append(processing["pending"])
        by_id = {(row.get("asset_id"), row.get("sensor_id")): row for row in reliability.get("sensors", [])}
        for key in expected:
            name = f"{key[0]}:{key[1]}"
            sensor = by_id.get(key)
            if sensor is None:
                issues.add(f"{name}:sensor_missing")
                continue
            age = sensor.get("heartbeat_age_seconds")
            if sensor.get("status") not in ("running", "reporting") or not number(age) or age > max_heartbeat_age:
                issues.add(f"{name}:heartbeat_unhealthy")
            drops = sensor.get("dropped_events")
            if not number(drops):
                missing.add(f"{name}:probe_drops_unavailable")
            elif drops:
                issues.add(f"{name}:probe_drops_nonzero")
            metrics = sensor.get("self_reported_metrics")
            if not isinstance(metrics, dict):
                missing.add(f"{name}:forwarder_metrics_unavailable")
                continue
            counts = {field: metrics.get(field) for field in COUNTERS}
            counts["stored_events"] = sensor.get("server_observed", {}).get("stored_events")
            if not all(number(value) for value in counts.values()):
                missing.add(f"{name}:counters_unavailable")
                continue
            if key in previous and any(counts[field] < previous[key][field] for field in counts):
                issues.add(f"{name}:counter_reset_or_event_deletion")
            previous[key] = counts
            first.setdefault(key, counts)
            last[key] = counts
            for field in ("spool_pending", "spool_bytes", "spool_corrupt_lines", "spool_blocked_events"):
                value = metrics.get(field)
                if not number(value):
                    missing.add(f"{name}:{field}_unavailable")
                elif value and field in ("spool_corrupt_lines", "spool_blocked_events"):
                    issues.add(f"{name}:{field}_nonzero")
            counts["spool_pending"] = metrics.get("spool_pending")
    if queue_sizes and queue_sizes[-1]:
        issues.add("evidence_queue_not_drained")
    if len(queue_sizes) >= 3 and all(a < b for a, b in zip(queue_sizes, queue_sizes[1:])):
        issues.add("evidence_queue_growing")
    for key, before in first.items():
        name = f"{key[0]}:{key[1]}"
        delta = {field: last[key][field] - before[field] for field in (*COUNTERS, "stored_events")}
        if number(last[key].get("spool_pending")) and last[key]["spool_pending"]:
            issues.add(f"{name}:spool_not_drained")
        if delta["stored_events"] <= 0:
            missing.add(f"{name}:no_new_server_events")
        if delta["uploaded"] != delta["stored_events"]:
            issues.add(f"{name}:upload_storage_delta_mismatch")
        if delta["rejected"] or delta["failed_batches"]:
            issues.add(f"{name}:forwarder_failures")
    # These APIs cannot prove kernel emitted counts, process identity or trigger correlation.
    missing.add("controlled_probe_receipts_and_restart_identity_require_external_validation")
    return {"status": "failed" if issues else "incomplete",
            "acceptance_passed": False, "issues": sorted(issues), "missing_evidence": sorted(missing),
            "elapsed_seconds": duration, "samples": len(samples)}


def fetch(base_url, path):
    with urlopen(base_url.rstrip("/") + path, timeout=15) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("Expected JSON object")
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--sensor", action="append", required=True, help="ASSET_ID:SENSOR_ID; repeat per sensor")
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory")
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("base URL must be HTTP(S), without credentials, query or fragment")
    if not 1 <= args.seconds <= 604800 or not 1 <= args.interval <= 60:
        parser.error("seconds must be 1..604800 and interval 1..60")
    try:
        expected = {(int(value.split(":", 1)[0]), value.split(":", 1)[1]) for value in args.sensor}
        if any(asset <= 0 or not sensor for asset, sensor in expected):
            raise ValueError()
    except (ValueError, IndexError):
        parser.error("sensor must be positive ASSET_ID:nonempty_SENSOR_ID")
    args.output.mkdir(parents=True, exist_ok=False)
    samples, started, interrupted = [], time.monotonic(), False
    raw = args.output / "samples.jsonl"
    try:
        with raw.open("x", encoding="utf-8") as handle:
            while True:
                sample = {"at": datetime.now(timezone.utc).isoformat(), "elapsed_seconds": time.monotonic() - started}
                try:
                    sample["health"] = fetch(args.base_url, "/api/health")
                    sample["reliability"] = fetch(args.base_url, "/api/runtime/ebpf/reliability")
                except Exception as exc:
                    sample["error"] = f"{type(exc).__name__}: {exc}"
                samples.append(sample)
                handle.write(json.dumps(sample, ensure_ascii=False) + "\n")
                handle.flush()
                remaining = args.seconds - (time.monotonic() - started)
                if remaining <= 0:
                    break
                time.sleep(min(args.interval, remaining))
    except KeyboardInterrupt:
        interrupted = True
    result = assess(samples, expected, time.monotonic() - started)
    result.update({"interrupted": interrupted, "base_url": args.base_url,
                   "expected_sensors": sorted(expected), "samples_sha256": hashlib.sha256(raw.read_bytes()).hexdigest()})
    if interrupted:
        result["issues"].append("operator_interrupted")
        result["status"] = "failed"
    with (args.output / "result.json").open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["status"] == "failed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
