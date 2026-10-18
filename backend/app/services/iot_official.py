"""Conservative official GHSA import and version applicability.

No title keyword exclusions, distro version comparisons, or implicit config
assumptions. Range membership is a candidate, never proof of exploitability.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from app import models

REPOSITORIES = {"zephyr": "zephyrproject-rtos/zephyr", "openwrt": "openwrt/openwrt"}


def import_snapshot(db, ecosystem, rows):
    if ecosystem not in REPOSITORIES:
        raise ValueError("Unsupported ecosystem")
    validated = []
    seen = set()
    for row in rows:
        key = row.get("ghsa_id", "")
        if not re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}", key):
            raise ValueError("Invalid GHSA id")
        url = row.get("html_url", "")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != "github.com"
                or parsed.path != f"/{REPOSITORIES[ecosystem]}/security/advisories/{key}"
                or parsed.query or parsed.fragment):
            raise ValueError("Official repository URL required")
        if key in seen or not isinstance(row.get("vulnerabilities"), list):
            raise ValueError("Duplicate advisory or missing vulnerability metadata")
        seen.add(key)
        payload = json.dumps(row, sort_keys=True, ensure_ascii=False)
        validated.append((key, url, payload))
    # Validate the complete batch before making changes; caller owns transaction.
    for key, url, payload in validated:
        record = db.query(models.IotOfficialAdvisory).filter_by(
            ecosystem=ecosystem, advisory_id=key).one_or_none()
        if record is None:
            record = models.IotOfficialAdvisory(ecosystem=ecosystem, advisory_id=key)
            db.add(record)
        record.source_url = url
        record.payload_json = payload
        record.content_sha256 = hashlib.sha256(payload.encode()).hexdigest()
    db.flush()
    return len(validated)


def version_in_range(version, expression):
    """Strict stable three-part versions only; unsupported syntax stays unknown."""
    def parse(value):
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
        return tuple(map(int, match.groups())) if match else None
    current = parse(version)
    if current is None or not expression:
        return None
    if expression.strip() == "*":
        return True
    results = []
    for term in expression.split(","):
        match = re.fullmatch(r"\s*(>=|<=|>|<|=)?\s*(v?\d+\.\d+\.\d+)\s*", term)
        if not match:
            return None
        target = parse(match[2])
        results.append({">=": current >= target, "<=": current <= target,
                        ">": current > target, "<": current < target,
                        "=": current == target}[match[1] or "="])
    return all(results)


def assess_snapshot(db, ecosystem, version):
    """Version-only coverage; never changes operational matches or device risk."""
    if ecosystem not in REPOSITORIES:
        raise ValueError("Unsupported ecosystem")
    results = []
    for record in db.query(models.IotOfficialAdvisory).filter_by(ecosystem=ecosystem).all():
        row = json.loads(record.payload_json)
        entries = row.get("vulnerabilities", [])
        # OpenWrt package versions and release versions are different domains.
        ranges = [version_in_range(version, entry.get("vulnerable_version_range", ""))
                  if (entry.get("package", {}).get("name", "").lower()
                      in {"zephyr", "zephyrproject-rtos/zephyr"}) else None
                  for entry in entries] if ecosystem == "zephyr" else []
        status = "insufficient_data"
        if ranges and all(value is False for value in ranges):
            status = "not_in_reported_range"
        elif True in ranges:
            status = "potentially_affected"
        results.append({"advisory_id": record.advisory_id, "cve_id": row.get("cve_id"),
                        "status": status, "source_url": record.source_url,
                        "snapshot_sha256": record.content_sha256,
                        "reason": "Version metadata only; component, build and reachability review required."})
    return {"ecosystem": ecosystem, "version": version, "count": len(results),
            "coverage_status": "partial" if results else "unassessed", "results": results}
