"""Validate per-device evidence manifests offline; never issue business acceptance."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

CHECKS = ("identity", "inventory", "intelligence", "applicability", "telemetry", "business", "remediation", "signoff")
IDENTITY = ("asset_id", "device_identity", "environment", "firmware", "kernel", "board",
            "code_revision", "collector_version", "config_sha256", "authorization_ref")


def validate(record, root):
    root = Path(root).resolve()
    errors, incomplete = [], []
    for field in IDENTITY:
        if not str(record.get(field) or "").strip():
            errors.append(f"missing_identity:{field}")
    if record.get("environment") not in ("physical", "virtual", "simulator"):
        errors.append("invalid_environment")
    try:
        start = datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(record["ended_at"].replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        errors.append("invalid_time_window")
    for field in ("config_sha256",):
        value = record.get(field, "")
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            errors.append(f"invalid_sha256:{field}")
    checks = record.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    for name in CHECKS:
        check = checks.get(name)
        if not isinstance(check, dict):
            errors.append(f"missing_check:{name}")
            continue
        status = check.get("status")
        if status not in ("passed", "failed", "not_applicable", "not_run"):
            errors.append(f"invalid_status:{name}")
        if status in ("failed", "not_applicable", "not_run") and not str(check.get("reason") or "").strip():
            errors.append(f"missing_reason:{name}")
        if status in ("failed", "not_run"):
            incomplete.append(name)
        evidence = check.get("evidence")
        if not isinstance(evidence, list):
            evidence = []
        if status in ("passed", "failed", "not_applicable") and not evidence:
            errors.append(f"missing_evidence:{name}")
        for receipt in evidence:
            if not isinstance(receipt, dict) or not isinstance(receipt.get("path"), str) or not receipt["path"]:
                errors.append(f"invalid_evidence:{name}")
                continue
            path = (root / receipt["path"]).resolve()
            if not path.is_relative_to(root):
                errors.append(f"evidence_outside_root:{name}")
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != receipt.get("sha256"):
                    errors.append(f"evidence_hash_mismatch:{name}")
            except OSError:
                errors.append(f"evidence_unreadable:{name}")
        if name == "remediation" and status == "passed" and not check.get("approval_ref"):
            errors.append("remediation_approval_missing")
        if name == "signoff" and status == "passed":
            if not check.get("reviewer") or not check.get("decision_ref"):
                errors.append("human_signoff_reference_missing")
    return {"status": "invalid" if errors else "incomplete" if incomplete else "record_complete",
            "errors": errors, "incomplete_checks": incomplete,
            "business_accepted": False,
            "note": "Only structure and local evidence hashes verified; device results and human signatures require independent review."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    result = validate(json.loads(args.record.read_text(encoding="utf-8")), args.evidence_root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "record_complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
