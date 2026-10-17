"""Stage 10 consolidated isolated-remediation authorization package builder.

READ-ONLY: assembles the evidence required by the Stage 10 task contract into
gitignored local files. It never opens a socket, never loads a private key,
never writes the production database and never touches a VM. It refuses to run
when either remediation write switch is enabled or the unified pipeline is not
the formal engine, so the package always describes a paused-at-gate state.

Outputs (all under local-archive/stage10-work/):
  authorization-request.json  sanitized evidence + gated action checklist
  clone-identity.json         proposed clone identity incl. generated secrets
Secrets live only in the gitignored local archive and are never printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from dotenv import dotenv_values  # noqa: E402
from app import models  # noqa: E402
from app.database import SessionLocal  # noqa: E402

WORK = ROOT / "local-archive" / "stage10-work"
M45_PREFLIGHT_RUN = "4ef1f86fcdfc45eb9dcec9b584b3c6b5"
OFFICIAL_SOURCE_URL = "https://ubuntu.com/security/cves/CVE-2026-94266.json"

GATED_ACTIONS = [
    "clone_snapshot_restore_verification",
    "clone_apt_index_refresh_download_install",
    "lab_repair_write_switch_enable",
    "dpkg_write_operations",
    "rollback_execution",
]


def write_private(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def risk_row(db):
    row = db.get(models.RiskAssessment, 126)
    if row is None:
        raise SystemExit("risk 126 missing; refusing to build a package")
    return {"id": row.id, "asset_id": row.asset_id, "cve_id": row.cve_id, "package": row.package_name,
            "review_status": row.review_status, "review_verdict": row.review_verdict,
            "human_review_required": bool(row.human_review_required),
            "recommended_action": row.recommended_action, "applicability_source": row.applicability_source,
            "ubuntu_priority": row.ubuntu_priority, "risk_direction": row.risk_direction,
            "affected_status": row.affected_status, "updated_at": str(row.updated_at)}


def official_row(db):
    row = (db.query(models.OfficialCveRecord).filter_by(cve_id="CVE-2026-94266")
           .order_by(models.OfficialCveRecord.fetched_at.desc()).first())
    if row is None:
        raise SystemExit("no official CVE-2026-94266 record")
    plan = json.loads(row.raw_json or "{}")
    noble = next((s for p in plan.get("packages", []) if isinstance(p, dict) for s in p.get("statuses", [])
                  if s.get("release_codename") == "noble"), {})
    fetched = row.fetched_at
    age_hours = None
    if fetched is not None:
        try:
            age_hours = round((datetime.now(timezone.utc).replace(tzinfo=None) - fetched).total_seconds() / 3600.0, 2)
        except TypeError:
            age_hours = None
    return {"id": row.id, "evidence_id": row.evidence_id, "source_url": row.source_url,
            "evidence_status": row.evidence_status, "content_sha256": row.content_sha256,
            "fetched_at": str(fetched), "age_hours": age_hours,
            "noble_status": noble.get("status", ""), "noble_pocket": noble.get("pocket", ""),
            "notices_ids": plan.get("notices_ids", [])}


def repair_runs(db):
    runs = []
    for row in db.query(models.HarnessRun).filter_by(asset_id=1).order_by(models.HarnessRun.created_at).yield_per(20):
        plan = json.loads(row.plan_json or "{}")
        if plan.get("adapter") != "ubuntu-apt-v1" and "preflight" not in (plan or {}):
            continue
        pre = plan.get("preflight") or {}
        runs.append({"run_id": row.id, "status": row.status, "created_at": str(row.created_at),
                     "plan_hash16": row.plan_hash[:16],
                     "target_version": (plan.get("official") or {}).get("fixed_version", ""),
                     "preflight_issues": pre.get("issues", []),
                     "candidate_versions": pre.get("candidate_versions", {}),
                     "identity_hostname": (pre.get("identity") or {}).get("hostname", "")})
    return runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-identity-generation", action="store_true",
                        help="reuse an existing clone-identity.json instead of generating new secrets")
    args = parser.parse_args()

    env = dotenv_values(ROOT / "backend" / ".env")
    switches = {"LINUXGUARD_ENABLE_DEVICE_REPAIR": env.get("LINUXGUARD_ENABLE_DEVICE_REPAIR"),
                "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR": env.get("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR")}
    pipeline = env.get("LINUXGUARD_UNIFIED_PIPELINE")
    if pipeline != "on":
        raise SystemExit("unified pipeline is not 'on'; refusing to build a package")
    if any(value != "0" for value in switches.values()):
        raise SystemExit("a remediation write switch is enabled; refusing to build a package")

    with SessionLocal() as db:
        connections = []
        for c in db.query(models.DeviceConnection).order_by(models.DeviceConnection.id):
            asset = db.get(models.LinuxAsset, c.asset_id) if c.asset_id else None
            connections.append({"id": c.id, "asset_id": c.asset_id, "host": c.host, "enabled": c.enabled,
                                "asset_hostname": asset.hostname if asset else "",
                                "identity_source": (asset.identity_source if asset else ""),
                                "identity_verified": bool(c.enabled and asset and asset.identity_source in
                                                          {"pinned_ssh_inventory", "authenticated_collection_node"})})
        evidence = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "stage10-isolated-ubuntu-clone-remediation",
            "production_state": {
                "unified_pipeline_mode": pipeline,
                "write_switches": switches,
                "write_switches_must_stay_zero_for_production": True,
                "risk_126": risk_row(db),
                "official_record": official_row(db),
                "registered_connections": connections,
                "historical_ubuntu_repair_runs": repair_runs(db),
            },
            "m45_preflight_reference_run": M45_PREFLIGHT_RUN,
            "official_source_url": OFFICIAL_SOURCE_URL,
            "gated_actions_before_which_execution_must_stop": GATED_ACTIONS,
            "authorization_not_granted_by_this_package": True,
        }

    WORK.mkdir(parents=True, exist_ok=True)
    request_path = WORK / "authorization-request.json"
    request_sha = write_private(request_path, evidence)

    identity_path = WORK / "clone-identity.json"
    if args.skip_identity_generation and identity_path.is_file():
        identity_sha = hashlib.sha256(identity_path.read_bytes()).hexdigest()
    else:
        node_token = secrets.token_urlsafe(36)
        identity = {
            "proposed": True,
            "source_vm": {"vmx": r"E:\2026_信安作品赛_CVE漏洞的检测和修复\Ubuntu 24.04\Ubuntu  24.04.vmx",
                          "hostname": "wyh-VMware-Virtual-Platform",
                          "machine_id_sha256": "ba0231461b97219f7fab5ba9105434545ae46d79f8a788d898e27cbd60723699",
                          "installed_curl_set": {"curl": "8.5.0-2ubuntu10.15",
                                                 "libcurl4t64:amd64": "8.5.0-2ubuntu10.15",
                                                 "libcurl3t64-gnutls:amd64": "8.5.0-2ubuntu10.15"}},
            "clone": {"proposed_hostname": "iotguard-stage10-clone",
                      "proposed_asset_note": "asset id assigned at registration; never reuse asset 1 bindings",
                      "proposed_node_id": "stage10-clone-node",
                      "node_token": node_token,
                      "token_env": "LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE",
                      "proposed_nat_ip": "192.168.183.110",
                      "nat_subnet": "192.168.183.0/24",
                      "vmnet8_dhcp_pool": "192.168.183.128-192.168.183.254",
                      "allowed_cidr_entry": "192.168.183.110/32",
                      "reverse_tunnel_port": 18446},
            "secrets_policy": "gitignored local archive only; never printed, never committed",
        }
        identity_sha = write_private(identity_path, identity)

    print(json.dumps({"authorization_request": str(request_path), "sha256": request_sha,
                      "clone_identity": str(identity_path), "identity_sha256": identity_sha,
                      "gated_actions": len(GATED_ACTIONS), "switches": switches}, ensure_ascii=False))


if __name__ == "__main__":
    main()
