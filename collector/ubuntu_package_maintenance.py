#!/usr/bin/env python3
"""Fixed Ubuntu curl maintenance tool; stdin is a Harness-bound JSON request.

Preflight is read-only (no apt update/download). Execute additionally requires
node-local write switches and an operator-provisioned, clone-specific permit.
No caller-supplied command, package manager option, URL or rollback is accepted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

ALLOW = frozenset({"curl", "libcurl4t64", "libcurl3t64-gnutls", "libcurl3t64-nss",
                   "libcurl4-openssl-dev", "libcurl4-gnutls-dev", "libcurl4-nss-dev", "libcurl4-doc"})
VERSION = re.compile(r"^[0-9][A-Za-z0-9.+:~\-]{0,127}$")


def command(args, timeout=45):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"})
    if len(result.stdout) + len(result.stderr) > 1_500_000:
        raise ValueError("output_limit")
    return result.returncode, result.stdout, result.stderr[:2000]


def checked(args, timeout=45):
    code, out, _ = command(args, timeout)
    if code:
        raise ValueError("read_command_failed:" + args[0])
    return out


def identity():
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v.strip('"')
    return {"hostname": socket.gethostname(), "distribution": values.get("ID"),
            "release": values.get("VERSION_ID"), "codename": values.get("VERSION_CODENAME"),
            "machine_id_sha256": hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest(),
            "architecture": checked(["dpkg", "--print-architecture"]).strip()}


def source_packages():
    text = checked(["dpkg-query", "-W", "-f=${db:Status-Status}|${binary:Package}|${Version}|${source:Package}|${source:Version}|${Architecture}\n"])
    rows = []
    for line in text.splitlines():
        fields = line.split("|")
        if len(fields) != 6 or fields[0] != "installed" or fields[3] != "curl":
            continue
        _, binary, version, source, source_version, arch = fields
        rows.append({"name": binary.split(":")[0], "binary": binary, "version": version,
                     "source": source, "source_version": source_version, "architecture": arch})
    return sorted(rows, key=lambda r: r["binary"])


def official_candidate(policy, name, version, codename):
    """Require every index advertising the pinned version to be an official pocket.

    apt subsequently enforces signed index/package hashes. Policy inspection
    alone is provenance metadata, not independent signature verification.
    """
    lines = policy.splitlines()
    active, origins = False, []
    for line in lines:
        parts = line.strip().split()
        candidate = parts[1:] if parts and parts[0] == "***" else parts
        if len(candidate) == 2 and candidate[1].isdigit() and VERSION.fullmatch(candidate[0]):
            active = candidate[0] == version
            continue
        if active and len(parts) >= 3 and parts[0].isdigit() and "://" in parts[1]:
            from urllib.parse import urlparse
            url, suite = urlparse(parts[1]), parts[2].split("/")[0]
            origins.append(url.scheme in {"http", "https"} and url.hostname in {
                "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"} and
                not url.username and not url.password and url.port in {None, 80, 443} and
                suite in {codename + "-security", codename + "-updates"})
    return bool(origins) and all(origins)


def simulation_changes(text):
    changes, removals = [], []
    for line in text.splitlines():
        if line.startswith("Remv "):
            removals.append(line)
        if line.startswith("Inst "):
            match = re.match(r"Inst (\S+)(?: \[([^]]+)\])? \((\S+)", line)
            if not match:
                raise ValueError("simulation_unparsed")
            changes.append({"binary": match[1], "old": match[2] or "", "new": match[3]})
    return changes, removals


def inspect(request):
    ident = identity()
    if any(ident.get(k) != request["identity"].get(k) for k in ("hostname", "distribution", "release", "codename")):
        raise ValueError("target_identity_changed")
    pinned_machine = request["identity"].get("machine_id_sha256")
    if pinned_machine and pinned_machine != ident["machine_id_sha256"]:
        raise ValueError("machine_identity_changed")
    packages = source_packages()
    if not packages or any(p["name"] not in ALLOW for p in packages):
        raise ValueError("source_binary_not_allowlisted")
    expected = request.get("targets", [])
    if sorted(p["binary"] for p in packages) != sorted(p["binary"] for p in expected):
        raise ValueError("source_binary_mapping_changed")
    policies, candidates, metadata, issues = {}, {}, {}, []
    version = request["fixed_version"]
    if not VERSION.fullmatch(version):
        raise ValueError("invalid_version")
    for pkg in packages:
        binary = pkg["binary"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", binary):
            raise ValueError("invalid_binary")
        policies[binary] = checked(["apt-cache", "policy", binary])
        match = re.search(r"^\s*Candidate:\s*(\S+)", policies[binary], re.M)
        candidates[binary] = match[1] if match else ""
        # Exact USN version only; a newer candidate needs a newly reviewed plan.
        if candidates[binary] != version or not official_candidate(policies[binary], binary, version, ident["codename"]):
            issues.append("official_candidate_unavailable:" + binary)
        code, text, _ = command(["apt-cache", "show", binary + "=" + version])
        metadata[binary] = text if not code else ""
        if code or not re.search(r"^SHA256: [a-f0-9]{64}$", text, re.M):
            issues.append("candidate_checksum_unavailable:" + binary)
        source = re.search(r"^Source: (\S+)(?: \(([^)]+)\))?$", text, re.M)
        if not source or source[1] != "curl" or (source[2] and source[2] != version):
            # curl's own binary may omit Source, in which case source defaults
            # to the binary name and version under Debian metadata semantics.
            if not (pkg["name"] == "curl" and not source and re.search(r"^Version: " + re.escape(version) + "$", text, re.M)):
                issues.append("candidate_source_mismatch:" + binary)
        if pkg["version"] == version:
            issues.append("version_unchanged:" + binary)
        if command(["dpkg", "--compare-versions", pkg["version"], "lt", version])[0] != 0:
            issues.append("upgrade_not_monotonic:" + binary)
    specs = [p["binary"] + "=" + version for p in packages]
    code, simulation, error = command(["apt-get", "--simulate", "--only-upgrade", "--no-remove", "--no-install-recommends", "install", *specs], 90)
    changes, removals = simulation_changes(simulation)
    # apt omits the native architecture qualifier in simulation output.
    native = {p["name"]: p["binary"] for p in packages if p["architecture"] == ident["architecture"]}
    for change in changes:
        change["binary"] = native.get(change["binary"], change["binary"])
    proposed = {(c["binary"], c["new"]) for c in changes}
    allowed = {(p["binary"], version) for p in packages}
    if code or removals or proposed != allowed or any(not c["old"] for c in changes):
        issues.append("dependency_scope_rejected")
    audit = checked(["dpkg", "--audit"])
    if audit.strip():
        issues.append("dpkg_incomplete")
    held = checked(["apt-mark", "showhold"]).splitlines()
    if any(p["binary"] in held or p["name"] in held for p in packages):
        issues.append("held_package")
    free = os.statvfs("/var/cache/apt/archives")
    if free.f_bavail * free.f_frsize < 256 * 1024 * 1024:
        issues.append("insufficient_disk_space")
    package_ready = not issues
    effective_uid = os.geteuid()
    if effective_uid != 0:
        issues.append("root_execution_node_required")
    return {"identity": ident, "packages": packages, "candidate_versions": candidates,
            "policy": policies, "candidate_metadata": metadata, "simulation": simulation,
            "simulation_error": error, "changes": changes, "removals": removals,
            "dpkg_audit": audit, "held": held, "issues": issues,
            "ready": not issues, "package_ready": package_ready,
            "execution_context": {"effective_uid": effective_uid},
            "observed_at": time.time(), "apt_lists_refreshed": False,
            "rollback": {"strategy": "isolated_vm_snapshot_restore", "automatic_downgrade": False,
                         "old_packages_retained": False, "snapshot_restore": "not_checked_by_guest"}}


def permit(request, ident):
    # Stage-10 契约：本脚本只服务隔离克隆实验室写路径。开关仅为必要条件，
    # 充分条件是逐克隆许可文件（asset+machine+plan 绑定）；设备写总开关
    # LINUXGUARD_ENABLE_DEVICE_REPAIR 属 OpenWrt 域，在此不作为前置条件。
    if os.getenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0") != "1":
        raise ValueError("ubuntu_lab_writes_disabled")
    path = os.getenv("LINUXGUARD_UBUNTU_LAB_PERMIT", "")
    grant = json.loads(Path(path).read_text()) if path else {}
    required = {"asset_id": request["asset_id"], "machine_id_sha256": ident["machine_id_sha256"],
                "plan_hash": request["plan_hash"], "isolated_clone": True, "restore_verified": True}
    if any(grant.get(k) != v for k, v in required.items()) or not grant.get("snapshot_id") or not grant.get("approved_by") or grant.get("expires_at", 0) <= time.time():
        raise ValueError("isolated_clone_authorization_required")
    return {k: grant[k] for k in (*required, "snapshot_id", "approved_by", "expires_at")}


def execute(request):
    if os.geteuid() != 0:
        raise ValueError("root_execution_node_required")
    before = inspect(request)
    if not before["ready"]:
        raise ValueError("preflight_rejected")
    pinned = request["preflight"]
    for key in ("identity", "packages", "candidate_versions", "changes", "candidate_metadata"):
        if before[key] != pinned[key]:
            raise ValueError("approved_preflight_changed:" + key)
    grant = permit(request, before["identity"])
    specs = [p["binary"] + "=" + request["fixed_version"] for p in before["packages"]]
    # Download through apt's signed-index verification, then validate the exact
    # archive set and hashes. dpkg receives only those fixed paths; a solver
    # race cannot cause it to install an unapproved dependency or remove a pkg.
    archives = []
    with tempfile.TemporaryDirectory(prefix="iotguard-ubuntu-") as folder:
        code, out, err = command(["apt-get", "-o", "APT::Get::AllowUnauthenticated=false",
            "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
            "-o", "Dir::Cache::archives=" + folder, "--download-only", "--only-upgrade", "--no-remove",
            "--no-install-recommends", "-y", "install", *specs], 180)
        if code:
            raise ValueError("official_package_download_failed")
        expected = {(p["name"], p["architecture"]): p for p in before["packages"]}
        paths, seen = [], set()
        for path in sorted(Path(folder).glob("*.deb")):
            fields = checked(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"])
            info = dict(line.split(": ", 1) for line in fields.splitlines() if ": " in line)
            key = (info.get("Package"), info.get("Architecture"))
            if key not in expected or key in seen or info.get("Version") != request["fixed_version"]:
                raise ValueError("downloaded_package_scope_rejected")
            pkg = expected[key]
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes = set(re.findall(r"^SHA256: ([a-f0-9]{64})$", before["candidate_metadata"][pkg["binary"]], re.M))
            if hashes != {sha}:
                raise ValueError("downloaded_package_checksum_changed")
            seen.add(key)
            paths.append(str(path))
            archives.append({"binary": pkg["binary"], "version": request["fixed_version"], "sha256": sha})
        if seen != set(expected):
            raise ValueError("downloaded_package_missing")
        if identity() != before["identity"] or source_packages() != before["packages"]:
            raise ValueError("target_changed_before_dpkg")
        permit(request, before["identity"])
        # Never retry a nonzero exit or interrupted package transaction.
        code, out, err = command(["dpkg", "--install", *paths], 180)
    return {"before": before, "after": {"identity": identity(), "packages": source_packages()},
            "exit_code": code, "stdout": out, "stderr": err,
            "snapshot_permit": grant, "archives": archives, "verification_pending": True}


def main():
    request = json.load(sys.stdin)
    if request.get("operation") == "dry_run":
        result = {"preflight": inspect(request)}
    elif request.get("operation") == "verify":
        result = {"identity": identity(), "packages": source_packages()}
    elif request.get("operation") == "execute":
        result = execute(request)
    else:
        raise ValueError("operation_not_allowlisted")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # The authenticated result retains a stable reason. No command is
        # retried; execute failures remain uncertain until independent collection.
        print(json.dumps({"error": str(exc)[:300], "error_type": type(exc).__name__}))
