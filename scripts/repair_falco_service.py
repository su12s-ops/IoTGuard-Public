"""Repair the existing Falco forwarding unit on the pinned Ubuntu collector.

Run on that node as root, with a private JSON configuration staged over pinned
SSH. Never accepts a shell command or prints the control token. Native Falco is
stopped by the existing unit's Conflicts/ExecStartPre, avoiding two probes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
from datetime import datetime, timezone


def updated_environment(original, values):
    lines = [line for line in original.splitlines()
             if line.split("=", 1)[0].strip() not in values]
    for key, value in values.items():
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise ValueError("invalid environment value")
        lines.append(key + "=" + json.dumps(value))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Root is required to restore the existing monitoring service")
    configuration = args.configuration.resolve()
    if stat.S_IMODE(configuration.stat().st_mode) & 0o077:
        raise SystemExit("Configuration must be private (0600)")
    data = json.loads(configuration.read_text())
    machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    if machine != data["machine_sha256"] or socket.gethostname().lower() != "wyh-vmware-virtual-platform":
        raise SystemExit("Refusing a different collector identity")
    if data["api_base"] != "http://127.0.0.1:18445/api" or data["asset_id"] != 1:
        raise SystemExit("Refusing a different backend or asset scope")
    environment = Path("/etc/linuxguard/falco.env")
    original = environment.read_text()
    values = {"API_BASE": data["api_base"], "ASSET_ID": "1",
        "SENSOR_ID": "wyh-vmware-virtual-platform:falco",
        "LINUXGUARD_CONTROL_TOKEN": data["control_token"]}
    updated = updated_environment(original, values)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = environment.with_name(environment.name + "." + stamp + ".bak")
    with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(original)
    temporary = environment.with_name(".falco.env." + stamp)
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(updated)
    temporary.replace(environment)
    # The configuration's secret is now in the root-only service environment.
    configuration.unlink()
    subprocess.run(["systemctl", "enable", "linuxguard-falco.service"], check=True, timeout=20)
    subprocess.run(["systemctl", "disable", "falco-modern-bpf.service"], check=True, timeout=20)
    subprocess.run(["systemctl", "restart", "linuxguard-falco.service"], check=True, timeout=60)
    subprocess.run(["systemctl", "is-active", "--quiet", "linuxguard-falco.service"], check=True, timeout=10)
    print("Existing Falco forwarding service restored; original environment backed up with mode 0600")


if __name__ == "__main__":
    main()
