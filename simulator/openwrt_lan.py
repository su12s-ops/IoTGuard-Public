#!/usr/bin/env python3
"""Provision only the named IoTGuard namespaces and LAN bridge ports."""
import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def command(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(" ".join(args) + ": " + result.stderr.strip())
    return result.stdout.strip()


def load(path):
    configuration = json.loads(Path(path).read_text(encoding="utf-8"))
    network = ipaddress.ip_network(f"{configuration['gateway']}/{configuration['prefix']}", strict=False)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", configuration["bridge"]):
        raise ValueError("Invalid bridge name")
    ids, addresses, macs = set(), set(), set()
    for row in configuration["devices"]:
        if not re.fullmatch(r"[a-z][a-z0-9]{1,8}", row["id"]) or row["kind"] not in {"camera", "sensor", "plug"}:
            raise ValueError("Invalid device profile")
        address = ipaddress.ip_address(row["ip"])
        mac = row["mac"].lower()
        if address not in network or str(address) in {configuration["gateway"], str(network.network_address), str(network.broadcast_address)}:
            raise ValueError("Device must use a usable LAN address")
        if not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", mac):
            raise ValueError("Use a locally administered unicast MAC")
        if row["id"] in ids or row["ip"] in addresses or mac in macs:
            raise ValueError("Duplicate device identity")
        ids.add(row["id"]); addresses.add(row["ip"]); macs.add(mac)
    return configuration


def prepare(configuration):
    bridge = configuration["bridge"]
    addresses = json.loads(command("ip", "-j", "addr", "show", "dev", bridge))
    if not any(info.get("local") == configuration["gateway"] for interface in addresses for info in interface.get("addr_info", [])):
        raise RuntimeError("Configured gateway is not on this bridge")
    existing = {line.split()[0] for line in command("ip", "netns", "list").splitlines()}
    reservations = command("uci", "show", "dhcp").splitlines()
    # Check all reservations/collisions before making changes.
    for row in configuration["devices"]:
        namespace = "ig-" + row["id"]
        section = "dhcp.iotguard_" + row["id"]
        for line in reservations:
            key, _, value = line.partition("=")
            if key.endswith(".ip") and key != section + ".ip" and row["ip"] in value.strip("'").split():
                raise RuntimeError("LAN IP reserved by another DHCP entry: " + row["ip"])
        prior = command("uci", "-q", "get", section, check=False)
        if prior and (command("uci", "-q", "get", section + ".name", check=False) != "iotguard-" + row["id"]):
            raise RuntimeError("Refusing an existing unrelated DHCP section: " + section)
        if namespace not in existing:
            if command("ip", "-o", "link", "show", "dev", namespace + "h", check=False):
                raise RuntimeError("Unowned bridge port already exists")
            probe = subprocess.run(["ping", "-c", "1", "-W", "1", row["ip"]], capture_output=True)
            neighbors = command("ip", "neigh", "show", "to", row["ip"])
            if probe.returncode == 0 or ("lladdr" in neighbors and row["mac"].lower() not in neighbors.lower()):
                raise RuntimeError("LAN IP already in use: " + row["ip"])
        else:
            actual = command("ip", "-n", namespace, "-j", "link", "show", "dev", "eth0")
            if json.loads(actual)[0].get("address", "").lower() != row["mac"].lower():
                raise RuntimeError("Existing namespace has another device identity")
    changed = False
    for row in configuration["devices"]:
        section = "dhcp.iotguard_" + row["id"]
        expected = {"name": "iotguard-" + row["id"], "mac": row["mac"], "ip": row["ip"], "leasetime": "12h", "dns": "1"}
        if command("uci", "-q", "get", section, check=False) != "host":
            command("uci", "set", section + "=host")
            changed = True
        for field, value in expected.items():
            if command("uci", "-q", "get", section + "." + field, check=False) != value:
                command("uci", "set", section + "." + field + "=" + value)
                changed = True
    if changed:
        command("uci", "commit", "dhcp")
        command("/etc/init.d/dnsmasq", "reload")
    for row in configuration["devices"]:
        namespace = "ig-" + row["id"]
        host, peer = namespace + "h", namespace + "p"
        if namespace not in existing:
            command("ip", "netns", "add", namespace)
            try:
                command("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
                command("ip", "link", "set", peer, "netns", namespace)
                command("ip", "-n", namespace, "link", "set", peer, "name", "eth0")
            except Exception:
                command("ip", "link", "del", host, check=False)
                command("ip", "netns", "del", namespace, check=False)
                raise
        command("ip", "link", "set", host, "master", bridge)
        command("ip", "link", "set", host, "up")
        command("ip", "-n", namespace, "link", "set", "eth0", "address", row["mac"])
        command("ip", "-n", namespace, "link", "set", "lo", "up")
        command("ip", "-n", namespace, "link", "set", "eth0", "up")
    print(json.dumps({"prepared": [row["id"] for row in configuration["devices"]], "bridge": bridge}))


def teardown(configuration):
    for row in configuration["devices"]:
        namespace = "ig-" + row["id"]
        if namespace not in {line.split()[0] for line in command("ip", "netns", "list").splitlines()}:
            continue
        links = json.loads(command("ip", "-n", namespace, "-j", "link", "show", "dev", "eth0"))
        if links[0].get("address", "").lower() != row["mac"].lower():
            raise RuntimeError("Refusing to stop an unrelated namespace")
        pids = command("ip", "netns", "pids", namespace)
        if pids:
            raise RuntimeError("Stop the procd service before removing namespaces")
        command("ip", "netns", "del", namespace)
        command("ip", "link", "del", namespace + "h", check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "stop", "list"])
    parser.add_argument("--config", default=str(ROOT / "lan_devices.json"))
    args = parser.parse_args()
    configuration = load(args.config)
    if args.action == "list":
        for row in configuration["devices"]:
            print(row["id"])
    elif args.action == "prepare":
        prepare(configuration)
    else:
        teardown(configuration)


if __name__ == "__main__":
    main()
