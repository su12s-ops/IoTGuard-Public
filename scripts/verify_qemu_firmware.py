"""Run signed-update acceptance on a separate, temporary QEMU instance.

Uses an operator supplied trusted ELF/config, an ephemeral lab signing key and
a separate loopback forwarding port. Never stops or enrolls an existing guest.
"""
import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import time
from urllib.request import urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from virtual_firmware import VirtualFirmwareStore, canonical, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="directory containing zephyr.elf and .config")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--qemu", default="qemu-system-arm")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("unprivileged port required")
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", args.port))
    args.output.mkdir(parents=True, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    public = args.output / "lab-signing.pub"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    store = VirtualFirmwareStore(args.output / "store", public, "qemu_cortex_a9", args.device_id)
    process = None
    log = (args.output / "qemu.log").open("wb")
    def restart(path):
        nonlocal process
        if process is not None:
            process.terminate(); process.wait(timeout=10)
        command = [args.qemu, "-machine", "xilinx-zynq-a9", "-cpu", "cortex-a9", "-m", "512M",
                   "-kernel", str(path / "zephyr.elf"), "-nic",
                   f"user,model=cadence_gem,hostfwd=tcp:127.0.0.1:{args.port}-:80", "-nographic", "-no-reboot"]
        if "CONFIG_APP_QEMU_HOST_ENTROPY=y" in (path / ".config").read_text():
            command += ["-semihosting-config", "enable=on,target=native"]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def probe():
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("QEMU exited before identity verification")
            try:
                with urlopen(f"http://127.0.0.1:{args.port}/api/system", timeout=2) as response:
                    return json.load(response)
            except OSError:
                time.sleep(0.5)
        raise TimeoutError("QEMU identity unavailable")

    def bundle(counter, version):
        path = args.output / f"bundle-{counter}"
        path.mkdir()
        for name in ("zephyr.elf", ".config"):
            shutil.copyfile(args.build / name, path / name)
        manifest = {"schema": 1, "board": "qemu_cortex_a9", "device_id": args.device_id,
                    "version": version, "counter": counter,
                    "files": {name: digest(path / name) for name in ("zephyr.elf", ".config")}}
        (path / "manifest.json").write_bytes(canonical(manifest))
        (path / "manifest.sig").write_bytes(base64.b64encode(key.sign(canonical(manifest))))
        return path, store.inspect(path)[1]

    result = {"isolated_qemu": True, "existing_guest_modified": False,
              "firmware_source": "operator_supplied_existing_build", "checks": []}
    try:
        first, ref1 = bundle(1, args.version)
        store.activate(first, ref1, restart, probe)
        result["checks"].append("signed_baseline_boot_verified")
        second, ref2 = bundle(2, args.version)
        store.activate(second, ref2, restart, probe)
        result["checks"].append("signed_release_switch_verified_same_binary")
        bad, bad_ref = bundle(3, "injected-wrong-version")
        try:
            store.activate(bad, bad_ref, restart, probe)
        except ValueError:
            assert store._read()["active"] == ref2 and store._read()["pending"] is None
            result["checks"].append("failed_identity_automatic_fallback_verified")
        else:
            raise AssertionError("injected wrong version was accepted")
        store.rollback(ref1, restart, probe)
        result["checks"].append("explicit_rollback_verified")
        store.recover(restart, probe)
        result["checks"].append("confirmed_release_restart_verified")
        result["passed"] = True
    finally:
        if process is not None and process.poll() is None:
            process.terminate(); process.wait(timeout=10)
        log.close()
        (args.output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
