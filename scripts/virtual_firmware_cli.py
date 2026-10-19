"""Operator CLI for signed QEMU-host firmware transactions.

The trusted restart helper accepts one argument: the verified release directory.
It must stop the old guest before starting the new guest, and return nonzero on
failure. Use recover after interruption, before permitting another update.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from virtual_firmware import VirtualFirmwareStore


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("identity redirects forbidden")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "activate", "rollback", "recover"])
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--board", choices=["qemu_cortex_a9"], default="qemu_cortex_a9")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--approved-sha256")
    parser.add_argument("--restart-helper", type=Path)
    parser.add_argument("--probe-url", default="http://127.0.0.1:8080/api/system")
    args = parser.parse_args()
    store = VirtualFirmwareStore(args.store, args.public_key, args.board, args.device_id)
    if args.action in {"verify", "activate"} and not args.bundle:
        parser.error("--bundle required")
    if args.action == "verify":
        manifest, ref = store.inspect(args.bundle)
        print(json.dumps({"manifest_sha256": ref, "manifest": manifest, "device_written": False}))
        return
    if not args.restart_helper or not args.restart_helper.is_absolute() or not args.restart_helper.is_file():
        parser.error("an absolute trusted --restart-helper executable is required")
    url = urlsplit(args.probe_url)
    if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"} or url.username or url.password
            or url.path != "/api/system" or url.query or url.fragment):
        parser.error("probe must use loopback QEMU forwarding and /api/system")
    if args.action != "recover" and not args.approved_sha256:
        parser.error("--approved-sha256 required")

    def restart(path):
        subprocess.run([str(args.restart_helper), str(path.resolve())], check=True, timeout=60,
                       env={key: value for key, value in __import__('os').environ.items()
                            if key in {"PATH", "SYSTEMROOT", "WINDIR", "LANG"}})

    def probe():
        opener = build_opener(NoRedirect)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                with opener.open(Request(args.probe_url), timeout=3) as response:
                    data = response.read(65537)
                    if len(data) > 65536:
                        raise ValueError("oversized identity")
                    return json.loads(data)
            except (OSError, ValueError):
                time.sleep(1)
        raise TimeoutError("QEMU identity did not recover")

    if args.action == "activate":
        ref = store.activate(args.bundle, args.approved_sha256, restart, probe)
    elif args.action == "rollback":
        ref = store.rollback(args.approved_sha256, restart, probe)
    else:
        ref = store.recover(restart, probe)
    print(json.dumps({"active_manifest_sha256": ref, "identity_verified": True,
                      "security_boundary": "trusted_qemu_host"}))


if __name__ == "__main__":
    main()
