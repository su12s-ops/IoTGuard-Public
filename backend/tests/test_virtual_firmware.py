"""Signed artifacts and crash/failure injection, without claiming live QEMU tests."""
import base64
import json
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from virtual_firmware import VirtualFirmwareStore, canonical, digest, atomic_json


@pytest.fixture
def firmware(tmp_path):
    key = Ed25519PrivateKey.generate()
    public = tmp_path / "trusted.pub"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo))
    store = VirtualFirmwareStore(tmp_path / "state", public, "qemu_cortex_a9", "synthetic-device")

    def bundle(counter, board="qemu_cortex_a9"):
        path = tmp_path / f"bundle-{counter}"
        path.mkdir()
        (path / "zephyr.elf").write_bytes(b"synthetic test bytes " + str(counter).encode())
        (path / ".config").write_text("CONFIG_TEST=y\n")
        manifest = {"schema": 1, "board": board, "device_id": "synthetic-device",
                    "version": f"0.0.{counter}", "counter": counter,
                    "files": {name: digest(path / name) for name in ("zephyr.elf", ".config")}}
        (path / "manifest.json").write_bytes(canonical(manifest))
        (path / "manifest.sig").write_bytes(base64.b64encode(key.sign(canonical(manifest))))
        return path
    running = {}
    def restart(path):
        running.update(json.loads((path / "manifest.json").read_text()))
    def probe():
        return {"device_id": running["device_id"], "firmware_version": running["version"]}
    return store, bundle, restart, probe


def test_success_and_explicit_rollback_keep_monotonic_counter(firmware):
    store, bundle, restart, probe = firmware
    first = bundle(1); ref1 = store.inspect(first)[1]
    store.activate(first, ref1, restart, probe)
    second = bundle(2); ref2 = store.inspect(second)[1]
    store.activate(second, ref2, restart, probe)
    assert store.rollback(ref1, restart, probe) == ref1
    assert store._read()["high_water"] == 2
    with pytest.raises(ValueError, match="counter"):
        store.activate(second, ref2, restart, probe)


@pytest.mark.parametrize("kind", ["bytes", "config", "signature", "target", "approval"])
def test_invalid_bundle_never_restarts(firmware, kind):
    store, bundle, _, _ = firmware
    path = bundle(1, board="wrong-board" if kind == "target" else "qemu_cortex_a9")
    import hashlib
    ref = hashlib.sha256(canonical(json.loads((path / "manifest.json").read_text()))).hexdigest()
    if kind in {"bytes", "config"}:
        (path / ("zephyr.elf" if kind == "bytes" else ".config")).write_text("tampered")
    if kind == "signature":
        (path / "manifest.sig").write_bytes(base64.b64encode(b"x" * 64))
    calls = []
    with pytest.raises(Exception):
        store.activate(path, "0" * 64 if kind == "approval" else ref, lambda p: calls.append(p), lambda: {})
    assert not calls


def test_failed_health_restores_previous_release(firmware):
    store, bundle, restart, probe = firmware
    first = bundle(1); ref1 = store.inspect(first)[1]
    store.activate(first, ref1, restart, probe)
    second = bundle(2); ref2 = store.inspect(second)[1]
    def health():
        result = probe()
        if result["firmware_version"] == "0.0.2":
            result["device_id"] = "wrong-device"
        return result
    with pytest.raises(ValueError, match="identity"):
        store.activate(second, ref2, restart, health)
    assert store._read()["active"] == ref1 and store._read()["pending"] is None
    assert probe()["firmware_version"] == "0.0.1"


def test_crash_keeps_pending_and_recovers_confirmed_release(firmware):
    store, bundle, restart, probe = firmware
    first = bundle(1); ref1 = store.inspect(first)[1]
    store.activate(first, ref1, restart, probe)
    second = bundle(2); ref2 = store.inspect(second)[1]
    def crash(_):
        raise KeyboardInterrupt("simulated host interruption")
    with pytest.raises(KeyboardInterrupt):
        store.activate(second, ref2, crash, probe)
    assert store._read()["pending"] == ref2
    assert store.recover(restart, probe) == ref1
    assert store._read()["pending"] is None
