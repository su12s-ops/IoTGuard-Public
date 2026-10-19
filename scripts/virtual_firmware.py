"""Signed firmware transactions for a trusted QEMU host, not device secure boot.

The public key, restart callback and identity probe belong to the operator;
none can be supplied by a downloaded manifest. Interrupted updates recover the
last confirmed release before starting a guest. No shell command is evaluated.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FILES = ("zephyr.elf", ".config")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify(bundle, public_key, *, board, device_id):
    bundle = Path(bundle)
    if (bundle / "manifest.json").stat().st_size > 16384:
        raise ValueError("manifest too large")
    raw = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(raw)
    key = serialization.load_pem_public_key(Path(public_key).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted key must be Ed25519")
    key.verify(base64.b64decode((bundle / "manifest.sig").read_bytes(), validate=True), canonical(manifest))
    if set(manifest) != {"schema", "board", "device_id", "version", "counter", "files"}:
        raise ValueError("invalid manifest fields")
    if manifest["schema"] != 1 or manifest["board"] != board or manifest["device_id"] != device_id:
        raise ValueError("firmware target mismatch")
    if type(manifest["counter"]) is not int or manifest["counter"] < 1:
        raise ValueError("invalid monotonic counter")
    if not isinstance(manifest["version"], str) or not manifest["version"].strip():
        raise ValueError("version required")
    if not isinstance(manifest["files"], dict) or set(manifest["files"]) != set(FILES):
        raise ValueError("exact image and Kconfig file set required")
    for name in FILES:
        path = bundle / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("invalid firmware file")
        if digest(path) != manifest["files"][name]:
            raise ValueError("firmware digest mismatch")
    return manifest, hashlib.sha256(canonical(manifest)).hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("wb") as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextmanager
def exclusive(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / "update.lock").open("a+b") as lock:
        lock.seek(0)
        if os.name == "nt":
            import msvcrt
            if not lock.read(1):
                lock.write(b"0"); lock.flush()
            lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


class VirtualFirmwareStore:
    def __init__(self, root, public_key, board, device_id):
        self.root = Path(root).resolve()
        self.public_key, self.board, self.device_id = public_key, board, device_id

    def inspect(self, bundle):
        return verify(bundle, self.public_key, board=self.board, device_id=self.device_id)

    def _read(self):
        path = self.root / "state.json"
        return json.loads(path.read_text()) if path.exists() else {
            "active": None, "previous": None, "pending": None, "high_water": 0}

    def _audit(self, event, **fields):
        from datetime import datetime, timezone
        with (self.root / "audit.jsonl").open("ab") as stream:
            stream.write(canonical({"event": event, "at": datetime.now(timezone.utc).isoformat(), **fields}) + b"\n")
            stream.flush(); os.fsync(stream.fileno())

    def _release(self, ref):
        if not isinstance(ref, str) or len(ref) != 64 or any(c not in "0123456789abcdef" for c in ref):
            raise ValueError("invalid release reference")
        path = self.root / "releases" / ref
        manifest, actual = self.inspect(path)
        if ref != actual:
            raise ValueError("stored release identity mismatch")
        return path, manifest

    def _start(self, ref, restart, probe):
        path, manifest = self._release(ref)
        restart(path)
        identity = probe()
        if (identity.get("device_id") != self.device_id or
                identity.get("firmware_version") != manifest["version"]):
            raise ValueError("post-update identity/version verification failed")

    def activate(self, bundle, approved_sha256, restart, probe):
        """Approve exact signed manifest; failures restore the confirmed release."""
        with exclusive(self.root):
            manifest, ref = self.inspect(bundle)
            if ref != approved_sha256:
                raise ValueError("approval does not match signed manifest")
            state = self._read()
            if state["pending"]:
                raise ValueError("interrupted update must be recovered first")
            if manifest["counter"] <= state["high_water"]:
                raise ValueError("replayed or downgraded update counter")
            releases = self.root / "releases"
            releases.mkdir(exist_ok=True)
            destination = releases / ref
            if not destination.exists():
                temporary = Path(tempfile.mkdtemp(prefix="staging-", dir=releases))
                try:
                    for name in (*FILES, "manifest.json", "manifest.sig"):
                        shutil.copyfile(Path(bundle) / name, temporary / name)
                        with (temporary / name).open("r+b") as stream:
                            os.fsync(stream.fileno())
                    if self.inspect(temporary)[1] != ref:
                        raise ValueError("bundle changed while staging")
                    os.replace(temporary, destination)
                finally:
                    if temporary.exists() and temporary.resolve().parent == releases.resolve():
                        shutil.rmtree(temporary)
            self._release(ref)
            state["pending"] = ref
            # Reserve the counter even after failure; never silently replay writes.
            state["high_water"] = manifest["counter"]
            atomic_json(self.root / "state.json", state)
            self._audit("activation_started", release=ref, previous=state["active"])
            try:
                self._start(ref, restart, probe)
            except Exception:
                self._audit("activation_failed", release=ref)
                if state["active"]:
                    self._start(state["active"], restart, probe)
                else:
                    # First enrollment has no known good fallback; remain pending.
                    raise
                state["pending"] = None
                atomic_json(self.root / "state.json", state)
                self._audit("fallback_verified", release=state["active"])
                raise
            state["previous"], state["active"], state["pending"] = state["active"], ref, None
            atomic_json(self.root / "state.json", state)
            self._audit("activation_verified", release=ref)
            return ref

    def recover(self, restart, probe):
        with exclusive(self.root):
            state = self._read()
            if not state["active"]:
                raise ValueError("no confirmed release; operator recovery required")
            self._start(state["active"], restart, probe)
            state["pending"] = None
            atomic_json(self.root / "state.json", state)
            self._audit("recovery_verified", release=state["active"])
            return state["active"]

    def rollback(self, approved_sha256, restart, probe):
        with exclusive(self.root):
            state = self._read()
            if state["pending"] or not state["previous"] or state["previous"] != approved_sha256:
                raise ValueError("rollback requires exact previous release approval and no pending update")
            state["pending"] = state["previous"]
            atomic_json(self.root / "state.json", state)
            # If rollback fails, recover() can still restore the last confirmed active release.
            self._start(state["previous"], restart, probe)
            state["active"], state["previous"], state["pending"] = state["previous"], state["active"], None
            atomic_json(self.root / "state.json", state)
            self._audit("rollback_verified", release=state["active"])
            return state["active"]
