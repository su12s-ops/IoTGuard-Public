#!/usr/bin/env python3
"""OpenWrt-Lab serial console session helper with incremental JSON logging.

Each command's result is appended to the log file immediately so a timeout or
crash never loses completed steps. Usable for both identity isolation and
later verification passes.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

BS = chr(92)
PIPE = BS * 2 + "." + BS + "pipe" + BS + "openwrt-lab-console"


class Console:
    def __init__(self, pipe: str = PIPE):
        self.fd = os.open(pipe, os.O_RDWR | os.O_BINARY)
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.alive = True
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        while self.alive:
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:
                break
            if chunk:
                with self.lock:
                    self.buf.extend(chunk)
            else:
                time.sleep(0.05)

    def send(self, line: str):
        os.write(self.fd, line.encode() + b"\n")

    def take(self):
        with self.lock:
            text = self.buf.decode("utf-8", errors="replace")
            self.buf.clear()
        return text

    def wait(self, needle: str, timeout: float):
        deadline = time.monotonic() + timeout
        collected = ""
        while time.monotonic() < deadline:
            collected += self.take()
            if needle in collected:
                return True, collected
            time.sleep(0.3)
        return False, collected

    def close(self):
        self.alive = False
        time.sleep(0.2)
        try:
            os.close(self.fd)
        except OSError:
            pass


def run(commands: list[tuple[str, str]], log_path: str, wake_wait: float = 15.0,
        cmd_timeout: float = 30.0) -> int:
    console = Console()
    session_path = Path(log_path)
    session: dict = {"started": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": []}
    if session_path.exists():
        session = json.loads(session_path.read_text(encoding="utf-8"))

    def persist():
        session_path.write_text(json.dumps(session, ensure_ascii=False, indent=1),
                                encoding="utf-8")

    console.send("")
    ok, boot = console.wait("#", timeout=wake_wait)
    session["boot"] = boot[-1500:]
    persist()
    print("prompt:", ok, flush=True)
    failures = []
    for name, command in commands:
        marker = f"LGQ{name}Z"
        console.take()
        console.send(command)
        console.send("echo " + marker + "_$?")
        found, text = console.wait(marker + "_0", timeout=cmd_timeout)
        session["steps"].append({"name": name, "command": command, "ok": found,
                                 "output": text[-2500:]})
        persist()
        print(f"{name}: {'OK' if found else 'FAIL'}", flush=True)
        if not found:
            failures.append(name)
        time.sleep(0.3)
    session["failures"] = failures
    session["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    persist()
    console.close()
    print("failures:", failures, flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    log_path = sys.argv[1]
    commands = json.loads(sys.argv[2])
    wake = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
    sys.exit(run([(c[0], c[1]) for c in commands], log_path, wake_wait=wake))
