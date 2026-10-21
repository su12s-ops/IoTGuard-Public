#!/usr/bin/env python3
"""Root-only, isolated loopback kernel verification. Never uploads production data."""
import argparse
from collections import Counter
from contextlib import nullcontext
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--report", required=True)
    parser.add_argument("--work-directory", help="Preserve raw local diagnostic records; directory must be new")
    args = parser.parse_args()
    assert os.geteuid() == 0
    binary = Path(__file__).resolve().parent / "build/iotguard-sensor"
    if args.work_directory:
        Path(args.work_directory).mkdir(mode=0o700)
    with (nullcontext(args.work_directory) if args.work_directory else tempfile.TemporaryDirectory(prefix="iotguard-native-")) as directory:
        work = Path(directory)
        hp = work / "health.json"
        data = work / "events.jsonl"
        err = work / "stderr"
        with data.open("w") as out, err.open("w") as errors:
            proc = subprocess.Popen([str(binary), str(hp)], stdout=out, stderr=errors)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise AssertionError(err.read_text())
                    if hp.exists() and json.loads(hp.read_text()).get("phase") == "running":
                        break
                    time.sleep(.1)
                else:
                    raise AssertionError("attach readiness timeout")
                # Same health path must not admit a second owner.
                second = subprocess.run([str(binary), str(hp), "1"], capture_output=True, timeout=5)
                assert second.returncode != 0
                server = socket.socket()
                server.bind(("127.0.0.1", 0)); server.listen(32)
                port = server.getsockname()[1]
                unused = socket.socket(); unused.bind(("127.0.0.1", 0))
                refused_port = unused.getsockname()[1]; unused.close()
                target = work / 'quoted"file'
                target.write_text("test")
                missing = str(work / "absent")
                sample_rss = []
                started = time.monotonic()
                loops = 0
                while time.monotonic() - started < args.seconds:
                    assert proc.poll() is None
                    target.read_bytes()
                    try:
                        os.open(missing, os.O_RDONLY)
                    except FileNotFoundError:
                        pass
                    client = socket.socket(); client.connect(("127.0.0.1", port))
                    conn, _ = server.accept(); conn.close(); client.close()
                    bad = socket.socket(); assert bad.connect_ex(("127.0.0.1", refused_port)) == errno.ECONNREFUSED; bad.close()
                    nonblock = socket.socket(); nonblock.setblocking(False)
                    nonblock.connect_ex(("127.0.0.1", port))
                    conn, _ = server.accept(); conn.close(); nonblock.close()
                    subprocess.run(["/bin/true"], check=True)
                    # Failed exec has its errno; it never rotates the successful exec identity.
                    if loops == 0:
                        try:
                            os.execv(missing, [missing])
                        except FileNotFoundError:
                            pass
                        # Two successful execs in one process must have distinct execution ids.
                        subprocess.run([sys.executable, "-c", "import os; os.execv('/bin/true',['/bin/true'])"], check=True)
                    status = Path(f"/proc/{proc.pid}/status").read_text()
                    sample_rss.append(int(next(line for line in status.splitlines() if line.startswith("VmRSS:")).split()[1]))
                    loops += 1
                    time.sleep(.2)
                server.close()
                proc.send_signal(signal.SIGINT)
                assert proc.wait(timeout=10) == 0, err.read_text()
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait()
        rows = [json.loads(line) for line in data.read_text().splitlines()]
        # WSL/container /proc PIDs differ from host-kernel BPF IDs. Attribute by
        # a unique controlled file, not by assuming PID namespace equivalence.
        host_pid = next(e["process_id"] for e in rows if e["file_path"] == str(target))
        mine = [e for e in rows if e["process_id"] == host_pid]
        assert any(e["operation"] == "exec" and e["result"] == "failure" and e["errno"] == errno.ENOENT for e in mine), [e for e in mine if e["operation"] == "exec"]
        assert sum(e["file_path"] == str(target) and e["result"] == "success" and (e["raw"]["flags"] & 3) == 0 for e in mine) == loops
        assert sum(e["file_path"] == missing and e["operation"] == "open" and e["errno"] == errno.ENOENT for e in mine) == loops
        assert sum(e["operation"] == "connect" and e["port"] == refused_port and e["errno"] == errno.ECONNREFUSED for e in mine) == loops
        assert any(e["operation"] == "connect" and e["result"] == "pending" for e in mine)
        executions = {}
        for e in rows:
            if e["operation"] == "exec" and e["result"] == "success":
                executions.setdefault(e["process_instance_id"], set()).add(e["process_exec_id"])
        assert any(len(ids) >= 2 for ids in executions.values())
        h = json.loads(hp.read_text())
        assert h["phase"] == "stopped"
        metrics = h["capabilities"]
        assert metrics["kernel_emitted"] == metrics["userspace_received"] == metrics["stdout_delivered"] == len(rows)
        assert metrics["ring_lost"] == metrics["map_errors"] == metrics["stdout_errors"] == metrics["abi_errors"] == 0
        # Controlled native records for separate FastAPI replay validation.
        Path(args.report + ".events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in mine[:100]))
        # Clean restart uses a new map set and successfully attaches again.
        with (work / "restart.jsonl").open("w") as output:
            restart = subprocess.run([str(binary), str(hp), "2"], stdout=output, capture_output=False, timeout=15)
        assert restart.returncode == 0
        # Broken output cannot report healthy success.
        broken = subprocess.Popen([str(binary), str(hp), "10"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        broken.stdout.close()
        time.sleep(1)
        for _ in range(10): subprocess.run(["/bin/true"])
        assert broken.wait(timeout=15) != 0
        assert json.loads(hp.read_text())["phase"] == "failed"
        report = {"passed": True, "duration_seconds": args.seconds, "loops": loops,
                  "events": len(rows), "by_operation": dict(Counter(e["operation"] for e in rows)),
                  "rss_first_kb": sample_rss[0], "rss_last_kb": sample_rss[-1], "rss_peak_kb": max(sample_rss),
                  "health": h, "checks": ["attach", "singleton", "open-success-and-failure", "exec-failure",
                  "exec-generation", "connect-success-refusal-and-pending", "json-escaping", "counter-reconciliation",
                  "continuous-run", "graceful-stop", "restart", "broken-output-fails"]}
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
