#!/usr/bin/env python3
"""Bounded native endurance test; retain counters, never full host event streams."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import threading
import time


def run(binary, directory, seconds, interval):
    directory.mkdir(parents=True, exist_ok=False)
    health = directory / 'health.json'
    marker = directory / 'controlled-open'
    marker.write_text('endurance probe\n')
    counts = {'records': 0, 'invalid': 0, 'controlled_opens': 0}
    lock = threading.Lock()
    started = time.monotonic()
    result = {'status': 'running', 'kernel': platform.release(), 'machine': platform.machine(),
              'started_epoch': time.time(), 'requested_seconds': seconds,
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    def save():
        tmp = directory / 'result.tmp'
        tmp.write_text(json.dumps(result, indent=2) + '\n')
        tmp.replace(directory / 'result.json')
    save()
    def reader():
        for line in proc.stdout:
            try:
                event = json.loads(line)
                with lock:
                    counts['records'] += 1
                    if event.get('file_path') == str(marker) and event.get('result') == 'success':
                        counts['controlled_opens'] += 1
            except (ValueError, TypeError):
                with lock:
                    counts['invalid'] += 1
    proc = None
    reader_thread = None
    samples = []
    loops = 0
    interrupted = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: interrupted.set())
    signal.signal(signal.SIGINT, lambda *_: interrupted.set())
    try:
        with (directory / 'stderr.log').open('w') as errors:
            proc = subprocess.Popen([str(binary), str(health)], stdout=subprocess.PIPE, stderr=errors, text=True)
            reader_thread = threading.Thread(target=reader, daemon=True)
            reader_thread.start()
            deadline = time.monotonic() + 20
            while not health.exists() or json.loads(health.read_text()).get('phase') != 'running':
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('attach_failed_or_timeout')
                time.sleep(.1)
            active_start = time.monotonic()
            with socket.socket() as listener, (directory / 'samples.jsonl').open('x') as log:
                listener.bind(('127.0.0.1', 0)); listener.listen(4); listener.settimeout(5)
                while time.monotonic() - active_start < seconds:
                    if interrupted.is_set():
                        raise RuntimeError('interrupted_before_requested_duration')
                    if proc.poll() is not None:
                        raise RuntimeError('sensor_exited')
                    marker.read_bytes()
                    subprocess.run(['/bin/true'], check=True, timeout=5)
                    with socket.create_connection(listener.getsockname(), timeout=5):
                        conn, _ = listener.accept(); conn.close()
                    loops += 1
                    values = dict(line.split(':', 1) for line in Path(f'/proc/{proc.pid}/status').read_text().splitlines() if ':' in line)
                    rss = int(values['VmRSS'].split()[0])
                    fd_count = len(list(Path(f'/proc/{proc.pid}/fd').iterdir()))
                    samples.append((rss, fd_count))
                    h = json.loads(health.read_text())
                    if time.time() - health.stat().st_mtime > 10:
                        raise RuntimeError('health_stale')
                    with lock:
                        row = {'elapsed': round(time.monotonic()-active_start, 2), 'rss_kb': rss,
                               'fds': fd_count, 'counts': dict(counts), 'health': h}
                    log.write(json.dumps(row)+'\n'); log.flush()
                    interrupted.wait(min(interval, max(0, seconds-(time.monotonic()-active_start))))
            proc.send_signal(signal.SIGINT)
            if proc.wait(timeout=15):
                raise RuntimeError('nonzero_exit')
            reader_thread.join(10)
            if reader_thread.is_alive():
                raise RuntimeError('reader_drain_timeout')
            h = json.loads(health.read_text())
            m = h['capabilities']
            checks = {'duration_completed': time.monotonic()-active_start >= seconds,
                      'stopped': h['phase'] == 'stopped',
                      'count_reconciliation': m['kernel_emitted'] == m['userspace_received'] == m['stdout_delivered'] == counts['records'],
                      'controlled_opens': counts['controlled_opens'] == loops,
                      'no_invalid_json': counts['invalid'] == 0,
                      'no_transport_or_map_loss': all(m[k] == 0 for k in ('ring_lost','map_errors','stdout_errors','abi_errors')),
                      'rss_growth_bounded_8mb': samples[-1][0] - samples[0][0] <= 8192,
                      'fd_growth_bounded': samples[-1][1] <= samples[0][1] + 1}
            result.update(status='passed' if all(checks.values()) else 'failed', checks=checks,
                          health=h, read_errors=m['read_errors'], unmatched_exits=m['unmatched_exits'])
    except Exception as exc:
        result.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
    finally:
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
        if reader_thread:
            reader_thread.join(5)
        result.update(elapsed_seconds=round(time.monotonic()-started, 2), finished_epoch=time.time(),
                      counts=counts, controlled_iterations=loops, samples=len(samples),
                      rss_first_kb=samples[0][0] if samples else None,
                      rss_last_kb=samples[-1][0] if samples else None,
                      rss_peak_kb=max((s[0] for s in samples), default=None))
        save()
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path(__file__).resolve().parent/'build/iotguard-sensor')
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=86400)
    parser.add_argument('--interval', type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 604800 or not 1 <= args.interval <= 300:
        parser.error('seconds: 1..604800; interval: 1..300')
    raise SystemExit(run(args.binary.resolve(), args.directory.resolve(), args.seconds, args.interval))
