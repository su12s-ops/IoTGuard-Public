# Native IoTGuard sensor

The default native path is **C CO-RE BPF → C libbpf loader → existing Python WAL
forwarder → RuntimeEvent plus durable evidence job → background evidence worker**.
The kernel probe and its loader/health accounting are C; HTTP/WAL and the platform
remain Python. Falco and the legacy bpftrace capture remain compatible alternatives.

## Build

Linux with BTF, ring buffer support and the syscall/sched tracepoints below is
required. Tested on x86-64 WSL2 kernel 6.6.87.2, clang 18, libbpf 1.3. Cross-kernel
CO-RE relocation is supported, but other kernel/architecture combinations need
their own attach and behavior verification. Missing required hooks fail startup.

Field testing on 2026-10-20 found controlled-event gaps on two Linux 7.0.0-38
nodes despite successful loading. That version is **not behavior-validated**.
See [the platform report](../../docs/archive/2026-10-21-ebpf-stability.md) for the
failure evidence and ongoing endurance tests; successful CO-RE load alone is
insufficient to claim kernel compatibility.

### Support status

| Kernel/platform | Status | Evidence required to change status |
| --- | --- | --- |
| x86-64 WSL2 Linux 6.6.87.2 | Build/attach and controlled behavior tested | Repeat the verifier after any probe/loader change; this is not a 24-hour pipeline result |
| Linux 7.0.0-38, two tested nodes | **Unsupported for behavior claims** | Resolve controlled-event gaps and pass `verify.py` on each architecture/configuration |
| OpenWrt 25.12.6 / Linux 6.12.112 | **Not validated; use logread fallback** | Confirm BTF, required hooks and privileges, then pass build/attach/controlled-event tests on the actual target |
| Other kernels, architectures and firmware | **Unknown** | Inventory prerequisites, then execute behavior and transport tests on the exact target |

`compatibility.sh` is a read-only prerequisite inventory. BTF/hook presence is necessary,
not sufficient. A version string or successful load never promotes an unknown target;
only controlled records reconciled against generated events do. Keep the result JSON and
raw verifier diagnostics tied to kernel build ID, architecture and sensor SHA256.

```bash
bash deploy/linux/install-ebpf-deps.sh
bash collector/native/build.sh
sudo collector/native/build/iotguard-sensor /tmp/ig-health.json 30 > /tmp/ig-events.jsonl
```

`build.sh` resolves Ubuntu's bpftool wrapper on WSL. Make generates `vmlinux.h`,
`guard.bpf.o`, the libbpf skeleton and `iotguard-sensor`; build artifacts are ignored.
For cross compilation, supply a target BTF header/toolchain separately. Linux
dependencies are separate from Zephyr build dependencies.

## Event contract

* `schema_version=1`, `source=c_ebpf`; records are JSONL with escaped strings.
* `execve`: success from `sched_process_exec`; failure from syscall exit. Successful
  execveat is also seen by sched, with unavailable argv flagged; failed execveat
  is outside current coverage. Executable path is distinct from argv[0].
* `openat`: `operation=open`, return fd or errno. This **does not prove byte
  reads/writes**. All supplied paths are collected; paths are not canonicalized,
  and relative paths retain that limitation. openat2/read/write/mmap are not covered.
* `connect`: syscall success/failure/pending (`EINPROGRESS`). These are socket
  connection operations, not packet inspection or proof of application-level
  connectivity. IP/port are available for IPv4/IPv6; other socket families retain
  family with no invented IP. Async completion needs a separate future socket-state probe.
* `retval`, `errno`, `result` survive API normalization and evidence serialization.
  Frontend timelines display outcomes. Legacy bpftrace events are attempts/initiated.
* Host-kernel PID/TID values are explicitly marked `pid_scope=host_kernel` (WSL
  namespace PIDs differ). Capture is scoped to the loader's PID namespace through
  `bpf_get_ns_current_pid_tgid`; the collector itself is excluded using namespace PID.
* `process_instance_id=boot-pid-leader_start`, while `process_exec_id` adds the
  observed successful-exec monotonic timestamp. Missing pre-attachment exec identity
  stays empty. Parent exec identity is supplied only when actually observed.
* argv is limited to 4 × 48 bytes; path to 256 bytes. `raw.truncation_flags` bits:
  1=truncated, 2=read unavailable, 4=argv unavailable (e.g. execveat/attach boundary).
  Non-ASCII filename bytes are losslessly escaped as byte-valued Unicode characters;
  they must not be treated as canonical decoded filesystem paths.
* Timestamp uses realtime minus current monotonic/event delta, with nanoseconds
  also retained. Host clock steps can affect wall-time estimates.

## Lifecycle and accounting

Loader locks its health path, loads all programs, attaches them, and only then
publishes running. Health is atomically refreshed each second. Failed attach/poll/
output exits nonzero; normal stop detaches, drains ring, and publishes stopped.
SIGKILL cannot publish: supervisor marks failed; absent supervisor, stale health
expires at the forwarder. Scope starts after attach and ends before detach.

Counters distinguish observed operations, emitted records, ring reservation loss,
map errors, read errors, unmatched exits, userspace receive, stdout delivery and
stdout/ABI errors. Pending operations at shutdown may have no exit record. Counters
reset on process restart; do not aggregate restarts as one uninterrupted window.
Ring loss is not whole-system loss; read/map errors are visible separately. Map
capacity is 32768 entries, ring 16 MiB. Kernel maps do not silently LRU-evict state.

Pipe backpressure is bounded: a blocked stdout fails within two seconds and reports
the loss boundary. It cannot promise lossless collection under overload or SIGKILL.
The durable guarantee begins at WAL append, not at kernel observation. Forwarder
memory staging is bounded to 2048 events; partial/malformed ACK leaves batches in
WAL. Rejected events require correction before that batch can drain. Monitor the
separate kernel, WAL and server counters rather than calling all gaps 'zero loss'.

Native events commit with a `runtime_evidence_job` in the same DB transaction.
The API acknowledges persistence, **not completed analysis**. Lifespan worker retries
jobs after crashes with bounded backoff; evidence + job deletion commit together.
`GET /api/runtime/ebpf/reliability` includes pending/retrying/oldest job status.
Legacy sources retain synchronous evidence generation for API compatibility.
Native pending jobs are bounded by `IOTGUARD_EVIDENCE_MAX_PENDING` (default 100000);
at capacity the API returns 503 and the sender retains WAL for retry. The bound
is enforced within the single-process writer lock; use one backend worker with
SQLite. Scale to a transactional queue/database before deploying multiple writers.
The default SQLite deployment still has one writer; this change does not claim
unbounded ingest throughput. Monitor backlog and disk space for capacity planning.

## Standing service

Place the repository at `/opt/iotguard`, build there, register the actual Linux
asset and create `/etc/iotguard/ebpf.env` from `deploy/linux/ebpf.env.example` (0600).
Never copy example credentials into production. Use the actual backend token.

```bash
sudo install -m 0644 deploy/linux/iotguard-ebpf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iotguard-ebpf
journalctl -u iotguard-ebpf -f
```

Supervisor stops the C probe first, drains the forwarder and preserves WAL on
outage. A crashed child fails the whole unit; systemd restarts it after 5 seconds.
State lives in `/var/lib/iotguard/sensor`. Do not run multiple pipelines against
the same state directory. The service conflicts with `linuxguard-falco`; choose one
primary stream per asset to avoid double observations. Observe-only: no LSM blocking.

Rollback: stop/disable `iotguard-ebpf`, retain its state/WAL, then restore the chosen
previous Falco service explicitly. Pending DB evidence jobs remain recoverable.

## Verification

```bash
sudo python3 collector/native/verify.py --seconds 180 --report /tmp/native-kernel.json
sudo python3 collector/native/verify_transport.py --report /tmp/native-transport.json
python collector/native/verify_ingest.py /tmp/native-kernel.json.events.jsonl /tmp/native-ingest.json
python -m pytest -q backend/tests/test_native_ebpf.py backend/tests/test_ebpf_wal_spool.py
```

Kernel test exercises success/refusal/pending, exec identity, quoting, counters,
stable RSS, singleton, stop/restart and broken pipes. Transport test uses real
kernel records and the production forwarder with an isolated durable loopback HTTP
stub, checking outage/WAL/reconnect, crash propagation and restart. Backend tests
exercise real FastAPI/SQLAlchemy paths separately. Neither test touches production
assets or claims a 24-hour endurance result.

Run `verify_ingest.py` in the backend Python environment. It replays the kernel
test's controlled `.events.jsonl` sample through an isolated FastAPI lifespan,
SQLite database and evidence worker, then verifies idempotent replay.

For bounded endurance sampling (root, a new output directory):

```bash
sudo python3 collector/native/soak.py --seconds 86400 --interval 30 --directory /var/tmp/iotguard-soak
```

This tests the C sensor, not the entire HTTP/backend pipeline. It retains counters
and health samples instead of full host events. `result.json` stays `running` until
completion; inspect sample timestamps to detect stale/interrupted runs. A passing
soak subset does not override a failed `verify.py` or nonzero unmatched/read counters.
Use `verify.py --work-directory NEW_DIRECTORY` to retain local raw diagnostics after
a functional assertion fails. `compatibility.sh` inventories prerequisites without
changing the kernel; unavailable paths are not proof that a kernel feature was compiled out.
