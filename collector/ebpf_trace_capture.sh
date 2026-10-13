#!/usr/bin/env bash
# LinuxGuard eBPF 实时采集（bpftrace 后端，真实内核探针）。
#
# 三类真实监控：
#   process : sys_enter_execve   —— 进程启动、PID/PPID、用户、命令、父子关系
#   network : tcp_v4/v6_connect  —— 哪个进程连接哪个 IP:端口、时间
#   file    : sys_enter_openat   —— 受控路径(/etc/mosquitto /etc/iotguard /etc/passwd
#                                   /etc/shadow /opt/firmware)的读/写、进程、时间
#
# 用法: sudo ./ebpf_trace_capture.sh <输出.jsonl> [采集秒数] [API_BASE]
# 依赖: bpftrace（root）、python3（后处理）
set -euo pipefail

OUT_JSON="${1:?用法: $0 <输出.jsonl> [秒数] [API_BASE]}"
DURATION="${2:-60}"
API_BASE="${3:-}"
HOSTNAME_VAL="$(hostname)"

command -v bpftrace >/dev/null || { echo "[LinuxGuard] 缺少 bpftrace（apt install bpftrace）" >&2; exit 2; }
command -v python3 >/dev/null || { echo "[LinuxGuard] 缺少 python3" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "[LinuxGuard] 需要 root 权限挂载 eBPF 探针" >&2; exit 2; }

RAW_OUT="${OUT_JSON}.raw"

BPF_PROGRAM=$(cat <<'PROG'
// ── 进程：execve（真实 tracepoint，PID/PPID/UID/文件名/父进程名） ──
tracepoint:syscalls:sys_enter_execve
{
  $ppid = curtask->real_parent->tgid;
  printf("LG|execve|%llu|%d|%d|%u|%s|%s|%s\n",
    nsecs, pid, $ppid, uid, comm, str(args->filename),
    @procname[$ppid]);
  @procname[pid] = str(args->filename);
}

// ── 网络：TCP connect（kprobe+retprobe 读取 sock 目的地址） ──
kprobe:tcp_v4_connect
{
  @sk[tid] = arg0;
}
kretprobe:tcp_v4_connect
/@sk[tid]/
{
  $sk = (struct sock *)@sk[tid];
  $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
  printf("LG|connect|%llu|%d|%u|%s|%s|%d\n",
    nsecs, pid, uid, comm, ntop($sk->__sk_common.skc_daddr), $port);
  delete(@sk[tid]);
}
kprobe:tcp_v6_connect
{
  @sk6[tid] = arg0;
}
kretprobe:tcp_v6_connect
/@sk6[tid]/
{
  $sk = (struct sock *)@sk6[tid];
  $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
  printf("LG|connect|%llu|%d|%u|%s|%s|%d\n",
    nsecs, pid, uid, comm, ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8), $port);
  delete(@sk6[tid]);
}

// ── 文件：受控路径 openat（读/写判定） ──
tracepoint:syscalls:sys_enter_openat
{
  $f = str(args->filename);
  if (strncmp($f, "/etc/mosquitto", 14) == 0 ||
      strncmp($f, "/etc/iotguard", 13) == 0 ||
      strncmp($f, "/etc/passwd", 11) == 0 ||
      strncmp($f, "/etc/shadow", 11) == 0 ||
      strncmp($f, "/opt/firmware", 13) == 0) {
    $mode = (args->flags & 3) == 0 ? "read" : "write";
    printf("LG|openat|%llu|%d|%d|%u|%s|%s|%s\n",
      nsecs, pid, curtask->real_parent->tgid, uid, comm, str(args->filename), $mode);
  }
}
PROG
)

echo "[LinuxGuard] 挂载 eBPF 探针（execve / tcp_connect / openat），采集 ${DURATION}s ..."

timeout --signal=INT --kill-after=5 "${DURATION}" bpftrace -q -e "$BPF_PROGRAM" > "${RAW_OUT}" 2> "${OUT_JSON}.err" || true

echo "[LinuxGuard] eBPF 探针结束，共捕获 $(grep -c '^LG|' "${RAW_OUT}" 2>/dev/null || echo 0) 条原始事件"

# ── 后处理：管道格式 → 后端统一事件 JSONL（uid→用户名、纳秒→ISO 时间） ──
python3 - "$RAW_OUT" "$OUT_JSON" "$HOSTNAME_VAL" <<'PYEOF'
import json, os, pwd, sys
from datetime import datetime, timezone

raw_path, out_path, hostname = sys.argv[1], sys.argv[2], sys.argv[3]
boot_epoch = None
try:
    with open("/proc/stat") as fh:
        for line in fh:
            if line.startswith("btime "):
                boot_epoch = int(line.split()[1])
                break
except OSError:
    boot_epoch = None

users = {}
def user_name(uid):
    if uid not in users:
        try:
            users[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            users[uid] = str(uid)
    return users[uid]

count = 0

def to_iso(nsecs: str) -> str:
    # bpftrace 的 nsecs 是自开机起的单调纳秒，需加上内核 btime 才是墙上时间。
    value = int(nsecs) / 1e9
    if boot_epoch:
        value += boot_epoch
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()

with open(raw_path, encoding="utf-8", errors="replace") as fh, open(out_path, "w", encoding="utf-8") as out:
    for line in fh:
        line = line.strip()
        if not line.startswith("LG|"):
            continue
        parts = line.split("|")
        kind = parts[1]
        try:
            if kind == "execve":
                _, _, nsecs, pid, ppid, uid, comm, filename, parent_name = parts
                parent = os.path.basename(parent_name) if "/" in parent_name else (parent_name or comm)
                event = {
                    "timestamp": to_iso(nsecs),
                    "hostname": hostname, "source": "ebpf_bpftrace", "event_type": "execve",
                    "process_name": os.path.basename(filename), "parent_process": parent,
                    "commandline": filename, "user": user_name(int(uid)),
                    "process_id": int(pid), "parent_process_id": int(ppid),
                    "severity": "info",
                    "rule": "LG-eBPF process execution",
                    "raw": {"kind": kind, "uid": int(uid), "comm": comm, "filename": filename},
                }
            elif kind == "connect":
                _, _, nsecs, pid, uid, comm, ip, port = parts
                event = {
                    "timestamp": to_iso(nsecs),
                    "hostname": hostname, "source": "ebpf_bpftrace", "event_type": "connect",
                    "process_name": comm, "commandline": f"{comm} -> {ip}:{port}",
                    "destination": ip, "port": int(port), "user": user_name(int(uid)),
                    "process_id": int(pid), "severity": "notice",
                    "rule": "LG-eBPF outbound connection",
                    "raw": {"kind": kind, "uid": int(uid), "comm": comm, "daddr": ip, "dport": int(port)},
                }
            elif kind == "openat":
                _, _, nsecs, pid, ppid, uid, comm, filename, mode = parts
                event = {
                    "timestamp": to_iso(nsecs),
                    "hostname": hostname, "source": "ebpf_bpftrace", "event_type": "openat",
                    "process_name": comm, "commandline": f"{comm} {mode} {filename}",
                    "file_path": filename, "user": user_name(int(uid)),
                    "process_id": int(pid), "parent_process_id": int(ppid),
                    "severity": "warning" if mode == "write" else "info",
                    "rule": f"LG-eBPF watched file {mode}",
                    "raw": {"kind": kind, "uid": int(uid), "comm": comm, "filename": filename, "mode": mode},
                }
            else:
                continue
        except (ValueError, IndexError):
            continue
        out.write(json.dumps(event, ensure_ascii=False) + "\n")
        count += 1
print(f"[LinuxGuard] 归一化完成：{count} 条事件 -> {out_path}")
PYEOF

if [ -n "$API_BASE" ]; then
  echo "[LinuxGuard] 上传到 ${API_BASE}/runtime/ebpf/upload ..."
  curl -fsS -F "file=@${OUT_JSON}" "${API_BASE}/runtime/ebpf/upload" && echo
fi
