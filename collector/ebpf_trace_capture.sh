#!/usr/bin/env bash
# LinuxGuard eBPF 实时采集（bpftrace 后端，真实内核探针）。
#
# 三类真实监控：
#   process : sys_enter_execve   —— 进程启动、PID/PPID、用户、命令、父子关系
#   network : tcp_v4/v6_connect  —— 哪个进程连接哪个 IP:端口、时间
#   file    : sys_enter_openat   —— 受控路径(/etc/mosquitto /etc/iotguard /etc/passwd
#                                   /etc/shadow /opt/firmware)的读/写、进程、时间
#
# eBPF 2.0 P1-1 探针增强（默认启用，PROBE_MODE=legacy 可回退）：
#   - execve 采集 argv（前 4 个参数，每参数 48 字节；NULL 守卫防止越界读 envp）
#   - 三类事件携带 process start_time（curtask->start_time，自开机单调纳秒）
#   - 后处理合成会话键 process_exec_id = lg-{boot8}-{pid}-{start_time}，
#     PID 复用可区分（D5 修复的采集侧基础）
#   - BPF 栈 512 字节预算实测约束：增强格式不重复读内核 filename（argv[0]
#     即程序名来源）；父进程名由后处理按 pid 顺序跟踪补齐（与旧 @procname
#     map 同为"探针启动后已知"语义，不虚构）
#
# 用法: sudo ./ebpf_trace_capture.sh <输出.jsonl> [采集秒数] [API_BASE] [auto|legacy]
# 依赖: bpftrace（root）、python3（后处理 collector/ebpf_capture_postprocess.py）
set -euo pipefail

OUT_JSON="${1:?用法: $0 <输出.jsonl> [秒数] [API_BASE] [auto|legacy]}"
DURATION="${2:-60}"
API_BASE="${3:-}"
PROBE_MODE="${4:-auto}"
HOSTNAME_VAL="$(hostname)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v bpftrace >/dev/null || { echo "[LinuxGuard] 缺少 bpftrace（apt install bpftrace）" >&2; exit 2; }
command -v python3 >/dev/null || { echo "[LinuxGuard] 缺少 python3" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "[LinuxGuard] 需要 root 权限挂载 eBPF 探针" >&2; exit 2; }

RAW_OUT="${OUT_JSON}.raw"

# ── P1 增强探针：argv（NULL 守卫，\x1f 分隔 / \x1e 终止）+ start_time ──────
# 格式：LG|execve|nsecs|pid|ppid|uid|comm|start_time|argv段
BPF_ENHANCED=$(cat <<'PROG'
// ── 进程：execve（PID/PPID/UID/comm/start_time/argv[0..3]） ──
tracepoint:syscalls:sys_enter_execve
{
  $ppid = curtask->real_parent->tgid;
  printf("LG|execve|%llu|%d|%d|%u|%s|%llu|%s\x1f%s\x1f%s\x1f%s\n",
    nsecs, pid, $ppid, uid, comm, curtask->start_time,
    str(uptr(args->argv[0]), 48),
    args->argv[1] != 0 ? str(uptr(args->argv[1]), 48) : "\x1e",
    (args->argv[1] != 0 && args->argv[2] != 0) ? str(uptr(args->argv[2]), 48) : "\x1e",
    (args->argv[1] != 0 && args->argv[2] != 0 && args->argv[3] != 0) ? str(uptr(args->argv[3]), 48) : "\x1e");
}

// ── 网络：TCP connect（kprobe+retprobe 读取 sock 目的地址 + start_time） ──
// P2-4（D8 修复）：retval != 0 的失败连接不产生事件（审计轮 §2.4：
// 失败连接不应计入网络证据）。map 项始终删除，避免谓词外泄导致泄漏。
kprobe:tcp_v4_connect
{
  @sk[tid] = arg0;
}
kretprobe:tcp_v4_connect
/@sk[tid]/
{
  $sk = (struct sock *)@sk[tid];
  if (retval == 0) {
    $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
    printf("LG|connect|%llu|%d|%u|%s|%s|%d|%llu\n",
      nsecs, pid, uid, comm, ntop($sk->__sk_common.skc_daddr), $port, curtask->start_time);
  }
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
  if (retval == 0) {
    $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
    printf("LG|connect|%llu|%d|%u|%s|%s|%d|%llu\n",
      nsecs, pid, uid, comm, ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8), $port, curtask->start_time);
  }
  delete(@sk6[tid]);
}

// ── 文件：受控路径 openat（读/写判定 + start_time） ──
tracepoint:syscalls:sys_enter_openat
{
  $f = str(args->filename);
  if (strncmp($f, "/etc/mosquitto", 14) == 0 ||
      strncmp($f, "/etc/iotguard", 13) == 0 ||
      strncmp($f, "/etc/passwd", 11) == 0 ||
      strncmp($f, "/etc/shadow", 11) == 0 ||
      strncmp($f, "/opt/firmware", 13) == 0) {
    $mode = (args->flags & 3) == 0 ? "read" : "write";
    printf("LG|openat|%llu|%d|%d|%u|%s|%s|%s|%llu\n",
      nsecs, pid, curtask->real_parent->tgid, uid, comm, str(args->filename), $mode, curtask->start_time);
  }
}
PROG
)

# ── 旧版探针（P0 及之前）：无 argv / start_time，用于增强版不可编译时回退 ──
BPF_LEGACY=$(cat <<'PROG'
tracepoint:syscalls:sys_enter_execve
{
  $ppid = curtask->real_parent->tgid;
  printf("LG|execve|%llu|%d|%d|%u|%s|%s|%s\n",
    nsecs, pid, $ppid, uid, comm, str(args->filename),
    @procname[$ppid]);
  @procname[pid] = str(args->filename);
}
kprobe:tcp_v4_connect
{
  @sk[tid] = arg0;
}
kretprobe:tcp_v4_connect
/@sk[tid]/
{
  $sk = (struct sock *)@sk[tid];
  if (retval == 0) {
    $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
    printf("LG|connect|%llu|%d|%u|%s|%s|%d\n",
      nsecs, pid, uid, comm, ntop($sk->__sk_common.skc_daddr), $port);
  }
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
  if (retval == 0) {
    $port = ($sk->__sk_common.skc_dport >> 8) | (($sk->__sk_common.skc_dport & 0xff) << 8);
    printf("LG|connect|%llu|%d|%u|%s|%s|%d\n",
      nsecs, pid, uid, comm, ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8), $port);
  }
  delete(@sk6[tid]);
}
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

run_probe() {  # $1=BPF 程序文本
  timeout --signal=INT --kill-after=5 "${DURATION}" bpftrace -q -e "$1" \
    > "${RAW_OUT}" 2> "${OUT_JSON}.err" || true
}

PROBE_PROFILE="enhanced"
if [ "${PROBE_MODE}" = "legacy" ]; then
  echo "[LinuxGuard] 使用旧版探针（PROBE_MODE=legacy：无 argv/start_time）"
  PROBE_PROFILE="legacy"
  run_probe "${BPF_LEGACY}"
else
  echo "[LinuxGuard] 挂载 eBPF 探针（execve+argv+start_time / tcp_connect / openat），采集 ${DURATION}s ..."
  run_probe "${BPF_ENHANCED}"
  # 增强版编译失败（无 BTF/字段缺失等）→ 自动回退旧版，如实降级不中断采集
  if [ ! -s "${RAW_OUT}" ] && grep -qi "error" "${OUT_JSON}.err" 2>/dev/null; then
    echo "[LinuxGuard] 增强探针编译失败，回退旧版探针（降级：无 argv/start_time）：" >&2
    grep "ERROR" "${OUT_JSON}.err" | head -3 >&2
    PROBE_PROFILE="legacy-fallback"
    run_probe "${BPF_LEGACY}"
  fi
fi

echo "[LinuxGuard] eBPF 探针结束（profile=${PROBE_PROFILE}），共捕获 $(grep -c '^LG|' "${RAW_OUT}" 2>/dev/null || echo 0) 条原始事件"

# ── 后处理：管道格式 → 后端统一事件 JSONL（P1 独立模块，新旧格式兼容） ──
python3 "${SCRIPT_DIR}/ebpf_capture_postprocess.py" "${RAW_OUT}" "${OUT_JSON}" "${HOSTNAME_VAL}"

# ── P0 采集可靠性：解析 bpftrace 丢失计数 → 探针健康文件（supervisor 语义） ──
# bpftrace 在退出时向 stderr 报告 "N events lost"（perf 缓冲丢失）。
# 能解析到 → dropped_events=真实数值；解析不到 → unavailable（绝不虚构为零）。
HEALTH_FILE="/tmp/linuxguard-probe-health.json"
LOST=$(grep -Eo '[0-9]+ events? lost' "${OUT_JSON}.err" 2>/dev/null | grep -Eo '^[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo "")
if [ -n "$LOST" ] && [ "$LOST" -ge 0 ] 2>/dev/null; then
  DROPPED_JSON="$LOST"
else
  DROPPED_JSON="null"
fi
cat > "$HEALTH_FILE" <<HEALTH
{"status": "running", "dropped_events": ${DROPPED_JSON}, "capabilities": {"driver": "bpftrace", "lost_source": "bpftrace_stderr", "probe_profile": "${PROBE_PROFILE}", "argv": $( [ "${PROBE_PROFILE}" = "enhanced" ] && echo true || echo false ), "start_time": $( [ "${PROBE_PROFILE}" = "enhanced" ] && echo true || echo false )}, "detail": "events lost: $(grep -Ec '[0-9]+ events? lost' "${OUT_JSON}.err" 2>/dev/null || echo 0) 条 stderr 丢失报告；null=本次运行未报告丢失计数（unavailable，非零丢失）；probe_profile=${PROBE_PROFILE}"}
HEALTH
echo "[LinuxGuard] 探针健康文件: ${HEALTH_FILE}（供转发器 --health-file 消费）"

if [ -n "$API_BASE" ]; then
  echo "[LinuxGuard] 上传到 ${API_BASE}/runtime/ebpf/upload ..."
  curl -fsS -F "file=@${OUT_JSON}" "${API_BASE}/runtime/ebpf/upload" && echo
fi
