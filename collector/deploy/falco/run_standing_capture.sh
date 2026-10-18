#!/usr/bin/env bash
# LinuxGuard Falco 常驻采集管线（P1-2 部署准备，未在本轮执行）。
#
# 管线：falco(JSON stdout) → 转发器 stdin（批量+重试+spool，P0 可靠性全保留）
# 恢复语义：转发器自行退出时 systemd Restart=always 拉起；
#           未确认批次在 spool 断点续传，不丢失。
#
# 用法（root，需已按 README 完成规则部署）:
#   API_BASE=http://<后端>:8000/api ASSET_ID=<已注册资产ID> LINUXGUARD_CONTROL_TOKEN=<令牌> \
#     ./run_standing_capture.sh [采集输出目录=/var/lib/linuxguard/falco]
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:8000/api}"
ASSET_ID="${ASSET_ID:-}"
STATE_DIR="${1:-/var/lib/linuxguard/falco}"
SENSOR_ID="${SENSOR_ID:-$(hostname):falco}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # collector/

mkdir -p "${STATE_DIR}"
FALCO_ERR="${STATE_DIR}/falco.err"
HEALTH_FILE="${STATE_DIR}/falco-probe-health.json"
SPOOL_FILE="${STATE_DIR}/forwarder-spool.jsonl"

[ "$(id -u)" -eq 0 ] || { echo "[LinuxGuard] Falco 探针需要 root" >&2; exit 2; }
command -v falco >/dev/null || { echo "[LinuxGuard] 缺少 falco" >&2; exit 2; }
command -v python3 >/dev/null || { echo "[LinuxGuard] 缺少 python3" >&2; exit 2; }
[ -n "${ASSET_ID}" ] || { echo "[LinuxGuard] 心跳模式需要 ASSET_ID（已注册资产）" >&2; exit 2; }
[ -n "${LINUXGUARD_CONTROL_TOKEN:-}" ] || { echo "[LinuxGuard] 心跳模式需要 LINUXGUARD_CONTROL_TOKEN" >&2; exit 2; }

# ── supervisor：把 falco stderr 的 drops 统计转成健康文件（P0 语义） ──
update_health() {  # $1=status（默认 running）
  # drops 三种真实来源（falco 0.44.1 VM 实测）：
  #   ① 退出摘要 "event drop detected: N occurrences"（常驻服务在停止时给出全量真值）
  #   ② 结构化 stats "drops":<N>（若引擎周期输出）
  #   ③ 阈值告警 "N events lost"
  # 解析到 → 数值（0=真实零）；解析不到 → null=unavailable（不虚构为零）。
  local dropped
  dropped=$(grep -Eo 'event drop detected: [0-9]+ occurrences' "${FALCO_ERR}" 2>/dev/null | tail -1 | grep -Eo '[0-9]+' || true)
  [ -n "${dropped}" ] || dropped=$(grep -Eo '"drops":[0-9]+' "${FALCO_ERR}" 2>/dev/null | tail -1 | grep -Eo '[0-9]+' || true)
  [ -n "${dropped}" ] || dropped=$(grep -Eo '[0-9]+ events? lost' "${FALCO_ERR}" 2>/dev/null | tail -1 | grep -Eo '^[0-9]+' || true)
  if [ -n "${dropped}" ]; then
    DROPPED_JSON="${dropped}"
  else
    DROPPED_JSON="null"
  fi
  printf '{"status": "%s", "dropped_events": %s, "capabilities": {"driver": "falco", "lost_source": "falco_stderr_stats"}, "detail": "falco stderr stats drops 解析；null=尚未观测到统计输出（unavailable）"}\n' \
    "${1:-running}" "${DROPPED_JSON}" > "${HEALTH_FILE}"
}
HEALTH_PID=""
health_loop() {
  while true; do update_health; sleep 15; done
}
cleanup() {
  [ -n "${HEALTH_PID}" ] && kill "${HEALTH_PID}" 2>/dev/null || true
  update_health stopped
}
trap cleanup EXIT
on_term() {
  # 外部 SIGTERM（非 systemctl stop——stop 走 KillSignal=SIGINT）按异常退出
  # 处理：保留 143 失败语义 → Restart=always 自动拉起；EXIT trap 幂等复跑。
  cleanup
  exit 143
}
trap on_term TERM
on_int() {
  # systemctl stop（SIGINT 广播整个 cgroup）：转发器自身同时收到 SIGINT，
  # 经 KeyboardInterrupt→finally（stopped 心跳 + 在途批次入 spool）后退出；
  # 先等转发器（其 stdin 即 falco stdout，等价等 falco 退出摘要落盘），
  # 再 cleanup（此时 update_health 才能读到真实 drops）并透传退出码
  # （spool 残留=1 → SuccessExitStatus=1 映射为正常停止）。
  wait "${FORWARDER_PID}"
  RC=$?
  cleanup
  exit "${RC}"
}
trap on_int INT
health_loop &
HEALTH_PID=$!

# 先重传 spool（P0 断点续传），再进入实时流
# 转发器放后台 + wait：wait 可被 trap 信号即时中断（前台外部命令会把
# trap 挂起到命令结束——转发器常驻即永不执行，外部 SIGTERM 将被吞掉）。
python3 "${SCRIPT_DIR}/ebpf_event_collector.py" \
  --api "${API_BASE}" --source falco --sensor-id "${SENSOR_ID}" --asset-id "${ASSET_ID}" \
  --heartbeat --health-file "${HEALTH_FILE}" --spool-file "${SPOOL_FILE}" \
  < <(
    exec falco \
      -o json_output=true \
      -o stdout_output.enabled=true \
      -o log_level=info \
      -o rule_matching=all \
      2> >(trap '' INT TERM; exec tee "${FALCO_ERR}" >&2)
  ) &
FORWARDER_PID=$!
wait "${FORWARDER_PID}"
exit $?
