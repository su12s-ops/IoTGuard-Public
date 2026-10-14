#!/usr/bin/env bash
# LinuxGuard Falco 常驻采集管线（P1-2 部署准备，未在本轮执行）。
#
# 管线：falco(JSON stdout) → 转发器 stdin（批量+重试+spool，P0 可靠性全保留）
# 失败语义：转发器非零退出时 systemd Restart=on-failure 拉起；
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
update_health() {
  # falco 结构化日志中的 stats 段含 "drops":<N>（含 kernel.drops 等嵌套字段）。
  # 解析到 → 数值（0=真实零）；解析不到 → null=unavailable（不虚构为零）。
  # 注：stderr 统计格式需在目标 VM 真实运行确认（见 README 验收步骤 6）。
  local dropped
  dropped=$(grep -Eo '"drops":[0-9]+' "${FALCO_ERR}" 2>/dev/null | tail -1 | grep -Eo '[0-9]+' || true)
  if [ -n "${dropped}" ]; then
    DROPPED_JSON="${dropped}"
  else
    DROPPED_JSON="null"
  fi
  cat > "${HEALTH_FILE}" <<HEALTH
{"status": "running", "dropped_events": ${DROPPED_JSON}, "capabilities": {"driver": "falco", "lost_source": "falco_stderr_stats"}, "detail": "falco stderr stats drops 解析；null=尚未观测到统计输出（unavailable）"}
HEALTH
}
HEALTH_PID=""
health_loop() {
  while true; do update_health; sleep 15; done
}
cleanup() {
  [ -n "${HEALTH_PID}" ] && kill "${HEALTH_PID}" 2>/dev/null || true
  update_health
}
trap cleanup EXIT
health_loop &
HEALTH_PID=$!

# 先重传 spool（P0 断点续传），再进入实时流
python3 "${SCRIPT_DIR}/ebpf_event_collector.py" \
  --api "${API_BASE}" --source falco --sensor-id "${SENSOR_ID}" --asset-id "${ASSET_ID}" \
  --heartbeat --health-file "${HEALTH_FILE}" --spool-file "${SPOOL_FILE}" \
  < <(
    exec falco \
      -o json_output=true \
      -o stdout_output.enabled=true \
      -o log_level=info \
      2> >(tee "${FALCO_ERR}" >&2)
  )
