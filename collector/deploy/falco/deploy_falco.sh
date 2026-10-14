#!/usr/bin/env bash
# LinuxGuard Falco 部署/回滚脚本（P1-2 部署准备；本轮未在任何主机执行）。
#
# 安全设计：
#   - 默认只做 --check（非特权、只读诊断，不改动系统）；
#   - --apply / --install-service / --rollback 均需 root 且显式键入确认；
#   - 所有写操作先备份到带时间戳目录，回滚按备份精确还原；
#   - 不加载内核模块、不改内核参数、不动 LSM（modern eBPF 探针为只读观测）。
#
# 用法:
#   ./deploy_falco.sh --check                 # 只读体检（无需 root）
#   sudo ./deploy_falco.sh --apply            # 部署规则到 /etc/falco/rules.d/
#   sudo ./deploy_falco.sh --install-service  # 追加安装 systemd 单元（不启动）
#   sudo ./deploy_falco.sh --rollback         # 按最近备份还原规则与服务
set -euo pipefail

MODE="${1:---check}"
FALCO_RULES_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/linuxguard_iot_rules.yaml"
FALCO_RULES_DST="/etc/falco/rules.d/linuxguard_iot_rules.yaml"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/linuxguard-falco.service"
UNIT_DST="/etc/systemd/system/linuxguard-falco.service"
BACKUP_ROOT="/var/lib/linuxguard/falco-deploy-backups"

note() { printf '[LinuxGuard] %s\n' "$*"; }
fail() { printf '[LinuxGuard] 失败: %s\n' "$*" >&2; exit 1; }

confirm_root() {
  [ "$(id -u)" -eq 0 ] || fail "该操作需要 root（sudo 授权窗口内执行）"
  printf '将执行: %s\n确认请输入 YES: ' "$1"
  read -r answer
  [ "${answer}" = "YES" ] || fail "未确认，已中止（未做任何变更）"
}

latest_backup() { ls -1dt "${BACKUP_ROOT}"/* 2>/dev/null | head -1 || true; }

# ── --check：只读体检 ───────────────────────────────────────────────────────
do_check() {
  local rc=0
  note "Falco 部署体检（只读，不做任何变更）"
  if command -v falco >/dev/null; then
    note "falco 版本: $(falco --version 2>&1 | head -1)"
  else
    note "缺失: falco 命令（要求 >=0.37；VM 实测 0.44.1）"; rc=1
  fi
  if [ -f /sys/kernel/btf/vmlinux ]; then
    note "内核 BTF: 存在（modern eBPF CO-RE 探针可用路线）"
  else
    note "内核 BTF: 缺失（modern 探针可能回退 kmod——需另行授权，本轮不处理）"
  fi
  [ -d /etc/falco ] && note "/etc/falco: 存在" || { note "缺失: /etc/falco"; rc=1; }
  [ -f "${FALCO_RULES_SRC}" ] || { note "缺失: 规则源 ${FALCO_RULES_SRC}"; rc=1; }
  if [ -e "${FALCO_RULES_DST}" ]; then
    if cmp -s "${FALCO_RULES_SRC}" "${FALCO_RULES_DST}"; then
      note "自定义规则: 已部署且与源一致"
    else
      note "自定义规则: 已存在但内容不一致（--apply 将备份后覆盖）"
    fi
  else
    note "自定义规则: 未部署（审计轮 VM 实测状态）"
  fi
  for svc in falco-modern-bpf falco falco-custom; do
    systemctl is-active --quiet "${svc}" 2>/dev/null && note "服务 ${svc}: 运行中（常驻采集前需协调互斥）" || true
  done
  command -v python3 >/dev/null && note "python3: $(python3 --version 2>&1)" || { note "缺失: python3（转发器）"; rc=1; }
  note "体检完成（rc=${rc}；1=存在缺失项，详见上行）"
  return "${rc}"
}

# ── --apply：部署规则（root + 确认；备份先行） ─────────────────────────────
do_apply() {
  confirm_root "复制 linuxguard_iot_rules.yaml → ${FALCO_RULES_DST}（备份原文件）"
  [ -f "${FALCO_RULES_SRC}" ] || fail "规则源不存在"
  [ -d /etc/falco ] || fail "/etc/falco 不存在（先安装 falco 包）"
  local backup
  backup="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "${backup}" /etc/falco/rules.d
  [ -e "${FALCO_RULES_DST}" ] && cp -a "${FALCO_RULES_DST}" "${backup}/" || true
  note "备份目录: ${backup}"
  cp "${FALCO_RULES_SRC}" "${FALCO_RULES_DST}"
  chmod 0644 "${FALCO_RULES_DST}"
  echo "${backup}" > "${BACKUP_ROOT}/latest"
  if falco --help 2>&1 | grep -q -- --dry-run; then
    falco --dry-run >/dev/null 2>&1 && note "falco --dry-run 校验通过" || fail "falco --dry-run 校验失败（请回滚或修正规则）"
  else
    note "该 falco 版本无 --dry-run：改用启动验证（见 README 验收步骤）"
  fi
  note "规则部署完成。常驻采集与验证步骤见 README（需另行授权窗口）"
}

# ── --install-service：安装 systemd 单元（root + 确认；不启动） ─────────────
do_install_service() {
  confirm_root "复制 linuxguard-falco.service → ${UNIT_DST} 并 daemon-reload（不启动服务）"
  [ -f "${UNIT_SRC}" ] || fail "单元源不存在"
  local backup
  backup="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)-service"
  mkdir -p "${backup}"
  [ -e "${UNIT_DST}" ] && cp -a "${UNIT_DST}" "${backup}/" || true
  cp "${UNIT_SRC}" "${UNIT_DST}"
  systemctl daemon-reload
  note "单元已安装（未启动）。启动/停止流程见 README；需 sudo 授权窗口内执行"
}

# ── --rollback：按最近备份还原 ──────────────────────────────────────────────
do_rollback() {
  confirm_root "按最近备份还原规则与 systemd 单元"
  local backup
  backup="$(cat "${BACKUP_ROOT}/latest" 2>/dev/null || true)"
  [ -n "${backup}" ] && [ -d "${backup}" ] || fail "无备份可回滚"
  if [ -f "${backup}/linuxguard_iot_rules.yaml" ]; then
    cp -a "${backup}/linuxguard_iot_rules.yaml" "${FALCO_RULES_DST}"
    note "规则已还原"
  elif [ ! -e "${backup}/linuxguard_iot_rules.yaml" ] && [ -e "${FALCO_RULES_DST}" ]; then
    rm -f "${FALCO_RULES_DST}"
    note "部署前不存在规则文件：已移除新增文件"
  fi
  if [ -f "${backup}/linuxguard-falco.service" ]; then
    cp -a "${backup}/linuxguard-falco.service" "${UNIT_DST}"
    systemctl daemon-reload
    note "服务单元已还原"
  elif [ -e "${UNIT_DST}" ]; then
    systemctl stop linuxguard-falco 2>/dev/null || true
    rm -f "${UNIT_DST}"
    systemctl daemon-reload
    note "部署前无该单元：已停止并移除"
  fi
  note "回滚完成。如原 falco-modern-bpf 曾运行，请按运维基线决定是否恢复"
}

case "${MODE}" in
  --check) do_check ;;
  --apply) do_apply ;;
  --install-service) do_install_service ;;
  --rollback) do_rollback ;;
  *) fail "用法: $0 [--check|--apply|--install-service|--rollback]" ;;
esac
