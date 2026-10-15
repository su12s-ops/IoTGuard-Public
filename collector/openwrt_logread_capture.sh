#!/bin/sh
# LinuxGuard eBPF 2.0 P2-2：OpenWrt 轻量化降级采集（logread 只读拉取）。
#
# 只读取设备原生日志与身份信息，零写入、零配置改动、零软件包安装：
#   - 身份段：主机名 / boot_id（重启边界）/ 本地时钟与 UTC 纪元（时区换算
#     依据）/ TZ 规格（呈现用，换算以 +%z 偏移为准）
#   - 日志段：logread 全量环形缓冲输出（设备只读，不在设备留存任何状态）
#
# 输出分段标记与 collect_openwrt_asset.sh 约定一致（===== SECTION =====），
# 由后端 app/services/openwrt_runtime_log.py 解析。
# 依赖：OpenWrt（/etc/openwrt_release）、BusyBox logread；无需 root 以外权限提升。
set -u
if [ ! -r /etc/openwrt_release ]; then
    echo 'This collector requires OpenWrt' >&2
    exit 2
fi
command -v logread >/dev/null 2>&1 || { echo 'logread unavailable' >&2; exit 2; }

printf '===== IDENTITY =====\n'
printf 'hostname: %s\n' "$(uname -n)"
printf 'boot_id: %s\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
printf 'device_utc_epoch: %s\n' "$(date -u +%s 2>/dev/null || true)"
printf 'device_local_offset: %s\n' "$(date +%z 2>/dev/null || true)"
printf 'tz_spec: %s\n' "$(cat /etc/TZ 2>/dev/null || true)"
printf '===== LOGREAD =====\n'
logread
