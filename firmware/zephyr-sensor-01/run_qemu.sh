#!/usr/bin/env bash
# Zephyr-Sensor-01 运行器（Ubuntu 侧）——手动驱动 QEMU，SLIRP + hostfwd 提供入站可达性。
#
# 用法: ./run_qemu.sh <build目录> <宿主端口> [QEMU_EXTRA]
# 例如: ./run_qemu.sh build 18080
#
# 入站链路（满足 IoTGuard 主动发现要求）：
#   IoTGuard(标准模式后端) → 127.0.0.1:<宿主端口> → QEMU hostfwd → 固件 :80
# 固件经 SLIRP DHCP 获得 10.0.2.15；本脚本不创建 TAP、不改路由、不需 root。
set -euo pipefail
BUILD_DIR="${1:?用法: $0 <build目录> <宿主端口> [mac]}"
HOST_PORT="${2:?缺少宿主端口}"
MAC="${3:-52:54:00:12:34:56}"
KERNEL="$BUILD_DIR/zephyr/zephyr.elf"
QEMU="${QEMU_BIN:-qemu-system-x86_64}"

[ -f "$KERNEL" ] || { echo "未找到 $KERNEL（先完成构建）" >&2; exit 2; }

exec "$QEMU" \
  -machine q35 -cpu kvm64 -m 8M \
  -kernel "$KERNEL" \
  -netdev user,id=n0,hostfwd=tcp::${HOST_PORT}-:80 \
  -device e1000,netdev=n0,mac="${MAC}" \
  -nographic -no-reboot \
  -serial mon:stdio
