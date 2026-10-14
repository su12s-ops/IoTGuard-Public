#!/bin/bash
# Zephyr-Sensor-01 QEMU 运行器（Ubuntu 侧，qemu_cortex_a9 路径）
# 系统 qemu-system-arm（apt 版 8.2.2）+ xilinx-zynq-a9 机器：GEM/cadence UART/GIC
# 与 Zephyr 设备树寄存器布局一致。SLIRP + hostfwd 提供入站可达性：宿主 8080 → 固件 :80
# （8080 在 IoTGuard DEFAULT_SCAN_PORTS 内）。不创建 TAP、不改路由、不需 root。
set -u
Q="${QEMU_BIN:-qemu-system-arm}"
BUILD="${1:-$HOME/zephyr-stage7/firmware/zephyr-sensor-01/build-arm}"
HOST_PORT="${2:-8080}"
KERNEL="$BUILD/zephyr/zephyr.elf"

[ -f "$KERNEL" ] || { echo "kernel not found: $KERNEL" >&2; exit 2; }

# cadence_gem 为 SoC 不可插拔设备：经 -nic model= 由机器内建实例挂载到
# SLIRP netdev（QEMU 8.2 验证通过；SDK 捆绑 xilinx-aarch64 二进制此前不可行）。
exec "$Q" \
  -machine xilinx-zynq-a9 -cpu cortex-a9 -m 512M \
  -kernel "$KERNEL" \
  -nic user,model=cadence_gem,hostfwd=tcp::${HOST_PORT}-:80 \
  -nographic -no-reboot
