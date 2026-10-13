#!/bin/bash
# Zephyr-Sensor-01 QEMU 运行器（Ubuntu 侧）
# 使用 SLIRP + hostfwd 提供入站可达性：宿主 18080 → 固件 :80
# 不创建 TAP、不改路由、不需 root。
set -u
Q="${QEMU_BIN:-$HOME/zephyr-stage7/sdk/hosttools/sysroots/x86_64-pokysdk-linux/usr/bin/qemu-system-x86_64}"
BUILD="${1:-$HOME/zephyr-stage7/firmware/zephyr-sensor-01/build}"
HOST_PORT="${2:-18080}"
KERNEL="$BUILD/zephyr/zephyr.bin"

[ -f "$KERNEL" ] || { echo "kernel not found: $KERNEL" >&2; exit 2; }

exec "$Q" \
  -machine q35 -cpu qemu64,+x2apic -m 8M \
  -kernel "$KERNEL" \
  -netdev user,id=n0,hostfwd=tcp::${HOST_PORT}-:80 \
  -device e1000,netdev=n0 \
  -nographic -no-reboot -serial none -monitor none
