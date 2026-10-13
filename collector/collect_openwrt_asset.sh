#!/bin/sh
# Read-only BusyBox-compatible inventory. Supports both opkg and apk.
set -u
if [ ! -r /etc/openwrt_release ]; then
    echo 'This collector requires OpenWrt' >&2
    exit 2
fi
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT HUP INT TERM
printf '===== META =====\n'
printf 'hostname: %s\n' "$(uname -n)"
printf 'architecture: %s\n' "$(uname -m)"
printf 'mac_address: %s\n' "$(cat /sys/class/net/br-lan/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null || true)"
printf '===== OS_RELEASE =====\n'
cat /etc/os-release 2>/dev/null || true
printf '\n===== KERNEL =====\n'
uname -r
printf '===== SYSTEM_BOARD =====\n'
ubus call system board || exit 3
complete=false
if command -v opkg >/dev/null 2>&1; then
    printf '===== OPKG_PACKAGES =====\n'
    if opkg list-installed > "$tmp"; then cat "$tmp"; complete=true; fi
elif command -v apk >/dev/null 2>&1; then
    printf '===== APK_PACKAGES =====\n'
    if apk list --installed --manifest > "$tmp"; then cat "$tmp"; complete=true; fi
    printf '\n===== APK_PACKAGE_DETAILS =====\n'
    # Keep manifest boundaries authoritative; the backend joins full raw tokens
    # to name + complete version rather than guessing where the version starts.
    if ! apk list --installed; then complete=false; fi
fi
printf '\n===== INVENTORY_STATUS =====\npackages_complete: %s\n' "$complete"
if [ "$complete" = true ]; then
    printf 'package_count: %s\n' "$(awk 'NF { n++ } END { print n+0 }' "$tmp")"
fi
printf '===== OPEN_PORTS =====\n'
if command -v ss >/dev/null 2>&1; then ss -lntup 2>/dev/null; else netstat -lntup 2>/dev/null; fi
printf '\n===== DHCP_LEASES =====\n'
cat /tmp/dhcp.leases 2>/dev/null || true
printf '\n===== BPF_CAPABILITIES =====\n'
printf 'btf: '; if [ -r /sys/kernel/btf/vmlinux ]; then echo present; else echo absent; fi
printf 'tracefs: '; if [ -d /sys/kernel/tracing/events ] || [ -d /sys/kernel/debug/tracing/events ]; then echo present; else echo absent; fi
printf 'falco: '; command -v falco 2>/dev/null || echo unavailable
printf 'tetragon: '; command -v tetragon 2>/dev/null || echo unavailable
printf 'boot_id: '; cat /proc/sys/kernel/random/boot_id 2>/dev/null || true
exit 0
