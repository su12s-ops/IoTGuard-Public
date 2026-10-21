#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v clang >/dev/null
command -v pkg-config >/dev/null
pkg-config --atleast-version=1.0 libbpf
test -r /sys/kernel/btf/vmlinux
tool="${BPFTOOL:-}"
if [ -z "$tool" ]; then
  tool="$(command -v bpftool || true)"
  if [ -z "$tool" ] || ! "$tool" version >/dev/null 2>&1; then
    # Ubuntu's wrapper looks for a tool matching uname; WSL has no such package.
    tool="$(find /usr/lib -maxdepth 2 -path '/usr/lib/linux-tools-*/bpftool' -type f | sort -V | tail -1)"
  fi
fi
[ -n "$tool" ] || { echo 'Install bpftool (Ubuntu: linux-tools-generic) or set BPFTOOL.' >&2; exit 2; }
exec make BPFTOOL="$tool" "$@"
