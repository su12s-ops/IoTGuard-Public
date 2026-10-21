#!/usr/bin/env bash
# Ubuntu/Debian build host only; no service installation or kernel changes.
set -euo pipefail
sudo apt-get update
sudo apt-get install -y clang make gcc pkg-config libbpf-dev libelf-dev zlib1g-dev python3
if apt-cache show bpftool 2>/dev/null | grep -q '^Package: bpftool$'; then
  sudo apt-get install -y bpftool
else
  sudo apt-get install -y linux-tools-generic
fi
