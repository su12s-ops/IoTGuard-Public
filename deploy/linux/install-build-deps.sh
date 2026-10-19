#!/usr/bin/env bash
# Explicitly invoked on a new Ubuntu 24.04 build host; does not enable services.
set -euo pipefail
if [[ ! -f /etc/os-release ]]; then
  echo 'Ubuntu 24.04 required' >&2; exit 2
fi
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
  echo 'This dependency list targets Ubuntu 24.04.' >&2; exit 2
fi
sudo apt-get update
sudo apt-get install -y git cmake ninja-build gperf ccache device-tree-compiler \
  gcc g++ make python3-dev python3-venv python3-pip xz-utils file wget \
  qemu-system-arm qemu-utils openssh-client libmagic1 libsdl2-dev
echo 'Build dependencies installed. Install the Zephyr SDK separately; no services started.'
