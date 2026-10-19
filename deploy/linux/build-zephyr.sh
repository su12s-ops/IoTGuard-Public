#!/usr/bin/env bash
# New west workspace only. SDK is supplied separately, never silently downloaded.
set -euo pipefail
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKSPACE="${1:?Usage: bash build-zephyr.sh /absolute/new-workspace}"
: "${ZEPHYR_SDK_INSTALL_DIR:?Set ZEPHYR_SDK_INSTALL_DIR to Zephyr SDK with arm-zephyr-eabi}"
[[ "$WORKSPACE" = /* ]] || { echo 'Workspace must be absolute' >&2; exit 2; }
[[ ! -e "$WORKSPACE" ]] || { echo 'Refusing to overwrite an existing workspace' >&2; exit 2; }
[[ -x "$ZEPHYR_SDK_INSTALL_DIR/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" ]] || {
  echo 'SDK arm-zephyr-eabi toolchain missing' >&2; exit 2;
}
mkdir -p -- "$WORKSPACE"
python3 -m venv "$WORKSPACE/.venv"
source "$WORKSPACE/.venv/bin/activate"
python -m pip install west
west init -m https://github.com/zephyrproject-rtos/zephyr --mr v4.4.2 "$WORKSPACE"
cd -- "$WORKSPACE"
west update
west zephyr-export
python -m pip install -r zephyr/scripts/requirements.txt
git -C zephyr apply --check "$REPO_ROOT/firmware/zephyr-sensor-01/patches/0001-soc-xlnx-zynq7000-map-SLCR-when-GEM-enabled.patch"
git -C zephyr apply "$REPO_ROOT/firmware/zephyr-sensor-01/patches/0001-soc-xlnx-zynq7000-map-SLCR-when-GEM-enabled.patch"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
west build -b qemu_cortex_a9 "$REPO_ROOT/firmware/zephyr-sensor-01" -d "$WORKSPACE/build-arm"
sha256sum "$WORKSPACE/build-arm/zephyr/zephyr.elf"
echo 'Built only; no QEMU instance or service was started.'
