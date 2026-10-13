#!/usr/bin/env bash
set -uo pipefail

OUTPUT="${1:-linux_asset_$(hostname)_$(date +%Y%m%d_%H%M%S).txt}"

# —— 暴露面自动探测（替代写死的 internal）——
PUBLIC_LISTEN=$(ss -tlnH 2>/dev/null | grep -E '0\.0\.0\.0:|:::' | grep -v '127\.0\.0\.1' | wc -l | tr -d ' ')
if   [ "${PUBLIC_LISTEN:-0}" -ge 3 ]; then EXPOSURE="public"
elif [ "${PUBLIC_LISTEN:-0}" -ge 1 ]; then EXPOSURE="dmz"
else                                     EXPOSURE="internal"
fi
BUSINESS="${BUSINESS_LEVEL:-normal}"

{
  echo "hostname: $(hostname)"
  echo "ip_address: $(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "architecture: $(uname -m)"
  echo "exposure_level: $EXPOSURE"
  echo "business_level: $BUSINESS"
  echo "owner: security-team"
  echo "description: collected by LinuxGuard (auto exposure=$EXPOSURE, $PUBLIC_LISTEN public listeners)"
  echo
  echo "===== HOSTNAME ====="
  hostname
  echo
  echo "===== OS_RELEASE ====="
  cat /etc/os-release 2>/dev/null || true
  echo
  echo "===== KERNEL ====="
  uname -a
  echo
  echo "===== IP_ADDRESS ====="
  hostname -I 2>/dev/null | awk '{print $1}' || true
  echo
  echo "===== DPKG_PACKAGES ====="
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -l | awk '/^ii/ {print $1" "$2" "$3" "$4}'
  fi
  echo
  echo "===== RPM_PACKAGES ====="
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n'
  fi
  echo
  echo "===== OPEN_PORTS ====="
  ss -tulnp 2>/dev/null || true
  echo
  echo "===== RUNNING_SERVICES ====="
  systemctl list-units --type=service --state=running --no-pager 2>/dev/null || true
  echo
  echo "===== APT_DEPENDENCY_GRAPH ====="
  if command -v apt-cache >/dev/null 2>&1; then
    for pkg in nginx apache2 redis-server openssh-server openssl sudo bash systemd curl; do
      if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "PACKAGE|$pkg"
        apt-cache depends "$pkg" 2>/dev/null | awk '/Depends:/ {print "DEPENDS|'"$pkg"'|"$2}' || true
        apt-cache rdepends "$pkg" 2>/dev/null | awk 'NF == 1 && $1 !~ /Reverse|Depends:/ {print "RDEPENDS|'"$pkg"'|"$1}' | head -20 || true
      fi
    done
  fi
} > "$OUTPUT"

echo "Asset inventory written to $OUTPUT"
