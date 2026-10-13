#!/usr/bin/env bash
set -euo pipefail

API_BASE="${1:-http://192.168.183.1:8000/api}"
DURATION="${2:-60}"
OUT_JSON="${3:-/tmp/linuxguard_falco.jsonl}"
OUT_ERR="${4:-/tmp/linuxguard_falco.err}"

echo "[LinuxGuard] API: ${API_BASE}"
echo "[LinuxGuard] duration: ${DURATION}s"

if ! command -v falco >/dev/null 2>&1; then
  echo "[LinuxGuard] falco command not found. Please install Falco first." >&2
  exit 1
fi

curl -fsS "${API_BASE}/health" >/dev/null
sudo systemctl stop falco-modern-bpf 2>/dev/null || true
sudo rm -f "${OUT_JSON}" "${OUT_ERR}"

echo "[LinuxGuard] starting Falco modern-bpf capture..."
sudo timeout "${DURATION}s" falco \
  -o json_output=true \
  -o stdout_output.enabled=true \
  > "${OUT_JSON}" 2>"${OUT_ERR}" &
FALCO_PID=$!

sleep 8
echo "[LinuxGuard] triggering representative runtime behaviors..."
curl -s http://localhost >/dev/null || true
sudo cat /etc/shadow >/dev/null || true
sudo bash -lc "whoami && id && uname -a" >/dev/null || true
sudo touch /etc/linuxguard_falco_test && sudo rm /etc/linuxguard_falco_test || true
sudo systemctl status ssh >/dev/null 2>&1 || true

wait "${FALCO_PID}" || true
sudo systemctl start falco-modern-bpf 2>/dev/null || true
sudo chmod a+r "${OUT_JSON}" "${OUT_ERR}" 2>/dev/null || true

echo "[LinuxGuard] captured lines:"
wc -l "${OUT_JSON}" "${OUT_ERR}" || true

echo "[LinuxGuard] uploading JSON events..."
curl -fsS -F "file=@${OUT_JSON}" "${API_BASE}/runtime/ebpf/upload"
echo

echo "[LinuxGuard] uploading Falco diagnostic text..."
curl -fsS -F "file=@${OUT_ERR}" "${API_BASE}/runtime/ebpf/upload" || true
echo

echo "[LinuxGuard] current platform summary:"
curl -fsS "${API_BASE}/runtime/ebpf/summary"
echo
