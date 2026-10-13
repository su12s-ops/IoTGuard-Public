#!/usr/bin/env bash
set -euo pipefail

API="${1:-http://192.168.183.1:8000/api}"
DURATION="${2:-180}"
MODE="${3:-upload}"
OUT="/tmp/lg_falco.jsonl"
ERR="/tmp/lg_falco.err"

echo "[capture] stopping falco service and starting standalone capture for ${DURATION}s ..."
sudo systemctl stop falco-modern-bpf 2>/dev/null || true
sudo rm -f "$OUT" "$ERR"
sudo timeout "${DURATION}s" falco \
  -o json_output=true \
  -o stdout_output.enabled=true \
  > "$OUT" 2>"$ERR" &
PID=$!
sleep 12

echo "[capture] triggering representative runtime behaviors ..."
cat /etc/shadow 2>/dev/null || true
sudo cat /root/.ssh/id_rsa 2>/dev/null || true
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null | head -5 || true
grep -rl "password" /etc/ 2>/dev/null | head -3 || true
ln -sf /etc/shadow /tmp/lg_sym_shadow 2>/dev/null || true
ln -sf /etc/passwd /tmp/lg_sym_passwd 2>/dev/null || true
strace -e trace=read -p $$ 2>/dev/null & SPID=$!
sleep 2
kill "$SPID" 2>/dev/null || true
strace ls 2>/dev/null || true
cp /bin/echo /dev/shm/lg_bin 2>/dev/null && chmod +x /dev/shm/lg_bin && /dev/shm/lg_bin lg_shm_test 2>/dev/null || true
ssh -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=2 localhost 2>/dev/null || true
ssh -p 9999 -o StrictHostKeyChecking=no -o ConnectTimeout=2 127.0.0.1 2>/dev/null || true
su -s /bin/bash nobody -c "id" 2>/dev/null || true
su -s /bin/bash www-data -c "whoami" 2>/dev/null || true
python3 -c "import os; os.system('bash -c id')" 2>/dev/null || true
awk 'BEGIN{system("id")}' 2>/dev/null || true
find / -name "credentials" -o -name ".aws" -o -name "*.csv" 2>/dev/null | head -5 || true
mkdir -p /tmp/lg_logs && touch /tmp/lg_logs/{a,b,c}.log && rm -rf /tmp/lg_logs 2>/dev/null || true
mkdir -p /tmp/lg_bulk && touch /tmp/lg_bulk/file{1..10} && rm -rf /tmp/lg_bulk 2>/dev/null || true
cat /etc/../etc/shadow 2>/dev/null || true
cat /var/log/../etc/passwd 2>/dev/null || true

rm -f /tmp/lg_sym_shadow /tmp/lg_sym_passwd /dev/shm/lg_bin 2>/dev/null || true

wait "$PID" || true
sudo systemctl start falco-modern-bpf 2>/dev/null || true
sudo chmod a+r "$OUT" "$ERR" 2>/dev/null || true

LINES="$(wc -l < "$OUT" 2>/dev/null || echo 0)"
echo "[capture] captured ${LINES} JSON lines"
if [[ "${LINES}" -le 0 ]]; then
  echo "[capture] no Falco JSON events were captured" >&2
  if [[ -s "$ERR" ]]; then
    echo "[capture] Falco stderr:" >&2
    tail -n 20 "$ERR" >&2 || true
  fi
  exit 2
fi

if [[ "${MODE}" == "output-only" ]]; then
  echo "{\"message\":\"capture complete\",\"file\":\"${OUT}\",\"count\":${LINES}}"
  exit 0
fi

UPLOAD_RESPONSE="$(curl -fsS -F "file=@${OUT}" "${API}/runtime/ebpf/upload")"
echo "$UPLOAD_RESPONSE"
UPLOADED_COUNT="$(printf '%s' "$UPLOAD_RESPONSE" | sed -n 's/.*"count":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "${UPLOADED_COUNT}" ]]; then
  echo "[capture] unable to parse upload response count" >&2
  exit 3
fi
if [[ "${UPLOADED_COUNT}" -le 0 ]]; then
  echo "[capture] upload succeeded but parser stored 0 runtime events" >&2
  exit 4
fi

SUMMARY_RESPONSE="$(curl -fsS "${API}/runtime/ebpf/summary")"
echo "$SUMMARY_RESPONSE"
SUMMARY_TOTAL="$(printf '%s' "$SUMMARY_RESPONSE" | sed -n 's/.*"total":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
if [[ -z "${SUMMARY_TOTAL}" ]]; then
  echo "[capture] unable to parse runtime summary total" >&2
  exit 5
fi
if [[ "${SUMMARY_TOTAL}" -le 0 ]]; then
  echo "[capture] runtime summary still reports 0 events after upload" >&2
  exit 6
fi
