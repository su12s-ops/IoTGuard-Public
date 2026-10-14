#!/usr/bin/env bash
# P2-4 (D8) 真实内核验证（严格版：任一断言失败即整体 FAIL）。
# retval 过滤覆盖"立即失败"类（路由不可达 ENETUNREACH，blackhole 临时路由构造）；
# 回环拒绝（127.0.0.1:1）属异步 RST：tcp_v4_connect 返回 0——如实记录为边界。
set -uo pipefail
cd "$(dirname "$0")/.." || cd /mnt/e/IoTGuard-Public
FAILURES=0
ARCHIVE="reports/ebpf-p24-$(date +%Y%m%d)"
mkdir -p "$ARCHIVE"

bash -n collector/ebpf_trace_capture.sh && echo "bash -n OK" || FAILURES=$((FAILURES+1))
echo "retval guards: $(grep -c 'if (retval == 0)' collector/ebpf_trace_capture.sh) (预期 4)"

# 临时 blackhole 路由（WSL 会话级，重启自动消失；仅测试用）
ip route add blackhole 240.0.0.1/32 2>/dev/null || ip route replace blackhole 240.0.0.1/32
trap 'ip route del blackhole 240.0.0.1/32 2>/dev/null' EXIT

run_case() {
  local MODE="$1" OUT="$2"
  rm -f "$OUT" "$OUT.raw"
  python3 -m http.server 8123 --bind 127.0.0.1 >/tmp/p24-http.log 2>&1 &
  local HTTP_PID=$!
  sleep 1
  bash collector/ebpf_trace_capture.sh "$OUT" 12 "" "$MODE" >/tmp/p24-capture-$MODE.log 2>&1 &
  local CAP_PID=$!
  sleep 5
  curl -s --max-time 1 http://240.0.0.1:80/ >/dev/null 2>&1; echo "[$MODE] no-route curl rc=$?"
  curl -s --max-time 1 http://127.0.0.1:1/ >/dev/null 2>&1; echo "[$MODE] loopback-refused curl rc=$?"
  curl -s --max-time 2 http://127.0.0.1:8123/ >/dev/null 2>&1; echo "[$MODE] ok-connect curl rc=$?"
  wait $CAP_PID
  kill $HTTP_PID 2>/dev/null; wait $HTTP_PID 2>/dev/null
  python3 - "$MODE" "$OUT.raw" <<'PY' || FAILURES=$((FAILURES+1))
import sys
mode, raw = sys.argv[1], sys.argv[2]
no_route = loop_refused = ok = 0
for line in open(raw, encoding="utf-8", errors="ignore"):
    f = line.rstrip("\n").split("|")
    if len(f) > 7 and f[0] == "LG" and f[1] == "connect":
        if f[7] == "80" and f[6] == "240.0.0.1":
            no_route += 1
        elif f[7] == "1":
            loop_refused += 1
        elif f[7] == "8123":
            ok += 1
print(f"[{mode}] connect 事件: 成功(8123)={ok} 无路由(240.0.0.1)={no_route} 回环拒绝(port1)={loop_refused}")
assert ok >= 1, f"[{mode}] 成功连接应保留事件"
assert no_route == 0, f"[{mode}] 无路由连接（retval!=0）不应产生事件"
print(f"[{mode}] PASS（回环拒绝={loop_refused} 条为已知异步 RST 边界，记录不断言）")
PY
}

run_case auto /tmp/p24-enh.jsonl
run_case legacy /tmp/p24-leg.jsonl

# 证据归档（WSL /tmp 随 VM 空闲关机清空——必须当场落盘到 /mnt/e）
cp -f /tmp/p24-enh.jsonl* /tmp/p24-leg.jsonl* /tmp/p24-capture-auto.log /tmp/p24-capture-legacy.log \
  "$ARCHIVE"/ 2>/dev/null
echo "evidence archived to $ARCHIVE/"

if [ "$FAILURES" -eq 0 ]; then
  echo "ALL P2-4 KERNEL VERIFICATION PASSED"
else
  echo "P2-4 KERNEL VERIFICATION FAILED ($FAILURES case(s))"
  exit 1
fi
