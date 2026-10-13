#!/usr/bin/env bash
# 一次性真实采集运行器：启动 eBPF 采集（后台）→ 执行四类真实行为 → 复制结果为测试 fixture。
# 在 WSL 内执行：bash run_real_capture_once.sh
set -uo pipefail
COLLECTOR_DIR="$(cd "$(dirname "$0")" && pwd)"
# 工程根目录由脚本位置推导，不依赖任何本机绝对路径。
PROJECT_ROOT="$(cd "$COLLECTOR_DIR/.." && pwd)"
FIXTURE="$PROJECT_ROOT/backend/tests/fixtures/ebpf_real_capture.jsonl"
OUT="/tmp/lg_real_once.jsonl"

rm -f "$OUT" "$OUT.raw" "$OUT.err"
cd "$COLLECTOR_DIR"
sudo bash ebpf_trace_capture.sh "$OUT" 25 > /tmp/lg_cap_once.log 2>&1 &
CAPTURE_PID=$!
sleep 9
sudo bash ebpf_selftest.sh > /tmp/lg_self_once.log 2>&1
SELFTEST_RC=$?
wait "$CAPTURE_PID"
tail -1 /tmp/lg_cap_once.log
sudo cp "$OUT" "$FIXTURE"
echo "selftest_rc=$SELFTEST_RC fixture_lines=$(wc -l < "$FIXTURE")"
python3 - "$FIXTURE" <<'PYEOF'
import json, collections, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
print("total:", len(rows), "| types:", dict(collections.Counter(r["event_type"] for r in rows)), "| first ts:", rows[0]["timestamp"][:19])
PYEOF
