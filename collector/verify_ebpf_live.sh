#!/usr/bin/env bash
# 阶段二在线端到端验证：从 WSL 向 Windows 后端上传真实 eBPF 采集并核对 API。
# 用法（在 WSL 内）: bash verify_ebpf_live.sh <后端主机IP> <端口>
set -euo pipefail
HOST_IP="${1:-auto}"
PORT="${2:-8010}"
API="http://${HOST_IP}:${PORT}/api"
CAPTURE="${3:-/tmp/lg_real.jsonl}"

if [ "$HOST_IP" = "auto" ]; then
    HOST_IP=$(ip route show default | head -1 | awk '{print $3}')
    if [ -z "$HOST_IP" ]; then
        HOST_IP=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
    fi
    echo "[verify] 自动检测后端主机: $HOST_IP"
    API="http://${HOST_IP}:${PORT}/api"
fi

echo "== 1. 健康检查 =="
curl -fsS "$API/health"; echo

echo "== 2. 上传真实 eBPF 采集文件（42 条内核事件） =="
curl -fsS -F "file=@${CAPTURE}" "$API/runtime/ebpf/upload"; echo

echo "== 3. 证据汇总（三类计数） =="
curl -fsS "$API/runtime/evidence/summary" | python3 -c "import json,sys; d=json.load(sys.stdin); print('total:', d['total'], '| by_type:', d['by_type'], '| watched_file_events:', d['watched_file_events'])"

echo "== 4. 网络事件（进程 → IP:端口） =="
curl -fsS "$API/runtime/evidence/network" | python3 -c "import json,sys; [print(' ', e['process'], '->', e['destination_ip'] + ':' + str(e['destination_port']), '@', e['timestamp'][:19]) for e in json.load(sys.stdin)['events']]"

echo "== 5. 受控路径文件事件 =="
curl -fsS "$API/runtime/evidence/file?watched_only=true" | python3 -c "import json,sys; [print(' ', e['process'], e['operation'], e['file_path'], '[' + e['severity'] + ']') for e in json.load(sys.stdin)['events'][:8]]"

echo "== 6. 进程树（bash→sh→wget 真实父子链） =="
DEVICE=$(head -1 "$CAPTURE" | python3 -c "import json,sys; print(json.load(sys.stdin)['hostname'])")
curl -fsS "$API/runtime/evidence/process-tree?device_id=$DEVICE" | python3 -c "
import json,sys
d = json.load(sys.stdin)['devices']['$DEVICE']
def walk(n, depth=0):
    print('  ' * depth + n['process'] + '(' + str(n['pid']) + ')')
    for c in n['children']:
        walk(c, depth + 1)
def find_sh_wget(n):
    for c in n['children']:
        if c['process'] == 'sh' and any(g['process'] == 'wget' for g in c['children']):
            return n
    return None
target = None
for r in d['roots']:
    if r['process'] == 'bash' and find_sh_wget(r):
        target = r
        break
if target:
    walk(target)
else:
    for r in d['roots']:
        walk(r)
print('process_count:', d['process_count'])
"
echo "== 验证完成 =="
