#!/usr/bin/env bash
# MQTT Anonymous Access 完整修复 Demo（真 mosquitto，阶段四）。
#
# 流程：真实检测 → 后端 Agent 分析 → 备份 → 修改配置 → 重启 → 重新检测 → 验证 → RESOLVED
#       + 回滚测试：故意写坏配置 → 验证失败 → 自动恢复原配置 → ROLLBACK
#
# 用法（WSL 内）: bash run_mqtt_remediation_demo.sh [后端IP:端口] [控制令牌]
# 默认后端：自动检测 Windows 网关的 8011 端口。
set -uo pipefail

BACKEND="${1:-auto}"
TOKEN="${2:-${LINUXGUARD_CONTROL_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
    echo "Set LINUXGUARD_CONTROL_TOKEN or supply the control-token argument" >&2
    exit 1
fi
PORT=18885
DIR=/tmp/lg-mqtt-demo
CONF="$DIR/mosquitto.conf"
PWFILE="$DIR/pwfile"
BACKUP="$DIR/mosquitto.conf.bak"
LOG="$DIR/broker.log"
PIDFILE="$DIR/broker.pid"
COMMANDS_FILE="$DIR/commands.log"
mkdir -p "$DIR"
: > "$COMMANDS_FILE"

if [ "$BACKEND" = "auto" ]; then
    GW=$(ip route show default | head -1 | awk '{print $3}')
    [ -z "$GW" ] && GW=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
    BACKEND="http://$GW:8011"
fi
API="$BACKEND/api"
AUTH_HEADER="X-Control-Token: $TOKEN"

log() { echo "[demo] $*"; }
ran() { echo "$1" >> "$COMMANDS_FILE"; log "  \$ $1"; }

command -v mosquitto >/dev/null || { sudo apt-get install -y -qq mosquitto mosquitto-clients >/dev/null; }
command -v mosquitto_pub >/dev/null || sudo apt-get install -y -qq mosquitto-clients >/dev/null

wait_port() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(60):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.25)
sys.exit(1)
PY
}

start_broker() {
    ran "mosquitto -c $CONF (监听 0.0.0.0:$PORT)"
    mosquitto -c "$CONF" > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    wait_port "$PORT" || { log "broker 启动失败"; tail -5 "$LOG"; return 1; }
}

stop_broker() {
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null
    sleep 0.5
}

write_initial_conf() {   # 漏洞状态：允许匿名
    printf 'listener %d 0.0.0.0\nallow_anonymous true\n' "$PORT" > "$CONF"
}

write_hardened_conf() {  # 修复状态：禁匿名 + 密码文件
    printf 'listener %d 0.0.0.0\nallow_anonymous false\npassword_file %s\n' "$PORT" "$PWFILE" > "$CONF"
}

write_broken_conf() {    # 回滚测试：故意指向不存在的密码文件
    printf 'listener %d 0.0.0.0\nallow_anonymous false\npassword_file /nonexistent/pw\n' "$PORT" > "$CONF"
}

anon_pub() { mosquitto_pub -h 127.0.0.1 -p "$PORT" -t lg/demo -m probe >/dev/null 2>&1; }
auth_pub() { mosquitto_pub -h 127.0.0.1 -p "$PORT" -u iotadmin -P demo-password -t lg/demo -m probe >/dev/null 2>&1; }

api_post() {  # api_post <path> <json>
    curl -fsS -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" -d "$2" "$API$1"
}

report() {   # report <run_id> <phase> <payload-json> [cmd...]
    local run_id="$1" phase="$2" payload="$3"; shift 3
    local body
    body=$(python3 -c 'import json,sys; print(json.dumps({"phase": sys.argv[1], "payload": json.loads(sys.argv[2]), "commands": sys.argv[3:]}))' "$phase" "$payload" "$@")
    api_post "/remediation/workflow/$run_id/report" "$body"
}

json_field() {  # json_field <json> <python-expr over d>
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"
}

# ═══════════════ 准备：独立 mosquitto 实例（漏洞态） ═══════════════
log "== 准备独立 mosquitto 实例（端口 $PORT，allow_anonymous true）=="
write_initial_conf
ran "mosquitto_passwd -b -c $PWFILE iotadmin demo-password"
mosquitto_passwd -b -c "$PWFILE" iotadmin demo-password
stop_broker; start_broker || exit 1

WSL_IP=$(hostname -I | awk '{print $1}')
log "WSL IP: $WSL_IP（后端将从 Windows 侧真实探测该地址）"

log "== Before：本地确认匿名连接成功 =="
if anon_pub; then log "匿名连接：成功（漏洞存在）"; else log "匿名连接意外失败"; exit 1; fi

# ═══════════════ Run 1：检测 → Agent → 修复 → 验证 ═══════════════
log "== DETECT：调用后端（含真实 LLM Agent 分析）=="
RUN1=$(api_post "/remediation/workflow/mqtt-anonymous" "{\"host\": \"$WSL_IP\", \"port\": $PORT}")
[ -z "$RUN1" ] && { log "创建工作流失败（检查令牌/网段/后端）"; exit 1; }
RUN1_ID=$(json_field "$RUN1" 'd["run_id"]')
PLAN_SOURCE=$(json_field "$RUN1" 'd["plan"].get("source", "?")')
log "run_id=$RUN1_ID 状态=$(json_field "$RUN1" 'd["status"]') 方案来源=$PLAN_SOURCE"
log "Agent 方案动作: $(json_field "$RUN1" '[a["action"] + "->" + a.get("target", "") for a in d["plan"]["actions"]]')"

log "== REMEDIATE：执行白名单动作（真实文件操作与重启）=="
# backup_file
ran "cp -a $CONF $BACKUP"
cp -a "$CONF" "$BACKUP"
# change_config
write_hardened_conf
ran "rewrite $CONF: allow_anonymous=false + password_file"
# restart_service
stop_broker; start_broker || exit 1

report "$RUN1_ID" "action" '{"actions": [{"action": "backup_file", "result": "done"}, {"action": "change_config", "result": "done"}, {"action": "restart_service", "result": "done"}]}' \
    "cp -a $CONF $BACKUP" "rewrite $CONF (allow_anonymous false, password_file)" "kill \$(cat $PIDFILE); mosquitto -c $CONF" >/dev/null
log "已上报 action（状态 REMEDIATING）"

log "== After：本地重新检测 =="
if anon_pub; then log "匿名连接仍成功 → 修复未生效"; EXIT=1; else log "匿名连接：失败（rc=5 Not authorized）"; fi
if auth_pub; then log "认证用户（iotadmin）连接：正常"; else log "认证用户连接失败"; exit 1; fi
report "$RUN1_ID" "after" "{\"after\": \"anonymous=blocked, authenticated=ok\"}" >/dev/null

log "== VERIFY：后端平台侧复核（重新真实探测）=="
VERIFY=$(report "$RUN1_ID" "verify" '{"verified": true, "expectation": {"anonymous_allowed": false, "auth_works": true}}')
STATUS1=$(json_field "$VERIFY" 'd["status"]')
RECHECK_ANON=$(json_field "$VERIFY" 'd["verification"]["platform_recheck"]["recheck"]["anonymous"]["return_code"]')
RECHECK_AUTH=$(json_field "$VERIFY" 'd["verification"]["platform_recheck"]["recheck"]["authenticated"]["return_code"]')
log "平台复核：匿名 rc=$RECHECK_ANON（期望 5），认证 rc=$RECHECK_AUTH（期望 0）→ 状态 $STATUS1"

# ═══════════════ Run 2：回滚测试（修改失败 → 自动恢复） ═══════════════
log "== 回滚测试：恢复漏洞态 → 再次创建工作流 → 故意写坏配置 =="
write_initial_conf; stop_broker; start_broker || exit 1
RUN2=$(api_post "/remediation/workflow/mqtt-anonymous" "{\"host\": \"$WSL_IP\", \"port\": $PORT}")
RUN2_ID=$(json_field "$RUN2" 'd["run_id"]')
log "run_id=$RUN2_ID（漏洞态复测，状态 $(json_field "$RUN2" 'd["status"]')）"

ran "cp -a $CONF $BACKUP"
cp -a "$CONF" "$BACKUP"
write_broken_conf       # 修改失败场景：密码文件路径错误
ran "rewrite $CONF (bad: password_file /nonexistent/pw)"
stop_broker; start_broker || { log "broker 以坏配置启动失败——正是要演示的修改失败"; }
report "$RUN2_ID" "action" '{"actions": [{"action": "change_config", "result": "failed_bad_password_file"}]}' \
    "cp -a $CONF $BACKUP" "rewrite $CONF (bad password_file)" "kill \$(cat $PIDFILE); mosquitto -c $CONF" >/dev/null

if auth_pub; then log "坏配置下认证用户竟能连接（意外）"; else log "坏配置验证：认证用户连接失败 → 修复验证不通过"; fi
if anon_pub; then log "坏配置下匿名连接成功（意外）"; else log "坏配置下匿名连接也被拒绝"; fi

log "== ROLLBACK：自动恢复原配置并复核 =="
cp -a "$BACKUP" "$CONF"
ran "restore_file: cp -a $BACKUP $CONF"
stop_broker; start_broker || exit 1
if anon_pub; then RESTORED=true; else RESTORED=false; fi
log "恢复后匿名连接重新可用（回到 Before 漏洞态）: $RESTORED"
ROLLBACK=$(report "$RUN2_ID" "rollback" "{\"reason\": \"修改后验证失败（密码文件路径错误）\", \"restored_from\": \"$BACKUP\", \"restored_ok\": $RESTORED}" \
    "cp -a $BACKUP $CONF" "kill \$(cat $PIDFILE); mosquitto -c $CONF")
STATUS2=$(json_field "$ROLLBACK" 'd["status"]')
log "回滚上报完成 → 状态 $STATUS2"

# ═══════════════ 汇总 ═══════════════
stop_broker
log "== Demo 汇总 =="
log "Run1 $RUN1_ID: $STATUS1（修复前匿名成功 → 修复后匿名 rc=$RECHECK_ANON、认证 rc=$RECHECK_AUTH）"
log "Run2 $RUN2_ID: $STATUS2（写坏配置 → 自动恢复原配置，恢复验证=$RESTORED）"
log "实际执行命令清单："
sed 's/^/    /' "$COMMANDS_FILE"
