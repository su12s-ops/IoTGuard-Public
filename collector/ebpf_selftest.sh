#!/usr/bin/env bash
# LinuxGuard eBPF 采集自测：在采集窗口内真实制造四类行为并验证可被捕获。
#
#   1) 启动进程        —— 启动 mosquitto（真实 IoT MQTT broker）
#   2) 创建子进程      —— bash → sh → wget 父子链（服务进程→shell→下载器模式）
#   3) 建立网络连接    —— mosquitto_pub 连接本机 MQTT；curl 连接本机 HTTP
#   4) 读取/修改文件   —— 读 /etc/passwd；写 /etc/iotguard/、/opt/firmware/；root 读 /etc/shadow
#
# 所有命令均为固定常量（不含任何用户输入拼接）。
# 用法: sudo ./ebpf_selftest.sh
set -uo pipefail

WORK="/tmp/linuxguard-ebpf-selftest"
FAILURES=0

need() { command -v "$1" >/dev/null || { echo "[selftest] 安装 $2"; apt-get install -y -qq "$2"; }; }

echo "[selftest] 准备依赖与受控路径 ..."
need mosquitto mosquitto
need mosquitto_pub mosquitto-clients
need curl curl
need wget wget
mkdir -p "$WORK" /etc/iotguard /opt/firmware

echo "[selftest] 1) 启动真实进程：mosquitto（读取 /etc/mosquitto/mosquitto.conf）"
mosquitto -c /etc/mosquitto/mosquitto.conf -p 18884 > "$WORK/mosquitto.log" 2>&1 &
MOSQ_PID=$!
sleep 1

echo "[selftest] 3a) 真实 MQTT 连接：mosquitto_pub → 127.0.0.1:18884"
mosquitto_pub -h 127.0.0.1 -p 18884 -t linuxguard/selftest -m "ebpf-proof" || FAILURES=$((FAILURES+1))

# 本机 HTTP 目标（避免外网依赖）
python3 -m http.server 18080 --bind 127.0.0.1 > "$WORK/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

echo "[selftest] 2) 父子进程链：bash → sh → wget（真实 execve 链）"
bash -c "sh -c 'wget -q -O /dev/null http://127.0.0.1:18080/'" || FAILURES=$((FAILURES+1))
curl -s -o /dev/null http://127.0.0.1:18080/ || FAILURES=$((FAILURES+1))

echo "[selftest] 4) 文件读/写：/etc/passwd 读、/etc/iotguard 写、/opt/firmware 写、/etc/shadow root 读"
cat /etc/passwd > /dev/null || FAILURES=$((FAILURES+1))
echo "selftest $(date -Iseconds)" >> /etc/iotguard/selftest.conf || FAILURES=$((FAILURES+1))
echo "firmware-probe $(date -Iseconds)" >> /opt/firmware/.selftest || FAILURES=$((FAILURES+1))
head -c 16 /etc/shadow > /dev/null 2>&1 || FAILURES=$((FAILURES+1))

sleep 1
kill "$MOSQ_PID" "$HTTP_PID" 2>/dev/null || true

echo "[selftest] 行为制造完成（失败项: ${FAILURES}）。日志在 $WORK"
echo "[selftest] 预期捕获：execve(mosquitto/bash/sh/wget/curl/mosquitto_pub) + connect(18884/18080) + openat(/etc/mosquitto/..., /etc/passwd, /etc/shadow, /etc/iotguard/selftest.conf, /opt/firmware/.selftest)"
exit "$FAILURES"
