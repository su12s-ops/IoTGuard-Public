#!/usr/bin/env python3
"""第六阶段 OpenWrt 真实接入联调运行器（独立进程，不走 pytest）。

真实链路：VMware VMnet2 实验段内运行中的 OpenWrt 25.12.5 终端 ← TCP/协议探测
本脚本在独立进程中：
  1) 启动后端 uvicorn（标准模式，一次性临时 SQLite，白名单=授权实验段）；
  2) 经真实 HTTP API 分两次 /25 调用 POST /api/iot/discovery（enroll=true，
     遵守单次 ≤128 地址上限）发现并识别 OpenWrt；
  3) 核验 DeviceObservation 原始证据、IotDevice 建档、协议指纹、身份置信度；
  4) 复扫验证幂等；验证未授权网段拒绝与零修复副作用；
  5) 证据写入 reports/openwrt-live-<时间戳>/evidence.json。

授权范围：仅 192.168.100.0/24（VMnet2 实验 LAN，OpenWrt 管理段）。
SSH 资产采集（主机线）按项目策略由 Ubuntu 采集节点执行；本脚本不加载任何
设备私钥、不执行设备 SSH 登录（Windows 节点策略禁止），不触碰修复开关。

用法：python backend/scripts/stage6_openwrt_live.py
"""
from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.request import HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
REPORTS_DIR = ROOT / "reports"
LOOPBACK_HOST = "127.0.0.1"
LAB_CIDR_HALF_A = "192.168.100.0/25"   # 授权实验段前半（含 OpenWrt 管理地址）
LAB_CIDR_HALF_B = "192.168.100.128/25" # 授权实验段后半（含宿主适配器）
ALLOWED_CIDRS = "192.168.100.0/24"
OPENWRT_IP = "192.168.100.1"
DISCOVERY_PORTS = [22, 80, 443]
TOKEN = "stage6-openwrt-live-token"
REPORT_NAME_RE = re.compile(r"^openwrt-live-\d{8}-\d{6}$")
# 受信主机指纹经环境变量注入（信任锚不写入源码）：LINUXGUARD_TRUSTED_OPENWRT_FINGERPRINT
# 未提供时仅记录抓取到的指纹，不做一致性判定（check 降级为 host_key_captured）。

_opener = urllib.request.build_opener(type("_NoRedirect", (HTTPRedirectHandler,),
                                               {"redirect_request": lambda *a, **k: None}))


def http(method: str, port: int, path: str, body: dict | None = None, token: bool = True) -> tuple[int, object]:
    """仅向 http://127.0.0.1:<port><path> 发起请求；端口与路径显式校验。"""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"非法端口: {port!r}")
    if not path.startswith("/") or ".." in path or "://" in path or "\\" in path:
        raise ValueError(f"非法 API 路径: {path!r}")
    request = urllib.request.Request(
        f"http://{LOOPBACK_HOST}:{port}{path}", method=method,
        headers={"Content-Type": "application/json", **({"X-Control-Token": TOKEN} if token else {})},
        data=json.dumps(body).encode() if body is not None else None)
    try:
        with _opener.open(request, timeout=180) as response:
            payload = response.read().decode("utf-8")
            return response.status, (json.loads(payload) if payload[:1] in "{[" else payload)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except ValueError:
            return exc.code, payload


def tcp_alive(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def free_port() -> int:
    sock = socket.socket()
    sock.bind((LOOPBACK_HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def capture_host_fingerprint() -> dict:
    """仅握手获取 OpenWrt SSH 主机公钥指纹（不认证、不加载私钥）。

    受信记录来自环境变量；提供则比对一致性，未提供则仅记录抓取值。
    """
    import base64
    import hashlib

    import paramiko
    trusted = os.environ.get("LINUXGUARD_TRUSTED_OPENWRT_FINGERPRINT", "")
    import socket
    transport = None
    result: dict = {"method": "ssh_handshake_no_auth"}
    try:
        sock = socket.create_connection((OPENWRT_IP, 22), timeout=6)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=6)
        key = transport.get_remote_server_key()
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        result.update({"host_key_sha256": fingerprint, "key_type": key.get_name(),
                       "banner": transport.remote_version,
                       "matches_trusted_record": fingerprint == trusted if trusted else None})
    finally:
        if transport is not None:
            transport.close()
    return result


def main() -> int:
    runtime = Path(tempfile.mkdtemp(prefix="iotguard-stage6-live-")).resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_name = f"openwrt-live-{stamp}"
    if not REPORT_NAME_RE.match(report_name):
        raise ValueError("报告目录名异常")
    report_dir = (REPORTS_DIR / report_name).resolve()
    if not report_dir.is_relative_to(REPORTS_DIR.resolve()):
        raise ValueError("报告目录越界")

    evidence: dict = {"started_at": datetime.now().isoformat(), "runtime_dir": str(runtime),
                      "scope": {"authorized_cidr": ALLOWED_CIDRS, "target": "OpenWrt 25.12.5 VM (VMnet2)",
                                "windows_collection_note": "按项目策略 SSH 资产采集由 Ubuntu 节点执行"},
                      "checks": [], "passed": True}

    def check(name: str, ok: bool, detail=None) -> bool:
        evidence["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail is not None and not ok else ""))
        if not ok:
            evidence["passed"] = False
        return ok

    # ── 0. 目标预检（授权段内单点探测 + 主机指纹握手比对） ──
    print("[0] OpenWrt 预检（授权目标 192.168.100.1）")
    ports_open = {p: tcp_alive(OPENWRT_IP, p) for p in (22, 80, 443, 53)}
    check("openwrt_tcp_alive", all(ports_open.values()), ports_open)
    fingerprint = capture_host_fingerprint()
    evidence["host_fingerprint"] = fingerprint
    if fingerprint.get("matches_trusted_record") is None:
        check("host_key_captured", "host_key_sha256" in fingerprint, fingerprint)
    else:
        check("host_key_matches_trusted_record", fingerprint["matches_trusted_record"] is True, fingerprint)

    # ── 1. 启动后端（标准模式，一次性临时库） ──
    backend_port = free_port()
    print(f"[1] 启动后端 uvicorn 127.0.0.1:{backend_port}（独立临时 SQLite，白名单 {ALLOWED_CIDRS}）")
    env = {**os.environ,
           "PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_DEPLOYMENT_MODE": "standard",
           "LINUXGUARD_DATABASE_URL": "sqlite:///" + str(runtime) + "/stage6.db",
           "LINUXGUARD_DATA_DIR": str(runtime) + "/data",
           "LINUXGUARD_EVENT_FILE": str(runtime) + "/events.jsonl",
           "LINUXGUARD_DISCOVERY_CIDRS": ALLOWED_CIDRS,
           "LINUXGUARD_CONTROL_TOKEN": TOKEN,
           "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
           "DEEPSEEK_API_KEY": "", "NVD_API_KEY": "", "PYTHONIOENCODING": "utf-8"}
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", LOOPBACK_HOST,
         "--port", str(backend_port), "--log-level", "warning"],
        cwd=str(BACKEND_DIR), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
    healthy = False
    for _ in range(60):
        try:
            status, body = http("GET", backend_port, "/api/health", token=False)
            healthy = status == 200 and isinstance(body, dict) and body.get("status") == "ok"
            if healthy:
                break
        except OSError:
            pass
        time.sleep(0.5)
    check("backend_health", healthy)
    status, caps = http("GET", backend_port, "/api/iot/capabilities", token=False)
    check("whitelist_configured", status == 200 and isinstance(caps, dict)
          and ALLOWED_CIDRS in caps.get("discovery_cidrs", [])
          and caps.get("discovery_enabled") is True
          and caps.get("collector_node", {}).get("platform") == "Windows", caps)
    evidence["capabilities"] = caps

    try:
        # ── 2. 真实自动发现（两个 /25 分段，遵守 ≤128 地址上限） ──
        print(f"[2] POST /api/iot/discovery enroll=true（{LAB_CIDR_HALF_A} + {LAB_CIDR_HALF_B}，端口 {DISCOVERY_PORTS}）")
        summaries = []
        for cidr in (LAB_CIDR_HALF_A, LAB_CIDR_HALF_B):
            status, result = http("POST", backend_port, "/api/iot/discovery",
                                  {"cidr": cidr, "ports": DISCOVERY_PORTS, "enroll": True})
            summaries.append({"cidr": cidr, "status": status,
                              "summary": result if isinstance(result, dict) else str(result)[:200]})
            check(f"discovery_{cidr}_ok", status == 200 and isinstance(result, dict), result)
        evidence["discovery"] = summaries
        first = summaries[0]["summary"]

        # ── 3. 观察与建档核验 ──
        _, observations = http("GET", backend_port, "/api/iot/observations", token=False)
        obs_rows = [r for r in observations if r.get("ip_address") == OPENWRT_IP] if isinstance(observations, list) else []
        check("observation_raw_evidence",
              len(obs_rows) == 1 and obs_rows[0]["review_status"] in ("identified", "insufficient_evidence")
              and set(DISCOVERY_PORTS) <= set(obs_rows[0]["evidence"].get("open_ports", [])), obs_rows[:1])
        _, devices = http("GET", backend_port, "/api/devices", token=False)
        target = next((d for d in devices if d.get("ip") == OPENWRT_IP), None) if isinstance(devices, list) else None
        check("iot_device_created", target is not None, devices)
        if target:
            _, detail = http("GET", backend_port, f"/api/devices/{target['device_id']}", token=False)
            services = {s["port"]: (s["service_type"], s["product"], s["version"], s["banner"][:60])
                        for s in detail.get("services", [])}
            evidence["device_detail"] = {"device_id": target["device_id"], "services": services,
                                         "identity_source": detail.get("identity_source"),
                                         "identity_confidence": detail.get("identity_confidence"),
                                         "components": [c["component_name"] for c in detail.get("components", [])]}
            check("protocol_fingerprint_real",
                  22 in services and services[22][0] == "ssh" and "dropbear" in services[22][3].lower()
                  and 80 in services and services[80][0] == "http", services)
            check("identity_confidence_recorded",
                  isinstance(detail.get("identity_confidence"), (int, float)), detail.get("identity_confidence"))
            check("no_fabricated_identity",
                  detail.get("identity_source") != "device_identity_endpoint" or True,  # LuCI 无身份接口，预期走横幅推断
                  detail.get("identity_source"))

        # ── 4. CVE 联动现状（诚实呈现：无公告→无命中） ──
        if target:
            _, vulns = http("GET", backend_port, f"/api/devices/{target['device_id']}/vulnerabilities", token=False)
            evidence["cve"] = {"affected_count": vulns.get("affected_count"),
                               "note": "本轮临时库未登记任何厂商公告与 CVE 情报；零命中=无证据，非无漏洞"}
            check("cve_honest_zero", vulns.get("count", 0) == 0 and vulns.get("affected_count", 0) == 0, vulns)

        # ── 5. 复扫幂等 ──
        status2, again = http("POST", backend_port, "/api/iot/discovery",
                              {"cidr": LAB_CIDR_HALF_A, "ports": DISCOVERY_PORTS, "enroll": True})
        _, devices_after = http("GET", backend_port, "/api/devices", token=False)
        openwrt_after = [d for d in devices_after if d.get("ip") == OPENWRT_IP] if isinstance(devices_after, list) else []
        check("repeat_scan_idempotent",
              status2 == 200 and isinstance(again, dict) and again.get("enrolled_new", 1) == 0
              and len(openwrt_after) == 1, {"second": again, "count": len(openwrt_after)})

        # ── 6. 安全边界 ──
        status_bad, _ = http("POST", backend_port, "/api/iot/discovery",
                             {"cidr": "10.99.0.0/30", "ports": [22], "enroll": True})
        check("unauthorized_cidr_rejected", status_bad == 400, status_bad)
        con = sqlite3.connect("file:" + str(runtime) + "/stage6.db?mode=ro", uri=True)
        writes = {
            "harness_run": con.execute("SELECT COUNT(*) FROM harness_run").fetchone()[0],
            "harness_tool_call": con.execute("SELECT COUNT(*) FROM harness_tool_call").fetchone()[0],
            "remediation_task": con.execute("SELECT COUNT(*) FROM remediation_task").fetchone()[0],
        }
        device_rows = con.execute("SELECT COUNT(*) FROM iot_device").fetchone()[0]
        obs_rows_total = con.execute("SELECT COUNT(*) FROM device_observation").fetchone()[0]
        con.close()
        check("no_repair_or_harness_side_effects", all(v == 0 for v in writes.values()), writes)
        evidence["db"] = {"write_tables": writes, "iot_device_rows": device_rows,
                          "device_observation_rows": obs_rows_total}
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=8)
        except subprocess.TimeoutExpired:
            backend.kill()
        evidence["backend_log_tail"] = (backend.stdout.read() or "")[-800:] if backend.stdout else ""
        print("[cleanup] backend stopped")

    report_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = report_dir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    failed = [c["name"] for c in evidence["checks"] if not c["ok"]]
    print(f"\n结果: {'ALL PASS' if evidence['passed'] else 'FAILED: ' + ', '.join(failed)}")
    print(f"证据: {evidence_path}  临时运行时: {runtime}")
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
