"""SmartCam-X1 真实发现闭环联调入口（独立集成测试，不走 pytest）。

与单元/Mock 测试的区别：本脚本在独立进程中启动真实的
  1) SmartCam-X1 模拟器进程（真实 TCP 监听 SSH/MQTT/HTTP/RTSP）
  2) 后端 uvicorn 进程（真实 HTTP API，独立临时 SQLite，不触碰 linuxguard.db）
然后通过真实 HTTP 调用 POST /api/iot/discovery {enroll:true} 验证完整闭环。

安全边界（本脚本自身的硬约束）：
- 出站 HTTP 仅允许 http 协议 + 回环字面量主机 127.0.0.1 + 显式端口，禁止重定向；
- SQL 语句全部为内联字面量，任何数据值通过 execute(sql, params) 参数绑定；
- 扫描 CIDR=127.0.0.0/25、白名单 127.0.0.0/8，绝不触碰非回环网络；
- CVE 命中验证使用显式标注的测试夹具（TEST-FIXTURE），仅写入一次性临时库。

用法: python backend/scripts/live_discovery_check.py
退出码 0 = 全部验收点通过；证据写入 reports/discovery-live-<时间戳>/evidence.json
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
SIMULATOR_DIR = ROOT / "simulator"
REPORTS_DIR = ROOT / "reports"
LOOPBACK_HOST = "127.0.0.1"      # 字面量主机：不做 DNS 解析，天然免疫 rebinding
CIDR = "127.0.0.0/25"            # 128 地址上限内，仅覆盖 127.0.0.1-126
ALLOWED_CIDRS = "127.0.0.0/8"
TOKEN = "live-discovery-check-token"
FIXTURE_CVE = "CVE-2026-90007"   # 显式测试夹具，仅存在于一次性临时库
REPORT_NAME_RE = re.compile(r"^discovery-live-\d{8}-\d{6}$")

# 禁止跟随重定向：回环测试端点不应发生 3xx，任何重定向都视为异常。
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
        with _opener.open(request, timeout=120) as response:
            payload = response.read().decode("utf-8")
            return response.status, (json.loads(payload) if payload[:1] in "{[" else payload)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except ValueError:
            return exc.code, payload


def tcp_alive(port: int) -> bool:
    try:
        with socket.create_connection((LOOPBACK_HOST, port), timeout=2.0):
            return True
    except OSError:
        return False


def free_ports(count: int) -> list[int]:
    holders, ports = [], []
    for _ in range(count):
        sock = socket.socket()
        sock.bind((LOOPBACK_HOST, 0))
        ports.append(sock.getsockname()[1])
        holders.append(sock)
    for sock in holders:
        sock.close()
    return ports


def _rows(cursor) -> list[dict]:
    return [dict(zip([c[0] for c in cursor.description], row)) for row in cursor]


def main() -> int:
    runtime = Path(tempfile.mkdtemp(prefix="iotguard-live-discovery-")).resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_name = f"discovery-live-{stamp}"
    if not REPORT_NAME_RE.match(report_name):
        raise ValueError("报告目录名异常")
    report_dir = (REPORTS_DIR / report_name).resolve()
    if not report_dir.is_relative_to(REPORTS_DIR.resolve()):
        raise ValueError("报告目录越界")

    evidence: dict = {"started_at": datetime.now().isoformat(), "runtime_dir": str(runtime),
                      "scope": {"cidr": CIDR, "allowed_cidrs": ALLOWED_CIDRS, "hosts": "loopback only"},
                      "checks": [], "passed": True}

    def check(name: str, ok: bool, detail=None) -> bool:
        evidence["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail is not None and not ok else ""))
        if not ok:
            evidence["passed"] = False
        return ok

    backend_port, http_p, ssh_p, mqtt_p, rtsp_p = free_ports(5)
    ports = sorted([http_p, ssh_p, mqtt_p, rtsp_p])

    # ── 1. 启动 SmartCam-X1 模拟器进程（真实服务） ──
    print(f"[1] 启动 SmartCam-X1 进程 ports={ports} (runtime: {runtime})")
    simulator = subprocess.Popen(
        [sys.executable, str(SIMULATOR_DIR / "smartcam_x1.py"), "--host", LOOPBACK_HOST,
         "--http-port", str(http_p), "--ssh-port", str(ssh_p),
         "--mqtt-port", str(mqtt_p), "--rtsp-port", str(rtsp_p)],
        cwd=str(SIMULATOR_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
    time.sleep(1.5)
    listeners = {port: tcp_alive(port) for port in ports}
    check("simulator_process_running", simulator.poll() is None)
    check("real_tcp_listeners", all(listeners.values()), listeners)
    evidence["simulator"] = {"pid": simulator.pid, "ports": ports, "listeners": listeners}

    # ── 2. 启动后端（独立临时库，不触碰 linuxguard.db） ──
    print(f"[2] 启动后端 uvicorn 127.0.0.1:{backend_port}（独立临时 SQLite）")
    env = {**os.environ,
           "PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_DEPLOYMENT_MODE": "standard",
           "LINUXGUARD_DATABASE_URL": "sqlite:///" + str(runtime) + "/live.db",
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
    check("target_in_whitelist", status == 200 and isinstance(caps, dict)
          and ALLOWED_CIDRS in caps.get("discovery_cidrs", []) and caps.get("discovery_enabled") is True, caps)
    evidence["capabilities"] = caps

    # ── 3. 写入显式标注的 CVE 测试夹具（参数绑定，一次性临时库） ──
    con = sqlite3.connect(str(runtime) + "/live.db")
    con.execute("INSERT INTO vulnerability_info (cve_id, title, affected_package, fixed_version, "
                "cvss_score, cvss_severity, source, description) VALUES (?,?,?,?,?,?,?,?)",
                (FIXTURE_CVE, "[TEST-FIXTURE] " + FIXTURE_CVE + " SmartCam MQTT broker",
                 "SmartCam MQTT broker", "1.7.0", 9.8, "Critical", "live_check_fixture",
                 "联调夹具：仅存在于一次性临时库，验证 NVD 通用匹配链路"))
    con.commit()
    con.close()

    try:
        # ── 4. 真实发现闭环：POST /api/iot/discovery enroll=true ──
        print(f"[3] POST /api/iot/discovery cidr={CIDR} ports={ports} enroll=true")
        status, result = http("POST", backend_port, "/api/iot/discovery",
                              {"cidr": CIDR, "ports": ports, "enroll": True})
        check("discovery_api_200", status == 200, result)
        evidence["discovery_response"] = result
        if status == 200 and isinstance(result, dict):
            check("real_tcp_found_device", result.get("responding_devices") == 1, result.get("scan"))
            check("observation_identified", result.get("identified") == 1)
            check("device_enrolled_new", result.get("enrolled_new") == 1)
            check("cve_matched_with_version_evidence", result.get("cve_matched") == 1)

        # ── 5. 台账与证据核验（API + 只读 SQL） ──
        _, observations = http("GET", backend_port, "/api/iot/observations", token=False)
        tcp_rows = [r for r in observations if r.get("source") == "tcp_connect"] if isinstance(observations, list) else []
        check("observation_evidence_saved",
              len(tcp_rows) == 1 and tcp_rows[0]["evidence"].get("open_ports") == ports
              and tcp_rows[0]["review_status"] == "identified", tcp_rows[:1])
        _, devices = http("GET", backend_port, "/api/devices", token=False)
        check("iot_device_created", isinstance(devices, list) and len(devices) == 1, devices)
        device_id = devices[0]["device_id"] if devices else ""
        _, detail = http("GET", backend_port, f"/api/devices/{device_id}", token=False)
        check("identity_with_confidence",
              isinstance(detail, dict) and detail.get("identity_source") == "device_identity_endpoint"
              and detail.get("identity_confidence") == 0.9
              and detail.get("vendor") == "SmartCam Technologies"
              and detail.get("firmware_version") == "2.4.7", detail)
        services = {s["port"]: (s["service_type"], s["product"], s["version"])
                    for s in detail.get("services", [])} if isinstance(detail, dict) else {}
        check("services_real_fingerprints",
              {v[0] for v in services.values()} == {"ssh", "http", "mqtt", "rtsp"}
              and services.get(mqtt_p, ("", "", ""))[1] == "SmartCam MQTT broker 1.6.2", services)
        _, vulns = http("GET", backend_port, f"/api/devices/{device_id}/vulnerabilities", token=False)
        fixture_hits = [m for m in vulns.get("matches", []) if m.get("cve_id") == FIXTURE_CVE] \
            if isinstance(vulns, dict) else []
        check("cve_candidate_not_confirmed",
              len(fixture_hits) == 1 and fixture_hits[0]["match_status"] == "potentially_affected"
              and fixture_hits[0]["applicability_source"] == "nvd_generic", fixture_hits)

        # ── 6. 重复扫描不产生重复资产 ──
        status2, again = http("POST", backend_port, "/api/iot/discovery",
                              {"cidr": CIDR, "ports": ports, "enroll": True})
        _, devices_after = http("GET", backend_port, "/api/devices", token=False)
        check("repeat_scan_no_duplicates",
              status2 == 200 and isinstance(again, dict) and again.get("enrolled_new") == 0
              and again.get("enrolled_existing") == 1 and len(devices_after) == 1,
              {"second": again, "device_count": len(devices_after)})
        evidence["repeat_scan"] = {"summary": again, "device_count_after": len(devices_after)}

        # ── 7. 安全边界：未授权网段 + 零修复/Harness 痕迹 ──
        status_bad, _ = http("POST", backend_port, "/api/iot/discovery",
                             {"cidr": "10.99.0.0/30", "ports": [22], "enroll": True})
        check("unauthorized_cidr_rejected", status_bad == 400, status_bad)
        con = sqlite3.connect("file:" + str(runtime) + "/live.db?mode=ro", uri=True)
        writes = {
            "harness_run": con.execute("SELECT COUNT(*) FROM harness_run").fetchone()[0],
            "harness_tool_call": con.execute("SELECT COUNT(*) FROM harness_tool_call").fetchone()[0],
            "remediation_task": con.execute("SELECT COUNT(*) FROM remediation_task").fetchone()[0],
            "remediation_workflow_run": con.execute("SELECT COUNT(*) FROM remediation_workflow_run").fetchone()[0],
        }
        rows = {
            "device_observation": _rows(con.execute("SELECT * FROM device_observation LIMIT 3")),
            "iot_device": _rows(con.execute("SELECT * FROM iot_device LIMIT 3")),
            "iot_device_service": _rows(con.execute("SELECT * FROM iot_device_service LIMIT 3")),
        }
        con.close()
        check("no_repair_or_harness_side_effects", all(v == 0 for v in writes.values()), writes)
        evidence["db"] = {"write_tables": writes, "inventory_rows": rows}
    finally:
        for proc in (backend, simulator):
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        evidence["process_logs"] = {
            "simulator_tail": (simulator.stdout.read() or "")[-600:] if simulator.stdout else "",
            "backend_tail": (backend.stdout.read() or "")[-600:] if backend.stdout else "",
        }
        print("[cleanup] backend & simulator stopped")

    report_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = report_dir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    failed = [c["name"] for c in evidence["checks"] if not c["ok"]]
    print(f"\n结果: {'ALL PASS' if evidence['passed'] else 'FAILED: ' + ', '.join(failed)}")
    print(f"证据: {evidence_path}  临时运行时: {runtime}")
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
