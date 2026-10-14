#!/usr/bin/env python3
"""第七阶段 Zephyr RTOS 真实接入联调运行器（独立进程，不走 pytest）。

真实链路：Windows 后端 → VMnet2 → Ubuntu 24.04 VM（VMnet2 地址:8080，经环境变量
LINUXGUARD_STAGE7_ZEPHYR_IP 注入；SLIRP hostfwd）→ qemu-system-arm xilinx-zynq-a9 → Zephyr v4.4.2 固件 :80。
本脚本在独立进程中：
  1) 预检：经真实 HTTP 直接访问固件 /api/system（授权段内），校验身份 JSON；
  2) 启动后端 uvicorn（标准模式，一次性临时 SQLite，白名单=授权实验段）；
  3) POST /api/iot/discovery (enroll=true) 单个 /25 真实扫描（≤128 地址上限）
     → Zephyr 设备经 device_identity_endpoint 建档（置信 0.9）；
  4) 核验固件扩展元数据（board/arch/build_id/telemetry simulated）、版本化组件、
     Zephyr 能力边界标注（ssh/package/eBPF = unsupported）、os_capability_profiles；
  5) CVE 分级：清洁库零命中（诚实无证据）→ 显式 TEST-FIXTURE 公告/情报三层
     （厂商精确 affected / NVD 候选 potentially_affected / 无关不出现）；
  6) 复扫幂等（enrolled_new=0、设备不重复、组件不重复）；
  7) 未授权网段 400、零修复/Harness 副作用；
  8) 证据写入 reports/zephyr-live-<时间戳>/evidence.json。

安全边界（本脚本自身的硬约束）：
- 真实探测仅指向授权实验段内的 192.168.100.0/24（VMnet2 实验 LAN）；
- 后端 HTTP 仅绑定 127.0.0.1；CVE 夹具 ID 全部带 TEST-FIXTURE 标记且仅写入
  一次性临时库（与 live_discovery_check.py 同口径），不触碰 linuxguard.db；
- 不加载设备私钥、不执行设备 SSH 登录、不触碰修复开关。

用法：LINUXGUARD_STAGE7_ZEPHYR_IP=<ubuntu-vmnet2-addr> python backend/scripts/stage7_zephyr_live.py
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
LAB_CIDR = "192.168.100.0/25"        # 授权实验段前半（含 Zephyr 经 Ubuntu hostfwd 的可达地址）
ALLOWED_CIDRS = "192.168.100.0/24"
# 固件可达入口（Ubuntu 宿主 VMnet2 地址，8080 经 SLIRP hostfwd → 固件 :80）。
# 具体地址属实验环境标识，经环境变量注入而不写入源码（公开仓整改底线）：
#   set LINUXGUARD_STAGE7_ZEPHYR_IP=<ubuntu-vmnet2-addr>（缺省时脚本退出并提示）
ZEPHYR_IP = os.environ.get("LINUXGUARD_STAGE7_ZEPHYR_IP", "")
ZEPHYR_PORT = 8080
DISCOVERY_PORTS = [22, 80, 443, 8080]
TOKEN = "stage7-zephyr-live-token"
FW_VERSION = "0.1.0-stage7"
OS_VERSION = "Zephyr RTOS 4.4.2"
REPORT_NAME_RE = re.compile(r"^zephyr-live-\d{8}-\d{6}$")

# CVE 夹具（仅存在于一次性临时库；与 mock 测试同口径，ID 段 2026-900xx）
FIXTURE_VENDOR_CVE = "CVE-2026-90011"   # 层1：厂商公告精确版本 → affected / 0.95
FIXTURE_NVD_CVE = "CVE-2026-90012"      # 层2：NVD 通用情报 → potentially_affected
FIXTURE_UNRELATED_CVE = "CVE-2026-90013"  # 层3：无关组件 → 不得出现

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


def probe_real(url: str) -> tuple[int, str]:
    """真实探测固件端点（仅 http + 授权段字面量主机）。"""
    host = url.split("/")[2]
    if not (host.startswith("192.168.100.") or host == LOOPBACK_HOST):
        raise ValueError(f"越界主机: {host}")
    with _opener.open(urllib.request.Request(url, method="GET"), timeout=8) as response:
        return response.status, response.read().decode("utf-8", errors="replace")


def free_port() -> int:
    sock = socket.socket()
    sock.bind((LOOPBACK_HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def seed_fixtures(db_path: str) -> None:
    """向一次性临时库写入显式 TEST-FIXTURE 公告与情报（与 register_advisory 同构）。"""
    con = sqlite3.connect(db_path)
    con.execute(
        "INSERT INTO iot_device_advisory (cve_id, vendor, model, component_name,"
        " affected_versions_json, fixed_versions_json, source_url, notes)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (FIXTURE_VENDOR_CVE, "IoTGuard-Lab", "Zephyr-Sensor-01", "Zephyr-Sensor-01 firmware",
         json.dumps([FW_VERSION]), json.dumps(["0.2.0"]),
         "https://iotguard.example/TEST-FIXTURE-stage7",
         "STAGE7 TEST-FIXTURE：联调夹具，非真实厂商公告，仅存在于一次性临时库"))
    con.execute(
        "INSERT INTO vulnerability_info (cve_id, title, affected_package, fixed_version,"
        " cvss_score, cvss_severity, source, \"references\", description)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (FIXTURE_VENDOR_CVE, f"{FIXTURE_VENDOR_CVE} / Zephyr-Sensor-01 firmware",
         "Zephyr-Sensor-01 firmware", "0.2.0", 7.5, "High",
         "stage7_test_fixture", "https://iotguard.example/TEST-FIXTURE-stage7",
         "STAGE7 TEST-FIXTURE（厂商公告层）"))
    con.execute(
        "INSERT INTO vulnerability_info (cve_id, title, affected_package, fixed_version,"
        " cvss_score, cvss_severity, source, description)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (FIXTURE_NVD_CVE, "STAGE7 fixture generic httpd issue",
         f"zephyr-sensor-httpd {FW_VERSION}", "1.0.0", 5.3, "Medium",
         "stage7_test_fixture", "STAGE7 TEST-FIXTURE（NVD 通用情报层）"))
    con.execute(
        "INSERT INTO vulnerability_info (cve_id, title, affected_package, fixed_version,"
        " cvss_score, cvss_severity, source, description)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (FIXTURE_UNRELATED_CVE, "STAGE7 fixture unrelated",
         "some-other-component", "2.0.0", 9.8, "Critical",
         "stage7_test_fixture", "STAGE7 TEST-FIXTURE（无关组件层，不得命中）"))
    con.commit()
    con.close()


def run_matching_inprocess(db_url: str, device_id: str) -> None:
    """在临时库上直接调用匹配服务（与设备线消费同代码路径）。"""
    env = {**os.environ, "PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_DATABASE_URL": db_url,
           "PYTHONIOENCODING": "utf-8"}
    code = (
        "from app.database import SessionLocal\n"
        "from app import models\n"
        "from app.services.device_vulnerability import run_device_matching\n"
        f"db = SessionLocal()\n"
        f"device = db.query(models.IotDevice).filter_by(device_id={device_id!r}).one()\n"
        "run_device_matching(db, device)\n"
        "db.commit(); db.close()\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=str(BACKEND_DIR), env=env,
                          capture_output=True, encoding="utf-8", timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"in-process matching failed: {proc.stderr[-400:]}")


def main() -> int:
    if not ZEPHYR_IP:
        print("[ERROR] 请先设置 LINUXGUARD_STAGE7_ZEPHYR_IP=<ubuntu-vmnet2-addr>"
              "（Ubuntu 宿主在 VMnet2 实验段的地址，固件经 SLIRP hostfwd 8080 呈现）")
        return 2
    runtime = Path(tempfile.mkdtemp(prefix="iotguard-stage7-live-")).resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_name = f"zephyr-live-{stamp}"
    if not REPORT_NAME_RE.match(report_name):
        raise ValueError("报告目录名异常")
    report_dir = (REPORTS_DIR / report_name).resolve()
    if not report_dir.is_relative_to(REPORTS_DIR.resolve()):
        raise ValueError("报告目录越界")

    evidence: dict = {
        "started_at": datetime.now().isoformat(), "runtime_dir": str(runtime),
        "scope": {
            "authorized_cidr": ALLOWED_CIDRS,
            "target": "Zephyr-Sensor-01 固件（Zephyr v4.4.2, qemu_cortex_a9）",
            "reachability": f"Windows 后端 → VMnet2 → Ubuntu VM {ZEPHYR_IP}:{ZEPHYR_PORT}"
                            "（SLIRP hostfwd）→ qemu-system-arm xilinx-zynq-a9 → 固件 :80",
            "note": f"{ZEPHYR_IP} 为 Ubuntu 宿主地址；:22/:80 属宿主服务，"
                    ":8080 为 QEMU guest 固件（NAT 拓扑如实记录，不伪称独立物理网口）",
        },
        "checks": [], "passed": True,
    }

    def check(name: str, ok: bool, detail=None) -> bool:
        evidence["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail is not None and not ok else ""))
        if not ok:
            evidence["passed"] = False
        return ok

    # ── 0. 固件预检：真实 HTTP 直连身份接口与首页 ──
    print(f"[0] Zephyr 固件预检（http://{ZEPHYR_IP}:{ZEPHYR_PORT}/api/system）")
    status, body = probe_real(f"http://{ZEPHYR_IP}:{ZEPHYR_PORT}/api/system")
    try:
        ident = json.loads(body[body.index("{"):body.rindex("}") + 1])
    except ValueError:
        ident = {}
    evidence["firmware_preflight"] = ident
    check("firmware_identity_endpoint_live",
          status == 200 and ident.get("device_type") == "zephyr_sensor"
          and ident.get("os") == OS_VERSION and ident.get("board") == "qemu_cortex_a9"
          and ident.get("arch") == "arm" and ident.get("mac_address")
          and ident.get("telemetry", {}).get("temperature_c", {}).get("simulated") is True,
          {"status": status, "keys": sorted(ident)[:8]})
    _, html = probe_real(f"http://{ZEPHYR_IP}:{ZEPHYR_PORT}/")
    check("firmware_index_html", "Zephyr-Sensor-01" in html, html[:80])

    # ── 1. 启动后端（标准模式，一次性临时库） ──
    backend_port = free_port()
    print(f"[1] 启动后端 uvicorn 127.0.0.1:{backend_port}（独立临时 SQLite，白名单 {ALLOWED_CIDRS}）")
    db_path = str(runtime) + "/stage7.db"
    env = {**os.environ,
           "PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_DEPLOYMENT_MODE": "standard",
           "LINUXGUARD_DATABASE_URL": "sqlite:///" + db_path,
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
    profiles = caps.get("os_capability_profiles", {}) if isinstance(caps, dict) else {}
    check("whitelist_and_os_profiles",
          status == 200 and isinstance(caps, dict)
          and ALLOWED_CIDRS in caps.get("discovery_cidrs", [])
          and caps.get("discovery_enabled") is True
          and caps.get("repair_execution_enabled") is False
          and profiles.get("zephyr", {}).get("ssh_inventory") == "unsupported"
          and profiles.get("zephyr", {}).get("cve_exact_versions", "").startswith("supported")
          and profiles.get("linux/openwrt", {}).get("ssh_inventory") == "supported",
          {"cidrs": caps.get("discovery_cidrs") if isinstance(caps, dict) else None,
           "profiles": list(profiles)})
    evidence["capabilities_summary"] = {
        "discovery_cidrs": caps.get("discovery_cidrs") if isinstance(caps, dict) else None,
        "repair_execution_enabled": caps.get("repair_execution_enabled") if isinstance(caps, dict) else None,
        "os_capability_profiles": profiles,
    }

    try:
        # ── 2. 真实自动发现（单个 /25，遵守 ≤128 地址上限） ──
        print(f"[2] POST /api/iot/discovery enroll=true（{LAB_CIDR}，端口 {DISCOVERY_PORTS}）")
        status, result = http("POST", backend_port, "/api/iot/discovery",
                              {"cidr": LAB_CIDR, "ports": DISCOVERY_PORTS, "enroll": True})
        evidence["discovery"] = {"cidr": LAB_CIDR, "status": status,
                                 "summary": result if isinstance(result, dict) else str(result)[:300]}
        check("discovery_scan_ok", status == 200 and isinstance(result, dict), result)

        # ── 3. 观察与建档核验（身份接口 → 0.9 置信 → 固件元数据） ──
        _, observations = http("GET", backend_port, "/api/iot/observations", token=False)
        obs_rows = [r for r in observations if r.get("ip_address") == ZEPHYR_IP] if isinstance(observations, list) else []
        obs_detail = obs_rows[0] if obs_rows else {}
        evidence["observation"] = {"count": len(obs_rows), "row": obs_detail}
        enrollment = {}
        try:
            enrollment = json.loads(json.dumps(obs_detail.get("evidence", {}))).get("enrollment", {})
        except (TypeError, ValueError):
            pass
        caps_marks = enrollment.get("capabilities", {})
        check("observation_with_capability_marks",
              len(obs_rows) == 1 and ZEPHYR_PORT in (obs_detail.get("evidence", {}).get("open_ports") or [])
              and str(caps_marks.get("ssh_inventory", "")).startswith("unsupported")
              and str(caps_marks.get("package_inventory", "")).startswith("unsupported")
              and str(caps_marks.get("ebpf_runtime", "")).startswith("unsupported"),
              {"open_ports": obs_detail.get("evidence", {}).get("open_ports"), "capabilities": caps_marks})

        _, devices = http("GET", backend_port, "/api/devices", token=False)
        target = next((d for d in devices if d.get("ip") == ZEPHYR_IP), None) if isinstance(devices, list) else None
        check("iot_device_created", target is not None, devices)
        device_id = target["device_id"] if target else ""
        if target:
            _, detail = http("GET", backend_port, f"/api/devices/{device_id}", token=False)
            services = {s["port"]: (s["service_type"], s["product"], s["version"])
                        for s in detail.get("services", [])}
            meta = json.loads(detail.get("metadata") or "{}")
            components = {c["component_name"]: c.get("version") for c in detail.get("components", [])}
            evidence["device_detail"] = {
                "device_id": device_id, "services": services, "metadata": meta,
                "components": components,
                "identity_source": detail.get("identity_source"),
                "identity_confidence": detail.get("identity_confidence"),
            }
            check("identity_endpoint_enrollment",
                  detail.get("identity_source") == "device_identity_endpoint"
                  and detail.get("identity_confidence") == 0.9
                  and detail.get("os") == OS_VERSION
                  and detail.get("device_type") == "zephyr_sensor"
                  and detail.get("firmware_version") == FW_VERSION,
                  {"identity_source": detail.get("identity_source"),
                   "confidence": detail.get("identity_confidence"), "os": detail.get("os")})
            check("firmware_metadata_recorded",
                  meta.get("board") == "qemu_cortex_a9" and meta.get("arch") == "arm"
                  and bool(meta.get("build_id")) and bool(meta.get("device_id"))
                  and meta.get("telemetry", {}).get("temperature_c", {}).get("simulated") is True
                  and meta.get("mac_address"),
                  {k: meta.get(k) for k in ("board", "arch", "build_id", "mac_address")})
            check("versioned_components",
                  components.get("Zephyr-Sensor-01 firmware") == FW_VERSION
                  and components.get(f"zephyr-sensor-httpd {FW_VERSION}") == FW_VERSION,
                  components)
            check("http_service_fingerprint",
                  ZEPHYR_PORT in services and services[ZEPHYR_PORT][0] == "http"
                  and services[ZEPHYR_PORT][1] == f"zephyr-sensor-httpd {FW_VERSION}"
                  and services[ZEPHYR_PORT][2] == FW_VERSION,
                  services.get(ZEPHYR_PORT))

        # ── 4. CVE 分级：清洁库诚实零命中 ──
        if device_id:
            _, vulns = http("GET", backend_port, f"/api/devices/{device_id}/vulnerabilities", token=False)
            evidence["cve_clean_db"] = vulns
            check("cve_honest_zero_clean_db",
                  isinstance(vulns, dict) and vulns.get("count", 0) == 0
                  and vulns.get("affected_count", 0) == 0,
                  vulns)

        # ── 5. TEST-FIXTURE 三层分级 + 复扫幂等（同一次复扫观察两者） ──
        print("[5] 写入显式 TEST-FIXTURE 公告/情报后复扫（幂等 + 三层分级）")
        seed_fixtures(db_path)
        status2, again = http("POST", backend_port, "/api/iot/discovery",
                              {"cidr": LAB_CIDR, "ports": DISCOVERY_PORTS, "enroll": True})
        _, devices_after = http("GET", backend_port, "/api/devices", token=False)
        z_after = [d for d in devices_after if d.get("ip") == ZEPHYR_IP] if isinstance(devices_after, list) else []
        check("repeat_scan_idempotent",
              status2 == 200 and isinstance(again, dict) and again.get("enrolled_new", 1) == 0
              and len(z_after) == 1 and z_after[0].get("device_id") == device_id,
              {"second_enrolled_new": again.get("enrolled_new") if isinstance(again, dict) else None,
               "device_ids": [d.get("device_id") for d in z_after]})
        evidence["discovery_second"] = again if isinstance(again, dict) else str(again)[:300]

        if device_id:
            # 若复扫流程未自动重跑匹配（已存在设备），显式走同代码路径补跑一次
            _, vulns2 = http("GET", backend_port, f"/api/devices/{device_id}/vulnerabilities", token=False)
            tier_rows = vulns2.get("matches", []) if isinstance(vulns2, dict) else []
            matching_path = "discovery_rescan"
            if not tier_rows:
                run_matching_inprocess("sqlite:///" + db_path, device_id)
                _, vulns2 = http("GET", backend_port, f"/api/devices/{device_id}/vulnerabilities", token=False)
                tier_rows = vulns2.get("matches", []) if isinstance(vulns2, dict) else []
                matching_path = "explicit_device_matching"
            by_cve = {m.get("cve_id"): m for m in tier_rows}
            tier1 = by_cve.get(FIXTURE_VENDOR_CVE, {})
            tier2 = by_cve.get(FIXTURE_NVD_CVE, {})
            evidence["cve_fixtures"] = {
                "matching_path": matching_path,
                "note": "CVE-2026-900xx 均为显式 TEST-FIXTURE，仅存在于一次性临时库，非真实漏洞结论",
                "tiers": {"vendor_exact": tier1, "nvd_generic": tier2,
                          "unrelated_ids_present": [c for c in by_cve if c == FIXTURE_UNRELATED_CVE]},
            }
            check("cve_tier_vendor_exact",
                  tier1.get("match_status") == "affected"
                  and tier1.get("applicability_source") == "vendor_advisory"
                  and tier1.get("confidence") == 0.95, tier1)
            check("cve_tier_nvd_candidate",
                  tier2.get("match_status") == "potentially_affected"
                  and tier2.get("applicability_source") == "nvd_generic", tier2)
            check("cve_tier_unrelated_absent", FIXTURE_UNRELATED_CVE not in by_cve, sorted(by_cve))

        # ── 6. 安全边界 ──
        status_bad, _ = http("POST", backend_port, "/api/iot/discovery",
                             {"cidr": "10.99.0.0/30", "ports": [22], "enroll": True})
        check("unauthorized_cidr_rejected", status_bad == 400, status_bad)
        con = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True)
        writes = {
            "harness_run": con.execute("SELECT COUNT(*) FROM harness_run").fetchone()[0],
            "harness_tool_call": con.execute("SELECT COUNT(*) FROM harness_tool_call").fetchone()[0],
            "remediation_task": con.execute("SELECT COUNT(*) FROM remediation_task").fetchone()[0],
        }
        device_rows = con.execute("SELECT COUNT(*) FROM iot_device").fetchone()[0]
        obs_rows_total = con.execute("SELECT COUNT(*) FROM device_observation").fetchone()[0]
        row_pk = con.execute("SELECT id FROM iot_device WHERE device_id=?",
                             (device_id,)).fetchone() if device_id else None
        if row_pk:
            comp_names = [r[0] for r in con.execute(
                "SELECT component_name FROM iot_device_component WHERE device_row_id=?",
                (row_pk[0],)).fetchall()]
            comp_rows = len(comp_names)
        else:
            comp_names, comp_rows = [], -1
        con.close()
        check("no_repair_or_harness_side_effects", all(v == 0 for v in writes.values()), writes)
        check("no_duplicate_components",
              comp_rows == len(set(comp_names)) and comp_rows > 0
              and "Zephyr-Sensor-01 firmware" in comp_names
              and f"zephyr-sensor-httpd {FW_VERSION}" in comp_names,
              comp_names)
        evidence["db"] = {"write_tables": writes, "iot_device_rows": device_rows,
                          "device_observation_rows": obs_rows_total,
                          "zephyr_device_components": comp_names}
        evidence["boundaries"] = [
            "端口开放仅来自 TCP 连接成功；身份与版本结论以设备 /api/system 自报为准（自报可被伪造，置信 0.9 上限）。",
            f"{ZEPHYR_IP}:{ZEPHYR_PORT} 为 Ubuntu 宿主 SLIRP hostfwd 入口，QEMU guest 固件经 NAT 呈现；:22/:80 属宿主服务，不归入固件身份。",
            "OpenSSH 9.6p1 组件来自宿主 :22；宿主 :80 的产品串被固件自报 services 覆盖为 zephyr-sensor-httpd（设备自报优先的既有管线行为，NAT 拓扑下需人工甄别）。",
            "CVE-2026-900xx 为 TEST-FIXTURE 联调夹具（仅一次性临时库）；清洁库零命中=无证据，非无漏洞。",
            "未发送任何漏洞利用载荷；未触碰修复开关（repair_execution_enabled=false）。",
            "固件遥测为编译内模拟（simulated=true），不冒充实物采样。",
        ]
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
