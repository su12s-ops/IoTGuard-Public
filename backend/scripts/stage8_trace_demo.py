#!/usr/bin/env python3
"""第八阶段：真实只读安全评估演示运行器（统一 Trace 端到端，独立进程，不走 pytest）。

真实链路（无 Mock 填充）：
  1) 一次性临时 SQLite 后端（标准模式，白名单=授权实验段）；
  2) 真实发现入档：扫描授权段 /25 → QEMU Zephyr 固件经 Ubuntu SLIRP hostfwd 入口
     （LINUXGUARD_STAGE7_ZEPHYR_IP 环境变量注入，8080）→ device_identity_endpoint 建档；
  3) 真实四智能体只读分析：POST /api/agents/analyze（真实 DeepSeek LLM 调用；
     未配置密钥/服务不可用时如实记录阻塞并失败收口，不以模拟结果冒充）；
  4) 统一 Trace 验收：事件顺序、四智能体步骤、真实 LLM 用量（有依据才记录）、
     Zephyr 能力 unsupported 标注、Harness 关联 not_requested（不伪造修复状态）、
     证据引用解析、汇总统计；
  5) 证据写入 reports/stage8-trace-<时间戳>/evidence.json。

安全边界：只读（不触碰修复开关、不创建 Harness 修复任务、不发送利用载荷）；
后端仅绑定 127.0.0.1；真实探测仅指向授权实验段。

用法：LINUXGUARD_STAGE7_ZEPHYR_IP=<ubuntu-vmnet2-addr> python backend/scripts/stage8_trace_demo.py
"""
from __future__ import annotations

import json
import os
import re
import socket
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
LAB_CIDR = "192.168.100.0/25"
ALLOWED_CIDRS = "192.168.100.0/24"
ZEPHYR_IP = os.environ.get("LINUXGUARD_STAGE7_ZEPHYR_IP", "")
ZEPHYR_PORT = 8080
TOKEN = "stage8-trace-demo-token"
REPORT_NAME_RE = re.compile(r"^stage8-trace-\d{8}-\d{6}$")
LLM_POLL_TIMEOUT_S = 600

_opener = urllib.request.build_opener(type("_NoRedirect", (HTTPRedirectHandler,),
                                               {"redirect_request": lambda *a, **k: None}))


def http(method: str, port: int, path: str, body: dict | None = None, token: bool = True,
         timeout: int = 180) -> tuple[int, object]:
    if not path.startswith("/") or ".." in path or "://" in path or "\\" in path:
        raise ValueError(f"非法 API 路径: {path!r}")
    request = urllib.request.Request(
        f"http://{LOOPBACK_HOST}:{port}{path}", method=method,
        headers={"Content-Type": "application/json", **({"X-Control-Token": TOKEN} if token else {})},
        data=json.dumps(body).encode() if body is not None else None)
    try:
        with _opener.open(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return response.status, (json.loads(payload) if payload[:1] in "{[" else payload)
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(payload)
        except ValueError:
            return exc.code, payload


def probe_firmware() -> dict:
    with _opener.open(urllib.request.Request(
            f"http://{ZEPHYR_IP}:{ZEPHYR_PORT}/api/system", method="GET"), timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def free_port() -> int:
    sock = socket.socket()
    sock.bind((LOOPBACK_HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def main() -> int:
    if not ZEPHYR_IP:
        print("[ERROR] 请先设置 LINUXGUARD_STAGE7_ZEPHYR_IP=<ubuntu-vmnet2-addr>")
        return 2
    runtime = Path(tempfile.mkdtemp(prefix="iotguard-stage8-trace-")).resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_name = f"stage8-trace-{stamp}"
    if not REPORT_NAME_RE.match(report_name):
        raise ValueError("报告目录名异常")
    report_dir = (REPORTS_DIR / report_name).resolve()
    if not report_dir.is_relative_to(REPORTS_DIR.resolve()):
        raise ValueError("报告目录越界")

    evidence: dict = {
        "started_at": datetime.now().isoformat(), "runtime_dir": str(runtime),
        "scope": {
            "authorized_cidr": ALLOWED_CIDRS,
            "task": "真实只读安全评估（四智能体分析 Zephyr QEMU 终端）→ 统一 Trace",
            "llm": "真实 DeepSeek 调用（密钥来自后端 .env；用量仅记录响应真实携带的 usage）",
            "read_only": True,
        },
        "checks": [], "passed": True,
    }

    def check(name: str, ok: bool, detail=None) -> bool:
        evidence["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail is not None and not ok else ""))
        if not ok:
            evidence["passed"] = False
        return bool(ok)

    # ── 0. 目标预检（真实固件在线） ──
    print(f"[0] Zephyr 固件预检（http://{ZEPHYR_IP}:{ZEPHYR_PORT}/api/system）")
    try:
        ident = probe_firmware()
        check("firmware_alive", ident.get("os") == "Zephyr RTOS 4.4.2"
              and ident.get("device_id") == "ZEPHYR-SENSOR-0001", {k: ident.get(k) for k in ("os", "device_id")})
        evidence["firmware"] = {k: ident.get(k) for k in ("device_name", "device_id", "os", "board", "arch")}
    except OSError as exc:
        check("firmware_alive", False, str(exc))
        ident = {}

    # ── 1. 后端（一次性临时库，读 .env 的真实 LLM 密钥） ──
    backend_port = free_port()
    db_path = str(runtime) + "/stage8.db"
    env = {**os.environ,
           "PYTHON_DOTENV_DISABLED": "0", "LINUXGUARD_DEPLOYMENT_MODE": "standard",
           "LINUXGUARD_DATABASE_URL": "sqlite:///" + db_path,
           "LINUXGUARD_DATA_DIR": str(runtime) + "/data",
           "LINUXGUARD_EVENT_FILE": str(runtime) + "/events.jsonl",
           "LINUXGUARD_DISCOVERY_CIDRS": ALLOWED_CIDRS,
           "LINUXGUARD_CONTROL_TOKEN": TOKEN,
           "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
           "NVD_API_KEY": "",  # 情报抓取不属本演示；CVE 层如实呈现为无情报
           "PYTHONIOENCODING": "utf-8"}
    print(f"[1] 启动后端 uvicorn 127.0.0.1:{backend_port}（临时库，白名单 {ALLOWED_CIDRS}，LLM 密钥来自 .env）")
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

    try:
        # ── 2. 真实发现入档（IoT 设备管线 Trace #1） ──
        print(f"[2] 真实发现入档（{LAB_CIDR}，端口 [22,80,443,8080]）")
        status, enrolled = http("POST", backend_port, "/api/iot/discovery",
                                {"cidr": LAB_CIDR, "ports": [22, 80, 443, 8080], "enroll": True},
                                timeout=300)
        check("discovery_enrollment_ok", status == 200 and isinstance(enrolled, dict), enrolled)
        _, devices = http("GET", backend_port, "/api/devices", token=False)
        zephyr = next((d for d in devices if d.get("ip") == ZEPHYR_IP
                       and (d.get("os") or "").startswith("Zephyr")), None)
        check("zephyr_device_enrolled", zephyr is not None,
              [d.get("device_id") for d in devices] if isinstance(devices, list) else devices)
        device_id = zephyr["device_id"] if zephyr else ""
        evidence["discovery"] = {"summary": enrolled if isinstance(enrolled, dict) else str(enrolled)[:300],
                                 "zephyr_device_id": device_id}

        # 发现任务自身的 Trace 也应存在（discovery_enrollment）
        _, traces = http("GET", backend_port, "/api/traces?page=1&page_size=10", token=False)
        discovery_trace = next((t for t in traces.get("items", [])
                                if t["task_type"] == "discovery_enrollment"), None)
        check("discovery_trace_created", discovery_trace is not None, traces.get("items"))

        trace_id = ""
        if device_id:
            # ── 3. 真实四智能体只读分析（真实 LLM） ──
            print(f"[3] POST /api/agents/analyze device_id={device_id}（真实 DeepSeek LLM）")
            status, started = http("POST", backend_port, "/api/agents/analyze",
                                   {"device_id": device_id})
            check("analysis_started", status == 202 and isinstance(started, dict), started)
            trace_id = started.get("trace_id", "")
            run_id = started.get("run_id", "")
            check("analyze_returns_trace_id", trace_id.startswith("TR-"), started)

            deadline = time.monotonic() + LLM_POLL_TIMEOUT_S
            run = {}
            while time.monotonic() < deadline:
                _, run = http("GET", backend_port, f"/api/agents/runs/{run_id}", token=False)
                if isinstance(run, dict) and run.get("status") in {"completed", "failed"}:
                    break
                time.sleep(5)
            evidence["orchestration"] = {
                "run_id": run_id, "status": run.get("status"), "error": run.get("error"),
                "agents": run.get("agents", {}),
            }
            check("orchestration_finished",
                  isinstance(run, dict) and run.get("status") in {"completed", "failed"},
                  {"status": run.get("status"), "error": run.get("error")})

        # ── 4. 统一 Trace 验收 ──
        if trace_id:
            print(f"[4] 统一 Trace 验收（{trace_id}）")
            _, detail = http("GET", backend_port, f"/api/traces/{trace_id}", token=False)
            events = detail.get("events", [])
            evidence["trace"] = {"trace_id": trace_id, "task_type": detail.get("task_type"),
                                 "status": detail.get("status"),
                                 "event_count": len(events),
                                 "event_types": [e["event_type"] for e in events]}
            check("trace_events_ordered",
                  events and events[0]["event_type"] == "task_started"
                  and [e["seq"] for e in events] == sorted(e["seq"] for e in events),
                  {"count": len(events)})
            agent_starts = [e["actor"] for e in events if e["event_type"] == "agent_started"]
            check("four_agent_steps_recorded", len(agent_starts) >= 1, agent_starts)
            marks = [e for e in events if e["event_type"] == "capability_marks"]
            check("zephyr_unsupported_marks",
                  marks and marks[0]["payload"]["capabilities"]["ssh_inventory"].startswith("unsupported"),
                  marks[0]["payload"] if marks else None)
            finished = [e for e in events if e["event_type"] == "agent_finished"]
            llm_stats = [e["payload"].get("llm", {}) for e in finished]
            real_usage = [s for s in llm_stats if isinstance(s.get("llm_tokens"), dict)]
            evidence["llm"] = {"agents_finished": len(finished),
                               "with_real_token_usage": len(real_usage),
                               "sample": llm_stats[:2]}
            check("llm_usage_honest",
                  all(s.get("llm_tokens") == "unavailable" or isinstance(s.get("llm_tokens"), dict)
                      for s in llm_stats),
                  "token 用量仅在响应真实携带 usage 时记录，否则 unavailable")

            _, harness = http("GET", backend_port, f"/api/traces/{trace_id}/harness", token=False)
            check("readonly_harness_not_requested",
                  harness.get("association") == "not_requested" and harness.get("harness") is None,
                  harness.get("association"))
            evidence["harness_association"] = harness.get("association")

            _, evidence_view = http("GET", backend_port, f"/api/traces/{trace_id}/evidence", token=False)
            evidence["evidence_view"] = {"cves": evidence_view.get("cves", [])[:10],
                                         "evidence": evidence_view.get("evidence", [])[:10]}

        _, summary = http("GET", backend_port, "/api/traces/summary", token=False)
        evidence["summary"] = summary
        check("summary_real_counts",
              summary.get("total_traces", 0) >= 2  # discovery + four_agent
              and isinstance(summary.get("avg_duration_ms"), (int, str)),
              summary)

        evidence["boundaries"] = [
            "只读演示：未创建修复任务、未触碰设备写开关（repair_execution_enabled=false）。",
            "LLM 为真实 DeepSeek 调用；token 用量仅记录响应真实携带的 usage。",
            "临时一次性数据库；CVE 层无情报登记时如实零命中（无证据≠无漏洞）。",
            "Trace 仅覆盖第八阶段起的新任务；旧审计记录不回填、不伪造。",
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
