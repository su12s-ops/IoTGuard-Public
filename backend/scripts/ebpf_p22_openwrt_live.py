#!/usr/bin/env python3
"""eBPF 2.0 P2-2 真实 OpenWrt logread 采集验收（独立进程，不起 pytest）。

真实链路：VMnet2 实验段 OpenWrt 25.12.5 ← SSH 只读（既有 DeviceConnection：
主机指纹钉扎 + 凭据环境变量引用）→ logread 拉取 → P0 统一事件管线。

验收点（全部真实执行，不用模拟日志冒充）：
  1) 主机指纹握手核对（与受信记录一致才继续；未提供受信值则如实降级记录）；
  2) 首次采集：真实 logread 事件入库（source=openwrt_logread、观察模式=syslog、
     资产绑定、SecurityEvidence 同步生成、时间窗口元数据）；
  3) 立即重复采集：全量幂等（duplicates=窗口行数、stored_new=0）；
  4) 制造真实新日志（一次失败 SSH 认证 → dropbear auth 行，设备零改动）后
     三采：窗口变化处理（新行入库、旧行判重）；
  5) 智能体数据质量（生产函数 in-process 调用）+ coverage/reliability 端点；
  6) CVE 风险层联调：评测库内登记 dropbear 风险记录（测试脚手架，非设备数据）
     → 证据下钻（真实 syslog 证据的直接匹配）；
  7) 统一 Trace：runtime_log_collection 任务可查（Trace API）。

设备重启路径未真实执行（避免对设备做重启干预）：boot_id 身份区分与窗口
重置语义由专项测试锁定，本脚本如实报告当前 boot_id 供跨运行比对。

数据库访问全部经生产 ORM（app.models + SessionLocal），零原生 SQL 字符串。

用法（仓库根目录；连接参数经环境变量，值不入跟踪文件）：
  LINUXGUARD_OPENWRT_HOST=... LINUXGUARD_OPENWRT_USER=... \
  LINUXGUARD_OPENWRT_KEY_FILE=... LINUXGUARD_OPENWRT_HOSTKEY_SHA256=... \
  python backend/scripts/ebpf_p22_openwrt_live.py
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

REPORTS_DIR = ROOT / "reports"
OPENWRT_HOST = os.getenv("LINUXGUARD_OPENWRT_HOST", "")
OPENWRT_USER = os.getenv("LINUXGUARD_OPENWRT_USER", "")
OPENWRT_KEY_FILE = os.getenv("LINUXGUARD_OPENWRT_KEY_FILE", "")   # 本地设备私钥路径（不入库）
TRUSTED_HOSTKEY = os.getenv("LINUXGUARD_OPENWRT_HOSTKEY_SHA256", "")  # 受信指纹（SHA256:…）
# 授权实验段（实验网段标识不入跟踪文件；运行前由环境变量提供）
ALLOWED_CIDRS = os.getenv("LINUXGUARD_OPENWRT_CIDRS", "")
CVE_ID = "CVE-2026-P22-LIVE"


def sh(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def require_env() -> None:
    missing = [name for name, value in (
        ("LINUXGUARD_OPENWRT_HOST", OPENWRT_HOST),
        ("LINUXGUARD_OPENWRT_USER", OPENWRT_USER),
        ("LINUXGUARD_OPENWRT_KEY_FILE", OPENWRT_KEY_FILE),
        ("LINUXGUARD_OPENWRT_CIDRS", ALLOWED_CIDRS)) if not value]
    if missing:
        raise SystemExit("缺少环境变量：" + ", ".join(missing) + "（实验网段标识不入跟踪文件）")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _checked_url(base: str, path: str) -> str:
    """CWE-918 缓解：本脚本只与本进程自建的评测后端通信（环回 http）。"""
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"评测后端地址不在允许范围（仅环回 http）: {base!r}")
    if not path.startswith("/") or ".." in path or "://" in path:
        raise ValueError(f"非法 API 路径: {path!r}")
    return base.rstrip("/") + path


class Backend:
    """标准模式后端 + 一次性评测库（与开发库隔离）。"""

    def __init__(self, report_dir: Path):
        self.port = free_port()
        self.token = "p22-" + secrets.token_hex(12)
        self.db_path = report_dir / "p22-live.db"
        self.base = f"http://127.0.0.1:{self.port}/api"
        self.proc = None

    def start(self):
        env = dict(os.environ)
        env.update({
            "LINUXGUARD_DATABASE_URL": f"sqlite:///{self.db_path.as_posix()}",
            "LINUXGUARD_CONTROL_TOKEN": self.token,
            "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
            "LINUXGUARD_DISCOVERY_CIDRS": ALLOWED_CIDRS,
        })
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--log-level", "warning"],
            cwd=str(ROOT / "backend"), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                with urllib.request.urlopen(_checked_url(self.base, "/health"), timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise RuntimeError("后端未能在 30s 内就绪")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)

    def request(self, method: str, path: str, payload: dict | None = None, timeout: int = 120) -> tuple[int, object]:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            _checked_url(self.base, path), data=data, method=method,
            headers={"Content-Type": "application/json", "X-Control-Token": self.token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8")
                return response.status, (json.loads(body) if body[:1] in "{[" else body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, json.loads(body)
            except ValueError:
                return exc.code, body


def capture_host_fingerprint() -> dict:
    """仅握手获取 OpenWrt SSH 主机公钥指纹（原生 Transport，不认证、不加载设备私钥）。

    握手捕获的指纹随后与受信记录比对（mismatch 即验收失败）；捕获阶段
    本身不做信任决策，因此不涉及主机密钥策略。
    """
    import base64

    import paramiko
    result: dict = {"method": "ssh_transport_handshake_no_auth"}
    sock = socket.create_connection((OPENWRT_HOST, 22), timeout=8)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)  # 完成 SSH 握手（不发起认证）
        key = transport.get_remote_server_key()
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        result.update({"host_key_sha256": fingerprint, "key_type": key.get_name(),
                       "banner": transport.remote_version})
        if TRUSTED_HOSTKEY:
            result["matches_trusted_record"] = fingerprint == TRUSTED_HOSTKEY
    finally:
        transport.close()
        sock.close()
    return result


def make_failed_ssh_attempt() -> dict:
    """一次失败 SSH 认证 → 设备自然产生 dropbear auth 日志（零改动）。

    现场用 ssh-keygen 生成一次性随机密钥对（未在任何设备登记，必然被拒）；
    密钥材料只存在于临时文件且用后即删，源码零密钥字面量。
    """
    import subprocess as sp
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        bogus_key = Path(tmp) / "ephemeral_unregistered_key"
        generated = sp.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(bogus_key)],
                           capture_output=True, text=True, timeout=30)
        if generated.returncode != 0:
            return {"attempted": False, "reason": "临时密钥生成失败（设备侧不产生新日志）"}
        result = sh(["ssh", "-i", str(bogus_key), "-o", "BatchMode=yes",
                     "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
                     f"{OPENWRT_USER}@{OPENWRT_HOST}", "exit"], timeout=30)
        return {"attempted": True, "exit_code": result.returncode,
                "expected": "认证失败（未登记公钥被设备拒绝，自然记录 auth 日志）"}


def main() -> int:
    require_env()
    if not Path(OPENWRT_KEY_FILE).is_file():
        raise SystemExit("设备私钥文件不可读（本地证据路径不入库）")
    report_dir = REPORTS_DIR / f"ebpf-p22-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    report_dir.mkdir(parents=True, exist_ok=True)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""), flush=True)

    print(f"[p22] 真实 OpenWrt logread 采集验收 → {report_dir}", flush=True)
    print("[p22] 1) 主机指纹握手核对", flush=True)
    fingerprint = capture_host_fingerprint()
    (report_dir / "host-fingerprint.json").write_text(
        json.dumps(fingerprint, ensure_ascii=False, indent=2), encoding="utf-8")
    pinned = TRUSTED_HOSTKEY or fingerprint.get("host_key_sha256", "")
    if not pinned:
        check("主机指纹捕获", False, "握手未取得指纹")
    else:
        check("主机指纹捕获", True, pinned)
        if TRUSTED_HOSTKEY:
            check("受信记录一致", fingerprint.get("matches_trusted_record") is True)
        else:
            check("受信记录一致", True, "未提供受信值：以本次捕获值为钉扎依据（如实降级）")

    backend = Backend(report_dir)
    # 设备密钥环境变量必须在子进程 spawn 前就位（子进程继承的是此刻的父进程环境）
    key_env_name = "LINUXGUARD_DEVICE_OPENWRT_KEY"
    os.environ[key_env_name] = str(Path(OPENWRT_KEY_FILE).resolve())
    backend.start()
    # in-process 生产 ORM 会话（与后端子进程共用同一评测库文件）
    os.environ["LINUXGUARD_DATABASE_URL"] = f"sqlite:///{backend.db_path.as_posix()}"
    import importlib

    import app.database as database_module
    importlib.reload(database_module)
    db = database_module.SessionLocal()
    try:
        from app import models

        # 2) 登记 OpenWrt 资产 + DeviceConnection（密钥/指纹经环境变量引用）
        print("[p22] 2) 资产与连接登记", flush=True)
        asset = models.LinuxAsset(hostname="OpenWrt", ip_address=OPENWRT_HOST, os_name="OpenWrt",
                                  os_version="25.12.5", distribution="openwrt",
                                  device_type="iot_gateway", identity_source="p22_live",
                                  identity_confidence=0.9, inventory_complete=True)
        db.add(asset)
        db.commit()
        status, connection = backend.request("POST", "/iot/connections", {
            "asset_id": asset.id, "label": "p22-logread-live", "host": OPENWRT_HOST,
            "port": 22, "username": OPENWRT_USER, "auth_type": "ssh_key",
            "key_path_env": key_env_name, "host_key_sha256": pinned, "enabled": True})
        if status >= 300:
            raise SystemExit(f"连接登记失败: {status} {connection}")
        connection_id = connection["id"]
        check("DeviceConnection 登记（指纹钉扎+密钥环境变量引用）", True, f"connection_id={connection_id}")

        # 3) 首次采集
        print("[p22] 3) 首次 logread 采集", flush=True)
        status, first = backend.request("POST", f"/iot/connections/{connection_id}/collect-logs")
        (report_dir / "collect-1.json").write_text(
            json.dumps(first, ensure_ascii=False, indent=2), encoding="utf-8")
        check("首次采集 HTTP 200", status == 200, str(first)[:200] if status != 200 else "")
        meta = first.get("log_window", {})
        check("真实事件入库（stored_new > 0）", first.get("stored_new", 0) > 0,
              f"stored_new={first.get('stored_new')} lines={meta.get('lines_total')}")
        check("时间窗口元数据", bool(meta.get("window_first")) and bool(meta.get("window_last")),
              f"[{meta.get('window_first')} → {meta.get('window_last')}] tz={meta.get('timezone_offset')}")
        check("boot_id 留档（跨重启身份比对基准）", bool(meta.get("boot_id")), meta.get("boot_id", ""))

        db.expire_all()
        total = db.query(models.RuntimeEvent).filter_by(source="openwrt_logread").count()
        bound = db.query(models.RuntimeEvent).filter_by(source="openwrt_logread",
                                                        asset_id=asset.id).count()
        check("source=openwrt_logread 且资产绑定", total > 0 and total == bound,
              f"events={total}（全部绑定 asset_id={asset.id}）")
        evidence = db.query(models.SecurityEvidence).filter_by(asset_id=asset.id).count()
        check("SecurityEvidence 同步生成", evidence > 0, f"evidence={evidence}")

        # 4) 立即重复采集 → 全量对账幂等（采集会话自身会产生少量新日志行，
        #    核心断言=窗口行全部命中判重或为新行，绝不重复入库）
        print("[p22] 4) 立即重复采集（幂等验收）", flush=True)
        status, second = backend.request("POST", f"/iot/connections/{connection_id}/collect-logs")
        (report_dir / "collect-2-idempotent.json").write_text(
            json.dumps(second, ensure_ascii=False, indent=2), encoding="utf-8")
        built2 = second.get("log_window", {}).get("events_built")
        check("重复采集全量对账（duplicates+stored_new=窗口行数）",
              built2 is not None
              and second.get("duplicates", -1) + second.get("stored_new", -1) == built2,
              f"duplicates={second.get('duplicates')} stored_new={second.get('stored_new')} built={built2}")
        check("重复采集无重复入库（stored_new 仅采集会话自身新日志）",
              0 <= second.get("stored_new", 99) <= 10,
              f"stored_new={second.get('stored_new')}（每次采集是一次 SSH 会话，设备侧自然新增少量行）")

        # 5) 制造真实新日志 → 三采（窗口变化）
        print("[p22] 5) 真实新日志（失败 SSH 认证 → dropbear auth 行）后三采", flush=True)
        attempt = make_failed_ssh_attempt()
        (report_dir / "failed-auth-attempt.json").write_text(
            json.dumps(attempt, ensure_ascii=False, indent=2), encoding="utf-8")
        time.sleep(3)
        status, third = backend.request("POST", f"/iot/connections/{connection_id}/collect-logs")
        (report_dir / "collect-3-window-change.json").write_text(
            json.dumps(third, ensure_ascii=False, indent=2), encoding="utf-8")
        check("窗口变化：新行入库", third.get("stored_new", 0) > 0,
              f"stored_new={third.get('stored_new')}（含本脚本 SSH 会话与失败认证产生的真实日志）")
        check("窗口变化：旧行判重", third.get("duplicates", 0) > 0, f"duplicates={third.get('duplicates')}")
        db.expire_all()
        auth_rows = db.query(models.RuntimeEvent).filter_by(source="openwrt_logread") \
            .filter(models.RuntimeEvent.process_name.ilike("%dropbear%")).count()
        check("dropbear/auth 真实日志行可见", auth_rows > 0, f"dropbear 相关事件 {auth_rows} 条")

        # 6) coverage / reliability / 智能体数据质量
        print("[p22] 6) 覆盖与智能体数据质量", flush=True)
        status, cov = backend.request("GET", f"/runtime/assets/{asset.id}/coverage")
        logread_sensors = [s for s in cov.get("sensors", []) if s.get("source") == "logread"]
        check("coverage 端点可见 logread 传感器", bool(logread_sensors),
              f"dropped={logread_sensors[0]['dropped_events'] if logread_sensors else 'n/a'}（None=unavailable）")
        status, rel = backend.request("GET", "/runtime/ebpf/reliability")
        rel_text = json.dumps(rel, ensure_ascii=False)
        (report_dir / "reliability.json").write_text(rel_text, encoding="utf-8")
        check("reliability 端点含 logread 语义", "logread" in rel_text)

        from app.services.agent_tools import tool_query_runtime_data_quality
        quality = tool_query_runtime_data_quality(db, "OpenWrt")
        (report_dir / "agent-data-quality.json").write_text(
            json.dumps(quality, ensure_ascii=False, indent=2), encoding="utf-8")
        check("智能体数据质量 found", quality.get("found") is True)
        check("数据质量声明降级边界（非 eBPF）",
              any("拉取式降级采集" in gap and "非 eBPF" in gap for gap in quality.get("data_gaps", [])))
        from app.services.agent_tools import (tool_query_file_evidence,
                                                tool_query_network_evidence,
                                                tool_query_process_evidence)
        evidence_views = {
            "process": tool_query_process_evidence(db, "OpenWrt", limit=200),
            "network": tool_query_network_evidence(db, "OpenWrt", limit=200),
            "file": tool_query_file_evidence(db, "OpenWrt", limit=200),
        }
        (report_dir / "agent-evidence.json").write_text(
            json.dumps(evidence_views, ensure_ascii=False, default=str, indent=2)[:200000], encoding="utf-8")
        check("智能体证据读取（真实 OpenWrt syslog 证据）",
              json.dumps(evidence_views, default=str).count("openwrt_logread") > 0)

        # 7) CVE 风险层联调：评测库登记 dropbear 风险（脚手架，ORM 写入）→ 证据下钻
        print("[p22] 7) CVE 风险层证据下钻", flush=True)
        db.add(models.VulnerabilityInfo(cve_id=CVE_ID,
                                        title="P2-2 OpenWrt syslog evidence integration check",
                                        description="评测脚手架：验证真实 logread 证据进入 CVE 下钻",
                                        cvss_severity="Medium", cvss_score=5.0,
                                        affected_package="dropbear",
                                        source="p22_harness"))
        db.add(models.RiskAssessment(asset_id=asset.id, cve_id=CVE_ID, package_name="dropbear",
                                     active=True, runtime_status="waiting"))
        db.commit()
        from app.services.runtime_telemetry import cve_runtime_evidence
        drill = cve_runtime_evidence(db, CVE_ID)
        (report_dir / "cve-evidence-drill.json").write_text(
            json.dumps(drill, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        block = (drill or {}).get("assets") or []
        matched = block[0].get("signals", {}).get("direct_count", 0) if block else 0
        check("CVE 证据下钻：真实 syslog 证据直接匹配 dropbear", matched > 0,
              f"direct_count={matched} runtime_status={block[0].get('runtime_status') if block else 'n/a'}")

        # 8) 统一 Trace
        print("[p22] 8) 统一 Trace", flush=True)
        status, traces = backend.request("GET", "/traces?task_type=runtime_log_collection&page_size=10")
        trace_text = json.dumps(traces, ensure_ascii=False, default=str)
        (report_dir / "trace-runs.json").write_text(trace_text, encoding="utf-8")
        check("Trace 记录 runtime_log_collection", "runtime_log_collection" in trace_text
              and "completed" in trace_text)
    finally:
        db.close()
        backend.stop()

    passed = sum(1 for _, ok, _ in checks if ok)
    summary = {"passed": passed, "total": len(checks),
               "checks": [{"name": name, "ok": ok, "detail": detail} for name, ok, detail in checks],
               "reboot_note": "真实重启未执行（避免设备干预）：boot_id 身份区分与窗口重置语义由专项测试锁定",
               "environment": {"host_env_provided": True, "user_env_provided": True,
                               "trusted_hostkey_provided": bool(TRUSTED_HOSTKEY)}}
    (report_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                             encoding="utf-8")
    print(f"\n[p22] 验收 {passed}/{len(checks)}；证据 → {report_dir}", flush=True)
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
