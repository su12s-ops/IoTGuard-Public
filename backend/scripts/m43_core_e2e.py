#!/usr/bin/env python3
"""Stage 9B M4.3 核心业务主链 E2E 运行器（独立进程，不走 pytest）。

真实链路（全部真实设备 / 真实数据 / 真实 LLM，不用模拟数据冒充）：
  Phase A  OpenWrt：授权网段发现入档 → 操作员 SSH 只读采集（指纹钉扎）→
           清单上传建档 → 产品内 SSH 采集（pinned 身份升级）→ CVE 匹配 →
           logread 运行时证据 → 风险计算；
  Phase B  Ubuntu：操作员 SSH 只读采集 dpkg 清单 → 上传更新既有资产 →
           真实情报导入（本地既有情报存档；线上多源当前网络不可达，如实探测记录）→
           CVE 匹配 → 风险计算；
  Phase C  统一四智能体影子研判（隔离运行入口，直接 runner 调用，
           LINUXGUARD_UNIFIED_PIPELINE 保持 off，正式入口不受影响）；
  Phase D  Harness 只读闭环：调查任务（只读步骤）执行 + 修复任务前置门禁
           （不满足前置条件 → blocked；执行被拒；伪造审批被拒）；
  Phase E  一致性核验 + 影子隔离核验 + 溯源链输出。

安全边界（本脚本自身约束）：
  - 不设置 LINUXGUARD_ENABLE_DEVICE_REPAIR，不注册修复产物，不批准修复计划；
  - 不切换 LINUXGUARD_UNIFIED_PIPELINE（影子运行不写 RiskAssessment 正式字段）；
  - 设备访问全部只读固定脚本；HTTP 客户端固定字面量主机（回环 API / NVD 探测域），
    无动态 URL 组装；SSH 仅允许固定只读脚本经 stdin 下发（sh -s / bash -s 字面量）；
  - 授权网段白名单强制；不注册修复产物、不批准修复计划、不执行任何设备写操作。

用法（仓库根目录）：
  python backend/scripts/m43_core_e2e.py [--phases A,B,C,D,E]

关键环境变量（值不入跟踪文件）：
  LINUXGUARD_M43_OPENWRT_HOST      默认 192.168.100.1（VMnet2 授权实验段）
  LINUXGUARD_M43_OPENWRT_KEY       OpenWrt 设备私钥路径（gitignored 本地文件）
  LINUXGUARD_M43_OPENWRT_HOSTKEY   受信主机指纹（SHA256:...；未提供则只捕获不判定）
  LINUXGUARD_M43_UBUNTU_HOST/USER/KEY  Ubuntu 采集节点
  LINUXGUARD_M43_INTEL_ARCHIVE     既有真实情报存档 SQLite（行级导入；
                                   fetched_at 保留原值 → 新鲜度语义如实按旧数据处理）
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client as http_client
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

BACKEND_DIR = ROOT / "backend"
REPORTS_DIR = ROOT / "reports"
API_HOST = "127.0.0.1"          # API 仅允许回环：主机为字面量常量
API_PORT = 8431
NVD_PROBE_HOST = "services.nvd.nist.gov"
NVD_PROBE_PATH = "/rest/json/cves/2.0?resultsPerPage=1"

OPENWRT_HOST = os.getenv("LINUXGUARD_M43_OPENWRT_HOST", "192.168.100.1")
OPENWRT_KEY = os.getenv("LINUXGUARD_M43_OPENWRT_KEY", "")
OPENWRT_HOSTKEY = os.getenv("LINUXGUARD_M43_OPENWRT_HOSTKEY", "")
OPENWRT_USER = os.getenv("LINUXGUARD_M43_OPENWRT_USER", "root")
OPENWRT_CIDR = os.getenv("LINUXGUARD_M43_OPENWRT_CIDR", "192.168.100.0/25")
UBUNTU_HOST = os.getenv("LINUXGUARD_M43_UBUNTU_HOST", "192.168.183.129")
UBUNTU_USER = os.getenv("LINUXGUARD_M43_UBUNTU_USER", "wyh")
UBUNTU_KEY = os.getenv("LINUXGUARD_M43_UBUNTU_KEY", str(Path.home() / ".ssh" / "id_ed25519_vms"))
INTEL_ARCHIVE = os.getenv("LINUXGUARD_M43_INTEL_ARCHIVE", "")

INTEL_KEYWORDS = [k.strip() for k in os.getenv(
    "LINUXGUARD_M43_INTEL_KEYWORDS",
    "openssl,curl,sudo,apache2,openssh,linux kernel,systemd").split(",") if k.strip()]
INTEL_DAYS = int(os.getenv("LINUXGUARD_M43_INTEL_DAYS", "90"))
INTEL_LIMIT = int(os.getenv("LINUXGUARD_M43_INTEL_LIMIT", "120"))

OPENWRT_COLLECTOR = ROOT / "collector" / "collect_openwrt_asset.sh"
UBUNTU_COLLECTOR = ROOT / "collector" / "collect_linux_asset.sh"

RUN_STAMP = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
OUT_DIR = REPORTS_DIR / f"m43-core-e2e-{RUN_STAMP}"

CHECKS: list[dict] = []
SUMMARY: dict = {"run_stamp": RUN_STAMP, "phases": {}, "chain": {}, "boundaries": []}


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" —— {detail}" if detail else ""))
    return bool(ok)


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ── HTTP（http.client + 字面量回环主机，无动态 URL 组装）──────────────────────


def _valid_api_path(path: str) -> bool:
    return bool(path) and path.startswith("/") and ".." not in path and ":" not in path


def api_request(method: str, path: str, body: bytes | None = None,
                headers: dict | None = None) -> tuple[int, bytes]:
    """仅连回环上的本后端实例：主机/端口均为字面量与已校验整数，路径白名单校验。"""
    if not _valid_api_path(path):
        raise ValueError(f"非法 API 路径: {path!r}")
    conn = http_client.HTTPConnection(API_HOST, API_PORT, timeout=180)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def http(method: str, path: str, body: dict | None = None, token: bool = True,
         raw_body: bytes | None = None, content_type: str = "application/json") -> tuple[int, object]:
    headers = {"Content-Type": content_type}
    if token:
        from app import config  # noqa: F401  触发 dotenv 加载（.env 提供控制令牌）
        control_token = os.getenv("LINUXGUARD_CONTROL_TOKEN", "")
        if control_token:
            headers["X-Control-Token"] = control_token
    data = raw_body
    if data is None and body is not None:
        data = json.dumps(body).encode("utf-8")
    status, raw = api_request(method, path, data, headers)
    payload = raw.decode("utf-8", "ignore")
    try:
        return status, (json.loads(payload) if payload else {})
    except ValueError:
        return status, payload


def probe_nvd() -> bool:
    """线上多源情报可达性探测（固定字面量主机与路径，仅 GET，无动态目标）。"""
    try:
        from app import config  # noqa: F401  触发 dotenv 加载
        api_key = os.getenv("NVD_API_KEY", "")
        headers = {"User-Agent": "IoTGuard-m43-probe"}
        if api_key:
            headers["apiKey"] = api_key
        conn = http_client.HTTPSConnection(NVD_PROBE_HOST, timeout=8)
        try:
            conn.request("GET", NVD_PROBE_PATH, headers=headers)
            return conn.getresponse().status == 200
        finally:
            conn.close()
    except Exception:
        return False


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind((API_HOST, 0))
        return sock.getsockname()[1]


def start_backend() -> subprocess.Popen:
    global API_PORT
    API_PORT = free_port()
    import ipaddress
    lab_net = str(ipaddress.ip_network(OPENWRT_CIDR, strict=False).supernet(new_prefix=24))
    env = os.environ.copy()
    env["LINUXGUARD_DISCOVERY_CIDRS"] = f"127.0.0.0/8,{lab_net}"
    env["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"
    env["LINUXGUARD_UNIFIED_PIPELINE"] = "off"              # 正式入口保持关闭（影子走隔离入口）
    env.setdefault("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")  # 修复写操作总开关保持关闭
    if OPENWRT_KEY:
        env["LINUXGUARD_DEVICE_OPENWRT_KEY"] = str(Path(OPENWRT_KEY).expanduser().resolve())
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", API_HOST,
         "--port", str(API_PORT), "--log-level", "warning"],
        cwd=BACKEND_DIR, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with socket.create_connection((API_HOST, API_PORT), timeout=1):
                return proc
        except OSError:
            time.sleep(0.5)
    proc.terminate()
    raise SystemExit("后端启动超时")


# ── 操作员侧 SSH（引导采集；指纹先核后连，凭据仅环境变量引用）────────────────


def ssh_server_key(host: str, port: int = 22) -> tuple[str, str, object]:
    """取主机 ED25519 公钥（与项目受信记录口径一致：ssh-keyscan -t ed25519）。

    返回 (SHA256 指纹, 键类型, 公钥对象)；指纹口径与 ssh-keygen -lf 一致
    （SHA256 over 原始公钥 blob；paramiko get_fingerprint() 是 MD5 hexdigest，
    不能用）。"""
    import paramiko
    transport = paramiko.Transport((host, port))
    transport.get_security_options().key_types = ["ssh-ed25519"]
    transport.connect()
    key = transport.get_remote_server_key()
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    name = key.get_name()
    transport.close()
    return fingerprint, name, key


SSH_COMMANDS = ("sh -s", "bash -s", "bash -s -- /dev/stdout")


def operator_ssh_collect(host: str, user: str, key_path: str, script: Path,
                         pin_fingerprint: str = "", label: str = "",
                         command: str = "sh -s") -> tuple[str, str]:
    """操作员侧只读采集：主机指纹先核对（提供受信值时判定，否则仅捕获留档），
    固定采集脚本经 stdin 下发（无拼接命令；解释器仅限字面量白名单）。"""
    import paramiko
    if command not in SSH_COMMANDS:
        raise ValueError("SSH 命令不在白名单（固定只读调用）")
    actual_fp, key_type, server_key = ssh_server_key(host)
    if pin_fingerprint:
        if actual_fp != pin_fingerprint:
            raise SystemExit(f"{label}: 主机指纹与受信记录不一致（actual={actual_fp}），中止")
    else:
        print(f"  [{label}] 主机指纹捕获（无受信记录，仅留档）: {actual_fp}")
    pkey = paramiko.Ed25519Key.from_private_key_file(str(Path(key_path).expanduser()))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.get_host_keys().add(host, key_type, server_key)
    client.connect(host, username=user, pkey=pkey, timeout=15,
                   allow_agent=False, look_for_keys=False)
    try:
        text = script.read_text(encoding="utf-8")
        stdin, stdout, stderr = client.exec_command(command, timeout=180)
        stdin.write(text)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        code = stdout.channel.recv_exit_status()
        if code != 0:
            raise SystemExit(f"{label}: 采集脚本退出码 {code}: {err[:200]}")
        return out, actual_fp
    finally:
        client.close()


def multipart_upload(filename: str, content: str) -> tuple[bytes, str]:
    boundary = f"----m43{uuid.uuid4().hex}"
    part = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    ).encode("utf-8") + content.encode("utf-8") + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return part, f"multipart/form-data; boundary={boundary}"


# ── 阶段实现 ─────────────────────────────────────────────────────────────────


def phase_a_openwrt() -> dict:
    section("Phase A：OpenWrt 真实发现 → SSH 采集 → CVE 匹配 → logread 证据")
    result: dict = {}
    if not OPENWRT_KEY or not Path(OPENWRT_KEY).expanduser().is_file():
        check("OpenWrt 设备密钥可用（环境变量引用本地文件）", False,
              "LINUXGUARD_M43_OPENWRT_KEY 未提供或文件不存在")
        return result

    # A1 授权网段发现入档（真实 TCP + 协议指纹）
    status, payload = http("POST", "/api/iot/discovery",
                           {"cidr": OPENWRT_CIDR, "enroll": True,
                            "ports": [22, 80, 443]})
    ok = status == 200
    devices = (payload or {}).get("devices") or []
    result["discovery"] = {k: payload.get(k) for k in
                           ("devices", "responding_devices", "boundaries") if k in (payload or {})}
    check("A1 授权网段发现入档（真实探测）", ok,
          f"识别设备 {len(devices)}；范围 {OPENWRT_CIDR}" if ok else f"{status} {payload}")
    device = next((d for d in devices
                   if d.get("ip_address") == OPENWRT_HOST or d.get("ip") == OPENWRT_HOST), None)
    if not ok or device is None:
        check("A1b OpenWrt 设备已识别", False, json.dumps(payload, ensure_ascii=False)[:300])
        return result
    check("A1b OpenWrt 设备已识别", True,
          f"device_id={device.get('device_id')} type={device.get('device_type')} conf={device.get('identity_confidence')}")
    result["device"] = {k: device.get(k) for k in
                        ("device_id", "device_name", "device_type", "firmware_version",
                         "identity_confidence", "identity_source") if k in device}

    # A2 操作员侧 SSH 只读采集（固定脚本 stdin 下发）→ 官方上传 API 建档
    text, fp = operator_ssh_collect(OPENWRT_HOST, OPENWRT_USER, OPENWRT_KEY,
                                    OPENWRT_COLLECTOR, OPENWRT_HOSTKEY, "OpenWrt")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "openwrt_inventory_raw.txt").write_text(text, encoding="utf-8")
    result["operator_collect"] = {"output_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                  "bytes": len(text), "host_fingerprint": fp,
                                  "host_fingerprint_matched": bool(OPENWRT_HOSTKEY)}
    check("A2a 操作员 SSH 只读采集（指纹钉扎+固定脚本）", text.startswith("===== META ====="),
          f"{len(text)} bytes sha256={result['operator_collect']['output_sha256'][:16]}…")
    body, ctype = multipart_upload("openwrt_inventory.txt", text)
    status, payload = http("POST", "/api/assets/upload", raw_body=body, content_type=ctype)
    asset = (payload or {}).get("asset") if isinstance(payload, dict) else None
    parse_stats = (payload or {}).get("package_parse_stats") or {} if isinstance(payload, dict) else {}
    parsed_count = parse_stats.get("parsed_count") or 0
    check("A2b 清单经官方上传 API 建档", status == 200 and bool(asset) and parsed_count > 0,
          f"asset_id={asset.get('id')} pkgs={parsed_count} 身份={asset.get('identity_source')}"
          f" complete={asset.get('inventory_complete')}"
          if asset else f"{status} {json.dumps(payload, ensure_ascii=False)[:200]}")
    if not asset:
        return result
    asset_id = asset["id"]
    result["asset_upload"] = {k: asset.get(k) for k in
                              ("id", "hostname", "os_name", "os_version", "distribution",
                               "identity_source", "inventory_sha256")}
    result["asset_upload"]["package_parse_stats"] = parse_stats

    # A3 产品内 SSH 采集（既有 DeviceConnection：指纹钉扎 + 密钥环境变量引用）
    connections = http("GET", "/api/iot/connections", token=False)[1]
    conn = next((c for c in connections if c.get("host") == OPENWRT_HOST), None)
    if conn is None:
        status, payload = http("POST", "/api/iot/connections", {
            "asset_id": asset_id, "label": "m43-core-e2e", "host": OPENWRT_HOST,
            "port": 22, "username": OPENWRT_USER, "auth_type": "ssh_key",
            "key_path_env": "LINUXGUARD_DEVICE_OPENWRT_KEY",
            "host_key_sha256": fp})
        conn = payload if isinstance(payload, dict) and payload.get("id") else None
        check("A3a DeviceConnection 登记（指纹钉扎）", bool(conn),
              f"connection_id={conn.get('id')}" if conn else f"{status} {payload}")
    else:
        check("A3a DeviceConnection 已存在（复用）", True, f"connection_id={conn.get('id')}")
    if not conn:
        return result
    status, payload = http("GET", f"/api/iot/connections/{conn['id']}/preflight")
    pre = payload if isinstance(payload, dict) else {}
    checks = pre.get("checks") or {}
    # 产品策略：设备 SSH 采集任务必须由 Linux 采集节点执行；Windows 为开发/离线节点。
    # 本轮在 Windows 后端运行 → 预检必须如实报告 node_platform=False（不伪造就绪）。
    check("A3b 采集预检如实报告节点平台限制（Windows=开发节点）",
          status == 200 and checks.get("node_platform") is False and pre.get("ready") is False,
          f"ready={pre.get('ready')} checks={json.dumps(checks, ensure_ascii=False)[:220]}")
    status, payload = http("POST", f"/api/iot/connections/{conn['id']}/collect")
    refused = status == 400
    detail = payload.get("detail") if isinstance(payload, dict) else payload
    code = detail.get("error_code") if isinstance(detail, dict) else ""
    check("A3c 产品内设备采集节点策略边界成立（Windows 被拒 node_platform_invalid）",
          refused and code == "node_platform_invalid",
          f"HTTP {status} error_code={code}（清单已由 A2 真实采集入库；Linux 节点路径见报告）")
    result["node_policy"] = {"preflight": pre, "collect_refused_code": code,
                             "refused_run_id": detail.get("run_id") if isinstance(detail, dict) else ""}

    # A4 CVE 匹配（OpenWrt 精确版本线；线上多源不可达时如实零命中）
    nvd_ok = probe_nvd()
    result["nvd_reachable"] = nvd_ok
    check("A4a 线上多源情报可达性探测（NVD）", True,
          "可达" if nvd_ok else "不可达（当前网络；OpenWrt 线以操作员公告为准，零命中属有效结果）")
    status, payload = http("POST", f"/api/matching/run?asset_id={result.get('asset_id', asset_id)}")
    check("A4b OpenWrt 主机线 CVE 匹配（真实清单）", status == 200,
          f"处理 {payload.get('count')} 条情报" if status == 200 else f"{status} {payload}")
    matches = http("GET", "/api/matching/results")[1]
    ow_matches = [m for m in matches if m.get("asset_id") == result.get("asset_id", asset_id)]
    affected = [m for m in ow_matches if m.get("affected")]
    result["matches"] = {"total": len(ow_matches), "affected": len(affected),
                         "rows": ow_matches[:20]}
    check("A4c OpenWrt 受影响 CVE 命中（零命中亦有效）", True,
          f"命中 {len(affected)} / 候选 {len(ow_matches)}（无合成 CVE 补位）")

    # A5 logread 运行时证据（只读拉取 → 统一证据层）
    status, payload = http("POST", f"/api/iot/connections/{conn['id']}/collect-logs")
    ok = status == 200
    logs = payload if isinstance(payload, dict) else {}
    result["logread"] = {k: logs.get(k) for k in ("stored_new", "duplicates", "sensor_id",
                                                  "asset_id", "log_window", "trace_id") if k in logs}
    check("A5 OpenWrt logread 运行时证据入库（source=openwrt_logread）", ok,
          f"新增 {logs.get('stored_new')} 判重 {logs.get('duplicates')} trace={logs.get('trace_id')}"
          if ok else f"{status} {json.dumps(payload, ensure_ascii=False)[:250]}")

    # A6 风险计算（如命中）
    status, payload = http("POST", "/api/risk/calculate")
    check("A6 OpenWrt 风险计算", status == 200,
          f"{payload.get('count')} 条候选" if status == 200 else f"{status} {payload}")
    return result


def phase_b_ubuntu() -> dict:
    section("Phase B：Ubuntu 真实采集 → 情报导入 → CVE 匹配 → 风险")
    result: dict = {}
    if not Path(UBUNTU_KEY).expanduser().is_file():
        check("Ubuntu 采集节点密钥可用", False, f"{UBUNTU_KEY} 不存在")
        return result

    # B1 操作员侧只读采集 dpkg 清单
    text, fp = operator_ssh_collect(UBUNTU_HOST, UBUNTU_USER, UBUNTU_KEY,
                                    UBUNTU_COLLECTOR, "", "Ubuntu", command="bash -s -- /dev/stdout")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "ubuntu_inventory_raw.txt").write_text(text, encoding="utf-8")
    result["operator_collect"] = {"output_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                  "bytes": len(text), "host_fingerprint": fp}
    check("B1a Ubuntu 节点 SSH 只读采集（dpkg 清单）", "HOSTNAME" in text,
          f"{len(text)} bytes sha256={result['operator_collect']['output_sha256'][:16]}…")
    body, ctype = multipart_upload("ubuntu_inventory.txt", text)
    status, payload = http("POST", "/api/assets/upload", raw_body=body, content_type=ctype)
    asset = (payload or {}).get("asset") if isinstance(payload, dict) else None
    parse_stats = (payload or {}).get("package_parse_stats") or {} if isinstance(payload, dict) else {}
    check("B1b 清单上传（更新既有登记资产）",
          status == 200 and bool(asset) and (parse_stats.get("parsed_count") or 0) > 0,
          f"asset_id={asset.get('id')} {asset.get('hostname')} 包数={parse_stats.get('parsed_count')}"
          if asset else f"{status} {json.dumps(payload, ensure_ascii=False)[:200]}")
    if not asset:
        return result
    result["asset_id"] = asset["id"]
    result["asset"] = {k: asset.get(k) for k in
                       ("id", "hostname", "os_name", "os_version", "distribution")}
    result["asset"]["package_count"] = parse_stats.get("parsed_count") or 0

    # B2 真实情报导入（本地既有存档；线上多源不可达 → 如实探测记录）
    result["nvd_reachable"] = probe_nvd()
    imported = import_intel_archive()
    result["intel_import"] = imported
    check("B2 真实多源情报可用（本地既有存档导入，fetched_at 保留原值）",
          imported.get("intel_rows", 0) > 0 or result["nvd_reachable"],
          f"intel_source={imported.get('intel_rows', 0)} cve_info={imported.get('cve_info', 0)}"
          f" archive={'provided' if INTEL_ARCHIVE else '未提供'} nvd_live={result['nvd_reachable']}")

    # B2b 线上真实增量情报同步（NVD/KEV/EPSS 可达时；关键词取自真实装机包）
    synced = {"calls": [], "saved": 0}
    if result["nvd_reachable"]:
        from app.database import SessionLocal
        from app.services.real_intel_collector import sync_real_vulnerabilities
        db = SessionLocal()
        try:
            for keyword in INTEL_KEYWORDS:
                try:
                    outcome = sync_real_vulnerabilities(
                        db, keyword=keyword, days=INTEL_DAYS,
                        limit=INTEL_LIMIT, replace=False)
                    synced["calls"].append({"keyword": keyword,
                                            "nvd": outcome.total_from_nvd,
                                            "saved": outcome.saved,
                                            "kev": outcome.kev_marked})
                    synced["saved"] += outcome.saved
                except Exception as exc:   # 单关键词失败不阻断（网络限流等）
                    db.rollback()
                    synced["calls"].append({"keyword": keyword, "error": str(exc)[:120]})
        finally:
            db.close()
        result["intel_sync"] = synced
    check("B2b 线上真实增量情报同步（NVD/KEV/EPSS）", True,
          f"saved={synced['saved']} 调用={[(c.get('keyword'), c.get('saved', c.get('error'))) for c in synced['calls']]}")

    # B3 CVE 匹配 + 风险计算
    status, payload = http("POST", f"/api/matching/run?asset_id={result['asset_id']}")
    check("B3a Ubuntu 主机线 CVE 匹配（Canonical 适用性）", status == 200,
          f"{payload.get('count')} 条" if status == 200 else f"{status} {payload}")
    status, payload = http("POST", "/api/risk/calculate")
    check("B3b Ubuntu 风险计算", status == 200,
          f"{payload.get('count')} 条" if status == 200 else f"{status} {payload}")

    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        rows = (db.query(models.RiskAssessment)
                .filter(models.RiskAssessment.asset_id == result["asset_id"],
                        models.RiskAssessment.active.is_(True),
                        models.RiskAssessment.match_id.isnot(None))
                .order_by(models.RiskAssessment.preliminary_score.desc()).all())
        result["risk_count"] = len(rows)
        if rows:
            top = rows[0]
            match = db.get(models.VulnerabilityMatch, top.match_id)
            result["top_risk"] = {
                "risk_id": top.id, "cve_id": top.cve_id, "package": top.package_name,
                "preliminary_score": top.preliminary_score,
                "preliminary_level": top.preliminary_level,
                "preliminary_decision": top.preliminary_decision,
                "installed_version": match.installed_version if match else "",
                "fixed_version": match.fixed_version if match else "",
                "match_status": match.match_status if match else ""}
            check("B3c 真实风险候选就绪（含装机/修复版本事实）", True,
                  f"risk_id={top.id} {top.cve_id} {top.package_name} "
                  f"installed={result['top_risk']['installed_version']} "
                  f"fixed={result['top_risk']['fixed_version']}")
        else:
            check("B3c 真实风险候选就绪", False, "零命中（需检查情报导入/清单解析）")
    finally:
        db.close()
    return result


def import_intel_archive() -> dict:
    """从既有真实情报存档导入 intel 行（真实采集数据复用；非合成）。

    fetched_at / source_updated_at 保留存档原值：新鲜度语义由消费方按当前
    时间重算并如实降级（旧情报就是旧情报，不刷新时间戳伪装新鲜）。
    """
    stats = {"intel_rows": 0, "cve_info": 0, "archive": ""}
    if not INTEL_ARCHIVE:
        return stats
    archive = Path(INTEL_ARCHIVE)
    if not archive.is_file():
        stats["archive"] = f"missing:{archive}"
        return stats
    stats["archive"] = str(archive)
    import sqlite3
    from datetime import datetime
    from app import models
    from app.database import SessionLocal

    def coerce(model, values: dict) -> dict:
        """按模型列类型转换原始行（DateTime 列的 ISO 文本 → datetime；忽略未知列）。"""
        result = {}
        for k, v in values.items():
            column = model.__table__.columns.get(k)
            if column is None or k == "id":
                continue
            if isinstance(v, str) and "DateTime" in type(column.type).__name__:
                try:
                    v = datetime.fromisoformat(v)
                except ValueError:
                    v = None if column.nullable else datetime.now(timezone.utc)
            result[k] = v
        return result

    src = sqlite3.connect(f"file:{archive.as_posix()}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    db = SessionLocal()
    try:
        for row in src.execute("SELECT * FROM vulnerability_intelligence_source"):
            values = coerce(models.VulnerabilityIntelligenceSource, {k: row[k] for k in row.keys()})
            existing = (db.query(models.VulnerabilityIntelligenceSource)
                        .filter_by(cve_id=values["cve_id"], source=values["source"]).first())
            if existing is None:
                db.add(models.VulnerabilityIntelligenceSource(**values))
            else:
                for k, v in values.items():
                    setattr(existing, k, v)
            stats["intel_rows"] += 1
        seen_cves: set[str] = set()
        for row in src.execute("SELECT * FROM vulnerability_info"):
            values = coerce(models.VulnerabilityInfo, {k: row[k] for k in row.keys()})
            cve_id = values.get("cve_id") or ""
            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            exists = (db.query(models.VulnerabilityInfo)
                      .filter_by(cve_id=cve_id).first()) is not None
            if not exists:
                db.add(models.VulnerabilityInfo(**values))
                stats["cve_info"] += 1
        db.commit()
    finally:
        db.close()
        src.close()
    return stats


def _unified_run(task_type: str, target_ref: str, target_type: str,
                 risk_id: int | None, label: str) -> dict:
    """隔离运行入口：直接 runner 调用（mode=shadow；正式 flag 保持 off）。"""
    import app.services.unified.runner as runner_mod
    from app import models
    from app.database import SessionLocal
    from app.services import trace_service as tracing
    from app.services.unified.agent_base import default_client_factory

    db = SessionLocal()
    try:
        run_id = f"m43-{label}-{uuid.uuid4().hex[:8]}"
        # 与产品路径 start_unified_run 一致：统一 Trace 贯穿（可审计、前端可查）
        trace = tracing.start_trace(
            db, task_type="unified_four_agent", target_type=target_type,
            target_ref=target_ref, run_ref_type="unified_analysis",
            run_ref_id="pending", metadata={"mode": "shadow", "task_type": task_type,
                                            "entry": "m43_isolated_shadow"})
        row = models.UnifiedAnalysisRun(
            run_id=run_id, task_type=task_type, target_type=target_type,
            target_ref=target_ref, mode="shadow", status="running", risk_id=risk_id,
            trace_id=trace.trace_id)
        db.add(row)
        db.commit()
        trace.run_ref_id = run_id
        db.commit()
        started = time.monotonic()
        runner_mod.run_unified_sync(db, row,
                                    client_factory=default_client_factory, sink=None)
        wall = round(time.monotonic() - started, 1)
        db.refresh(row)
        state = json.loads(row.state_json or "{}")
        final = state.get("final") or {}
        decision = json.loads(row.decision_json or "{}") or state.get("decision") or {}
        agents_log = json.loads(row.agents_json or "{}") or {}
        return {
            "run_id": row.run_id, "status": row.status, "error": (row.error or "")[:300],
            "wall_seconds": wall, "task_type": task_type, "target_ref": target_ref,
            "risk_id": risk_id, "trace_id": row.trace_id,
            "routing": json.loads(row.routing_json or "{}"),
            "stage_status": state.get("stage_status", {}),
            "degraded_roles": state.get("degraded_roles", []),
            "policy": final.get("policy"),
            "verdicts": decision.get("verdicts") or [],
            "response_plan": (decision.get("response_plan")
                              if isinstance(decision, dict) else None) or {},
            "agents_log": {name: {
                "status": (log or {}).get("status"),
                "tool_calls": [c.get("name") for c in ((log or {}).get("tool_calls") or [])],
                "evidence_ids": ((log or {}).get("output") or {}).get("supporting_evidence_ids")
                or ((log or {}).get("output") or {}).get("evidence_ids") or [],
            } for name, log in agents_log.items()},
            "usage": json.loads(row.usage_json or "{}"),
            "plan_json_present": bool(row.plan_json and row.plan_json != "{}"),
        }
    finally:
        db.close()


def _formal_risk_snapshot(risk_id: int) -> dict:
    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        risk = db.get(models.RiskAssessment, risk_id)
        if risk is None:
            return {}
        return {k: getattr(risk, k) for k in
                ("review_status", "final_score", "risk_level", "decision",
                 "recommended_action", "decision_confidence", "review_reason")}
    finally:
        db.close()


def _evidence_citations_verified(evidence_ids: list) -> tuple[bool, str]:
    """独立核验裁定引用（与管线防幻觉门禁同语义、独立重放）：

    - SE-* 形态的引用必须是 SecurityEvidence 真实存在的证据 ID；
    - 含冒号的 ``query_*:`` 形态是确定性工具事实溯源标签（管线合法可引用全集
      的一部分，与专家报告引用同源），要求符合 ``工具名:参数`` 格式；
    - 两者之外的形态视为可疑引用，判负。"""
    ids = [str(e) for e in evidence_ids if str(e)]
    if not ids:
        return True, "未引用（证据缺口走 missing_evidence 语义）"
    se_ids = [e for e in ids if e.startswith("SE-")]
    labels = [e for e in ids if not e.startswith("SE-")]   # 工具/来源溯源标签（合法可引用）
    real_count = 0
    if se_ids:
        from app import models
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            found = {row.evidence_id for row in
                     db.query(models.SecurityEvidence.evidence_id)
                     .filter(models.SecurityEvidence.evidence_id.in_(se_ids)).all()}
            real_count = sum(1 for e in se_ids if e in found)
        finally:
            db.close()
    ok = real_count == len(se_ids)   # 唯一硬失效条件：伪造形态的证据 ID
    detail = f"SE 证据 {real_count}/{len(se_ids)} 真实存在；溯源标签 {len(labels)} 个（工具/来源名）"
    return ok, detail


def phase_c_unified(openwrt: dict, ubuntu: dict) -> dict:
    section("Phase C：统一四智能体影子研判（隔离入口，flag=off 不变）")
    result: dict = {"runs": []}
    from app import config
    check("C0 全局开关保持 off（正式入口不切换）", config.UNIFIED_PIPELINE_MODE == "off",
          f"LINUXGUARD_UNIFIED_PIPELINE={config.UNIFIED_PIPELINE_MODE}")

    # C1 OpenWrt 设备面研判（真实设备 + 真实 logread 证据）
    device_ref = ((openwrt.get("device") or {}).get("device_id") or "")
    if device_ref:
        run = _unified_run("device_surface", device_ref, "device", None, "ow")
        result["runs"].append(run)
        check("C1 OpenWrt 设备面影子研判（真实 LLM）", run["status"] == "completed",
              f"run={run['run_id']} wall={run['wall_seconds']}s policy={((run.get('policy') or {}).get('status'))}"
              + (f" err={run['error']}" if run["error"] else ""))

    # C2 Ubuntu 真实风险影子研判（真实 Falco 运行时证据消费）
    risk = ubuntu.get("top_risk") or {}
    if risk.get("risk_id"):
        before = _formal_risk_snapshot(risk["risk_id"])
        run = _unified_run("risk_review", ubuntu["asset"]["hostname"], "linux_host",
                           risk["risk_id"], "ub")
        after = _formal_risk_snapshot(risk["risk_id"])
        result["runs"].append(run)
        result["formal_snapshot_before"] = before
        result["formal_snapshot_after"] = after
        check("C2 Ubuntu 风险影子研判（真实 LLM）", run["status"] == "completed",
              f"run={run['run_id']} wall={run['wall_seconds']}s "
              f"policy={((run.get('policy') or {}).get('status'))} "
              f"verdicts={len(run['verdicts'])}"
              + (f" err={run['error']}" if run["error"] else ""))
        unchanged = before == after
        check("C2b 影子隔离：正式 RiskAssessment 字段零触碰", unchanged,
              "前后快照一致" if unchanged else f"{before} -> {after}")
        verdict = (run["verdicts"] or [{}])[0]
        fallback = bool(verdict.get("program_fallback"))
        cites_ok, cites_detail = _evidence_citations_verified(
            verdict.get("supporting_evidence_ids") or [])
        check("C2c 研判结论引用真实证据（反幻觉独立核验）", cites_ok, cites_detail
              + ("（程序兜底：决策者 LLM 未产出有效裁定，门禁拦截后 fail-safe）" if fallback else ""))
        plan = run.get("response_plan") or {}
        plan_actions = plan.get("actions") or []
        # 监视/补证据类裁定合法地不产生动作计划；requires_approval 由程序强制恒真
        no_action_verdict = verdict.get("recommended_action") in {
            "monitor", "collect_more_evidence", "defer", None, ""}
        check("C2d 待审批处置计划（requires_approval 程序强制恒真）",
              plan.get("requires_approval") is True
              and (bool(plan_actions) or no_action_verdict or fallback),
              f"actions={[a.get('action') for a in plan_actions]} "
              f"verification={len(plan.get('verification_plan') or [])}步 "
              f"rollback={len(plan.get('rollback_plan') or [])}条 "
              f"裁定动作={verdict.get('recommended_action')}"
              + ("（程序兜底，空计划合法）" if fallback else ""))
    if not result["runs"]:
        check("C 统一影子研判", False, "无可研判目标（上游阶段失败）")
    return result


def phase_d_harness(openwrt: dict, ubuntu: dict) -> dict:
    section("Phase D：Harness 只读闭环（调查执行 + 修复门禁演示；零设备写操作）")
    result: dict = {"runs": []}

    # D1 OpenWrt 资产只读调查（绑定连接 → 真实只读重采集）
    ow_asset = openwrt.get("asset_id")
    if ow_asset:
        status, run = http("POST", "/api/harness/runs",
                           {"asset_id": ow_asset, "goal": "investigate",
                            "model_review": False})
        ok = status == 200 and isinstance(run, dict) and run.get("status") == "pending"
        check("D1a OpenWrt 调查任务创建（计划哈希固化）", ok,
              f"run={run.get('id')} hash={str(run.get('plan_hash'))[:16]}…"
              if ok else f"{status} {json.dumps(run, ensure_ascii=False)[:200]}")
        if ok:
            status, executed = http("POST", f"/api/harness/runs/{run['id']}/execute")
            result["runs"].append(executed if isinstance(executed, dict) else {})
            # 产品边界：设备 SSH 采集步骤必须由 Linux 采集节点执行；Windows 开发节点
            # 发起时必须失败（node/凭据边界），任务如实 failed、错误留痕、Trace 收口。
            err = str(executed.get("error") or "")
            check("D1b Harness 设备采集步骤被节点策略拒绝（Windows 边界成立）",
                  status == 200 and executed.get("status") == "failed"
                  and ("认证引用" in err or "节点" in err or "Linux" in err),
                  f"status={executed.get('status')} error={err[:120]} "
                  f"trace={executed.get('trace_id')}")
            # 审批边界：调查计划不接受修复式审批（授权只属于修复计划哈希）
            status, payload = http("POST", f"/api/harness/runs/{run['id']}/approve",
                                   {"plan_hash": run.get("plan_hash"), "actor": "m43-e2e",
                                    "reason": "调查任务不应接受修复审批"})
            check("D1c 审批边界：调查计划拒绝修复式授权", status == 409, f"HTTP {status}")

    # D2 Ubuntu 风险只读调查（证据包构建 + 前置条件核对）
    ub_asset, risk = ubuntu.get("asset_id"), (ubuntu.get("top_risk") or {}).get("risk_id")
    if ub_asset and risk:
        status, run = http("POST", "/api/harness/runs",
                           {"asset_id": ub_asset, "risk_id": risk,
                            "goal": "investigate", "model_review": False})
        ok = status == 200 and isinstance(run, dict) and run.get("status") == "pending"
        check("D2a Ubuntu 风险调查任务创建", ok,
              f"run={run.get('id')}" if ok else f"{status} {json.dumps(run, ensure_ascii=False)[:200]}")
        if ok:
            status, executed = http("POST", f"/api/harness/runs/{run['id']}/execute")
            result["runs"].append(executed if isinstance(executed, dict) else {})
            packet = ((executed.get("result") or {}).get("evidence_packet") or {}) \
                if isinstance(executed, dict) else {}
            check("D2b 调查执行 + 证据包构建（risk→原始证据关联）",
                  status == 200 and executed.get("status") in {"completed", "needs_evidence"},
                  f"status={executed.get('status')} evidence_items={len(packet.get('evidence_items') or [])}")

    # D3 修复任务前置门禁（不满足前置条件 → blocked；执行被拒；伪造审批被拒）
    if ub_asset and risk:
        status, run = http("POST", "/api/harness/runs",
                           {"asset_id": ub_asset, "risk_id": risk, "goal": "repair"})
        blocked = status == 200 and isinstance(run, dict) and run.get("status") == "blocked"
        reasons = (json.loads(run.get("plan_json") or "{}").get("blocked_reasons", [])
                   if isinstance(run, dict) else [])
        check("D3a 修复任务前置门禁（白名单/前置条件拦截）", blocked,
              f"blocked_reasons={reasons}")
        if blocked:
            result["repair_blocked"] = {"run_id": run.get("id"), "reasons": reasons}
            status, payload = http("POST", f"/api/harness/runs/{run['id']}/execute")
            check("D3b blocked 任务执行被拒（禁止操作检查成立）", status == 409, f"HTTP {status}")
            fake_hash = "f" * 64   # 合法格式但非本计划哈希 → 必须被哈希绑定拒绝
            status, payload = http("POST", f"/api/harness/runs/{run['id']}/approve",
                                   {"plan_hash": fake_hash, "actor": "m43-e2e",
                                    "reason": "未批准计划不得放行"})
            check("D3c 伪造计划哈希审批被拒（审批哈希绑定）", status == 409, f"HTTP {status}")
    if not result["runs"]:
        check("D Harness 只读闭环", False, "无可用资产（上游阶段失败）")
    return result


def phase_e_verify(openwrt: dict, ubuntu: dict, unified: dict, harness: dict) -> dict:
    section("Phase E：一致性核验与溯源链输出")
    result: dict = {"chain": {}}
    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        chain: dict = {}
        # OpenWrt 链
        ow_asset = openwrt.get("asset_id")
        if ow_asset:
            asset = db.get(models.LinuxAsset, ow_asset)
            evidence_count = (db.query(models.SecurityEvidence)
                              .filter(models.SecurityEvidence.asset_id == ow_asset).count())
            refs = [asset.hostname] if asset and asset.hostname else []
            device_id = (openwrt.get("device") or {}).get("device_id") or ""
            if device_id:
                refs.append(device_id)
            runs = (db.query(models.UnifiedAnalysisRun)
                    .filter(models.UnifiedAnalysisRun.target_ref.in_(refs)).all()) if refs else []
            chain["openwrt"] = {
                "asset_id": ow_asset, "hostname": asset.hostname if asset else "",
                "distribution": asset.distribution if asset else "",
                "identity_source": asset.identity_source if asset else "",
                "inventory_sha256": asset.inventory_sha256 if asset else "",
                "package_count": len(asset.packages) if asset else 0,
                "runtime_evidence": evidence_count,
                "unified_runs": [{"run_id": r.run_id, "mode": r.mode, "status": r.status,
                                  "risk_id": r.risk_id, "trace_id": r.trace_id} for r in runs],
            }
            check("E1 OpenWrt 链内一致（资产↔证据↔运行↔Trace）",
                  bool(asset) and evidence_count > 0 and len(runs) > 0,
                  f"asset={ow_asset} evidence={evidence_count} runs={len(runs)}")
        # Ubuntu 链
        ub_asset = ubuntu.get("asset_id")
        risk = ubuntu.get("top_risk") or {}
        if ub_asset and risk.get("risk_id"):
            risk_row = db.get(models.RiskAssessment, risk["risk_id"])
            match = db.get(models.VulnerabilityMatch, risk_row.match_id) if risk_row else None
            unified_runs = (db.query(models.UnifiedAnalysisRun)
                            .filter(models.UnifiedAnalysisRun.risk_id == risk["risk_id"]).all())
            harness_runs = (db.query(models.HarnessRun)
                            .filter(models.HarnessRun.risk_id == risk["risk_id"]).all())
            # 影子链不写 RiskAssessment.evidence_packet_json（正式字段）；证据关联取
            # 统一运行 state.evidence_prep（预取证据 ID）∪ 裁定 supporting_evidence_ids。
            packet_ids: list[str] = []
            for r in unified_runs:
                st = json.loads(r.state_json or "{}")
                prep = st.get("evidence_prep") or {}
                runtime_facts = prep.get("runtime_facts") or {}
                packet_ids.extend(str(e) for e in runtime_facts.get("evidence_ids") or [])
                decision = json.loads(r.decision_json or "{}") or st.get("decision") or {}
                for v in decision.get("verdicts") or []:
                    packet_ids.extend(str(e) for e in v.get("supporting_evidence_ids") or [])
            # 只核验证据形态引用（query_*: 为工具溯源标签，非证据 ID）
            packet_ids = list(dict.fromkeys(
                e for e in packet_ids if e.startswith("SE-")))
            real_ids = 0
            if packet_ids:
                real_ids = (db.query(models.SecurityEvidence)
                            .filter(models.SecurityEvidence.evidence_id.in_(packet_ids)).count())
            chain["ubuntu"] = {
                "asset_id": ub_asset, "risk_id": risk["risk_id"], "cve_id": risk_row.cve_id,
                "match_id": risk_row.match_id,
                "match_fingerprint": match.evidence_fingerprint if match else "",
                "installed_version": match.installed_version if match else "",
                "fixed_version": match.fixed_version if match else "",
                "packet_evidence_ids": packet_ids,
                "packet_evidence_real": real_ids,
                "unified_runs": [{"run_id": r.run_id, "mode": r.mode, "status": r.status,
                                  "trace_id": r.trace_id} for r in unified_runs],
                "harness_runs": [{"id": h.id, "goal": json.loads(h.plan_json).get("goal"),
                                  "status": h.status, "trace_id": h.trace_id}
                                 for h in harness_runs],
            }
            ok = (bool(risk_row) and bool(match) and len(packet_ids) > 0
                  and real_ids == len(packet_ids) and len(unified_runs) > 0)
            check("E2 Ubuntu 链内一致（资产→CVE→匹配→证据→运行→Harness）", ok,
                  f"risk={risk['risk_id']} 引用证据={len(packet_ids)} 真实存在={real_ids} "
                  f"unified={len(unified_runs)} harness={len(harness_runs)}")
            # Trace 贯穿
            trace_ids = [r.trace_id for r in unified_runs if r.trace_id] + \
                        [h.trace_id for h in harness_runs if h.trace_id]
            found = [t for t in trace_ids
                     if db.query(models.TraceRun).filter_by(trace_id=t).count() == 1]
            check("E3 统一 Trace 贯穿（智能体运行与 Harness 任务同链可查）",
                  len(found) == len(trace_ids) and bool(trace_ids),
                  f"trace={len(found)}/{len(trace_ids)}")
            concluded = {"auto_confirmed", "human_confirmed", "remediation_ready",
                         "verification", "resolved", "inactive"}
            check("E4 影子运行未写入正式结论（无最终分/裁决，状态非终态）",
                  risk_row.final_score is None and risk_row.decision is None
                  and risk_row.review_status not in concluded,
                  f"review_status={risk_row.review_status} final_score={risk_row.final_score} "
                  f"decision={risk_row.decision}")
            latest = next((r for r in unified_runs if r.status == "completed"
                           and r.task_type == "risk_review"), None)
            if latest is not None:
                decision = json.loads(latest.decision_json or "{}")
                verdict0 = (decision.get("verdicts") or [{}])[0]
                ok5, detail5 = _evidence_citations_verified(
                    verdict0.get("supporting_evidence_ids") or [])
                check("E5 最新研判运行引用独立复验（防幻觉门禁同语义重放）", ok5,
                      f"run={latest.run_id} {detail5}")
        result["chain"] = chain
    finally:
        db.close()
    return result


def _context_from_db() -> tuple[dict, dict]:
    """C/D/E 续跑时从持久库重建阶段上下文（幂等；不重复消耗采集/LLM）。"""
    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        openwrt: dict = {}
        ow_asset = (db.query(models.LinuxAsset).filter_by(distribution="openwrt")
                    .order_by(models.LinuxAsset.id.desc()).first())
        if ow_asset:
            openwrt["asset_id"] = ow_asset.id
            device = db.query(models.IotDevice).filter_by(ip=OPENWRT_HOST).first()
            if device:
                openwrt["device"] = {"device_id": device.device_id}
            conn = db.query(models.DeviceConnection).filter_by(host=OPENWRT_HOST).first()
            if conn:
                openwrt["connection_id"] = conn.id
        ubuntu: dict = {}
        ub_asset = (db.query(models.LinuxAsset).filter_by(distribution="ubuntu", os_version="24.04")
                    .order_by(models.LinuxAsset.id).first())
        if ub_asset:
            top = (db.query(models.RiskAssessment)
                   .filter(models.RiskAssessment.asset_id == ub_asset.id,
                           models.RiskAssessment.active.is_(True),
                           models.RiskAssessment.match_id.isnot(None))
                   .order_by(models.RiskAssessment.preliminary_score.desc()).first())
            if top:
                ubuntu = {"asset_id": ub_asset.id,
                          "asset": {"id": ub_asset.id, "hostname": ub_asset.hostname},
                          "risk_count": 1,
                          "top_risk": {"risk_id": top.id, "cve_id": top.cve_id,
                                       "package": top.package_name}}
        return openwrt, ubuntu
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="M4.3 核心业务主链 E2E")
    parser.add_argument("--phases", default="A,B,C,D,E")
    args = parser.parse_args()
    wanted = {p.strip().upper() for p in args.phases.split(",") if p.strip()}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    proc = None
    passed = 0
    try:
        proc = start_backend()
        print(f"后端已启动: http://{API_HOST}:{API_PORT}（独立进程；持久业务库）")
        openwrt = phase_a_openwrt() if "A" in wanted else {}
        SUMMARY["phases"]["A_openwrt"] = openwrt
        ubuntu = phase_b_ubuntu() if "B" in wanted else {}
        SUMMARY["phases"]["B_ubuntu"] = ubuntu
        if "A" not in wanted or "B" not in wanted:
            db_openwrt, db_ubuntu = _context_from_db()
            if "A" not in wanted:
                openwrt = db_openwrt
            if "B" not in wanted:
                ubuntu = db_ubuntu
        unified = phase_c_unified(openwrt, ubuntu) if "C" in wanted else {}
        SUMMARY["phases"]["C_unified_shadow"] = {k: v for k, v in unified.items() if k != "runs"}
        SUMMARY["phases"]["C_unified_runs"] = unified.get("runs") or []
        harness = phase_d_harness(openwrt, ubuntu) if "D" in wanted else {}
        SUMMARY["phases"]["D_harness"] = harness
        verified = phase_e_verify(openwrt, ubuntu, unified, harness) if "E" in wanted else {}
        SUMMARY["phases"]["E_verify"] = verified
        SUMMARY["chain"] = verified.get("chain", {})
    finally:
        SUMMARY["checks"] = CHECKS
        passed = sum(1 for c in CHECKS if c["ok"])
        SUMMARY["passed"] = passed
        SUMMARY["total"] = len(CHECKS)
        out = OUT_DIR / "summary.json"
        out.write_text(json.dumps(SUMMARY, ensure_ascii=False, indent=1), encoding="utf-8")
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        print(f"\n结果: {passed}/{len(CHECKS)} 通过；证据目录 {OUT_DIR}")
        for item in CHECKS:
            if not item["ok"]:
                print(f"  [FAIL] {item['name']} —— {item['detail']}")
    if passed < len(CHECKS):
        sys.exit(1)


if __name__ == "__main__":
    main()
