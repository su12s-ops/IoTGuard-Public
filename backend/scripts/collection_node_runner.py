#!/usr/bin/env python3
"""IoTGuard Linux 采集节点 runner（在 Ubuntu/Linux 采集节点上运行；仅标准库）。

角色：后端（含 Windows 开发节点）不执行设备 SSH；本 runner 在已登记的
Linux 采集节点上运行，拉取（pull）后端转交的采集任务并执行：

  1. GET  /api/iot/collection-node/claim   原子领取一个 queued_remote 任务；
  2. 校验 Collector 脚本 SHA256 与任务钉扎一致、目标地址在授权网段内；
  3. ssh-keyscan 取主机公钥 → 本地计算 SHA256 指纹与任务钉扎值比对 →
     仅在一致时以该公钥构造临时 known_hosts（先核后连，TOFU 免除）；
  4. ssh BatchMode + 固定脚本经 stdin 下发（sh -s），只读采集；
  5. POST /api/iot/collection-node/results/{run_id} 回传结果或明确的失败码。

安全边界：
  - 私钥材料只从本节点环境变量引用的本地路径读取，永不进入任何请求载荷；
  - 主机指纹不一致 → 立即失败上报（host_key_mismatch），不降级不重试其他主机；
  - 采集失败必须如实回传 error_code，绝不以旧清单或静默跳过代替本轮结果；
  - 所有请求携带 X-Collection-Node-Token；本 runner 不落盘任何设备数据副本
    （临时 known_hosts 目录用后即删）；
  - 后端 URL 只允许 http/https；请求前解析目标主机并做地址边界校验：
    链路本地/未指定/组播地址一律拒绝，环回与私网目标均须在显式允许列表内放行
    （LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS，逗号分隔 IP/CIDR；节点与后端
    同处授权实验网段是本产品部署形态，私网放行必须由操作员逐项声明）。

用法：
  python3 collection_node_runner.py --once    # 领取并执行一个任务后退出
  python3 collection_node_runner.py --serve   # 常驻轮询（产品运行模式）

环境变量：
  LINUXGUARD_COLLECTION_NODE_ID        节点身份（须与后端登记一致）
  LINUXGUARD_NODE_BACKEND_URL          后端基地址，通过部署环境配置
  LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS 允许联系的后端地址白名单（IP/CIDR）
  LINUXGUARD_NODE_TOKEN                节点独立令牌（匹配后端 LINUXGUARD_COLLECTION_NODE_TOKEN）
  LINUXGUARD_DEVICE_OPENWRT_KEY        OpenWrt 设备私钥在本节点的路径
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


MAX_OUTPUT_BYTES = 2_000_000
SSH_CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 180


class RunnerError(RuntimeError):
    """携带稳定 error_code 的节点侧失败；冒号前缀即 error_code。"""


def log(message: str) -> None:
    print(f"[collection-node {time.strftime('%H:%M:%S')}] {message}", flush=True)


def env_required(name: str) -> str:
    value = (os.getenv(name, "") or "").strip()
    if not value:
        raise SystemExit(f"缺少环境变量 {name}")
    return value


def parse_address_allowlist(raw: str) -> list:
    networks = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            networks.append(ipaddress.ip_network(item, strict=False))
        else:
            networks.append(ipaddress.ip_network(f"{item}/128" if ":" in item else f"{item}/32"))
    return networks


def validate_backend_url(base_url: str, allowlist: list) -> str:
    """http/https 限定 + host 解析 + 地址边界校验，返回规范化 URL。"""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit("LINUXGUARD_NODE_BACKEND_URL 只允许 http/https 且须包含主机名")
    if parsed.username or parsed.password:
        raise SystemExit("后端 URL 不允许内嵌凭据")
    try:
        answers = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    except OSError as exc:
        raise SystemExit(f"后端主机名解析失败: {exc}")
    for address_text in answers:
        address = ipaddress.ip_address(address_text)
        if (address.is_link_local or address.is_multicast
                or address.is_unspecified or address.is_reserved):
            raise SystemExit(f"后端地址边界校验失败：拒绝 {address}")
        if allowlist and not any(address in network for network in allowlist):
            raise SystemExit(f"后端地址不在 LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS 白名单内：{address}")
        if not allowlist:
            raise SystemExit(f"未配置后端显式白名单，拒绝 {address}")
    return base_url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


class Backend:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        if not path.startswith("/") or ".." in path or ":" in path:
            raise ValueError(f"非法 API 路径: {path!r}")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json", "X-Collection-Node-Token": self.token})
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
                raw = response.read().decode("utf-8", "ignore")
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "ignore")
            try:
                return exc.code, json.loads(raw)
            except ValueError:
                return exc.code, {"raw": raw[:300]}
        except urllib.error.URLError as exc:
            log(f"后端不可达: {exc.reason}")
            return 0, None
        except (OSError, http.client.HTTPException) as exc:
            # 后端重启/代理中断会把 RemoteDisconnected 等裸连接错误抛进这里；
            # 节点必须存活并在下个轮询周期重试，绝不能因此退出常驻循环。
            log(f"后端连接中断: {type(exc).__name__}: {exc}")
            return 0, None


def collector_fingerprint(script_text: str) -> str:
    return hashlib.sha256(script_text.encode("utf-8")).hexdigest()


def host_in_authorized_cidrs(host: str, cidrs: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        return False
    for item in cidrs or []:
        try:
            if address in ipaddress.ip_network(item, strict=True):
                return True
        except ValueError:
            continue
    return False


def resolve_contained_path(directory: Path, name: str) -> Path:
    """规范化目录内路径并校验包含关系，杜绝 ../ 逃逸。"""
    base = directory.resolve()
    candidate = (base / name).resolve()
    if candidate.parent != base:
        raise RunnerError("path_invalid: 路径越界")
    return candidate


def fetch_and_verify_host_key(host: str, pinned: str, workdir: Path, port: int = 22) -> Path:
    """ssh-keyscan 取键 → 指纹比对 → 返回钉扎 known_hosts 文件路径。"""
    if not pinned.startswith("SHA256:") or len(pinned) != len("SHA256:") + 43:
        raise RunnerError("host_key_invalid: 任务中的主机指纹格式无效")
    scan = subprocess.run(["ssh-keyscan", "-p", str(port), "-t", "ed25519", "-T", "8", host],
                          capture_output=True, text=True, timeout=20)
    matched_blob = ""
    for line in scan.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) != 3 or parts[1] != "ssh-ed25519":
            continue
        try:
            blob = base64.b64decode(parts[2])
        except (ValueError, TypeError):
            continue
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        if actual == pinned:
            matched_blob = parts[2]
            break
    if not matched_blob:
        # 如实失败：键取不到或指纹不一致都走同一错误码，不给网络侧探听空间。
        raise RunnerError("host_key_mismatch: 主机指纹与任务钉扎不一致或取键失败")
    known_hosts = resolve_contained_path(workdir, "known_hosts")
    key_host = host if port == 22 else f"[{host}]:{port}"
    known_hosts.write_text(f"{key_host} ssh-ed25519 {matched_blob}\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    return known_hosts


def run_collector(assignment: dict, key_path: str, workdir: Path) -> str:
    """指纹钉扎 + BatchMode + 固定脚本 stdin 下发；返回采集输出。"""
    connection = assignment["connection"]
    host = connection["host"]
    known_hosts = fetch_and_verify_host_key(host, connection.get("host_key_sha256", ""), workdir, int(connection.get("port", 22)))
    command = [
        "ssh", "-i", key_path, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "StrictHostKeyChecking=yes",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}", "-p", str(connection.get("port", 22)),
        f"{connection['username']}@{host}",
        "bash -s -- /dev/stdout" if assignment.get("collector_type") == "linux_ssh" else "sh -s",
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(
            assignment["collector_script"].encode("utf-8"), timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise TimeoutError("采集超时，远端结束状态未知")
    if process.returncode != 0:
        detail = "SSH 或固定 Collector 失败；未提交新清单"
        raise RunnerError(f"collector_exit_{process.returncode}: {detail}")
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise RunnerError("collector_output_too_large: 采集输出超出上限")
    return stdout.decode("utf-8", "strict")


def execute_assignment(backend: Backend, assignment: dict) -> None:
    run_id = assignment["run_id"]
    log(f"领取任务 {run_id}（collector={assignment.get('collector_type')}）")
    key_env = assignment["connection"].get("key_path_env") or ""
    key_path = (os.getenv(key_env, "") or "").strip()
    host = assignment["connection"]["host"]
    try:
        local = assignment.get("execution") == "node_local"
        if assignment.get("collector_type") not in {"openwrt_ssh", "linux_ssh"}:
            raise RunnerError("collector_unsupported: 仅允许已登记固定 Collector")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", assignment["connection"].get("username", "")):
            raise RunnerError("username_invalid: 非法 SSH 用户名")
        if assignment["connection"].get("auth_type") != "ssh_key" or assignment["connection"].get("key_passphrase_env"):
            raise RunnerError("authentication_unsupported: 节点当前须使用无口令的本地密钥引用")
        if not re.fullmatch(r"LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}", key_env):
            raise RunnerError("key_reference_invalid: 凭据引用命名不合规")
        if collector_fingerprint(assignment["collector_script"]) != assignment.get("collector_sha256"):
            raise RunnerError("collector_sha_mismatch: 脚本摘要与任务钉扎不一致")
        if local and (assignment.get("collector_type") != "linux_ssh" or socket.gethostname() != assignment["asset"]["hostname"]):
            raise RunnerError("node_identity_mismatch: 本机不是绑定的 Ubuntu 资产")
        if not local and not key_path:
            raise RunnerError(f"key_reference_missing: 节点未设置 {key_env}")
        key = Path(key_path).expanduser().resolve()
        if not local and (not key.is_absolute() or not key.is_file()):
            raise RunnerError("key_reference_invalid: 私钥引用须为本节点可读的绝对路径")
        if not host_in_authorized_cidrs(host, assignment.get("authorized_cidrs") or []):
            raise RunnerError("target_not_authorized: 目标地址不在授权网段")
        workdir = Path(tempfile.mkdtemp(prefix="iotguard-collect-"))
        try:
            workdir.chmod(0o700)
            if local:
                process = subprocess.run(["bash", "-s", "--", "/dev/stdout"],
                    input=assignment["collector_script"].encode(), capture_output=True, timeout=COMMAND_TIMEOUT)
                if process.returncode or len(process.stdout) > MAX_OUTPUT_BYTES:
                    raise RunnerError("local_collection_failed: 本机固定 Collector 执行失败或超限")
                text = process.stdout.decode("utf-8", "strict")
            else:
                text = run_collector(assignment, str(key), workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        status, payload = backend.request("POST", f"/api/iot/collection-node/results/{run_id}", {
            "node_id": os.getenv("LINUXGUARD_COLLECTION_NODE_ID", ""),
            "node_platform": "Linux",
            "local_hostname": socket.gethostname() if local else "",
            "status": "succeeded",
            "host_fingerprint_verified": not local,
            "ssh_authentication": "not_applicable" if local else "succeeded",
            "collector_sha256": assignment.get("collector_sha256"),
            "inventory_text": text,
            "output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "output_bytes": len(text.encode("utf-8")),
        })
        log(f"结果回传完成: HTTP {status} run_status={(payload or {}).get('status')}")
        accepted = {"completed"} if not assignment.get("harness_adapter") else {"awaiting_approval", "preflight_failed", "verified", "verification_required"}
        if status != 200 or (payload or {}).get("status") not in accepted:
            raise SystemExit("本轮结果未确认入库；不得显示采集成功")
    except TimeoutError as exc:
        report_failure(backend, run_id, "collector_timeout", str(exc), False)
    except RunnerError as exc:
        message = str(exc)
        code = message.split(":", 1)[0].strip() or "collection_failed"
        verified = False
        report_failure(backend, run_id, code, message, verified)
    except Exception as exc:  # noqa: BLE001 — 节点侧任何异常都必须以明确失败收口
        report_failure(backend, run_id, "collection_failed", f"{exc.__class__.__name__}: {exc}"[:300], False)


def report_failure(backend: Backend, run_id: str, code: str, detail: str, fingerprint_verified: bool) -> None:
    status, payload = backend.request("POST", f"/api/iot/collection-node/results/{run_id}", {
        "node_id": os.getenv("LINUXGUARD_COLLECTION_NODE_ID", ""),
        "node_platform": "Linux",
        "status": "failed",
        "error_code": code[:64],
        "detail": detail[:400],
        "host_fingerprint_verified": bool(fingerprint_verified),
        "ssh_authentication": "unknown",
    })
    log(f"失败已如实回传: code={code} HTTP {status} run_status={(payload or {}).get('status')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="IoTGuard Linux 采集节点 runner")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="领取并执行一个任务后退出")
    mode.add_argument("--serve", action="store_true", help="常驻轮询（产品运行模式）")
    parser.add_argument("--interval", type=int, default=15, help="serve 模式轮询间隔秒数")
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        raise SystemExit("采集节点必须在 Ubuntu/Linux 上运行")
    node_id = env_required("LINUXGUARD_COLLECTION_NODE_ID")
    base_url = validate_backend_url(
        env_required("LINUXGUARD_NODE_BACKEND_URL"),
        parse_address_allowlist(os.getenv("LINUXGUARD_NODE_ALLOWED_BACKEND_HOSTS", "")))
    token = env_required("LINUXGUARD_NODE_TOKEN")
    backend = Backend(base_url, token)

    while True:
        try:
            status, payload = backend.request(
                "GET", f"/api/iot/collection-node/claim?node_id={node_id}&node_platform=Linux")
        except Exception as exc:  # noqa: BLE001 — 常驻循环必须吞掉单次轮询异常并重试
            log(f"领取轮询异常: {type(exc).__name__}: {exc}")
            time.sleep(max(args.interval, 3))
            continue
        if status != 200 and args.once:
            raise SystemExit(f"领取失败 HTTP {status}: {payload}; 本轮未执行采集")
        assignment = ((payload or {}).get("assignment")) if status == 200 else None
        if assignment:
            execute_assignment(backend, assignment)
            if args.once:
                return
        elif args.once:
            log("没有待领取的采集任务")
            return
        time.sleep(max(args.interval, 3))


if __name__ == "__main__":
    main()
