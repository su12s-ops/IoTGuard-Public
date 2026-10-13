"""Narrow device tools. No model-supplied commands or persisted credentials."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import time
from pathlib import Path

import paramiko
from fastapi import HTTPException, Request


class DeviceOperationError(ValueError):
    """Public diagnostics never include library errors or credential values."""
    def __init__(self, code, message, *, host_identity="not_attempted", authentication="not_attempted", exit_status=None):
        super().__init__(message)
        self.code = code
        self.host_identity = host_identity
        self.authentication = authentication
        self.exit_status = exit_status


class HostKeyMismatch(paramiko.SSHException):
    pass


def collection_only_mode():
    return os.getenv("LINUXGUARD_DEPLOYMENT_MODE", "standard") == "collection_only"


def collector_node():
    return {"id": os.getenv("LINUXGUARD_COLLECTOR_NODE_ID", "backend-local"),
            "platform": platform.system(), "mode": os.getenv("LINUXGUARD_DEPLOYMENT_MODE", "standard")}


def connection_signature(row):
    fields = {key: getattr(row, key) for key in ("id", "asset_id", "host", "port", "username", "auth_type",
        "credential_env", "key_path_env", "key_passphrase_env", "host_key_sha256", "enabled")}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def require_control(request: Request) -> None:
    expected = os.getenv("LINUXGUARD_CONTROL_TOKEN", "")
    supplied = request.headers.get("X-Control-Token", "")
    if not expected:
        raise HTTPException(503, "请在后端配置 LINUXGUARD_CONTROL_TOKEN 后启用设备操作。")
    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(401, "设备操作令牌无效。")


def allowed_networks():
    raw = os.getenv("LINUXGUARD_DISCOVERY_CIDRS", "")
    try:
        return [ipaddress.ip_network(item.strip(), strict=True) for item in raw.split(",") if item.strip()]
    except ValueError as exc:
        raise ValueError("后端 LINUXGUARD_DISCOVERY_CIDRS 配置无效") from exc


def allowed_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("设备地址必须是明确的 IP，不接受域名或 URL") from exc
    if address.is_multicast or address.is_unspecified or not any(address in n for n in allowed_networks()):
        raise ValueError("设备地址不在后端配置的允许网段内")
    return str(address)


class PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint

    def missing_host_key(self, client, hostname, key):
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if not hmac.compare_digest(actual, self.fingerprint):
            raise HostKeyMismatch("SSH host key fingerprint mismatch")
        if client is not None:
            client._iotguard_host_key_verified = True


def open_connection(connection):
    if collection_only_mode() and platform.system() != "Linux":
        raise DeviceOperationError("node_platform_invalid", "受控采集模式仅允许在 Ubuntu/Linux 节点执行 SSH")
    if not connection.enabled:
        raise DeviceOperationError("connection_disabled", "设备连接已禁用")
    host = allowed_host(connection.host)
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", connection.host_key_sha256 or ""):
        raise DeviceOperationError("host_key_unconfigured", "须先通过可信渠道配置明确的 SSH 主机指纹")
    auth_type = getattr(connection, "auth_type", None) or "password"
    def reference(name):
        if not re.fullmatch(r"LINUXGUARD_DEVICE_[A-Z0-9_]{1,80}", name or ""):
            raise DeviceOperationError("authentication_reference_invalid", "设备凭据必须来自专用 LINUXGUARD_DEVICE_ 环境变量")
        value = os.getenv(name, "")
        if not value:
            raise DeviceOperationError("authentication_reference_missing", "后端尚未设置设备认证引用变量")
        return value

    auth = {}
    if auth_type == "password":
        auth["password"] = reference(connection.credential_env)
    elif auth_type == "ssh_key":
        raw_path = reference(getattr(connection, "key_path_env", ""))
        path = Path(raw_path).expanduser()
        # A server-side path reference is accepted; key material never enters API payloads.
        try:
            usable = path.is_absolute() and path.is_file() and path.stat().st_size <= 65536
        except OSError as exc:
            raise DeviceOperationError("key_reference_unavailable", "无法检查后端私钥引用文件") from exc
        if not usable:
            raise DeviceOperationError("key_reference_invalid", "私钥引用须指向后端可读的绝对文件路径，且文件不能超过 64 KB")
        passphrase_ref = getattr(connection, "key_passphrase_env", "")
        passphrase = reference(passphrase_ref) if passphrase_ref else None
        try:
            auth["pkey"] = paramiko.Ed25519Key.from_private_key_file(str(path), password=passphrase)
        except (paramiko.SSHException, OSError, ValueError) as exc:
            raise DeviceOperationError("key_load_failed", "无法加载 ED25519 私钥，请核对后端密钥引用和口令配置") from exc
    else:
        raise DeviceOperationError("authentication_type_unsupported", "不支持的设备认证方式")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey(connection.host_key_sha256))
    try:
        client.connect(host, port=connection.port, username=connection.username, **auth,
                       allow_agent=False, look_for_keys=False, timeout=8, auth_timeout=8, banner_timeout=8)
    except HostKeyMismatch as exc:
        client.close()
        raise DeviceOperationError("host_key_mismatch", "SSH 主机指纹不匹配，认证与采集已阻止", host_identity="failed") from exc
    except paramiko.AuthenticationException as exc:
        verified = bool(getattr(client, "_iotguard_host_key_verified", False))
        client.close()
        raise DeviceOperationError("authentication_failed", "SSH 身份认证失败", host_identity="verified" if verified else "unknown",
                                   authentication="failed") from exc
    except Exception as exc:
        verified = bool(getattr(client, "_iotguard_host_key_verified", False))
        client.close()
        raise DeviceOperationError("ssh_connection_failed", "SSH 连接失败，请核对授权地址、指纹与节点认证引用",
                                   host_identity="verified" if verified else "unknown", authentication="unknown") from exc
    return client


def run_fixed_script(client, script: str, timeout: int = 45, max_bytes: int = 2_000_000) -> str:
    """Only callers holding a fixed backend tool may provide script text."""
    stdin, stdout, stderr = client.exec_command("sh -s", timeout=8)
    channel = stdout.channel
    try:
        stdin.write(script)
        stdin.flush()
        channel.shutdown_write()
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                output.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(65536))
            if len(output) + len(errors) > max_bytes:
                raise ValueError("设备输出超出上限；采集被停止")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                raise TimeoutError("设备工具执行超时；需复查远端状态")
            time.sleep(0.01)
        status = channel.recv_exit_status()
        if status != 0:
            # Do not expose potentially sensitive remote output in API errors.
            raise DeviceOperationError("collector_exit_failed", f"设备工具执行失败，退出码 {status}", exit_status=status)
        try:
            return output.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DeviceOperationError("output_encoding_invalid", "设备采集输出不是有效 UTF-8") from exc
    finally:
        channel.close()
