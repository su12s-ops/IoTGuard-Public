"""通用下载工具（仅公网 http/https 资源）。用法: python download.py <url> <out> [proxy]
proxy 支持 http://host:port 或 socks5://host:port

安全约束（SSRF 防护）：
- 仅 http/https，拒绝 URL 携带用户名/密码；
- 每次请求前解析主机名并阻断环回/私有/保留/链路本地/组播地址（含重定向目标）；
- 禁止自动重定向，手动逐跳复验（最多 5 跳）；
- 输出路径禁止 ".." 段，写入限制在当前工作目录子树内。
"""
import ipaddress
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.request import HTTPRedirectHandler

MAX_REDIRECTS = 5
_opener = urllib.request.build_opener(
    type("_NoRedirect", (HTTPRedirectHandler,), {"redirect_request": lambda *a, **k: None}))


def _checked_url(url: str) -> str:
    """请求前校验：协议白名单 + 无凭据 + 解析后 IP 必须为公网单播地址。"""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"仅允许 http/https URL: {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise ValueError("URL 不允许携带用户名/密码")
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("URL 缺少主机名")
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                                       proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ValueError(f"主机名解析失败: {hostname}") from exc
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    for address in addresses:
        if (address.is_loopback or address.is_private or address.is_reserved or address.is_link_local
                or address.is_multicast or address.is_unspecified):
            raise ValueError(f"拒绝非公网地址目标: {hostname} -> {address}")
    return url


def _checked_output(out: str) -> Path:
    parts = out.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("输出路径不允许包含 .. 段")
    resolved = Path(out).resolve()
    if not resolved.is_relative_to(Path.cwd().resolve()):
        raise ValueError("输出路径必须位于当前工作目录内")
    return resolved


def _fetch(url: str) -> bytes:
    for _ in range(MAX_REDIRECTS + 1):
        _checked_url(url)
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with _opener.open(request, timeout=150) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "") if exc.code in (301, 302, 303, 307, 308) else ""
            if not location:
                raise
            url = urllib.parse.urljoin(url, location)
    raise ValueError(f"重定向次数超过 {MAX_REDIRECTS}")


url, out = sys.argv[1], sys.argv[2]
proxy = sys.argv[3] if len(sys.argv) > 3 else None

if proxy and proxy.startswith("socks5"):
    import socks
    host, port = proxy.replace("socks5://", "").split(":")
    socks.set_default_proxy(socks.SOCKS5, host, int(port))
    socket.socket = socks.socksocket
elif proxy:
    _opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        type("_NoRedirect", (HTTPRedirectHandler,), {"redirect_request": lambda *a, **k: None}))

try:
    out_path = _checked_output(out)
    data = _fetch(url)
    out_path.write_bytes(data)
    print(f"OK {len(data)} bytes -> {out}")
except Exception as exc:
    print(f"FAIL {type(exc).__name__}: {exc}")
    sys.exit(1)
