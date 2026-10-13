"""智能设备在线识别：对授权范围内的单个目标做协议级探测，建立
Device → Service → Component 清单。

识别原则：
- 只依据目标真实返回的报文判断协议与产品（服务端先发的 SSH 横幅、HTTP 状态行
  与 Server/Title、RTSP OPTIONS 响应、MQTT CONNACK），不按端口号猜测。
- 设备身份优先来自设备自身暴露的只读身份接口（如 /api/system JSON），
  拿不到时降级为横幅/标题推断，并记录 identity_confidence。
- 风险分当前只是"服务暴露基线"（由识别到的事实计算），设备级 CVE 匹配
  在后续阶段接入 matching_engine，本阶段不伪造漏洞数量。
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl

from app import models

PROBE_USER_AGENT = "LinuxGuard-DeviceProbe/0.3"
DEFAULT_PROBE_PORTS = [22, 80, 443, 554, 1883, 8000, 8080, 8443, 8554, 8883]

# 暴露基线权重：仅由已识别服务的事实构成，上限 40（漏洞评分阶段接入后另行覆盖）。
_EXPOSURE_WEIGHTS = {"ssh": 12, "mqtt": 12, "rtsp": 8, "http": 8, "https": 8}
_EXPOSURE_ANON_BONUS = 6  # MQTT 匿名接入被实际验证时追加
_EXPOSURE_CAP = 40


def _connect(host: str, port: int, timeout: float) -> socket.socket | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except OSError:
        return None


def _recv_all(sock: socket.socket, idle_timeout: float = 1.2) -> bytes:
    chunks = bytearray()
    try:
        while len(chunks) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.extend(chunk)
    except (OSError, socket.timeout):
        pass
    return bytes(chunks)


def probe_ssh(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """SSH 服务端会先发送版本横幅，直接读取即可识别。"""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        # 真实 SSH 服务在连接后立即发送横幅；短暂等待即无横幅可视为非 SSH。
        sock.settimeout(min(timeout, 1.0))
        banner_bytes = b""
        try:
            while b"\r" not in banner_bytes and len(banner_bytes) < 255:
                chunk = sock.recv(64)
                if not chunk:
                    break
                banner_bytes += chunk
        except (OSError, socket.timeout):
            pass
        banner = banner_bytes.decode("ascii", errors="replace").strip()
        if not banner.startswith("SSH-"):
            return None
        # 完成版本交换礼貌收尾：回复客户端横幅再关闭。
        try:
            sock.sendall(b"SSH-2.0-" + PROBE_USER_AGENT.encode("ascii").replace(b"/", b"_") + b"\r\n")
        except OSError:
            pass
        product_token = banner.split("SSH-2.0-", 1)[-1].split("SSH-1.99-", 1)[-1]
        product_token = product_token.split(" ", 1)[0].strip() or "ssh"
        product, version = product_token, ""
        token_match = re.match(r"([A-Za-z][A-Za-z0-9]*?)[-_]?((?:[0-9][A-Za-z0-9_.-]*)?)$", product_token)
        if token_match and token_match.group(2):
            product, version = token_match.group(1), token_match.group(2)
        return {"service_type": "ssh", "product": product or product_token, "version": version,
                "banner": banner, "auth_state": "auth_required",
                "evidence": {"banner": banner}}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse_http_payload(payload: bytes) -> tuple[dict | None, str]:
    """解析 HTTP 响应报文（明文与 TLS 解密后的载荷共用）。"""
    if not payload.startswith(b"HTTP/"):
        return None, ""
    header_block, _, body = payload.partition(b"\r\n\r\n")
    lines = header_block.decode("iso-8859-1", errors="replace").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    server = headers.get("server", "")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body.decode("utf-8", errors="replace"),
                            re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    version = ""
    version_match = re.search(r"([A-Za-z][A-Za-z0-9_.-]*)/([0-9][A-Za-z0-9_.-]*)", server)
    if version_match:
        version = version_match.group(2)
    result = {"service_type": "http", "product": server or "http", "version": version,
              "banner": lines[0] if lines else "", "auth_state": "unknown",
              "evidence": {"status_line": lines[0] if lines else "", "server": server, "title": title}}
    return result, body.decode("utf-8", errors="replace")


def probe_http(host: str, port: int, timeout: float = 2.0, path: str = "/") -> tuple[dict | None, str]:
    """GET 探测；返回 (服务识别结果, 响应正文)。"""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None, ""
    try:
        request = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {PROBE_USER_AGENT}\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(request.encode("ascii"))
        payload = _recv_all(sock)
        return _parse_http_payload(payload)
    except OSError:
        return None, ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_https(host: str, port: int, timeout: float = 2.0, path: str = "/") -> tuple[dict | None, str]:
    """TLS 之上的 HTTP 指纹探测。仅做指纹识别，不校验证书（证书有效性不是
    服务指纹的一部分），识别结论仍以解密后的真实 HTTP 响应为准。"""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None, ""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=host)
    except (OSError, ssl.SSLError):
        try:
            sock.close()
        except OSError:
            pass
        return None, ""
    try:
        tls_sock.settimeout(timeout)
        request = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {PROBE_USER_AGENT}\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n")
        tls_sock.sendall(request.encode("ascii"))
        payload = _recv_all(tls_sock)
        result, body = _parse_http_payload(payload)
        if result:
            result["service_type"] = "https"
        return result, body
    except (OSError, ssl.SSLError):
        return None, ""
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


def probe_banner(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """通用横幅抓取兜底：先静默读取（SSH/FTP/SMTP 等服务端先发型协议），
    无数据再发送空行试探。只记录原始可读文本，不猜测协议与产品。"""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None

    def _read_some(wait: float) -> bytes:
        try:
            sock.settimeout(wait)
            return sock.recv(256)
        except (OSError, socket.timeout):
            return b""

    try:
        banner_bytes = _read_some(min(timeout, 1.0))
        if not banner_bytes:
            try:
                sock.sendall(b"\r\n")
            except OSError:
                return None
            banner_bytes = _read_some(min(timeout, 1.0))
        text = banner_bytes.decode("utf-8", errors="replace")
        # 二进制协议问候里可能混有可读片段；只保留可打印部分做证据。
        printable = "".join(ch for ch in text if ch.isprintable() or ch in "\t ").strip()
        if len(printable) < 4:
            return None
        return {"service_type": "unknown", "product": "", "version": "",
                "banner": printable[:256], "auth_state": "unknown",
                "evidence": {"raw_banner": text[:512], "method": "banner_grab",
                             "note": "仅横幅证据；未识别协议，不猜测产品与版本"}}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_rtsp(host: str, port: int, timeout: float = 2.0) -> dict | None:
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        payload = _recv_all(sock)
        text = payload.decode("utf-8", errors="replace")
        if not text.startswith("RTSP/"):
            return None
        status_line = text.split("\r\n", 1)[0]
        headers = {}
        for line in text.split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        server = headers.get("server", "")
        version = ""
        version_match = re.search(r"/([0-9][A-Za-z0-9_.-]*)", server)
        if version_match:
            version = version_match.group(1)
        return {"service_type": "rtsp", "product": server or "rtsp", "version": version,
                "banner": status_line, "auth_state": "unknown",
                "evidence": {"status_line": status_line, "public": headers.get("public", "")}}
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _mqtt_connect_packet(client_id: str = "linuxguard-probe") -> bytes:
    def mqtt_string(value: str) -> bytes:
        raw = value.encode("utf-8")
        return len(raw).to_bytes(2, "big") + raw

    variable = mqtt_string("MQTT") + bytes([0x04, 0x02, 0x00, 0x3C])  # v3.1.1, clean session
    payload = mqtt_string(client_id)
    body = variable + payload
    return bytes([0x10, len(body)]) + body


def probe_mqtt(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """发送真实 MQTT CONNECT，依据 CONNACK 判定（匿名接入/需要认证都算 MQTT）。"""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(_mqtt_connect_packet())
        header = b""
        try:
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    break
                header += chunk
        except (OSError, socket.timeout):
            pass
        if len(header) < 4 or header[0] != 0x20:
            return None
        return_code = header[3]
        auth_state = "anonymous_accepted" if return_code == 0 else "auth_required"
        sock.sendall(bytes([0xE0, 0x00]))  # DISCONNECT
        return {"service_type": "mqtt", "product": "mqtt-broker", "version": "", "banner": "",
                "auth_state": auth_state,
                "evidence": {"connack_return_code": return_code}}
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


_PORT_HINTS = {
    22: ("ssh", "http", "rtsp", "mqtt"),
    80: ("http", "rtsp", "mqtt", "ssh"),
    443: ("https", "http", "ssh", "mqtt", "rtsp"),
    554: ("rtsp", "http", "mqtt", "ssh"),
    1883: ("mqtt", "http", "rtsp", "ssh"),
    8883: ("mqtt", "https", "http", "rtsp", "ssh"),
    8000: ("http", "rtsp", "mqtt", "ssh"),
    8080: ("http", "rtsp", "mqtt", "ssh"),
    8443: ("https", "http", "mqtt", "rtsp", "ssh"),
    8554: ("rtsp", "http", "mqtt", "ssh"),
    # 常见互联网服务端口：服务端先发型协议优先横幅，其余按最可能的协议探测。
    21: ("banner", "ssh", "http"),
    23: ("banner", "ssh", "http"),
    25: ("banner", "ssh", "http"),
    587: ("banner", "ssh", "http"),
    3306: ("banner", "ssh", "http"),
    3389: ("banner", "ssh", "http"),
    5432: ("banner", "http", "ssh"),
    6379: ("banner", "http", "ssh"),
    9200: ("http", "https", "banner"),
}
_DEFAULT_PROBE_ORDER = ("ssh", "http", "https", "rtsp", "mqtt")


def identify_service(host: str, port: int, timeout: float = 2.0,
                     banner_fallback: bool = False) -> dict | None:
    """按协议有效性识别端口上的服务。端口只决定探测顺序（提示），
    结论一律以真实协议响应为准；未识别时按默认顺序重试。
    banner_fallback=True 时（互联网扫描路径），所有协议探测失败后保留
    原始横幅作为"未识别"证据，不猜测协议。"""
    def _probes():
        return {
            "ssh": lambda: probe_ssh(host, port, timeout),
            "http": lambda: probe_http(host, port, timeout)[0],
            "https": lambda: probe_https(host, port, timeout)[0],
            "rtsp": lambda: probe_rtsp(host, port, timeout),
            "mqtt": lambda: probe_mqtt(host, port, timeout),
            "banner": lambda: probe_banner(host, port, timeout),
        }

    probes = _probes()
    order = _PORT_HINTS.get(port, _DEFAULT_PROBE_ORDER)
    for kind in order:
        result = probes[kind]()
        if result:
            return result
    if banner_fallback and "banner" not in order:
        return probes["banner"]()
    return None


def _http_json(host: str, port: int, path: str, timeout: float = 2.0) -> dict | None:
    _, body = probe_http(host, port, timeout, path=path)
    if not body:
        return None
    try:
        start = body.index("{")
        end = body.rindex("}")
        parsed = json.loads(body[start:end + 1])
        return parsed if isinstance(parsed, dict) else None
    except (ValueError, json.JSONDecodeError):
        return None


def build_identity(host: str, service_results: dict[int, dict]) -> dict:
    """从真实响应推导设备身份。优先设备自身身份接口，其次横幅/标题。"""
    identity = {
        "device_name": "", "device_type": "unknown", "vendor": "", "model": "",
        "firmware_version": "", "os": "", "confidence": 0.0, "source": "banner_heuristic",
        "metadata": {},
    }
    http_ports = [port for port, result in service_results.items() if result["service_type"] == "http"]
    system_info = None
    for port in http_ports:
        for path in ("/api/system", "/system/info"):
            system_info = _http_json(host, port, path)
            if system_info:
                identity["source"] = "device_identity_endpoint"
                identity["confidence"] = 0.9
                identity["metadata"]["identity_endpoint"] = path
                break
        if system_info:
            break
    if system_info:
        for field in ("device_name", "device_type", "vendor", "model", "firmware_version", "os"):
            value = str(system_info.get(field, "")).strip()
            if value:
                identity[field] = value[:128]
        if system_info.get("mac_address"):
            identity["metadata"]["mac_address"] = str(system_info["mac_address"])
        if system_info.get("serial_number"):
            identity["metadata"]["serial_number"] = str(system_info["serial_number"])
        # 固件扩展元数据（第七阶段：board/build_id/遥测等来自设备自报或编译配置），
        # 仅原样保存为证据，不参与身份判重。
        for extra in ("board", "soc", "arch", "build_id", "device_id", "status", "uptime_s", "telemetry"):
            if extra in system_info:
                identity["metadata"][extra] = system_info[extra]
        # 设备自报的服务产品信息比横幅推断更权威，覆盖到识别结果。
        reported = system_info.get("services")
        if isinstance(reported, list):
            for item in reported:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("type", ""))
                product = str(item.get("product", "")).strip()
                if not product:
                    continue
                for result in service_results.values():
                    if result["service_type"] == kind:
                        result["product"] = product[:128]
                        version_match = re.search(r"([0-9][A-Za-z0-9_.-]*)\s*$", product)
                        if version_match:
                            result["version"] = version_match.group(1)[:64]
    else:
        # 降级：用 HTTP 标题/Server 头与 RTSP Server 头推断名称。
        clues = []
        for port, result in service_results.items():
            title = result.get("evidence", {}).get("title", "")
            server = result.get("evidence", {}).get("server", "")
            for clue in (title, server):
                if clue and len(clue) >= 3:
                    clues.append(clue)
        if clues:
            name = clues[0][:64]
            identity["device_name"] = name
            identity["confidence"] = 0.35
    # RTSP 在线通常意味着视频设备。
    if identity["device_type"] == "unknown" and any(r["service_type"] == "rtsp" for r in service_results.values()):
        identity["device_type"] = "video_device"
    if not identity["device_name"]:
        identity["device_name"] = f"unknown-device-{host}"
    return identity


def _device_key(identity: dict, host: str) -> str:
    mac = identity.get("metadata", {}).get("mac_address", "")
    basis = f"{identity.get('vendor', '')}|{identity.get('model', '')}|{mac or host}"
    return "DEV-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12].upper()


def _service_component(service: dict) -> tuple[str, str] | None:
    """从服务识别结果推导 (组件名, 版本)。未识别协议（横幅兜底）不推导组件。"""
    service_type = service["service_type"]
    product = service.get("product", "")
    version = service.get("version", "")
    if service_type == "ssh":
        return ("dropbear ssh", version) if "dropbear" in product.lower() else (product or "ssh-server", version)
    if service_type == "mqtt":
        return ("SmartCam MQTT broker" if "smartcam" in product.lower() else product or "mqtt-broker", version)
    if service_type in ("http", "https"):
        return (product or ("embedded httpd" if service_type == "http" else "https-server"), version)
    if service_type == "rtsp":
        return (product or "rtsp-service", version)
    return (product, version) if product else None


def _exposure_baseline(service_results: dict[int, dict]) -> tuple[float, dict]:
    factors = {}
    total = 0.0
    for result in service_results.values():
        service_type = result["service_type"]
        weight = _EXPOSURE_WEIGHTS.get(service_type, 4)
        total += weight
        factors[f"port_service:{service_type}"] = weight
        if service_type == "mqtt" and result.get("auth_state") == "anonymous_accepted":
            total += _EXPOSURE_ANON_BONUS
            factors["mqtt_anonymous_access"] = _EXPOSURE_ANON_BONUS
    return min(total, _EXPOSURE_CAP), factors


def upsert_device(db, host: str, ports: list[int] | None = None, timeout: float = 2.0,
                  banner_fallback: bool = False, scan_scope: str | None = None,
                  device_type_default: str | None = None) -> tuple[models.IotDevice, dict]:
    """探测目标端口 → 识别服务 → 推导身份 → 幂等写入设备/服务/组件清单。

    banner_fallback：所有协议探测失败时保留原始横幅（service_type=unknown）。
    scan_scope / device_type_default：互联网扫描路径标记来源，并在身份未能
    识别设备类型时使用调用方给定的保守默认类型（如 internet_server）。
    """
    target_ports = sorted(set(ports or DEFAULT_PROBE_PORTS))
    service_results: dict[int, dict] = {}
    refused = []
    for port in target_ports:
        result = identify_service(host, port, timeout, banner_fallback=banner_fallback)
        if result:
            service_results[port] = result
        else:
            refused.append(port)
    if not service_results:
        raise ValueError(f"{host} 指定端口均无响应或无法识别；未创建设备记录")

    identity = build_identity(host, service_results)
    if identity["device_type"] == "unknown" and device_type_default:
        identity["device_type"] = device_type_default
    if scan_scope:
        identity["metadata"]["scan_scope"] = scan_scope
    device_key = _device_key(identity, host)
    device = db.query(models.IotDevice).filter_by(device_id=device_key).one_or_none()
    if device is None:
        device = models.IotDevice(device_id=device_key)
        db.add(device)
        device.first_seen_at = models.utcnow()
    device.device_name = identity["device_name"] or device.device_name
    device.device_type = identity["device_type"]
    device.vendor = identity["vendor"]
    device.model = identity["model"]
    device.firmware_version = identity["firmware_version"]
    device.os = identity["os"]
    device.ip = host
    device.status = "online"
    device.identity_source = identity["source"]
    device.identity_confidence = identity["confidence"]
    device.metadata_json = json.dumps(identity["metadata"], ensure_ascii=False)
    baseline, factors = _exposure_baseline(service_results)
    device.risk_score, device.risk_score_basis = baseline, "service_exposure_baseline"
    device.security_status = "unassessed"  # 设备级漏洞匹配在后续阶段接入
    device.last_seen_at = models.utcnow()
    db.flush()  # 生成 device.id，供服务/组件外键使用

    for port, result in service_results.items():
        service = db.query(models.IotDeviceService).filter_by(device_row_id=device.id, port=port).one_or_none()
        if service is None:
            service = models.IotDeviceService(device_row_id=device.id, port=port)
            db.add(service)
            service.first_seen_at = models.utcnow()
        service.transport = "tcp"
        service.service_type = result["service_type"]
        service.product = result["product"][:128]
        service.version = result["version"][:64]
        service.banner = result["banner"][:2048]
        service.auth_state = result["auth_state"]
        service.status = "open"
        service.evidence_json = json.dumps(result["evidence"], ensure_ascii=False)
        service.last_seen_at = models.utcnow()
        db.flush()

    known_ports = {service.port for service in device.services}
    for port in known_ports - set(service_results):
        closed = db.query(models.IotDeviceService).filter_by(device_row_id=device.id, port=port).one()
        closed.status = "closed"
        closed.last_seen_at = models.utcnow()

    def put_component(name: str, component_type: str, version: str, cpe: str, source: str,
                      service_row_id: int | None):
        component = db.query(models.IotDeviceComponent).filter_by(device_row_id=device.id, component_name=name).one_or_none()
        if component is None:
            component = models.IotDeviceComponent(device_row_id=device.id, component_name=name)
            db.add(component)
            # autoflush=False 的会话下，同轮多个服务可能推导出同名组件；
            # 立即 flush 让后续查询看到挂起行，避免重复插入违反唯一约束。
            db.flush()
        component.component_type = component_type
        component.version = version[:128]
        component.cpe = cpe[:255]
        component.source = source
        component.service_row_id = service_row_id
        component.updated_at = models.utcnow()

    # 固件组件（来自设备身份）
    if device.model and device.firmware_version:
        vendor_token = re.sub(r"[^a-z0-9_]+", "_", (device.vendor or "unknown").lower()).strip("_")
        model_token = re.sub(r"[^a-z0-9_]+", "_", device.model.lower()).strip("_")
        put_component(f"{device.model} firmware", "firmware", device.firmware_version,
                      f"cpe:2.3:o:{vendor_token}:{model_token}:{device.firmware_version}".lower(),
                      "device_identity", None)
    # 服务组件（来自服务横幅）
    for port, result in service_results.items():
        derived = _service_component(result)
        if not derived:
            continue
        name, version = derived
        service_row = db.query(models.IotDeviceService).filter_by(device_row_id=device.id, port=port).one()
        put_component(name, "software", version, "", "service_banner", service_row.id)

    db.commit()
    report = {
        "host": host,
        "probed_ports": target_ports,
        "identified": {str(port): result["service_type"] for port, result in service_results.items()},
        "no_response": refused,
        "identity_source": identity["source"],
        "identity_confidence": identity["confidence"],
        "exposure_factors": factors,
    }
    return device, report
