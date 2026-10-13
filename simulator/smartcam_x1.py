#!/usr/bin/env python3
"""SmartCam-X1 智能摄像头设备模拟器（阶段一测试设备）。

真实监听四个服务，供 IoTGuard 后端做在线发现与服务识别：

  - SSH   ：优先用 paramiko 提供完整 SSH 握手（服务端 banner 标识 dropbear_2022.83）；
            未安装 paramiko 时退化为真实的 SSH 版本横幅交换（服务端先发 banner）。
  - MQTT  ：最小但符合 MQTT 3.1.1 报文格式的 broker：CONNECT/CONNACK、
            PINGREQ/PINGRESP、SUBSCRIBE/SUBACK、UNSUBSCRIBE/UNSUBACK、
            PUBLISH（含 qos1 PUBACK 与通配符订阅转发）。默认接受任意连接
            （匿名接入），这正是廉价摄像头暴露面的真实形态。
  - HTTP  ：嵌入式 Web 管理界面（登录页 + /api/system 身份信息 JSON）。
  - RTSP  ：RTSP/1.0 控制面（OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN + SDP）。
            媒体面（RTP 流）未实现，探测与识别不需要媒体面。

只依赖标准库；paramiko 为可选依赖。运行示例：

    python smartcam_x1.py                       # 标准端口 22/80/554/1883
    python smartcam_x1.py --http-port 8080 --ssh-port 22022

本文件同时提供程序化接口 start_all()/stop_all() 供后端测试直接拉起设备。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── 设备身份（模拟真实固件对外暴露的只读信息，与代码逻辑解耦） ────────────────
DEVICE_PROFILE = {
    "device_name": "SmartCam-X1",
    "device_type": "ip_camera",
    "vendor": "SmartCam Technologies",
    "model": "SmartCam-X1",
    "firmware_version": "2.4.7",
    "os": "SmartCamOS 2.4.7 (Linux 4.9.68 armv7l)",
    "hardware": "SCX1-IMX335",
    "mac_address": "A4:CF:12:9B:E3:40",
    "serial_number": "SCX1-2026-0816-0001",
}

SSH_BANNER = "SSH-2.0-dropbear_2022.83 SmartCamX1\r\n"
HTTP_SERVER_HEADER = "SmartCam-X1 httpd/2.4.7"
RTSP_SERVER_HEADER = "SmartCam-X1 RTSP/2.4.7"
# 真实摄像头常见的出厂口令；本阶段仅作为设备事实存在，弱口令检测在后续阶段实现。
DEVICE_ACCOUNTS = {("admin", "admin123")}

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="generator" content="SmartCam-X1 httpd/2.4.7">
<title>SmartCam-X1 管理登录</title>
</head>
<body>
<h1>SmartCam-X1</h1>
<p>SmartCam Technologies 智能网络摄像头 · 固件 2.4.7</p>
<form method="post" action="/login">
<input name="username" placeholder="用户名"><input name="password" type="password" placeholder="密码">
<button type="submit">登录</button>
</form>
</body>
</html>
"""


def _system_payload(http_port: int, ssh_port: int, mqtt_port: int, rtsp_port: int) -> dict:
    payload = dict(DEVICE_PROFILE)
    # 如实报告当前实际监听端口（程序化拉起时可能不是标准端口）。
    payload["services"] = [
        {"type": "http", "port": http_port, "product": HTTP_SERVER_HEADER},
        {"type": "ssh", "port": ssh_port, "product": "dropbear SSH 2022.83"},
        {"type": "mqtt", "port": mqtt_port, "product": "SmartCam MQTT broker 1.6.2"},
        {"type": "rtsp", "port": rtsp_port, "product": RTSP_SERVER_HEADER},
    ]
    payload["note"] = "device read-only identity endpoint"
    return payload


# ── HTTP 管理界面 ─────────────────────────────────────────────────────────────
class _CameraHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = HTTP_SERVER_HEADER
    sys_version = ""

    def log_message(self, *args):  # 静默访问日志
        pass

    def _send(self, status: int, content_type: str, body: bytes, extra_headers: dict | None = None):
        self.send_response(status)
        self.send_header("Server", HTTP_SERVER_HEADER)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html", "/login"):
            self._send(200, "text/html; charset=utf-8", LOGIN_PAGE.encode("utf-8"))
        elif self.path in ("/api/system", "/system/info"):
            payload = _system_payload(self.server.server_address[1], self.server.ssh_port,
                                      self.server.mqtt_port, self.server.rtsp_port)
            self._send(200, "application/json", json.dumps(payload).encode("utf-8"))
        else:
            self._send(404, "text/plain; charset=utf-8", b"404 Not Found")

    def do_POST(self):
        # 登录接口存在但本阶段不实现会话（识别只依赖 GET 暴露面）。
        if self.path == "/login":
            self._send(401, "text/plain; charset=utf-8", b"401 Unauthorized")
        else:
            self._send(404, "text/plain; charset=utf-8", b"404 Not Found")


class _CameraHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, ssh_port: int, mqtt_port: int, rtsp_port: int):
        super().__init__(address, _CameraHttpHandler)
        self.ssh_port = ssh_port
        self.mqtt_port = mqtt_port
        self.rtsp_port = rtsp_port


# ── MQTT 3.1.1 最小 broker ────────────────────────────────────────────────────
def _mqtt_remaining_length(data: bytes, offset: int) -> tuple[int, int]:
    """解析 MQTT 变长剩余长度，返回 (长度, 下一个字节偏移)。"""
    multiplier, value = 1, 0
    for _ in range(4):
        if offset >= len(data):
            raise ValueError("truncated remaining length")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value, offset
        multiplier *= 128
    raise ValueError("malformed remaining length")


def _mqtt_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated string")
    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    if offset + length > len(data):
        raise ValueError("truncated string")
    return data[offset:offset + length].decode("utf-8", errors="replace"), offset + length


def _topic_matches(filter_topic: str, topic: str) -> bool:
    if filter_topic == topic:
        return True
    parts = filter_topic.split("/")
    actual = topic.split("/")
    for index, part in enumerate(parts):
        if part == "#":
            return True
        if index >= len(actual):
            return False
        if part not in ("+", actual[index]):
            return False
    return len(parts) == len(actual)


def load_mqtt_config(path: str) -> dict:
    """解析 mosquitto 风格的 MQTT 配置（演示子集：allow_anonymous / password_file）。"""
    config = {"allow_anonymous": True, "password_file": "", "config_path": path or ""}
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    key, _, value = line.partition(" ")
                    value = value.strip()
                    if key == "allow_anonymous":
                        config["allow_anonymous"] = value.lower() == "true"
                    elif key == "password_file":
                        config["password_file"] = value
        except OSError:
            pass
    return config


class _MqttBroker:
    """接受任意 CONNECT（无账号校验），支持订阅/发布/通配符转发。

    阶段四起真实读取配置文件（mosquitto 风格）：
      allow_anonymous true|false
      password_file <路径>   （演示格式：每行 user:password）
    allow_anonymous=false 时无凭据/错误凭据返回 CONNACK rc=5（Not authorized），
    正确用户名密码返回 rc=0 —— 供修复 Demo 真实验证。
    """

    def __init__(self, config_path: str = ""):
        self.config = load_mqtt_config(config_path)
        self._lock = threading.Lock()
        self._subscribers: dict[int, set[str]] = {}  # conn id -> topic filters

    def _auth_result(self, username: str | None, password: str | None) -> int:
        if self.config.get("allow_anonymous", True):
            return 0
        if not username:
            return 5
        password_file = self.config.get("password_file", "")
        if not password_file or not os.path.isfile(password_file):
            return 5
        try:
            with open(password_file, encoding="utf-8") as fh:
                for line in fh:
                    user, _, stored = line.strip().partition(":")
                    if user == username and stored == (password or ""):
                        return 0
        except OSError:
            return 5
        return 5

    def handle(self, conn: socket.socket, conn_id: int):
        buffer = bytearray()
        try:
            while True:
                packet = self._read_packet(conn, buffer)
                if packet is None:
                    return
                self._dispatch(conn, conn_id, packet)
        except (OSError, ValueError):
            pass
        finally:
            with self._lock:
                self._subscribers.pop(conn_id, None)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_connect(self, packet: bytes) -> tuple[int, bool]:
        """解析 MQTT 3.1.1 CONNECT（含 username/password），返回 (connack rc, accepted)。"""
        offset = 1
        _, offset = _mqtt_remaining_length(packet, offset)
        _, offset = _mqtt_string(packet, offset)      # protocol name
        if offset >= len(packet):
            return 5, False
        offset += 1                                    # protocol level
        flags = packet[offset]
        offset += 1
        offset += 2                                    # keep alive
        _, offset = _mqtt_string(packet, offset)       # client id
        if flags & 0x04:                               # will flag
            _, offset = _mqtt_string(packet, offset)   # will topic
            _, offset = _mqtt_string(packet, offset)   # will message
        username = password = None
        if flags & 0x80:
            username, offset = _mqtt_string(packet, offset)
        if flags & 0x40:
            password, offset = _mqtt_string(packet, offset)
        rc = self._auth_result(username, password)
        return rc, rc == 0

    def _read_packet(self, conn: socket.socket, buffer: bytearray) -> bytes | None:
        def recv_at_least(size: int) -> bool:
            while len(buffer) < size:
                chunk = conn.recv(4096)
                if not chunk:
                    return False
                buffer.extend(chunk)
            return True

        if not recv_at_least(2):
            return None
        try:
            remaining, header_end = _mqtt_remaining_length(buffer, 1)
        except ValueError:
            return None
        if not recv_at_least(header_end + remaining):
            return None
        packet = bytes(buffer[:header_end + remaining])
        del buffer[:header_end + remaining]
        return packet

    def _dispatch(self, conn: socket.socket, conn_id: int, packet: bytes):
        packet_type = packet[0] >> 4
        if packet_type == 1:  # CONNECT：真实解析用户名/密码并按配置判定
            try:
                rc, accepted = self._handle_connect(packet)
            except (ValueError, IndexError):
                rc, accepted = 5, False
            conn.sendall(bytes([0x20, 0x02, 0x00, rc]))
            if not accepted:
                conn.close()
        elif packet_type == 12:  # PINGREQ
            conn.sendall(bytes([0xD0, 0x00]))
        elif packet_type == 8:  # SUBSCRIBE
            packet_id = int.from_bytes(packet[2:4], "big")
            offset, filters = 5, set()
            while offset < len(packet):
                topic, offset = _mqtt_string(packet, offset)
                filters.add(topic)
                offset += 1  # requested QoS
            granted = b"".join(bytes([0x00]) for _ in filters)
            with self._lock:
                self._subscribers.setdefault(conn_id, set()).update(filters)
            conn.sendall(bytes([0x90, len(granted) + 2]) + packet_id.to_bytes(2, "big") + granted)
        elif packet_type == 10:  # UNSUBSCRIBE
            packet_id = int.from_bytes(packet[2:4], "big")
            conn.sendall(bytes([0xB0, 0x02]) + packet_id.to_bytes(2, "big"))
        elif packet_type == 3:  # PUBLISH
            qos = (packet[0] >> 1) & 0x03
            topic, offset = _mqtt_string(packet, 2)
            if qos:
                offset += 2  # packet id
            payload = packet[offset:]
            header = bytes([0x30, len(topic.encode()) + 2 + len(payload)]) + len(topic.encode()).to_bytes(2, "big") + topic.encode()
            with self._lock:
                targets = [
                    (cid, topic_filter)
                    for cid, filters in self._subscribers.items()
                    for topic_filter in filters
                    if _topic_matches(topic_filter, topic)
                ]
            for cid, _ in targets:
                peer = self._peers.get(cid)
                if peer:
                    try:
                        peer.sendall(header + payload)
                    except OSError:
                        pass
            if qos == 1:
                packet_id = int.from_bytes(packet[4:6], "big")
                conn.sendall(bytes([0x40, 0x02]) + packet_id.to_bytes(2, "big"))
        elif packet_type == 14:  # DISCONNECT
            conn.close()

    def register_peer(self, conn_id: int, peer: socket.socket):
        self._peers = getattr(self, "_peers", {})
        self._peers[conn_id] = peer


class _MqttListener(threading.Thread):
    daemon = True

    def __init__(self, address, config_path: str = ""):
        super().__init__(name="smartcam-mqtt")
        self.broker = _MqttBroker(config_path)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(address)
        self.server.listen(16)
        self._next_id = 0
        self._conn_id_lock = threading.Lock()

    def run(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with self._conn_id_lock:
                self._next_id += 1
                conn_id = self._next_id
            self.broker.register_peer(conn_id, conn)
            threading.Thread(target=self.broker.handle, args=(conn, conn_id), daemon=True).start()

    def stop(self):
        try:
            self.server.close()
        except OSError:
            pass


# ── RTSP 控制面 ───────────────────────────────────────────────────────────────
SDP_TEMPLATE = (
    "v=0\r\n"
    "o=- 0 0 IN IP4 0.0.0.0\r\n"
    "s=SmartCam-X1 Main Stream\r\n"
    "i=SmartCam-X1 4MP Camera\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
    "a=control:track0\r\n"
    "m=audio 0 RTP/AVP 8\r\n"
    "a=control:track1\r\n"
)


def _rtsp_handle(conn: socket.socket):
    session = "SCX1-483920"
    try:
        conn.settimeout(10)
        buffer = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buffer += chunk
            if b"\r\n\r\n" not in buffer:
                continue
            request, buffer = buffer.split(b"\r\n\r\n", 1)
            lines = request.decode("utf-8", errors="replace").split("\r\n")
            if not lines:
                continue
            head = lines[0].split(" ")
            method = head[0].upper() if head else ""
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            cseq = headers.get("cseq", "1")

            def respond(status: str, extra: str = "", body: bytes = b""):
                head_line = f"RTSP/1.0 {status}\r\nCSeq: {cseq}\r\nServer: {RTSP_SERVER_HEADER}\r\n"
                body_block = f"Content-Length: {len(body)}\r\n" if body else ""
                conn.sendall((head_line + body_block + extra + "\r\n").encode("utf-8") + body)

            if method == "OPTIONS":
                respond("200 OK", "Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n")
            elif method == "DESCRIBE":
                body = SDP_TEMPLATE.encode("utf-8")
                respond("200 OK", "Content-Type: application/sdp\r\n", body)
            elif method == "SETUP":
                respond("200 OK", f"Session: {session};timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n")
            elif method in ("PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER"):
                respond("200 OK", f"Session: {session}\r\n")
            else:
                respond("501 Not Implemented")
            if method == "TEARDOWN":
                return
    except (OSError, socket.timeout):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


class _RtspListener(threading.Thread):
    daemon = True

    def __init__(self, address):
        super().__init__(name="smartcam-rtsp")
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(address)
        self.server.listen(16)

    def run(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=_rtsp_handle, args=(conn,), daemon=True).start()

    def stop(self):
        try:
            self.server.close()
        except OSError:
            pass


# ── SSH 服务 ─────────────────────────────────────────────────────────────────
class _SshListener(threading.Thread):
    daemon = True

    def __init__(self, address):
        super().__init__(name="smartcam-ssh")
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(address)
        self.server.listen(16)
        self._paramiko = None
        try:
            import paramiko  # noqa: F401
            self._paramiko = paramiko
        except ImportError:
            self._paramiko = None
        self.host_key = None
        if self._paramiko is not None:
            try:
                self.host_key = self._paramiko.RSAKey.generate(2048)
            except Exception:
                self.host_key = None

    def run(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            if self._paramiko is not None and self.host_key is not None:
                threading.Thread(target=self._serve_paramiko, args=(conn,), daemon=True).start()
            else:
                threading.Thread(target=self._serve_banner, args=(conn,), daemon=True).start()

    def _serve_banner(self, conn: socket.socket):
        """无 paramiko 时的真实 SSH 版本交换：服务端先发 banner，再读客户端 banner。"""
        try:
            conn.settimeout(10)
            conn.sendall(SSH_BANNER.encode("ascii"))
            conn.recv(256)  # 客户端 banner；本阶段不继续 KEX
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve_paramiko(self, conn: socket.socket):
        paramiko = self._paramiko

        class _ServerInterface(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                if (username, password) in DEVICE_ACCOUNTS:
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return "password"

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_exec_request(self, channel, command):
                channel.send(f"{DEVICE_PROFILE['model']} 管理接口未开放远程命令。\n".encode("utf-8"))
                channel.send_exit_status(1)
                channel.close()
                return True

        try:
            conn.settimeout(20)
            transport = paramiko.Transport(conn)
            # 真实设备的 SSH 服务端横幅（paramiko 默认会宣告自己的实现名，这里改掉）。
            try:
                transport.local_version = SSH_BANNER.strip()
            except Exception:
                pass
            transport.add_server_key(self.host_key)
            transport.start_server(server=_ServerInterface())
            channel = transport.accept(timeout=15)
            if channel is not None:
                transport.close()
        except (OSError, Exception):
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        try:
            self.server.close()
        except OSError:
            pass


# ── 组装与程序化接口 ─────────────────────────────────────────────────────────
def start_all(host: str = "0.0.0.0", *, http_port: int = 80, ssh_port: int = 22,
              mqtt_port: int = 1883, rtsp_port: int = 554,
              mqtt_config_path: str = "") -> dict:
    """启动全部服务（阻塞调用方除外），返回句柄。测试可直接调用。"""
    http = _CameraHttpServer((host, http_port), ssh_port, mqtt_port, rtsp_port)
    threading.Thread(target=http.serve_forever, name="smartcam-http", daemon=True).start()

    mqtt = _MqttListener((host, mqtt_port), config_path=mqtt_config_path)
    mqtt.start()
    rtsp = _RtspListener((host, rtsp_port))
    rtsp.start()
    ssh = _SshListener((host, ssh_port))
    ssh.start()
    return {
        "http": http, "mqtt": mqtt, "rtsp": rtsp, "ssh": ssh,
        "address": {"host": host, "http": http_port, "ssh": ssh_port, "mqtt": mqtt_port, "rtsp": rtsp_port},
    }


def stop_all(handles: dict) -> None:
    handles["http"].shutdown()
    handles["http"].server_close()
    for key in ("mqtt", "rtsp", "ssh"):
        handles[key].stop()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SmartCam-X1 智能摄像头模拟器")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--mqtt-port", type=int, default=1883)
    parser.add_argument("--rtsp-port", type=int, default=554)
    args = parser.parse_args(argv)
    handles = start_all(args.host, http_port=args.http_port, ssh_port=args.ssh_port,
                        mqtt_port=args.mqtt_port, rtsp_port=args.rtsp_port)
    address = handles["address"]
    print(f"SmartCam-X1 模拟设备已启动 {DEVICE_PROFILE['vendor']} {DEVICE_PROFILE['model']} "
          f"固件 {DEVICE_PROFILE['firmware_version']}")
    print(f"  HTTP  http://{args.host}:{address['http']}/  （设备信息: /api/system）")
    print(f"  SSH   {args.host}:{address['ssh']}")
    print(f"  MQTT  {args.host}:{address['mqtt']}（匿名接入，无账号校验）")
    print(f"  RTSP  rtsp://{args.host}:{address['rtsp']}/stream1")
    print("按 Ctrl+C 停止")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        stop_all(handles)
        print("已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
