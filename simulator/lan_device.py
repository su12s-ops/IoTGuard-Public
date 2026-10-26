#!/usr/bin/env python3
"""Independent LAN device process: real HTTP/MJPEG, MQTT and RTSP discovery.

Only the Python standard library is required. Identity, telemetry and images
explicitly identify themselves as simulations; no vendor firmware is emulated.
"""
import argparse
import html
import json
import math
from pathlib import Path
import signal
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def mqtt_string(value):
    data = value.encode()
    return len(data).to_bytes(2, "big") + data


def mqtt_packet(header, body):
    length, encoded = len(body), bytearray([header])
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (128 if length else 0))
        if not length:
            break
    return bytes(encoded) + body


def read_exact(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def read_string(data, offset=0):
    if offset + 2 > len(data):
        raise ValueError("truncated MQTT string")
    count = int.from_bytes(data[offset:offset + 2], "big")
    end = offset + 2 + count
    if end > len(data):
        raise ValueError("truncated MQTT string")
    return data[offset + 2:end].decode("utf-8"), end


def topic_matches(pattern, topic):
    left, right = pattern.split("/"), topic.split("/")
    for index, segment in enumerate(left):
        if segment == "#":
            return index == len(left) - 1
        if index >= len(right) or (segment != "+" and segment != right[index]):
            return False
    return len(left) == len(right)


class Device:
    def __init__(self, profile, gateway, frame_dir=None):
        self.profile = profile
        self.gateway = gateway
        self.started = time.monotonic()
        self.lock = threading.RLock()
        self.power = False
        self.stopping = threading.Event()
        self.frames = [p.read_bytes() for p in sorted(Path(frame_dir).glob("*.jpg"))] if frame_dir else []
        self.topic = "iotguard/" + profile["id"] + "/telemetry"

    def telemetry(self):
        elapsed = time.monotonic() - self.started
        result = {"simulation": True, "device_id": self.profile["id"], "timestamp": int(time.time()),
                  "uptime_s": int(elapsed)}
        if self.profile["kind"] == "sensor":
            result.update(temperature_c=round(23 + 2 * math.sin(elapsed / 45), 2),
                          humidity_percent=round(48 + 6 * math.cos(elapsed / 70), 2))
        elif self.profile["kind"] == "plug":
            with self.lock:
                result.update(power=self.power, voltage_v=220.0, watts=round(36 + math.sin(elapsed), 2) if self.power else 0.0)
        else:
            result.update(stream="/stream.mjpg", frame=int(elapsed * 2), media="synthetic_test_pattern")
        return result

    def identity(self, http_port=80, mqtt_port=1883, rtsp_port=554, extra_http_port=None):
        camera = self.profile["kind"] == "camera"
        return {"device_name": self.profile["name"],
                "device_type": {"camera": "ip_camera", "sensor": "sensor", "plug": "smart_plug"}[self.profile["kind"]],
                "device_id": self.profile["id"], "vendor": "IoTGuard Lab",
                "model": {"camera": "LabCam", "sensor": "LabTempHumidity", "plug": "LabPlug"}[self.profile["kind"]],
                "firmware_version": "sim-1.0.0", "os": "IoTGuard simulator on OpenWrt (shared host kernel)",
                "mac_address": self.profile["mac"], "serial_number": "IOTGUARD-SIM-" + self.profile["id"],
                "simulation": True, "simulation_profile": self.profile["kind"], "gateway": self.gateway,
                "telemetry_topic": self.topic,
                "control_topic": "iotguard/" + self.profile["id"] + "/set" if self.profile["kind"] == "plug" else None,
                "telemetry": self.telemetry(),
                "media_capabilities": {"http_mjpeg": camera and bool(self.frames), "rtsp": "discovery_control_only" if camera else "unsupported", "rtp": False},
                "services": [{"type": "http", "port": http_port, "product": "IoTGuard HTTP simulator 1.0.0"},
                             {"type": "mqtt", "port": mqtt_port, "product": "IoTGuard MQTT simulator 1.0.0"}]
                            + ([{"type": "rtsp", "port": rtsp_port, "product": "IoTGuard RTSP discovery simulator 1.0.0"}] if camera else [])
                            + ([{"type": "http", "port": extra_http_port, "product": "IoTGuard HTTP simulator 1.0.0"}] if extra_http_port else [])}

    def switch(self, value):
        if self.profile["kind"] != "plug" or not isinstance(value, dict) or type(value.get("power")) is not bool:
            raise ValueError('Only a plug accepts {"power":true|false}')
        with self.lock:
            self.power = value["power"]
        return self.telemetry()


class HttpHandler(BaseHTTPRequestHandler):
    server_version = "IoTGuardSim/1.0.0"
    sys_version = ""

    def log_message(self, *_):
        pass

    def send_body(self, body, content_type="application/json", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        device = self.server.device
        path = self.path.split("?", 1)[0]
        if path in {"/api/system", "/system/info"}:
            self.send_body(json.dumps(device.identity(*self.server.ports), ensure_ascii=False).encode())
        elif path == "/api/telemetry":
            self.send_body(json.dumps(device.telemetry()).encode())
        elif path in {"/snapshot.jpg", "/stream.mjpg"} and device.profile["kind"] == "camera" and device.frames:
            if path == "/snapshot.jpg":
                self.send_body(device.frames[int(time.monotonic() * 2) % len(device.frames)], "image/jpeg")
                return
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                while not device.stopping.is_set():
                    frame = device.frames[int(time.monotonic() * 2) % len(device.frames)]
                    self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
                    self.wfile.flush()
                    device.stopping.wait(.5)
            except (OSError, ConnectionError):
                pass
        elif path == "/":
            name = html.escape(device.profile["name"])
            media = '<img style="width:100%;max-width:640px" src="/stream.mjpg" alt="Synthetic camera test pattern">' if device.frames else ""
            control = '<button onclick="fetch(\'/api/switch\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({power:!state.power})})">切换模拟插座</button>' if device.profile["kind"] == "plug" else ""
            page = '<!doctype html><meta charset="utf-8"><title>' + name + '</title><body style="font:16px system-ui;max-width:760px;margin:40px auto;padding:20px;background:#eef3f8"><h1>' + name + '</h1><p>IoTGuard 实验模拟设备 · 独立 LAN IP / MAC · 非实体硬件</p>' + media + control + '<pre id="data"></pre><p><a href="/api/system">设备身份 JSON</a> · <a href="/api/telemetry">遥测 JSON</a></p><script>let state={};async function refresh(){state=await(await fetch("/api/telemetry")).json();document.getElementById("data").textContent=JSON.stringify(state,null,2)}refresh();setInterval(refresh,2000)</script></body>'
            self.send_body(page.encode(), "text/html; charset=utf-8")
        else:
            self.send_body(b'{"error":"not_found"}', status=404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/api/switch" or not 0 < length <= 1024:
                raise ValueError("Unsupported request")
            result = self.server.device.switch(json.loads(self.rfile.read(length)))
            self.send_body(json.dumps(result).encode())
        except (ValueError, TypeError):
            self.send_body(b'{"error":"invalid_simulated_switch_request"}', status=400)


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # No reverse DNS dependency while a namespace is acquiring its lease.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "IoTGuardSim"
        self.server_port = self.server_address[1]


class MqttHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn, server = self.request, self.server
        conn.settimeout(90)
        subscribed, authenticated = set(), False
        send_lock = threading.Lock()
        def send(packet):
            with send_lock:
                conn.sendall(packet)
        with server.peers_lock:
            server.peers[conn] = (subscribed, send_lock)
        try:
            while not server.device.stopping.is_set():
                header = read_exact(conn, 1)[0]
                length, multiplier = 0, 1
                for _ in range(4):
                    digit = read_exact(conn, 1)[0]
                    length += (digit & 127) * multiplier
                    if not digit & 128:
                        break
                    multiplier *= 128
                else:
                    raise ValueError("Bad MQTT length")
                if length > 65536:
                    raise ValueError("Packet too large")
                body = read_exact(conn, length)
                kind = header >> 4
                if kind == 1:
                    protocol, offset = read_string(body)
                    if protocol != "MQTT" or len(body) < offset + 4 or body[offset] != 4:
                        raise ValueError("MQTT 3.1.1 required")
                    send(b"\x20\x02\x00\x00")
                    authenticated = True  # Explicit anonymous lab broker.
                elif not authenticated:
                    raise ValueError("CONNECT required")
                elif kind == 12:
                    send(b"\xd0\x00")
                elif kind == 8:
                    packet_id, offset, count = body[:2], 2, 0
                    while offset < len(body):
                        topic, offset = read_string(body, offset)
                        if offset >= len(body):
                            raise ValueError("Missing QoS")
                        offset += 1
                        with server.peers_lock:
                            subscribed.add(topic)
                        count += 1
                    send(mqtt_packet(0x90, packet_id + b"\x00" * count))
                    server.publish()
                elif kind == 3:
                    topic, offset = read_string(body)
                    qos = (header >> 1) & 3
                    if qos not in (0, 1):
                        raise ValueError("Only QoS 0/1 supported")
                    packet_id = body[offset:offset + 2] if qos else b""
                    offset += 2 if qos else 0
                    if topic == "iotguard/" + server.device.profile["id"] + "/set":
                        server.device.switch(json.loads(body[offset:]))
                        server.publish()
                    if qos:
                        send(b"\x40\x02" + packet_id)
                elif kind == 10:
                    offset = 2
                    while offset < len(body):
                        topic, offset = read_string(body, offset)
                        with server.peers_lock:
                            subscribed.discard(topic)
                    send(b"\xb0\x02" + body[:2])
                elif kind == 14:
                    return
        except (OSError, EOFError, ValueError, UnicodeError):
            pass
        finally:
            with server.peers_lock:
                server.peers.pop(conn, None)


class MqttServer(TcpServer):
    def __init__(self, address, device):
        self.device, self.peers, self.peers_lock = device, {}, threading.Lock()
        super().__init__(address, MqttHandler)

    def publish(self):
        body = mqtt_string(self.device.topic) + json.dumps(self.device.telemetry()).encode()
        packet = mqtt_packet(0x30, body)
        with self.peers_lock:
            peers = [(conn, lock) for conn, (topics, lock) in self.peers.items()
                     if any(topic_matches(topic, self.device.topic) for topic in topics)]
        for conn, lock in peers:
            try:
                with lock:
                    conn.sendall(packet)
            except OSError:
                pass


class RtspHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = self.request.recv(1024)
                if not chunk:
                    return
                data += chunk
            lines = data.decode(errors="replace").split("\r\n")
            method = lines[0].split()[0]
            cseq = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("cseq:")), "1")
            if not cseq.isdigit():
                return
            status = "200 OK" if method in {"OPTIONS", "DESCRIBE"} else "501 Not Implemented"
            body = b"v=0\r\ns=IoTGuard synthetic camera; use HTTP MJPEG\r\nt=0 0\r\n" if method == "DESCRIBE" else b""
            response = f"RTSP/1.0 {status}\r\nCSeq: {cseq}\r\nServer: IoTGuardSim/1.0.0\r\nPublic: OPTIONS, DESCRIBE\r\nContent-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n"
            self.request.sendall(response.encode() + body)
        except (OSError, IndexError):
            pass


def start(profile, gateway, *, host="0.0.0.0", http_port=80, mqtt_port=1883, rtsp_port=554, frame_dir=None, extra_http_port=None):
    device = Device(profile, gateway, frame_dir)
    servers = []
    try:
        http = HttpServer((host, http_port), HttpHandler)
        http.device = device
        servers.append(http)
        mqtt = MqttServer((host, mqtt_port), device)
        servers.append(mqtt)
        rtsp = None
        if profile["kind"] == "camera":
            rtsp = TcpServer((host, rtsp_port), RtspHandler)
            servers.append(rtsp)
        extra_http = None
        if extra_http_port is not None:
            extra_http = HttpServer((host, extra_http_port), HttpHandler)
            extra_http.device = device
            servers.append(extra_http)
        ports = (http.server_port, mqtt.server_address[1], rtsp.server_address[1] if rtsp else 0,
                 extra_http.server_port if extra_http else None)
        for server in servers:
            if isinstance(server, HttpServer):
                server.ports = ports
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        def telemetry_loop():
            while not device.stopping.wait(2):
                mqtt.publish()
        threading.Thread(target=telemetry_loop, daemon=True).start()
        return device, servers
    except Exception:
        for server in servers:
            server.server_close()
        raise


def stop(device, servers):
    device.stopping.set()
    for server in servers:
        server.shutdown()
        server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(Path(__file__).with_name("lan_devices.json")))
    parser.add_argument("--device", required=True)
    args = parser.parse_args()
    configuration = json.loads(Path(args.config).read_text(encoding="utf-8"))
    profile = next(row for row in configuration["devices"] if row["id"] == args.device)
    device, servers = start(profile, configuration["gateway"], frame_dir=Path(__file__).parent / "frames" / args.device,
                            extra_http_port=configuration.get("http_alternative_port"))
    signal.signal(signal.SIGTERM, lambda *_: device.stopping.set())
    signal.signal(signal.SIGINT, lambda *_: device.stopping.set())
    print(json.dumps({"device": args.device, "simulation": True, "services": device.identity()["services"]}), flush=True)
    try:
        device.stopping.wait()
    finally:
        stop(device, servers)


if __name__ == "__main__":
    main()
