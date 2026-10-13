"""阶段一：智能设备升级——模拟设备真实运行 + 协议识别 + 设备清单 API。

不使用 mock：SmartCam-X1 模拟器在本机真实监听 SSH/HTTP/MQTT/RTSP，
后端通过真实协议交互完成发现与识别。
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

SIMULATOR_DIR = Path(__file__).resolve().parents[2] / "simulator"
if str(SIMULATOR_DIR) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_DIR))

import smartcam_x1  # noqa: E402

from app.services.device_inventory import identify_service  # noqa: E402


def _free_ports(count: int) -> list[int]:
    holders, ports = [], []
    for _ in range(count):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        ports.append(sock.getsockname()[1])
        holders.append(sock)
    for sock in holders:
        sock.close()
    return ports


@pytest.fixture(scope="module")
def smartcam():
    http_port, ssh_port, mqtt_port, rtsp_port = _free_ports(4)
    handles = smartcam_x1.start_all(
        "127.0.0.1", http_port=http_port, ssh_port=ssh_port,
        mqtt_port=mqtt_port, rtsp_port=rtsp_port,
    )
    yield {
        "host": "127.0.0.1", "http": http_port, "ssh": ssh_port,
        "mqtt": mqtt_port, "rtsp": rtsp_port, "handles": handles,
    }
    smartcam_x1.stop_all(handles)


@pytest.fixture()
def iot_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "stage1-test-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")


def _auth_headers():
    return {"X-Control-Token": "stage1-test-token"}


def _raw_roundtrip(port: int, payload: bytes, read: int = 1024, timeout: float = 3.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        return sock.recv(read)


# ── 模拟器本身：四个服务真实在线且说真实协议 ────────────────────────────────

def test_simulator_ssh_sends_real_banner(smartcam):
    data = _raw_roundtrip(smartcam["ssh"], payload=b"", read=256)
    assert data.startswith(b"SSH-2.0-")
    assert b"dropbear" in data


def test_simulator_http_serves_camera_page(smartcam):
    payload = b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    with socket.create_connection(("127.0.0.1", smartcam["http"]), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(payload)
        chunks = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks += chunk
    assert chunks.startswith(b"HTTP/")
    assert b"SmartCam-X1" in chunks
    assert b"SmartCam-X1 httpd/2.4.7" in chunks  # Server 头


def test_simulator_mqtt_answers_connack(smartcam):
    from app.services.device_inventory import _mqtt_connect_packet
    data = _raw_roundtrip(smartcam["mqtt"], _mqtt_connect_packet(), read=4)
    assert data[0] == 0x20  # CONNACK
    assert data[3] == 0x00  # 匿名接入被接受（廉价摄像头真实形态）


def test_simulator_rtsp_answers_options(smartcam):
    payload = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    data = _raw_roundtrip(smartcam["rtsp"], payload)
    assert data.startswith(b"RTSP/1.0 200")
    assert b"DESCRIBE" in data


# ── 识别服务：协议级探测逐端口验证 ──────────────────────────────────────────

def test_identify_service_detects_all_four_protocols(smartcam):
    host = smartcam["host"]
    assert identify_service(host, smartcam["ssh"])["service_type"] == "ssh"
    http = identify_service(host, smartcam["http"])
    assert http["service_type"] == "http"
    mqtt = identify_service(host, smartcam["mqtt"])
    assert mqtt["service_type"] == "mqtt"
    assert mqtt["auth_state"] == "anonymous_accepted"
    rtsp = identify_service(host, smartcam["rtsp"])
    assert rtsp["service_type"] == "rtsp"


def test_identify_service_returns_none_on_closed_port():
    assert identify_service("127.0.0.1", _free_ports(1)[0]) is None


# ── 设备 API：发现 → 清单 → 详情 → 重新探测 ────────────────────────────────

def _discover(smartcam, client):
    return client.post(
        "/api/devices/discover",
        json={"host": smartcam["host"],
              "ports": [smartcam["ssh"], smartcam["http"], smartcam["mqtt"], smartcam["rtsp"]]},
        headers=_auth_headers(),
    )


def test_discover_creates_device_with_services_and_components(smartcam, iot_env, client):
    response = _discover(smartcam, client)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["device_name"] == "SmartCam-X1"
    assert data["device_type"] == "ip_camera"
    assert data["vendor"] == "SmartCam Technologies"
    assert data["firmware_version"] == "2.4.7"
    assert data["os"]
    assert data["status"] == "online"
    assert data["identity_source"] == "device_identity_endpoint"
    service_types = {service["service_type"] for service in data["services"]}
    assert service_types == {"ssh", "http", "mqtt", "rtsp"}
    components = data["components"]
    assert any(c["component_type"] == "firmware" and c["version"] == "2.4.7" for c in components)
    assert len(components) >= 4  # 固件 + 四个服务组件
    report = data["discovery_report"]
    assert set(report["identified"].values()) == {"ssh", "http", "mqtt", "rtsp"}


def test_device_list_and_detail_roundtrip(smartcam, iot_env, client):
    assert _discover(smartcam, client).status_code == 200
    listed = client.get("/api/devices").json()
    assert len(listed) == 1
    summary = listed[0]
    assert summary["device_name"] == "SmartCam-X1"
    assert set(summary["open_ports"]) == {smartcam["ssh"], smartcam["http"], smartcam["mqtt"], smartcam["rtsp"]}
    assert summary["security_status"] == "unassessed"
    detail = client.get(f"/api/devices/{summary['device_id']}").json()
    assert detail["firmware_version"] == "2.4.7"
    assert len(detail["services"]) == 4
    assert len(detail["components"]) >= 4
    assert detail["vulnerability_count"] == 0  # 设备级 CVE 匹配在后续阶段，当前如实为 0
    assert detail["discovery_report"] if "discovery_report" in detail else True


def test_device_detail_404_for_unknown(smartcam, iot_env, client):
    assert client.get("/api/devices/DEV-NOTEXIST").status_code == 404


def test_refresh_updates_existing_device(smartcam, iot_env, client):
    created = _discover(smartcam, client).json()
    response = client.post(f"/api/devices/{created['device_id']}/refresh", headers=_auth_headers())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "online"
    assert len([s for s in data["services"] if s["status"] == "open"]) == 4


def test_discover_is_idempotent(smartcam, iot_env, client):
    _discover(smartcam, client)
    _discover(smartcam, client)
    listed = client.get("/api/devices").json()
    assert len(listed) == 1
    assert len(listed[0]["open_ports"]) == 4


# ── 安全边界：令牌与授权网段 ─────────────────────────────────────────────────

def test_discover_requires_control_token(smartcam, iot_env, client):
    response = client.post("/api/devices/discover",
                           json={"host": smartcam["host"], "ports": [smartcam["http"]]})
    assert response.status_code == 401


def test_discover_rejects_wrong_token(smartcam, iot_env, client):
    response = client.post("/api/devices/discover",
                           json={"host": smartcam["host"], "ports": [smartcam["http"]]},
                           headers={"X-Control-Token": "wrong"})
    assert response.status_code == 401


def test_discover_rejects_host_outside_allowed_network(smartcam, iot_env, client):
    response = client.post("/api/devices/discover",
                           json={"host": "203.0.113.10"}, headers=_auth_headers())
    assert response.status_code == 400


def test_discover_rejects_hostname_not_ip(smartcam, iot_env, client):
    response = client.post("/api/devices/discover",
                           json={"host": "example.com"}, headers=_auth_headers())
    assert response.status_code == 400
