import json
from pathlib import Path
import socket
import sys
import urllib.request

import pytest

SIMULATOR = Path(__file__).resolve().parents[2] / "simulator"
sys.path.insert(0, str(SIMULATOR))
import lan_device as simulator
from openwrt_lan import load


@pytest.fixture
def devices():
    configuration = load(SIMULATOR / "lan_devices.json")
    rows = []
    try:
        for profile in configuration["devices"]:
            device, servers = simulator.start(profile, configuration["gateway"], host="127.0.0.1",
                http_port=0, mqtt_port=0, rtsp_port=0, frame_dir=SIMULATOR / "frames" / profile["id"])
            rows.append((device, servers))
        yield rows
    finally:
        for device, servers in rows:
            simulator.stop(device, servers)


def http(servers, path, data=None):
    request = urllib.request.Request("http://127.0.0.1:" + str(servers[0].server_port) + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(request, timeout=3)


def receive_mqtt(conn):
    header = simulator.read_exact(conn, 1)[0]
    length, multiplier = 0, 1
    while True:
        digit = simulator.read_exact(conn, 1)[0]
        length += (digit & 127) * multiplier
        if not digit & 128:
            break
        multiplier *= 128
    return header, simulator.read_exact(conn, length)


def test_four_profiles_keep_separate_identities_and_truthful_capabilities(devices):
    identities = []
    for device, servers in devices:
        with http(servers, "/api/system") as response:
            value = json.load(response)
        assert value["simulation"] is True
        assert value["firmware_version"] == "sim-1.0.0"
        assert value["mac_address"] == device.profile["mac"]
        assert not any(service["type"] == "ssh" for service in value["services"])
        assert not value["media_capabilities"]["rtp"]
        identities.append(value)
    assert len({value["mac_address"] for value in identities}) == 4
    assert len({value["device_id"] for value in identities}) == 4
    assert identities[0]["media_capabilities"]["http_mjpeg"]
    assert identities[2]["telemetry"]["temperature_c"] > 0


def test_camera_serves_real_mjpeg_and_does_not_claim_rtsp_playback(devices):
    _, servers = devices[0]
    with http(servers, "/snapshot.jpg") as response:
        assert response.headers["Content-Type"] == "image/jpeg"
        assert response.read(2) == b"\xff\xd8"
    with http(servers, "/stream.mjpg") as response:
        assert "multipart/x-mixed-replace" in response.headers["Content-Type"]
        assert b"--frame\r\nContent-Type: image/jpeg" in response.read(128)
    for method, expected in [("OPTIONS", b"200 OK"), ("PLAY", b"501 Not Implemented")]:
        with socket.create_connection(("127.0.0.1", servers[2].server_address[1]), timeout=2) as conn:
            conn.sendall((method + " rtsp://127.0.0.1/live RTSP/1.0\r\nCSeq: 1\r\n\r\n").encode())
            assert expected in conn.recv(1024)


def test_mqtt_subscription_and_plug_command_change_actual_simulator_state(devices):
    device, servers = devices[3]
    with socket.create_connection(("127.0.0.1", servers[1].server_address[1]), timeout=3) as conn:
        conn.sendall(simulator.mqtt_packet(0x10, simulator.mqtt_string("MQTT") + b"\x04\x02\x00\x3c" + simulator.mqtt_string("verification")))
        assert receive_mqtt(conn) == (0x20, b"\x00\x00")
        conn.sendall(simulator.mqtt_packet(0x82, b"\x00\x01" + simulator.mqtt_string("iotguard/plug01/#") + b"\x00"))
        assert receive_mqtt(conn) == (0x90, b"\x00\x01\x00")
        header, body = receive_mqtt(conn)
        topic, offset = simulator.read_string(body)
        assert header == 0x30 and topic == device.topic and json.loads(body[offset:])["power"] is False
        conn.sendall(simulator.mqtt_packet(0x30, simulator.mqtt_string("iotguard/plug01/set") + b'{"power":true}'))
        for _ in range(3):
            _, body = receive_mqtt(conn)
            _, offset = simulator.read_string(body)
            if json.loads(body[offset:])["power"]:
                break
        else:
            pytest.fail("MQTT command did not change the plug")
        with http(servers, "/api/telemetry") as response:
            assert json.load(response)["power"] is True
        with http(servers, "/api/switch", {"power": False}) as response:
            assert json.load(response)["power"] is False
        conn.sendall(b"\xe0\x00")


def test_real_discovery_keeps_two_cameras_separate_and_preserves_simulation(client, devices, monkeypatch, control_headers):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.1/32")
    ids = []
    for _, servers in devices[:2]:
        response = client.post("/api/devices/discover", headers=control_headers,
            json={"host": "127.0.0.1", "ports": [servers[0].server_port]})
        assert response.status_code == 200, response.text
        value = response.json()
        assert value["simulation"] is True
        assert json.loads(value["metadata"])["media_capabilities"]["http_mjpeg"]
        ids.append(value["device_id"])
    assert len(set(ids)) == 2
    overview = client.get("/api/devices/business/overview").json()
    assert len(overview["devices"]) == 2
    assert all(row["simulation"] and row["ip_address"] == "127.0.0.1" for row in overview["devices"])


def test_lan_configuration_rejects_duplicate_addresses(tmp_path):
    data = json.loads((SIMULATOR / "lan_devices.json").read_text(encoding="utf-8"))
    data["devices"][1]["ip"] = data["devices"][0]["ip"]
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load(path)


def test_alternative_http_port_reports_the_same_mac_and_real_listener_ports():
    configuration = load(SIMULATOR / "lan_devices.json")
    device, servers = simulator.start(configuration["devices"][0], configuration["gateway"],
        host="127.0.0.1", http_port=0, mqtt_port=0, rtsp_port=0, extra_http_port=0)
    try:
        with http(servers, "/api/system") as response:
            primary = json.load(response)
        with urllib.request.urlopen("http://127.0.0.1:" + str(servers[-1].server_port) + "/api/system", timeout=3) as response:
            alternative = json.load(response)
        assert primary["mac_address"] == alternative["mac_address"]
        assert {service["port"] for service in alternative["services"] if service["type"] == "http"} == {
            servers[0].server_port, servers[-1].server_port}
    finally:
        simulator.stop(device, servers)
