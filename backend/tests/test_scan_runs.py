"""阶段六：互联网授权目标主动扫描——真实监听 + 扫描执行 + CVE 匹配接入。

不使用 mock：SmartCam-X1 模拟器、自签名 TLS/HTTP 服务与自定义横幅服务
在本机真实监听，扫描引擎通过真实 TCP/协议交互完成端口扫描、指纹识别、
设备落库与 CVE 匹配。同步路径直接调用 execute_scan；API 路径走后台线程
+ 轮询，验证 202/run_id 生命周期。
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

SIMULATOR_DIR = Path(__file__).resolve().parents[2] / "simulator"
if str(SIMULATOR_DIR) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_DIR))

import smartcam_x1  # noqa: E402

from app import models  # noqa: E402
from app.services import scan_service  # noqa: E402


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


def _generate_self_signed(directory: str) -> tuple[str, str]:
    """测试专用的临时自签证书（cryptography 随 paramiko 一同安装，不提交密钥文件）。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = Path(directory) / "scan-test-cert.pem"
    key_path = Path(directory) / "scan-test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return str(cert_path), str(key_path)


class _TlsHttpServer(threading.Thread):
    """自签 TLS 之上的极简 HTTP 服务（Server: nginx/1.18.0），模拟互联网主机的 HTTPS。"""

    RESPONSE = (b"HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\n"
                b"Content-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def __init__(self, host: str, port: int, cert: str, key: str):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self._cert, self._key = cert, key
        self._stop = threading.Event()
        self._ready = threading.Event()

    def run(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._cert, self._key)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(8)
        server.settimeout(0.2)
        self._ready.set()
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._serve, args=(conn, context), daemon=True).start()
        server.close()

    def _serve(self, conn, context):
        try:
            tls = context.wrap_socket(conn, server_side=True)
            tls.settimeout(2.0)
            tls.recv(4096)
            tls.sendall(self.RESPONSE)
            tls.close()
        except OSError:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        self.join(timeout=3)


class _BannerServer(threading.Thread):
    """连接即问候、收到任意数据再次问候的自定义服务：模拟无法归类的协议，
    验证横幅兜底只存证据、不猜协议。"""

    BANNER = b"CUSTOM-GATEWAY 3.2.1 ready.\r\n"

    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self._stop = threading.Event()
        self._ready = threading.Event()

    def run(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(8)
        server.settimeout(0.2)
        self._ready.set()
        while not self._stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        server.close()

    def _serve(self, conn):
        try:
            conn.sendall(self.BANNER)
            conn.settimeout(2.0)
            while True:
                data = conn.recv(512)
                if not data:
                    return
                conn.sendall(self.BANNER)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        self.join(timeout=3)


CLOSED_PORT = 1  # 本机回环上无监听的端口，用于验证关闭端口不进入结论


@pytest.fixture(scope="module")
def lab():
    http_port, ssh_port, mqtt_port, rtsp_port, tls_port, banner_port = _free_ports(6)
    with tempfile.TemporaryDirectory(prefix="linuxguard-scan-tls-") as directory:
        cert, key = _generate_self_signed(directory)
        handles = smartcam_x1.start_all(
            "127.0.0.1", http_port=http_port, ssh_port=ssh_port,
            mqtt_port=mqtt_port, rtsp_port=rtsp_port,
        )
        tls = _TlsHttpServer("127.0.0.1", tls_port, cert, key)
        banner = _BannerServer("127.0.0.1", banner_port)
        tls.start(); banner.start()
        tls._ready.wait(3); banner._ready.wait(3)
        yield {
            "host": "127.0.0.1", "http": http_port, "ssh": ssh_port, "mqtt": mqtt_port,
            "rtsp": rtsp_port, "https": tls_port, "banner": banner_port, "handles": handles,
        }
        tls.stop(); banner.stop()
        smartcam_x1.stop_all(handles)


@pytest.fixture()
def scan_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "scan-run-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")
    monkeypatch.setenv("LINUXGUARD_SCAN_TIMEOUT", "1.5")
    monkeypatch.setenv("LINUXGUARD_SCAN_WORKERS", "8")


def _seed_mqtt_cve(db) -> None:
    """预置 NVD 通用数据：与模拟器 MQTT 组件同名的 CVE，修复版本高于装机版本。"""
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-90001", title="SmartCam MQTT broker 匿名接入 RCE",
        affected_package="SmartCam MQTT broker", fixed_version="1.7.0",
        cvss_score=9.8, cvss_severity="Critical", source="nvd_test_fixture",
    ))
    db.commit()


def _make_target(db, ports: list[int]) -> models.ScanTarget:
    target = models.ScanTarget(
        name="自有测试主机", ip_address="127.0.0.1",
        authorization_basis="本人本地测试环境，授权扫描",
        ports_profile_json=json.dumps(ports),
    )
    db.add(target)
    db.commit()
    return target


def _make_run(db, target: models.ScanTarget, ports: list[int]) -> models.ScanRun:
    run = models.ScanRun(
        run_id=scan_service.new_scan_run_id(), target_id=target.id,
        target_ip=target.ip_address, status="running",
        ports_scanned=json.dumps(ports), ports_scanned_count=len(ports),
    )
    db.add(run)
    db.commit()
    return run


def _live_ports(lab) -> list[int]:
    return [lab["ssh"], lab["http"], lab["mqtt"], lab["rtsp"], lab["https"], lab["banner"]]


# ── 同步执行路径（execute_scan） ──────────────────────────────────────────────


def test_sweep_ports_reports_only_open_ports(lab):
    ports = scan_service.sweep_ports("127.0.0.1", _live_ports(lab) + [CLOSED_PORT], 1.0, 8)
    assert ports == sorted(_live_ports(lab))


def test_execute_scan_identifies_services_and_matches_cve(session_factory, lab):
    db = session_factory()
    try:
        _seed_mqtt_cve(db)
        target = _make_target(db, _live_ports(lab) + [CLOSED_PORT])
        run = _make_run(db, target, _live_ports(lab) + [CLOSED_PORT])

        scan_service.execute_scan(db, run, target, _live_ports(lab) + [CLOSED_PORT], 1.5, 8)

        assert run.status == "completed"
        assert run.open_ports_count == len(_live_ports(lab))
        assert run.ports_scanned_count == len(_live_ports(lab)) + 1

        identified = {item["port"]: item for item in json.loads(run.identified_services_json)}
        types = {item["service_type"] for item in identified.values()}
        assert types == {"ssh", "http", "mqtt", "rtsp", "https"}
        assert identified[lab["https"]]["product"] == "nginx/1.18.0"
        assert identified[lab["https"]]["version"] == "1.18.0"
        assert identified[lab["mqtt"]]["product"] == "SmartCam MQTT broker 1.6.2"
        assert identified[lab["mqtt"]]["version"] == "1.6.2"

        unmatched = json.loads(run.unmatched_ports_json)
        assert [item["port"] for item in unmatched] == [lab["banner"]]
        assert "CUSTOM-GATEWAY" in unmatched[0]["banner"]

        # 设备清单：身份来自设备自报身份接口，来源标记为互联网扫描
        device = db.query(models.IotDevice).filter_by(device_id=run.device_id).one()
        assert device.device_type == "ip_camera"
        assert device.identity_source == "device_identity_endpoint"
        metadata = json.loads(device.metadata_json)
        assert metadata.get("scan_scope") == "internet_target"
        open_services = {service.port: service for service in device.services if service.status == "open"}
        assert set(open_services) == set(_live_ports(lab))

        # CVE 匹配：预置的 NVD 通用数据命中 MQTT 组件（1.6.2 < 1.7.0）
        match = db.query(models.DeviceVulnerabilityMatch).filter_by(
            device_row_id=device.id, cve_id="CVE-2026-90001").one()
        assert match.affected is True
        assert match.match_status == "potentially_affected"
        assert run.vulnerability_hits == 1
        findings = json.loads(run.findings)
        assert findings["security_status"] == "at_risk"
        assert findings["boundaries"]
        assert target.last_run_id == run.id
    finally:
        db.close()


def test_execute_scan_is_idempotent(session_factory, lab):
    db = session_factory()
    try:
        _seed_mqtt_cve(db)
        target = _make_target(db, _live_ports(lab))
        first = _make_run(db, target, _live_ports(lab))
        scan_service.execute_scan(db, first, target, _live_ports(lab), 1.5, 8)
        second = _make_run(db, target, _live_ports(lab))
        scan_service.execute_scan(db, second, target, _live_ports(lab), 1.5, 8)

        assert first.device_id == second.device_id
        device = db.query(models.IotDevice).filter_by(device_id=first.device_id).one()
        open_ports = [service.port for service in device.services if service.status == "open"]
        assert sorted(open_ports) == sorted(_live_ports(lab))
        matches = db.query(models.DeviceVulnerabilityMatch).filter_by(
            device_row_id=device.id, cve_id="CVE-2026-90001").all()
        assert len(matches) == 1
        assert second.vulnerability_hits == 1
    finally:
        db.close()


def test_execute_scan_silent_target_completes_without_device(session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")
    db = session_factory()
    try:
        target = _make_target(db, [CLOSED_PORT])
        run = _make_run(db, target, [CLOSED_PORT])
        scan_service.execute_scan(db, run, target, [CLOSED_PORT], 0.5, 4)

        assert run.status == "completed"
        assert run.open_ports_count == 0
        assert run.device_id == ""
        findings = json.loads(run.findings)
        assert "无响应" in findings["summary"]
        assert db.query(models.IotDevice).count() == 0
    finally:
        db.close()


def test_execute_scan_defaults_to_internet_server_type(session_factory, lab, monkeypatch):
    """无设备身份接口（仅 HTTPS + 未知协议）时使用保守默认类型 internet_server。"""
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")
    db = session_factory()
    try:
        ports = [lab["https"], lab["banner"]]
        target = _make_target(db, ports)
        run = _make_run(db, target, ports)
        scan_service.execute_scan(db, run, target, ports, 1.5, 8)

        assert run.status == "completed"
        device = db.query(models.IotDevice).filter_by(device_id=run.device_id).one()
        assert device.device_type == "internet_server"
        assert device.identity_source == "banner_heuristic"
    finally:
        db.close()


def test_execute_scan_rechecks_allowed_network_at_scan_time(session_factory, monkeypatch):
    """登记后白名单收紧：扫描时重新校验并拒绝执行（调用方记为 failed）。"""
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")
    db = session_factory()
    try:
        target = _make_target(db, [22])
        run = _make_run(db, target, [22])
        monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "10.0.0.0/8")
        with pytest.raises(ValueError, match="允许网段"):
            scan_service.execute_scan(db, run, target, [22], 0.5, 4)
    finally:
        db.close()


def test_normalize_ports_enforces_caps(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_SCAN_MAX_PORTS", "3")
    assert scan_service.normalize_ports([80, 443, 8080]) == [80, 443, 8080]
    with pytest.raises(ValueError, match="最多"):
        scan_service.normalize_ports([1, 2, 3, 4])
    with pytest.raises(ValueError, match="1–65535"):
        scan_service.normalize_ports([0])


# ── API 路径（后台线程 + 轮询生命周期） ───────────────────────────────────────


def test_api_scan_lifecycle(client, session_factory, lab, scan_env):
    db = session_factory()
    try:
        _seed_mqtt_cve(db)
    finally:
        db.close()

    headers = {"X-Control-Token": "scan-run-token"}
    target = client.post("/api/scans/targets", json={
        "name": "互联网演示主机", "ip": "127.0.0.1",
        "authorization_basis": "本人本地测试环境，授权扫描",
        "ports": _live_ports(lab) + [CLOSED_PORT],
    }, headers=headers)
    assert target.status_code == 200
    target_id = target.json()["id"]

    started = client.post("/api/scans/runs", json={"target_id": target_id}, headers=headers)
    assert started.status_code == 202
    run_id = started.json()["run_id"]

    body = None
    deadline = time.time() + 60
    while time.time() < deadline:
        body = client.get(f"/api/scans/runs/{run_id}").json()
        if body["status"] != "running":
            break
        time.sleep(0.25)
    assert body is not None and body["status"] == "completed", body
    assert body["open_ports_count"] == len(_live_ports(lab))
    assert body["identified_count"] == 5
    assert body["vulnerability_hits"] == 1
    assert body["device_id"]

    runs = client.get(f"/api/scans/runs?target_id={target_id}").json()
    assert [item["run_id"] for item in runs] == [run_id]

    # 扫描产物进入既有设备与漏洞 API（前端与四智能体直接消费）
    vulnerabilities = client.get(f"/api/devices/{body['device_id']}/vulnerabilities").json()
    assert vulnerabilities["affected_count"] == 1
    assert vulnerabilities["matches"][0]["cve_id"] == "CVE-2026-90001"


def test_api_start_scan_rejects_target_drifted_out_of_cidr(client, session_factory, scan_env, monkeypatch):
    db = session_factory()
    try:
        target = _make_target(db, [22])
        target_id = target.id
    finally:
        db.close()
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "10.0.0.0/8")
    resp = client.post("/api/scans/runs", json={"target_id": target_id},
                       headers={"X-Control-Token": "scan-run-token"})
    assert resp.status_code == 400
    assert "允许网段" in resp.json()["detail"]
