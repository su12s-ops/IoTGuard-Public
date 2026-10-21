"""阶段二：eBPF → SecurityEvidence → 数据库 → API → 智能体。

fixture 是 WSL Ubuntu 24.04（内核 6.6）上 bpftrace 真实采集的 40 条内核事件
（17 execve / 3 connect / 20 openat），采集时真实执行了：
启动 mosquitto、bash→sh→wget 子进程链、MQTT/HTTP 连接、
受控路径读/写（/etc/passwd、/etc/shadow、/etc/mosquitto、/etc/iotguard、/opt/firmware）。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.evidence_queries import get_runtime_evidence

FIXTURE = Path(__file__).parent / "fixtures" / "ebpf_real_capture.jsonl"


@pytest.fixture(scope="module")
def real_capture() -> list[dict]:
    lines = FIXTURE.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines]


@pytest.fixture(autouse=True)
def iot_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "stage2-test-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")


def _auth():
    return {"X-Control-Token": "stage2-test-token"}


def _upload(client, events):
    payload = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
    return client.post(
        "/api/runtime/ebpf/upload",
        files={"file": ("ebpf_real_capture.jsonl", payload.encode("utf-8"), "application/jsonl")},
        headers=_auth(),
    )


# ── fixture 本身是真实采集 ───────────────────────────────────────────────────

def test_real_capture_fixture_covers_three_types(real_capture):
    types = {event["event_type"] for event in real_capture}
    assert {"execve", "connect", "openat"} <= types
    assert all(event["source"] == "ebpf_bpftrace" for event in real_capture)
    assert len(real_capture) == 40


# ── eBPF → Evidence → 数据库 → API ──────────────────────────────────────────

def test_upload_real_capture_creates_typed_evidence(client, real_capture):
    response = _upload(client, real_capture)
    assert response.status_code == 200, response.text
    assert response.json()["count"] == 40

    summary = client.get("/api/runtime/evidence/summary").json()
    assert summary["total"] == 40
    assert summary["by_type"].get("process", 0) == 17
    assert summary["by_type"].get("network", 0) == 3
    assert summary["by_type"].get("file", 0) == 20
    assert summary["watched_file_events"] >= 20
    assert summary["latest_timestamp"].startswith("2026-")  # 真实墙上时间


def test_process_evidence_has_pid_ppid_user_and_chain(client, real_capture):
    _upload(client, real_capture)
    data = client.get("/api/runtime/evidence/process").json()
    events = data["events"]
    names = {event["process"] for event in events}
    assert {"bash", "sh", "wget", "mosquitto", "mosquitto_pub", "curl"} <= names
    for event in events:
        assert event["pid"] > 0 and event["ppid"] > 0 and event["user"]
        assert event["evidence_id"].startswith("SE-")
    # 真实父子关系：sh(pid) 与 wget(pid, ppid=sh.pid)
    sh = next(e for e in events if e["process"] == "sh")
    wget = next(e for e in events if e["process"] == "wget")
    assert wget["ppid"] == sh["pid"]


def test_network_evidence_has_process_ip_port_time(client, real_capture):
    _upload(client, real_capture)
    events = client.get("/api/runtime/evidence/network").json()["events"]
    by_port = {event["destination_port"]: event for event in events}
    mqtt = by_port[18884]  # mosquitto_pub → 本机 MQTT broker
    assert mqtt["process"] == "mosquitto_pub"
    assert mqtt["destination_ip"] == "127.0.0.1"
    assert mqtt["timestamp"]
    http_events = [e for e in events if e["destination_port"] == 18080]
    assert {event["process"] for event in http_events} == {"wget", "curl"}


def test_file_evidence_on_watched_paths(client, real_capture):
    _upload(client, real_capture)
    events = client.get("/api/runtime/evidence/file", params={"watched_only": True}).json()["events"]
    paths = {event["file_path"] for event in events}
    assert "/etc/mosquitto/mosquitto.conf" in paths            # mosquitto 读自身配置
    assert "/etc/passwd" in paths
    assert "/etc/shadow" in paths
    assert "/etc/iotguard/selftest.conf" in paths              # 写入
    assert "/opt/firmware/.selftest" in paths                  # 写入
    by_path = {event["file_path"]: event for event in events}
    # openat proves an open attempt, not completed byte reads/writes.
    assert by_path["/etc/iotguard/selftest.conf"]["operation"] == "open"
    assert by_path["/opt/firmware/.selftest"]["severity"] == "warning"
    assert by_path["/etc/shadow"]["operation"] == "open"
    assert by_path["/etc/mosquitto/mosquitto.conf"]["process"] == "mosquitto"
    assert by_path["/etc/iotguard/selftest.conf"]["process"] == "bash"


def test_process_tree_links_parent_child(client, real_capture):
    _upload(client, real_capture)
    hostname = real_capture[0]["hostname"]
    tree = client.get("/api/runtime/evidence/process-tree", params={"device_id": hostname}).json()
    device = tree["devices"][hostname]
    assert device["process_count"] >= 10

    def chain_exists(node, names):
        if node["process"] != names[0]:
            return False
        if len(names) == 1:
            return True
        return any(chain_exists(child, names[1:]) for child in node["children"])

    # 真实采集到的父子链：bash → sh → wget
    assert any(chain_exists(root, ["bash", "sh", "wget"]) for root in device["roots"])


def test_upload_is_idempotent_for_evidence(client, real_capture):
    _upload(client, real_capture)
    _upload(client, real_capture)
    summary = client.get("/api/runtime/evidence/summary").json()
    assert summary["total"] == 40  # 同一证据哈希不重复入库


def test_evidence_filter_by_type_and_device(client, real_capture):
    _upload(client, real_capture)
    hostname = real_capture[0]["hostname"]
    response = client.get("/api/runtime/evidence", params={"type": "file", "device_id": hostname}).json()
    assert response["count"] == 20
    assert all(event["device_id"] == hostname for event in response["events"])


# ── 智能体证据链路 ───────────────────────────────────────────────────────────

def test_agent_runtime_tool_returns_typed_evidence(client, real_capture, session_factory):
    _upload(client, real_capture)
    hostname = real_capture[0]["hostname"]
    db = session_factory()
    try:
        result = get_runtime_evidence(db, hostname=hostname)
        typed = result["security_evidence"]
        assert typed["type_counts"]["process"] >= 17
        assert typed["type_counts"]["network"] >= 3
        assert typed["type_counts"]["file"] >= 20
        assert typed["process_tree"]["process_count"] >= 10
        assert any(event["destination_port"] == 18884 for event in typed["network_events"])
    finally:
        db.close()


# ── Falco 格式归一化（生产 VM 走 Falco 路线） ─────────────────────────────────

def test_falco_event_also_becomes_typed_evidence(client):
    falco_write = {
        "output": "LG-IoT watched file write: proc=wget file=/etc/shadow",
        "priority": "Error", "rule": "LinuxGuard IoT Watched File Write",
        "time": "2026-09-30T08:00:00.000000000Z",
        "output_fields": {
            "evt.type": "openat", "proc.name": "wget", "proc.cmdline": "wget -O /etc/shadow http://x",
            "proc.pid": 4242, "proc.ppid": 4241, "proc.pname": "sh", "user.name": "root",
            "fd.name": "/etc/shadow", "evt.arg.flags": "O_WRONLY|O_CREAT",
        },
    }
    falco_connect = {
        "output": "LG-IoT outbound connect",
        "priority": "Notice", "rule": "LinuxGuard IoT Outbound Connection",
        "time": "2026-09-30T08:00:01.000000000Z",
        "output_fields": {
            "evt.type": "connect", "proc.name": "curl", "proc.cmdline": "curl http://198.51.100.9/x",
            "proc.pid": 4300, "user.name": "www-data", "fd.rip": "198.51.100.9", "fd.rport": 443,
        },
    }
    response = client.post("/api/runtime/ebpf/events", json=[falco_write, falco_connect], headers=_auth())
    assert response.status_code == 200, response.text
    files = client.get("/api/runtime/evidence/file").json()["events"]
    shadow = next(e for e in files if e["file_path"] == "/etc/shadow")
    assert shadow["process"] == "wget" and shadow["user"] == "root"
    assert shadow["operation"] == "open" and shadow["severity"] == "error"
    networks = client.get("/api/runtime/evidence/network").json()["events"]
    outbound = next(e for e in networks if e["destination_ip"] == "198.51.100.9")
    assert outbound["destination_port"] == 443 and outbound["process"] == "curl"


# ── eBPF LSM 实验功能（默认 observe，enforce 双重门禁） ────────────────────────

def test_lsm_defaults_to_observe(client):
    status = client.get("/api/runtime/lsm/status").json()
    assert status["default_mode"] == "observe"
    assert status["experimental"] is True
    assert status["enforce_enabled_any"] is False


def test_lsm_enforce_requires_ack_and_kernel_support(client, iot_env):
    # 未显式确认 → 400
    response = client.put("/api/runtime/lsm/policies", json={"mode": "enforce"}, headers=_auth())
    assert response.status_code == 400
    # 显式确认但内核能力未上报 → 409，策略保持 observe
    response = client.put("/api/runtime/lsm/policies",
                          json={"mode": "enforce", "enforce_ack": True}, headers=_auth())
    assert response.status_code == 409
    assert client.get("/api/runtime/lsm/policies").json()["mode"] == "observe"


def test_lsm_capability_gates_enforce_and_auto_downgrades(client, iot_env):
    # 采集端上报内核支持
    capability = {"device_id": "", "bpf_lsm_supported": True,
                  "lsm_list": "capability,landlock,bpf", "detail": "test probe"}
    assert client.post("/api/runtime/lsm/capability", json=capability, headers=_auth()).status_code == 200
    response = client.put("/api/runtime/lsm/policies",
                          json={"mode": "enforce", "enforce_ack": True}, headers=_auth())
    assert response.status_code == 200 and response.json()["mode"] == "enforce"
    # 内核能力消失（重启后不支持）→ 自动降级 observe
    capability["bpf_lsm_supported"] = False
    client.post("/api/runtime/lsm/capability", json=capability, headers=_auth())
    assert client.get("/api/runtime/lsm/status").json()["enforce_enabled_any"] is False


def test_lsm_write_requires_control_token(client, iot_env):
    response = client.put("/api/runtime/lsm/policies", json={"mode": "observe"})
    assert response.status_code == 401
