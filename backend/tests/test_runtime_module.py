import json

from app import models
from app.services import ebpf_event_collector as collector


def seed_runtime_asset(session_factory, hostname="vm-runtime-01", ip_address="10.0.0.10"):
    db = session_factory()
    try:
        asset = models.LinuxAsset(
            hostname=hostname,
            ip_address=ip_address,
            os_name="Ubuntu",
            os_version="22.04",
            distribution="ubuntu",
            exposure_level="public",
            business_level="core",
        )
        db.add(asset)
        db.flush()
        db.add(
            models.AssetPackage(
                asset_id=asset.id,
                package_name="nginx",
                package_version="1.18.0-ubuntu1.3",
                package_manager="dpkg",
            )
        )
        db.add(
            models.AssetPackage(
                asset_id=asset.id,
                package_name="openssl",
                package_version="3.0.2-0ubuntu1.10",
                package_manager="dpkg",
            )
        )
        db.add(
            models.AssetService(
                asset_id=asset.id,
                service_name="nginx",
                port=443,
                protocol="tcp",
                listen_address="0.0.0.0",
                process_name="nginx",
                is_public_exposed=True,
            )
        )
        db.commit()
    finally:
        db.close()


def test_parse_event_lines_accepts_json_arrays(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "DATA_DIR", tmp_path)
    monkeypatch.setattr(collector, "EVENT_FILE", tmp_path / "ebpf_events.jsonl")

    payloads = collector.parse_event_lines(
        json.dumps(
            [
                {"hostname": "vm-runtime-01", "source": "falco_json", "event_type": "execve"},
                {"hostname": "vm-runtime-02", "source": "falco_json", "event_type": "connect"},
            ]
        )
    )

    assert len(payloads) == 2
    assert payloads[0]["hostname"] == "vm-runtime-01"
    assert payloads[1]["event_type"] == "connect"


def test_normalize_event_preserves_explicit_probe_category():
    event = collector.normalize_event(
        {
            "hostname": "vm-runtime-01",
            "source": "runtime_probe_ssh",
            "event_type": "execve",
            "process_name": "nginx",
            "commandline": "nginx -v",
            "parent_process": "linuxguard-runtime-probe",
            "severity": "Informational",
            "rule": "Nginx version probe",
            "category": "process_execution",
        }
    )

    assert event["category"] == "process_execution"
    assert event["parent_process"] == "linuxguard-runtime-probe"


def test_runtime_demo_endpoint_generates_asset_mapped_events(client, session_factory, tmp_path, monkeypatch, control_headers):
    monkeypatch.setattr(collector, "DATA_DIR", tmp_path)
    monkeypatch.setattr(collector, "EVENT_FILE", tmp_path / "ebpf_events.jsonl")
    seed_runtime_asset(session_factory)

    response = client.post("/api/runtime/ebpf/demo", params={"per_asset": 4}, headers=control_headers)

    assert response.status_code == 200
    assert response.json()["count"] == 4

    status = client.get("/api/runtime/ebpf/status").json()
    assert status["db_event_count"] == 4
    assert status["matched_asset_count"] == 1
    assert status["available_hosts"] == ["vm-runtime-01"]
    assert status["observation_mode_counts"]["probe"] == 4


def test_runtime_upload_supports_json_array_and_filters(client, session_factory, tmp_path, monkeypatch, control_headers):
    monkeypatch.setattr(collector, "DATA_DIR", tmp_path)
    monkeypatch.setattr(collector, "EVENT_FILE", tmp_path / "ebpf_events.jsonl")
    seed_runtime_asset(session_factory)

    payload = json.dumps(
        [
            {
                "hostname": "vm-runtime-01",
                "source": "falco_json",
                "event_type": "connect",
                "process_name": "nginx",
                "commandline": "nginx: worker process",
                "destination": "203.0.113.5",
                "port": 443,
                "severity": "critical",
                "rule": "Network connection from nginx",
            }
        ]
    ).encode()

    response = client.post(
        "/api/runtime/ebpf/upload",
        files={"file": ("events.json", payload, "application/json")},
     headers=control_headers)

    assert response.status_code == 200
    assert response.json()["count"] == 1

    # Falco JSON alone does not establish the driver as eBPF.
    events = client.get("/api/runtime/ebpf/events", params={"hostname": "vm-runtime-01", "mode": "sensor"}).json()
    assert events["count"] == 1
    assert events["events"][0]["category"] == "network_activity"

    correlations = client.get("/api/runtime/ebpf/correlations").json()
    assert correlations[0]["event_count"] == 1
    assert "nginx" in correlations[0]["matched_services"]


def test_runtime_status_reports_unmatched_hosts(client, session_factory, tmp_path, monkeypatch, control_headers):
    monkeypatch.setattr(collector, "DATA_DIR", tmp_path)
    monkeypatch.setattr(collector, "EVENT_FILE", tmp_path / "ebpf_events.jsonl")
    seed_runtime_asset(session_factory)

    client.post(
        "/api/runtime/ebpf/events",
        json={
            "hostname": "other-host",
            "source": "falco_json",
            "event_type": "execve",
            "process_name": "bash",
            "commandline": "bash -lc whoami",
            "severity": "warning",
            "rule": "Shell execution",
        },
     headers=control_headers)

    status = client.get("/api/runtime/ebpf/status").json()

    assert status["db_event_count"] == 1
    assert status["matched_asset_count"] == 0
    assert status["unmatched_hosts"] == ["other-host"]
