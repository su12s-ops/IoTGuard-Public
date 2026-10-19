def test_demo_targets_can_be_saved_and_listed(client, monkeypatch, control_headers):
    monkeypatch.setenv("VM_HOSTS", "")
    monkeypatch.setenv("VM_HOST", "")
    monkeypatch.setenv("VM_PORTS", "")
    monkeypatch.setenv("BIONIC_CONTAINER", "")

    response = client.put(
        "/api/demo/targets",
        json={
            "targets": [
                {
                    "label": "Aliyun VM",
                    "target_type": "ssh",
                    "enabled": True,
                    "host": "47.0.0.10",
                    "ssh_port": 22,
                    "username": "ubuntu",
                    "credential_env": "LINUXGUARD_DEMO_TEST",
                    "asset_hostname": "aliyun-node-01",
                    "container_name": "",
                    "install_falco_if_missing": False,
                    "collect_asset": True,
                    "collect_runtime": True,
                    "notes": "cloud vm",
                },
                {
                    "label": "Legacy Container",
                    "target_type": "container",
                    "enabled": True,
                    "host": "",
                    "ssh_port": 22,
                    "username": "",
                    "password": "",
                    "asset_hostname": "",
                    "container_name": "bionic-c",
                    "install_falco_if_missing": False,
                    "collect_asset": True,
                    "collect_runtime": True,
                    "notes": "local docker",
                },
            ]
        },
     headers=control_headers)

    assert response.status_code == 200
    data = response.json()
    assert len(data["targets"]) == 2
    assert data["targets"][0]["label"] == "Aliyun VM"
    assert data["targets"][1]["target_type"] == "container"

    listed = client.get("/api/demo/targets", headers=control_headers)
    assert listed.status_code == 200
    assert [item["label"] for item in listed.json()["targets"]] == ["Aliyun VM", "Legacy Container"]


def test_demo_start_requires_enabled_targets(client, monkeypatch, control_headers):
    monkeypatch.setenv("VM_HOSTS", "")
    monkeypatch.setenv("VM_HOST", "")
    monkeypatch.setenv("VM_PORTS", "")
    monkeypatch.setenv("BIONIC_CONTAINER", "")

    response = client.put("/api/demo/targets", json={"targets": []}, headers=control_headers)
    assert response.status_code == 200

    started = client.post("/api/demo/start", headers=control_headers)
    assert started.status_code == 400
    assert started.json()["detail"] == "No enabled demo targets configured"


def test_demo_targets_bootstrap_three_ports_on_same_host(client, monkeypatch, control_headers):
    monkeypatch.setenv("VM_HOSTS", "192.168.183.128")
    monkeypatch.setenv("VM_PORTS", "2222,2223,2224")
    monkeypatch.setenv("VM_LABELS", "Ubuntu 22.04,Ubuntu 24.04,Ubuntu 18.04")
    monkeypatch.setenv("VM_USER", "vmuser")
    monkeypatch.setenv("VM_PASS", "secret")
    monkeypatch.setenv("BIONIC_CONTAINER", "")

    response = client.get("/api/demo/targets", headers=control_headers)
    assert response.status_code == 200
    targets = response.json()["targets"]

    assert [(item["label"], item["host"], item["ssh_port"]) for item in targets] == [
        ("Ubuntu 22.04", "192.168.183.128", 2222),
        ("Ubuntu 24.04", "192.168.183.128", 2223),
        ("Ubuntu 18.04", "192.168.183.128", 2224),
    ]

    listed_again = client.get("/api/demo/targets", headers=control_headers)
    assert listed_again.status_code == 200
    assert len(listed_again.json()["targets"]) == 3
