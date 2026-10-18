from app import models
from app.services.iot_business import overview
from app.services.iot_official import import_snapshot
from app.services.device_vulnerability import run_device_matching


def test_iot_overview_keeps_infrastructure_separate(session_factory):
    with session_factory() as db:
        db.add_all([models.LinuxAsset(hostname="control-node", distribution="ubuntu"),
                    models.LinuxAsset(hostname="router", distribution="openwrt", os_version="25.12.6")])
        db.commit()
        result = overview(db)
        assert result["device_count"] == 1
        assert result["infrastructure_count"] == 1
        assert result["devices"][0]["matches"]["assessment"] == "unassessed"
        assert result["devices"][0]["next_action"] == "collect_inventory"


def test_kernel_official_range_does_not_use_application_version(session_factory):
    with session_factory() as db:
        device = models.IotDevice(device_id="real-identity", device_name="sensor", os="Zephyr RTOS 4.4.2",
                                  firmware_version="0.3.0-iotguard")
        db.add(device)
        db.flush()
        db.add(models.IotDeviceComponent(device_row_id=device.id, component_name="Zephyr RTOS", version="4.4.2"))
        row = {"ghsa_id": "GHSA-82gq-cmqw-xgx2", "cve_id": "CVE-2026-76787",
               "html_url": "https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-82gq-cmqw-xgx2",
               "vulnerabilities": [{"package": {"name": "zephyr"}, "vulnerable_version_range": ">= 4.0.0, <= 4.4.2"}]}
        import_snapshot(db, "zephyr", [row])
        db.commit()
        for _ in range(2):
            result = run_device_matching(db, device)
            assert result["stats"]["potentially_affected"] == 1
        match = db.query(models.DeviceVulnerabilityMatch).one()
        assert match.installed_version == "4.4.2"
        assert match.match_status == "potentially_affected"
        assert match.applicability_source == "official_ghsa"
        assert overview(db)["devices"][0]["runtime"] == "ebpf_not_applicable"
        component = db.query(models.IotDeviceComponent).one()
        component.version = "4.5.0"
        db.commit()
        result = run_device_matching(db, device)
        assert result["stats"]["not_in_reported_range"] == 1
        assert not db.query(models.DeviceVulnerabilityMatch).one().affected


def test_business_api_empty_state(client):
    response = client.get('/api/devices/business/overview')
    assert response.status_code == 200
    assert response.json()['device_count'] == 0
    assert response.json()['closure_status'] == 'partial'
