"""Read-only business view over the two existing IoT inventory models."""
from collections import Counter
import json

from app import models


def _summary(rows):
    counts = Counter(row.match_status for row in rows)
    return {"count": len(rows), "confirmed": counts["affected"],
            "pending": sum(counts[k] for k in ("insufficient_data", "potentially_affected", "unknown")),
            "statuses": dict(counts), "assessment": "partial" if rows else "unassessed"}


def overview(db):
    """Do not merge identities by IP or promote infrastructure into IoT devices."""
    devices = []
    for asset in db.query(models.LinuxAsset).filter(models.LinuxAsset.distribution == "openwrt"):
        rows = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id, active=True).all()
        devices.append({"key": f"asset:{asset.id}", "name": asset.hostname,
                        "ecosystem": "openwrt", "version": asset.os_version,
                        "inventory_complete": bool(asset.inventory_complete),
                        "identity_confidence": asset.identity_confidence,
                        "component_count": len(asset.packages), "matches": _summary(rows),
                        "runtime": "requires_sensor_evidence",
                        "remediation": "requires_device_specific_plan",
                        "next_action": "collect_inventory" if not asset.inventory_complete else "review_applicability",
                        "detail_path": "/iot", "task_path": f"/device-tasks?asset={asset.id}"})
    for device in db.query(models.IotDevice).all():
        metadata = json.loads(device.metadata_json or "{}")
        zephyr = (device.os or "").lower().startswith("zephyr")
        rows = db.query(models.DeviceVulnerabilityMatch).filter_by(device_row_id=device.id, active=True).all()
        devices.append({"key": f"device:{device.device_id}", "name": device.device_name or device.device_id,
                        "ip_address": device.ip, "device_type": device.device_type,
                        "identity_source": device.identity_source,
                        "simulation": metadata.get("simulation") is True,
                        "gateway": metadata.get("gateway"),
                        "ecosystem": "zephyr" if zephyr else "other_iot",
                        "version": device.os if zephyr else device.firmware_version,
                        "inventory_complete": None, "identity_confidence": device.identity_confidence,
                        "component_count": len(device.components), "matches": _summary(rows),
                        "runtime": "ebpf_not_applicable" if zephyr else "requires_sensor_evidence",
                        "remediation": "firmware_update_not_automated" if zephyr else "requires_device_specific_plan",
                        "next_action": "review_applicability" if rows else "match_vulnerabilities",
                        "detail_path": "/devices", "task_path": "/device-tasks"})
    return {"devices": devices, "device_count": len(devices),
            "infrastructure_count": db.query(models.LinuxAsset).filter(
                models.LinuxAsset.distribution != "openwrt").count(),
            "official_snapshot_counts": {ecosystem: db.query(models.IotOfficialAdvisory).filter_by(
                ecosystem=ecosystem).count() for ecosystem in ("openwrt", "zephyr")},
            "closure_status": "partial", "note": "Snapshot coverage, applicability and repair verification are separate stages."}
