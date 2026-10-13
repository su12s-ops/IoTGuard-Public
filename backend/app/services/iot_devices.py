"""OpenWrt inventory, bounded discovery and source-scoped exact-version evidence."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app import models
from app.services import device_access
from app.services.asset_parser import parse_asset_text, save_parsed_asset
from app.services.device_access import (allowed_networks, allowed_host, open_connection, run_fixed_script,
    connection_signature, DeviceOperationError)

COLLECTOR = Path(__file__).resolve().parents[3] / "collector" / "collect_openwrt_asset.sh"


def observation(db, *, scope, identity_key, **values):
    row = db.query(models.DeviceObservation).filter_by(scope=scope, identity_key=identity_key).one_or_none()
    if row is None:
        row = models.DeviceObservation(scope=scope, identity_key=identity_key)
        db.add(row)
    for key, value in values.items():
        setattr(row, key, value)
    row.last_seen_at = models.utcnow()
    return row


def save_gateway_observations(db, asset, rows, *, commit=True):
    for item in rows:
        try:
            address = str(ipaddress.ip_address(item["ip_address"]))
        except (KeyError, ValueError):
            continue
        mac = str(item.get("mac_address", "")).lower()[:32]
        expiry = str(item.get("lease_expiry", ""))
        expired = expiry.isdigit() and int(expiry) > 0 and int(expiry) < time.time()
        observation(db, scope=f"gateway:{asset.id}", identity_key=mac or address,
                    gateway_asset_id=asset.id, ip_address=address, mac_address=mac,
                    hostname=str(item.get("hostname", ""))[:128], source="dhcp_lease",
                    presence="expired_lease" if expired else "lease_record",
                    evidence_json=json.dumps({"lease_expiry": expiry, "online_verified": False}))
    if commit:
        db.commit()
    else:
        db.flush()


def collect_openwrt(db, connection, *, commit=True, audit=None, on_authenticated=None):
    """Validate a complete snapshot, then update only the explicitly bound asset."""
    audit = audit if audit is not None else {}
    existing = db.get(models.LinuxAsset, connection.asset_id) if connection.asset_id else None
    if not existing or existing.distribution != "openwrt":
        raise DeviceOperationError("asset_binding_required", "真实采集必须先绑定已有 OpenWrt 资产")
    try:
        allowed_host(connection.host)
    except ValueError as exc:
        raise DeviceOperationError("target_not_authorized", "设备管理地址不在明确授权范围内") from exc
    try:
        script = COLLECTOR.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeviceOperationError("collector_unavailable", "固定 OpenWrt Collector 不可用") from exc
    actual_script_hash = hashlib.sha256(script.encode()).hexdigest()
    if audit.get("collector_sha256") and audit["collector_sha256"] != actual_script_hash:
        raise DeviceOperationError("collector_changed", "Collector 在执行前发生变化，未开始 SSH")
    audit.update(collector_type="openwrt_ssh", collector_sha256=actual_script_hash,
                 node=device_access.collector_node())
    client = open_connection(connection)
    audit.update(ssh_host_identity="verified", ssh_authentication="succeeded")
    try:
        if on_authenticated:
            on_authenticated(audit)
        text = run_fixed_script(client, script)
    finally:
        client.close()
    audit.update(collector_exit_status=0, remote_execution_status="exited", output_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(), output_bytes=len(text.encode("utf-8")))
    parsed = parse_asset_text(text)
    parsed.inventory_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    audit["package_parse_stats"] = parsed.package_parse_stats
    if parsed.distribution != "openwrt" or not all((parsed.hostname, parsed.device_model, parsed.os_version, parsed.kernel_version, parsed.architecture)):
        raise DeviceOperationError("device_identity_incomplete", "采集结果缺少完整 OpenWrt 设备身份字段")
    if not parsed.inventory_complete:
        raise DeviceOperationError("inventory_incomplete", "采集清单不完整或解析错误；保留已有完整资产")
    if any(p["package_manager"] == "apk" for p in parsed.packages) and not parsed.package_parse_stats.get("details_matches"):
        raise DeviceOperationError("apk_details_missing", "在线 APK 采集须提供逐包架构和来源；保留已有完整资产")
    if existing:
        if existing.device_model and parsed.device_model != existing.device_model:
            raise DeviceOperationError("device_model_mismatch", "设备型号与已绑定资产不一致")
        if existing.mac_address and parsed.mac_address != existing.mac_address:
            raise DeviceOperationError("device_mac_mismatch", "设备 MAC 与已绑定资产不一致")
        if parsed.mac_address and db.query(models.LinuxAsset).filter(
                models.LinuxAsset.id != existing.id, models.LinuxAsset.distribution == "openwrt",
                models.LinuxAsset.mac_address == parsed.mac_address).first():
            raise DeviceOperationError("device_identity_conflict", "采集 MAC 已属于另一资产；未合并或覆盖资产")
        for field in ("owner", "business_level", "exposure_level", "description"):
            setattr(parsed, field, getattr(existing, field))
    parsed.ip_address = connection.host
    parsed.identity_source = "pinned_ssh_inventory"
    parsed.identity_confidence = 0.95
    metadata = json.loads(parsed.inventory_metadata_json)
    metadata.update(source="openwrt_ssh", connection_id=connection.id,
                    connection_signature=connection_signature(connection), node=device_access.collector_node(),
                    ssh_identity_verified_by_platform=True, collector_sha256=audit["collector_sha256"],
                    collection_run_id=audit.get("run_id"), started_at=audit.get("started_at"),
                    timestamp_basis="backend_received_at", cve_applicability="not_evaluated_for_this_snapshot",
                    previous_inventory_sha256=existing.inventory_sha256)
    parsed.inventory_collected_at = models.utcnow()
    parsed.inventory_metadata_json = json.dumps(metadata, ensure_ascii=False)
    if not parsed.mac_address:
        parsed.hostname += "-" + hashlib.sha256(connection.host_key_sha256.encode()).hexdigest()[:12]
    prior = db.query(models.LinuxAsset).filter_by(hostname=parsed.hostname).first()
    if prior:
        bound = db.query(models.DeviceConnection).filter_by(asset_id=prior.id).first()
        if bound and bound.id != connection.id:
            raise ValueError("该设备身份已绑定其他连接，请编辑现有连接而不是重复绑定")
    asset = save_parsed_asset(db, parsed, asset_id=connection.asset_id, commit=False)
    asset.last_seen_at = models.utcnow()
    connection.asset_id = asset.id
    save_gateway_observations(db, asset, parsed.observations, commit=False)
    audit.update(asset_collection="succeeded", asset_id=asset.id, package_count=len(parsed.packages),
                 architecture_counts={arch: sum(p["architecture"] == arch for p in parsed.packages)
                                      for arch in {p["architecture"] for p in parsed.packages}})
    if commit:
        db.commit()
    else:
        db.flush()
    return asset


def _probe(address, ports, timeout):
    found = []
    for port in ports:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                found.append(port)
        except OSError:
            pass
    return address, found


def discover(db, cidr, ports, timeout=0.3):
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4 or network.num_addresses > 128:
        raise ValueError("每次仅支持最多 128 个地址的 IPv4 网段")
    if not any(network.version == n.version and network.subnet_of(n) for n in allowed_networks()):
        raise ValueError("探测范围不在后端允许网段内")
    addresses = [str(address) for address in network.hosts()]
    found = 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        for address, open_ports in pool.map(lambda address: _probe(address, ports, timeout), addresses):
            if not open_ports:
                continue
            found += 1
            observation(db, scope=str(network), identity_key=address, ip_address=address,
                        source="tcp_connect", presence="responded",
                        evidence_json=json.dumps({"open_ports": open_ports, "device_type": "unknown",
                                                  "identity_confidence": 0, "online_verified": True}))
    db.commit()
    return {"scanned_addresses": len(addresses), "responding_devices": found,
            "scope": str(network), "note": "仅发现指定端口有响应的设备；无响应不能证明设备不存在，开放端口不能确认设备型号。"}


def match_openwrt(db, asset, target_cves):
    """Exact vendor-scoped versions. Never compare opkg/apk with dpkg semantics."""
    packages = {p.package_name: p for p in asset.packages}
    advisories = db.query(models.OpenWrtAdvisory).filter_by(release=asset.os_version).all()
    for advisory in advisories:
        if target_cves and advisory.cve_id not in target_cves:
            continue
        if not db.query(models.VulnerabilityInfo).filter_by(cve_id=advisory.cve_id).first():
            db.add(models.VulnerabilityInfo(cve_id=advisory.cve_id,
                title=f"{advisory.cve_id} / OpenWrt {advisory.package_name}",
                affected_package=advisory.package_name, source="openwrt_operator_advisory",
                references=advisory.source_url, description="依据保留的人工厂商适用性记录重建；未自动验证公告正文。"))
            db.flush()
    candidates = {(a.cve_id, a.package_name): a for a in advisories if not target_cves or a.cve_id in target_cves}
    # An upstream name match is only a candidate without distribution applicability.
    for vuln in db.query(models.VulnerabilityInfo).all():
        if ":" in vuln.cve_id or (target_cves and vuln.cve_id not in target_cves):
            continue
        if vuln.affected_package in packages:
            candidates.setdefault((vuln.cve_id, vuln.affected_package), None)
    result = []
    for (cve_id, name), advisory in candidates.items():
        package = packages.get(name)
        if not package:
            continue
        installed = package.package_version or ""
        fixed = json.loads(advisory.fixed_versions_json) if advisory else []
        affected = json.loads(advisory.affected_versions_json) if advisory else []
        status, code, confidence, is_affected = "insufficient_data", "openwrt_applicability_missing", 0.35, True
        reason = "缺少与当前 OpenWrt 固件版本对应的厂商适用性证据，需复核；不采用其他发行版修复版本。"
        if not asset.inventory_complete:
            code, confidence, reason = "inventory_incomplete", 0.0, "本次软件清单不完整，不能确认修复。"
        elif advisory and installed in fixed:
            status, code, confidence, is_affected = "fixed", "openwrt_exact_fixed_version", 0.95, False
            reason = f"版本精确命中人工整理的 OpenWrt 已修复版本记录：{advisory.source_url}"
        elif advisory and installed in affected:
            status, code, confidence = "affected", "openwrt_exact_affected_version", 0.95
            reason = f"版本精确命中人工整理的 OpenWrt 受影响版本记录：{advisory.source_url}"
        values = dict(installed_version=installed, fixed_version=fixed[0] if fixed else "",
                      affected=is_affected, match_status=status, reason_code=code, match_reason=reason, confidence=confidence)
        values["evidence_fingerprint"] = hashlib.sha256(json.dumps(
            {**values, "release": asset.os_version, "package": name,
             "source": advisory.source_url if advisory else ""}, sort_keys=True).encode()).hexdigest()
        row = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id, cve_id=cve_id, package_name=name).one_or_none()
        if row is None:
            row = models.VulnerabilityMatch(asset_id=asset.id, cve_id=cve_id, package_name=name)
            db.add(row)
        for key, value in values.items():
            setattr(row, key, value)
        row.active = True
        row.updated_at = models.utcnow()
        result.append((asset.id, cve_id, name))
    db.flush()
    return result
