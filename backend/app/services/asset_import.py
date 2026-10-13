"""Versioned JSON import adapter for the existing asset persistence layer."""
from __future__ import annotations

import json

from pydantic import ValidationError

from app.schemas import AssetInventoryDocument, OpenWrtExportDocument
from app.services.asset_parser import ParsedAsset, parse_asset_text


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 包含重复字段")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("JSON 包含非法数值")


def parse_asset_document(content: str) -> ParsedAsset:
    if not content.lstrip().startswith(("{", "[")):
        return parse_asset_text(content)
    try:
        payload = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, TypeError) as exc:
        raise ValueError("资产 JSON 格式无效或字段重复；未保存资产") from exc
    if isinstance(payload, dict) and payload.get("sample_only") is True:
        raise ValueError("此文件标记为 sample_only，仅供结构适配，不能作为完整资产入库；请使用未删减的正式档案")
    if isinstance(payload, dict) and payload.get("schema_version") == "1.0":
        return _parse_openwrt_export(payload)
    try:
        document = AssetInventoryDocument.model_validate(payload)
    except (ValueError, TypeError, ValidationError) as exc:
        # Pydantic errors include input values; never forward them to API users.
        raise ValueError("资产 JSON 不符合 schema_version=1 契约，或软件包条数/解析状态无效；未保存资产") from exc
    fields = document.asset.model_dump()
    fields["distribution"] = fields["distribution"].strip().lower()
    fields["hostname"] = fields["hostname"].strip()
    if not fields["hostname"]:
        raise ValueError("资产缺少主机名")
    if fields["distribution"] == "openwrt":
        from app.services.asset_parser import normalize_mac
        fields["mac_address"] = normalize_mac(fields["mac_address"])
        if not fields["mac_address"] or not all(fields[key] for key in ("os_version", "architecture", "device_model")):
            raise ValueError("OpenWrt JSON 须提供 MAC、完整固件版本、架构及设备型号")
        if fields["firmware_version"] and fields["firmware_version"] != fields["os_version"]:
            raise ValueError("OpenWrt 固件版本字段不一致")
        if any(p.package_manager not in {"apk", "opkg"} for p in document.packages):
            raise ValueError("OpenWrt 软件包管理器必须为 apk 或 opkg")
        suffix = "-" + fields["mac_address"].replace(":", "")
        if not fields["hostname"].endswith(suffix):
            fields["hostname"] += suffix
        if len(fields["hostname"]) > 128:
            raise ValueError("OpenWrt 身份主机名过长")
        fields.update(os_name="OpenWrt", firmware_version=fields["os_version"], device_type="iot_gateway")
    collection = document.collection
    parsed = ParsedAsset(**fields, inventory_complete=collection.packages_complete,
                         inventory_collected_at=collection.collected_at)
    parsed.packages = [p.model_dump() for p in document.packages]
    parsed.services = [s.model_dump() for s in document.services]
    parsed.package_parse_stats = {"raw_count": collection.package_count, "parsed_count": len(parsed.packages),
                                  "rejected_count": 0, "errors": [], "declared_count": collection.package_count,
                                  "count_matches": True}
    parsed.inventory_metadata_json = json.dumps({"format": "iotguard_asset_v1", "source": collection.source,
        "collector_version": collection.collector_version, "source_verification": "operator_supplied",
        "package_parse_stats": parsed.package_parse_stats}, ensure_ascii=False)
    return parsed


def _parse_openwrt_export(payload) -> ParsedAsset:
    try:
        document = OpenWrtExportDocument.model_validate(payload)
    except (ValueError, TypeError, ValidationError) as exc:
        raise ValueError("OpenWrt 1.0 JSON 的结构、原始包记录、条数或解析状态无效；未保存资产") from exc
    device = document.device
    if device.firmware.distribution.strip().lower() != "openwrt":
        raise ValueError("1.0 导出档案不能确认设备发行版为 OpenWrt")
    from app.services.asset_parser import normalize_mac
    mac = normalize_mac(device.mac_address)
    architectures = {p.architecture for p in document.software_inventory.packages if p.architecture != "noarch"}
    target_arch = {"x86/64": "x86_64", "x86/generic": "i386"}.get(device.firmware.target)
    architecture = target_arch or (next(iter(architectures)) if len(architectures) == 1 else "")
    if not architecture:
        raise ValueError("无法从固件 target 或软件包记录确定体系结构")
    suffix = "-" + (mac.replace(":", "") if mac else document.asset_id)
    hostname = device.hostname.strip()
    if not hostname:
        raise ValueError("资产缺少主机名")
    if not hostname.endswith(suffix):
        hostname += suffix
    if len(hostname) > 128:
        raise ValueError("资产身份主机名过长")
    software = document.software_inventory
    stats = {"raw_count": software.raw_count, "parsed_count": len(software.packages),
             "rejected_count": 0, "errors": [], "declared_count": software.package_count, "count_matches": True}
    declared_ip = device.ip_address or (document.management.ip_address if document.management else "")
    parsed = ParsedAsset(hostname=hostname, ip_address=declared_ip, distribution="openwrt", os_name="OpenWrt",
        os_version=device.firmware.version, firmware_version=device.firmware.version, kernel_version=device.kernel,
        architecture=architecture, device_type="iot_gateway", device_model=device.board_name, mac_address=mac,
        identity_source="uploaded_inventory" if mac else "uploaded_inventory_id", identity_confidence=0.7 if mac else 0.5,
        inventory_external_id="openwrt-json:" + document.asset_id, inventory_complete=True,
        inventory_collected_at=document.generated_at, package_parse_stats=stats)
    parsed.packages = [{"package_name": p.name, "package_version": p.version,
                        "package_manager": "apk", "architecture": p.architecture} for p in software.packages]
    parsed.inventory_metadata_json = json.dumps({"format": "openwrt_export_1.0", "external_asset_id": document.asset_id,
        "asset_type": document.asset_type, "collection_method": document.collection_method,
        "timestamp_basis": "export_generated_at",
        "source_verification": "operator_supplied", "ssh_identity_verified_by_platform": False,
        "original_hostname": device.hostname, "device": device.model_dump(), "package_parse_stats": stats,
        "management": document.management.model_dump() if document.management else None,
        "integrity": document.integrity.model_dump() if document.integrity else None,
        "source_file_hash_verification": "not_verified_external_files_unavailable" if document.integrity else "not_provided",
        "software_source": software.source,
        "package_metadata": [{"name": p.name, "source": p.source, "license": p.license, "status": p.status}
                             for p in software.packages]}, ensure_ascii=False)
    return parsed
