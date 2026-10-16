import re
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models


@dataclass
class ParsedAsset:
    hostname: str = ""
    ip_address: str = ""
    os_name: str = ""
    os_version: str = ""
    distribution: str = ""
    kernel_version: str = ""
    architecture: str = ""
    exposure_level: str = "internal"
    business_level: str = "normal"
    owner: str = ""
    description: str = ""
    device_type: str = "linux_server"
    device_model: str = ""
    mac_address: str = ""
    firmware_version: str = ""
    identity_source: str = "uploaded_inventory"
    identity_confidence: float = 0.7
    capabilities_json: str = "{}"
    inventory_complete: bool = True
    package_parse_stats: dict = field(default_factory=dict)
    inventory_collected_at: datetime | None = None
    inventory_sha256: str = ""
    inventory_metadata_json: str = "{}"
    inventory_external_id: str | None = None
    observations: list[dict] = field(default_factory=list)
    package_metadata: list[dict] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)


SECTION_RE = re.compile(r"^===== ([A-Z0-9_]+) =====$")


def record_collection_evidence(db, asset_id, text, audit):
    import hashlib
    run_id = audit.get("run_id")
    if not run_id:
        return ""
    evidence_id = "INV-" + run_id
    if not db.query(models.CollectionEvidence).filter_by(evidence_id=evidence_id).first():
        db.add(models.CollectionEvidence(evidence_id=evidence_id, run_id=run_id, asset_id=asset_id,
            content_sha256=hashlib.sha256(text.encode()).hexdigest(), raw_text=text))
        db.flush()
    audit["inventory_evidence_id"] = evidence_id
    return evidence_id


def normalize_mac(value: str) -> str:
    value = value.strip().lower()
    if value and (not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value)
                  or value == "00:00:00:00:00:00" or int(value[:2], 16) & 1):
        raise ValueError("设备 MAC 格式无效或不是单播地址")
    return value


def split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = "META"
    sections[current] = []
    seen_sections = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = SECTION_RE.match(line)
        if match:
            current = match.group(1)
            if current in seen_sections or (current == "META" and sections["META"]):
                raise ValueError("采集文本包含重复段落；未保存资产")
            seen_sections.add(current)
            sections[current] = []
            continue
        if line:
            sections.setdefault(current, []).append(line)
    return sections


def _read_key(lines: list[str], key: str, default: str = "") -> str:
    prefix = key.lower() + ":"
    for line in lines:
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return default


def _parse_os_release(lines: list[str]) -> tuple[str, str, str]:
    values = {}
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
    # 麒麟等发行版的 ID 存在大小写差异（kylin/Kylin），统一小写后再匹配
    distribution = values.get("ID", "").strip().lower()
    return values.get("NAME", distribution), values.get("VERSION_ID", ""), distribution


def _parse_packages(lines: list[str], manager: str, stats: dict | None = None) -> list[dict]:
    packages = []
    for number, line in enumerate(lines, 1):
        row = None
        if manager == "opkg" and " - " in line:
            name, version = line.split(" - ", 1)
            row = {"package_name": name.strip(), "package_version": version.strip(),
                   "package_manager": manager, "architecture": ""}
        elif manager == "dpkg" and line.startswith("ii "):
            parts = line.split()
            if len(parts) == 4:
                row = {"package_name": parts[1], "package_version": parts[2],
                       "package_manager": manager, "architecture": parts[3]}
        elif "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) in (2, 3):
                row = {"package_name": parts[0], "package_version": parts[1],
                       "package_manager": manager, "architecture": parts[2] if len(parts) == 3 else ""}
        else:
            parts = line.split()
            # apk --manifest has exactly two fields. Never guess boundaries in name-version.
            if len(parts) in (2, 3):
                row = {"package_name": parts[0], "package_version": parts[1],
                       "package_manager": manager, "architecture": parts[2] if len(parts) == 3 else ""}
        valid = row and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:\-]{0,127}", row["package_name"])
        valid = valid and re.fullmatch(r"[A-Za-z0-9+_.:~\-]{1,128}", row["package_version"])
        valid = valid and re.fullmatch(r"[A-Za-z0-9_.\-]{0,64}", row["architecture"])
        if stats is not None:
            stats["raw_count"] += 1
            if row and row["package_name"] in stats["seen"]:
                valid = False
            if not valid:
                stats["rejected_count"] += 1
                if len(stats["errors"]) < 20:
                    # Raw lines may contain unintended sensitive data; diagnostics expose positions only.
                    stats["errors"].append({"manager": manager, "line": number, "code": "invalid_or_duplicate_package"})
            else:
                stats["seen"].add(row["package_name"])
                stats["parsed_count"] += 1
        if valid:
            packages.append(row)
    return packages


def _parse_services(lines: list[str], public: bool) -> list[dict]:
    services = []
    for line in lines:
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                if not parts[1].isdigit() or not 1 <= int(parts[1]) <= 65535:
                    continue
                services.append(
                    {
                        "service_name": parts[0],
                        "port": int(parts[1]),
                        "protocol": parts[2],
                        "listen_address": parts[3] if len(parts) > 3 else "",
                        "process_name": parts[4] if len(parts) > 4 else parts[0],
                        "is_public_exposed": public,
                    }
                )
            continue
        match = re.search(r":(\d+)\s", line)
        proc = re.search(r'users:\(\("([^"]+)"', line) or re.search(r'\d+/([^\s]+)', line)
        if match:
            services.append(
                {
                    "service_name": proc.group(1) if proc else "unknown",
                    "port": int(match.group(1)),
                    "protocol": "tcp" if "tcp" in line.lower() else "udp",
                    "listen_address": "0.0.0.0" if "0.0.0.0" in line or "*" in line else "127.0.0.1",
                    "process_name": proc.group(1) if proc else "",
                    "is_public_exposed": public,
                }
            )
    return services


def parse_asset_text(text: str) -> ParsedAsset:
    sections = split_sections(text)
    meta = sections.get("META", [])
    os_name, os_version, distribution = _parse_os_release(sections.get("OS_RELEASE", []))
    hostname = _read_key(meta, "hostname") or (sections.get("HOSTNAME", [""])[0] if sections.get("HOSTNAME") else "")
    exposure = _read_key(meta, "exposure_level", "internal")
    business = _read_key(meta, "business_level", "normal")
    parsed = ParsedAsset(
        hostname=hostname,
        ip_address=_read_key(meta, "ip_address") or (sections.get("IP_ADDRESS", [""])[0] if sections.get("IP_ADDRESS") else ""),
        os_name=os_name or _read_key(meta, "os_name"),
        os_version=os_version or _read_key(meta, "os_version"),
        distribution=distribution or _read_key(meta, "distribution"),
        kernel_version=(sections.get("KERNEL", [""])[0] if sections.get("KERNEL") else ""),
        architecture=_read_key(meta, "architecture", "x86_64"),
        exposure_level=exposure,
        business_level=business,
        owner=_read_key(meta, "owner"),
        description=_read_key(meta, "description"),
    )
    stats = {"raw_count": 0, "parsed_count": 0, "rejected_count": 0, "errors": [], "seen": set()}
    for section, manager in (("DPKG_PACKAGES", "dpkg"), ("RPM_PACKAGES", "rpm"),
                             ("OPKG_PACKAGES", "opkg"), ("APK_PACKAGES", "apk")):
        parsed.packages.extend(_parse_packages(sections.get(section, []), manager, stats))
    stats.pop("seen")
    declared = _read_key(sections.get("INVENTORY_STATUS", []), "package_count")
    if declared:
        if not declared.isdigit():
            raise ValueError("软件包条数声明无效")
        stats["declared_count"] = int(declared)
        stats["count_matches"] = int(declared) == stats["raw_count"] == stats["parsed_count"]
    else:
        stats["declared_count"] = None
        stats["count_matches"] = stats["raw_count"] == stats["parsed_count"]
    parsed.package_parse_stats = stats
    detail_lines = sections.get("APK_PACKAGE_DETAILS")
    if detail_lines is not None:
        expected = {f"{p['package_name']}-{p['package_version']}": p for p in parsed.packages if p["package_manager"] == "apk"}
        if len(expected) != sum(p["package_manager"] == "apk" for p in parsed.packages):
            raise ValueError("APK 包名和完整版本组合无法唯一关联详细记录；未保存资产")
        seen = set()
        for number, line in enumerate(detail_lines, 1):
            match = re.fullmatch(r"(\S+)\s+([A-Za-z0-9_.\-]{1,64})\s+\{([^{}]+)\}\s+\(([^()]*)\)\s+\[installed\]", line)
            if not match or match[1] not in expected or match[1] in seen:
                stats["rejected_count"] += 1
                if len(stats["errors"]) < 20:
                    stats["errors"].append({"manager": "apk", "line": number, "code": "apk_details_invalid_or_unmatched"})
                continue
            package = expected[match[1]]
            if len(match[3]) > 512 or len(match[4]) > 255:
                raise ValueError("APK 来源或许可证字段超出上限")
            package["architecture"] = match[2]
            seen.add(match[1])
            parsed.package_metadata.append({"name": package["package_name"], "source": match[3], "license": match[4], "status": "installed"})
        if seen != set(expected):
            stats["rejected_count"] += len(set(expected) - seen)
        stats["details_count"] = len(detail_lines)
        stats["details_matches"] = len(detail_lines) == len(expected) == len(seen) and not stats["rejected_count"]
    board = {}
    if distribution == "openwrt" or sections.get("SYSTEM_BOARD"):
        try:
            board = json.loads("\n".join(sections.get("SYSTEM_BOARD", [])) or "{}")
        except (ValueError, TypeError):
            board = {}
        release = board.get("release") or {}
        parsed.distribution = "openwrt"
        parsed.os_name = "OpenWrt"
        parsed.device_type = "iot_gateway"
        parsed.os_version = release.get("version") or parsed.os_version
        parsed.firmware_version = parsed.os_version
        parsed.device_model = board.get("board_name") or board.get("model") or ""
        parsed.mac_address = normalize_mac(_read_key(meta, "mac_address"))
        # Default hostnames (e.g. OpenWrt) are not globally unique device identities.
        if parsed.mac_address and not parsed.hostname.endswith("-" + parsed.mac_address.replace(':', '')):
            parsed.hostname = f"{parsed.hostname or 'openwrt'}-{parsed.mac_address.replace(':', '')}"
        parsed.kernel_version = board.get("kernel") or parsed.kernel_version
        parsed.inventory_complete = _read_key(sections.get("INVENTORY_STATUS", []), "packages_complete") == "true"
        caps = {}
        for line in sections.get("BPF_CAPABILITIES", []):
            if ":" in line:
                key, value = line.split(":", 1)
                caps[key.strip()] = value.strip()
        caps["collector_compatibility"] = "requires_probe"
        parsed.capabilities_json = json.dumps(caps, ensure_ascii=False)
        for line in sections.get("DHCP_LEASES", []):
            parts = line.split()
            if len(parts) >= 4:
                parsed.observations.append({"lease_expiry": parts[0], "mac_address": parts[1],
                                            "ip_address": parts[2], "hostname": "" if parts[3] == "*" else parts[3]})
    public = exposure == "public"
    parsed.services.extend(_parse_services(sections.get("OPEN_PORTS", []), public))
    parsed.services.extend(_parse_services(sections.get("RUNNING_SERVICES", []), public))
    parsed.inventory_complete = bool(parsed.inventory_complete and parsed.packages
                                     and not stats["rejected_count"] and stats["count_matches"])
    parsed.inventory_metadata_json = json.dumps({"format": "sectioned_text", "package_parse_stats": stats,
        "package_metadata": parsed.package_metadata,
        "device_board": board if parsed.distribution == "openwrt" else None,
        "package_details_available": detail_lines is not None,
        "package_sources": sections.get("PACKAGE_SOURCES", []),
        "openssl_implementation": sections.get("OPENSSL_IMPLEMENTATION", []),
        "apt_policy": sections.get("APT_POLICY", [])}, ensure_ascii=False)
    return parsed


def save_parsed_asset(db: Session, parsed: ParsedAsset, asset_id: int | None = None, *, commit: bool = True) -> models.LinuxAsset:
    stats = parsed.package_parse_stats
    if stats and (stats.get("rejected_count") or not stats.get("count_matches", True)):
        raise ValueError("软件包清单存在格式错误、重复记录或条数不一致；未覆盖已有资产，请核对采集结果")
    if parsed.inventory_complete and not parsed.packages:
        raise ValueError("完整软件包清单不能为空；未覆盖已有资产")
    if parsed.distribution == "openwrt" and not parsed.mac_address and parsed.identity_source != "pinned_ssh_inventory" and not parsed.inventory_external_id:
        raise ValueError("OpenWrt 离线采集缺少设备 MAC，不能仅凭默认主机名合并资产；请补齐身份信息或使用校验指纹的 SSH 采集。")
    if asset_id:
        asset = db.get(models.LinuxAsset, asset_id)
        if not asset:
            raise ValueError("指定资产不存在")
    elif parsed.inventory_external_id and (external_asset := db.query(models.LinuxAsset).filter_by(
            inventory_external_id=parsed.inventory_external_id).one_or_none()):
        asset = external_asset
    elif parsed.distribution == "openwrt" and parsed.mac_address:
        assets = db.query(models.LinuxAsset).filter_by(distribution="openwrt", mac_address=parsed.mac_address).all()
        if len(assets) > 1:
            raise ValueError("设备 MAC 对应多个资产，请先核对资产身份")
        asset = assets[0] if assets else db.query(models.LinuxAsset).filter_by(hostname=parsed.hostname).first()
    else:
        asset = db.query(models.LinuxAsset).filter_by(hostname=parsed.hostname).first()
    if not asset:
        asset = models.LinuxAsset(hostname=parsed.hostname)
        db.add(asset)
        db.flush()
    elif parsed.distribution == "openwrt" and (asset.distribution != "openwrt"
            or (asset.mac_address and parsed.mac_address and asset.mac_address != parsed.mac_address)
            or (asset.mac_address and not parsed.mac_address and not parsed.inventory_external_id)):
        raise ValueError("采集身份与已有资产不一致；未覆盖资产")
    if parsed.inventory_collected_at and asset.inventory_collected_at:
        existing_time = asset.inventory_collected_at
        if existing_time.tzinfo is None:
            existing_time = existing_time.replace(tzinfo=timezone.utc)
        if parsed.inventory_collected_at < existing_time:
            raise ValueError("该档案采集时间早于已有快照；未覆盖资产")
    if parsed.inventory_external_id:
        if asset.inventory_external_id and asset.inventory_external_id != parsed.inventory_external_id:
            raise ValueError("设备外部资产编号已变化；请核对身份")
        asset.inventory_external_id = parsed.inventory_external_id
    # Later offline imports without a MAC must not erase a previously verified identity.
    if asset.mac_address and not parsed.mac_address:
        parsed.mac_address = asset.mac_address
    for field_name in [
        "ip_address",
        "os_name",
        "os_version",
        "distribution",
        "kernel_version",
        "architecture",
        "exposure_level",
        "business_level",
        "owner",
        "description",
        "device_type", "device_model", "mac_address", "firmware_version", "identity_source",
        "identity_confidence", "capabilities_json", "inventory_complete",
        "inventory_sha256", "inventory_metadata_json",
    ]:
        setattr(asset, field_name, getattr(parsed, field_name))
    asset.inventory_collected_at = parsed.inventory_collected_at or models.utcnow()
    # A partial collector result must not erase the last known package inventory.
    if parsed.inventory_complete:
        db.query(models.AssetPackage).filter_by(asset_id=asset.id).delete()
    db.query(models.AssetService).filter_by(asset_id=asset.id).delete()
    db.flush()
    for package in parsed.packages if parsed.inventory_complete else []:
        db.add(models.AssetPackage(asset_id=asset.id, **package))
    for service in parsed.services:
        db.add(models.AssetService(asset_id=asset.id, **service))
    if commit:
        db.commit()
    else:
        db.flush()
    db.refresh(asset)
    db.expire(asset, ["packages", "services"])
    return asset
