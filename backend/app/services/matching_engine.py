"""Deterministic, incremental asset/package vulnerability matching."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.utils.version_compare import is_version_less
from app.services.vulnerability_intelligence.kylin_provider import is_kylin_distribution, kylin_release_token
from app.services.vulnerability_intelligence.service import (
    base_cve_id,
    canonical_applicability,
    intelligence_fingerprint,
    kylin_applicability,
)


from app.services.ubuntu_security_collector import RELEASE_CODENAMES

# 发行版适用性记录在前端/证据里的展示名；reason_code 前缀取 source 本身
VENDOR_LABELS = {
    "canonical": ("Canonical", "Ubuntu"),
    "kylin": ("麒麟官方安全公告", "Kylin"),
}


def _asset_codename(asset: models.LinuxAsset) -> str:
    if is_kylin_distribution(asset.distribution):
        return kylin_release_token(asset.os_version)
    version = (asset.os_version or "").strip()
    for prefix, codename in RELEASE_CODENAMES.items():
        if version.startswith(prefix):
            return codename
    return ""


def _applies_to_asset(asset: models.LinuxAsset, cve_id: str) -> bool:
    if ":" not in cve_id:
        return True
    parts = cve_id.split(":")
    codename = parts[1] if len(parts) > 1 else ""
    return _asset_codename(asset) == codename


def _fingerprint(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


UNVERIFIED_UPSTREAM_REASON = "upstream_range_unverified_by_vendor"
# 上游 CPE 修复版本来自其他发行分支；Ubuntu 以回移植方式发版，跨分支版本比较
# 既可能误报（分支内版本低但回移植已修复）也可能误报（新分支版本高但补丁未回移植）。
UNVERIFIED_UPSTREAM_CONFIDENCE = 0.55


def _annotate_unverified_upstream(values: dict, package_name: str, installed: str) -> None:
    """Mark version-range conclusions made without a vendor applicability record.

    When Canonical publishes no status for (release, package), the upstream/NVD
    range cannot distinguish a backport branch from an upstream branch. Keep the
    conservative match_status, but state the evidence gap explicitly instead of
    presenting a vendor-verified conclusion.
    """
    if values.get("match_status") not in {"potentially_affected", "fixed"}:
        return
    caveat = (
        f"缺 {package_name} 在该发行版的厂商适用性记录（Canonical per-release 状态缺失）；"
        f"Ubuntu 采用回移植发版，安装版本 {installed or '未知'} 与上游修复版本的比较不能替代发行版公告，"
        "需导入官方适用性记录后复核。"
    )
    values["reason_code"] = UNVERIFIED_UPSTREAM_REASON
    values["confidence"] = UNVERIFIED_UPSTREAM_CONFIDENCE
    values["match_reason"] = f"{values.get('match_reason', '')} {caveat}".strip()
    # A higher upstream version also cannot prove a distro patch is installed.
    if values["match_status"] == "fixed":
        values.update(match_status="unknown", affected=True)


def _evaluate_match(
    asset: models.LinuxAsset,
    vulnerability: models.VulnerabilityInfo,
    package: models.AssetPackage | None,
    canonical: dict | None = None,
) -> dict:
    package_name = vulnerability.affected_package
    installed = (package.package_version or "").strip() if package else ""
    fixed = (vulnerability.fixed_version or "").strip()

    if canonical:
        source_name = (canonical.get("source") or "canonical").lower()
        vendor, os_label = VENDOR_LABELS.get(source_name, (source_name or "vendor", ""))
        reason_prefix = source_name or "canonical"
        # Never inherit an upstream fixed version into a different distro branch.
        fixed = (canonical.get("fixed_version") or "").strip()
        status = canonical.get("status", "under_investigation")
        if status == "not_affected":
            return {
                "installed_version": installed,
                "fixed_version": fixed,
                "affected": False,
                "match_status": "not_affected",
                "reason_code": f"{reason_prefix}_not_affected",
                "match_reason": f"{vendor} marks {package_name} on {os_label} {canonical.get('release', '')} as not affected.",
                "confidence": 0.99,
            }
        if status in {"affected", "under_investigation"} and package is not None and installed:
            return {
                "installed_version": installed,
                "fixed_version": fixed,
                "affected": True,
                "match_status": status,
                "reason_code": f"{reason_prefix}_{status}",
                "match_reason": (
                    f"{vendor} status for {package_name} on {os_label} {canonical.get('release', '')} is {status}; "
                    "no upstream/CPE override is allowed."
                ),
                "confidence": 0.95 if status == "affected" else 0.65,
            }

    if package is None:
        return {
            "installed_version": "",
            "fixed_version": fixed,
            "affected": False,
            "match_status": "not_applicable",
            "reason_code": "package_not_installed",
            "match_reason": f"{asset.hostname} 未安装 {package_name}。",
            "confidence": 0.95,
        }
    if not installed:
        return {
            "installed_version": "",
            "fixed_version": fixed,
            "affected": True,
            "match_status": "insufficient_data",
            "reason_code": "installed_version_missing",
            "match_reason": f"{asset.hostname} 已安装 {package_name}，但缺少已安装版本，不能判定为不受影响。",
            "confidence": 0.0,
        }
    if not fixed:
        return {
            "installed_version": installed,
            "fixed_version": "",
            "affected": True,
            "match_status": "unknown",
            "reason_code": "fixed_version_missing",
            "match_reason": f"{asset.hostname} 已安装 {package_name} {installed}，但缺少可靠修复版本，需补充证据。",
            "confidence": 0.45,
        }

    try:
        affected = is_version_less(installed, fixed)
    except Exception as exc:
        return {
            "installed_version": installed,
            "fixed_version": fixed,
            "affected": True,
            "match_status": "data_error",
            "reason_code": "version_compare_error",
            "match_reason": f"{asset.hostname} 的 {package_name} 版本比较失败：{exc}",
            "confidence": 0.0,
        }

    if affected:
        return {
            "installed_version": installed,
            "fixed_version": fixed,
            "affected": True,
            "match_status": "potentially_affected",
            "reason_code": "installed_version_below_fixed",
            "match_reason": f"{asset.hostname} 当前安装 {package_name} {installed}，低于修复版本 {fixed}。",
            "confidence": 0.92,
        }
    return {
        "installed_version": installed,
        "fixed_version": fixed,
        "affected": False,
        "match_status": "fixed",
        "reason_code": "installed_version_fixed",
        "match_reason": f"{asset.hostname} 当前安装 {package_name} {installed}，不低于修复版本 {fixed}。",
        "confidence": 0.88,
    }


def run_matching(db: Session, cve_ids: list[str] | None = None, *, asset_id: int | None = None) -> int:
    """Idempotently upsert matches and deactivate stale rows without deleting history."""
    asset_query = db.query(models.LinuxAsset)
    if asset_id is not None:
        asset_query = asset_query.filter_by(id=asset_id)
    assets = asset_query.all()
    target_cves = {base_cve_id(item) for item in cve_ids or []}
    vulnerabilities = [
        item for item in db.query(models.VulnerabilityInfo).all()
        if not target_cves or base_cve_id(item.cve_id) in target_cves
    ]
    existing_query = db.query(models.VulnerabilityMatch)
    if asset_id is not None:
        existing_query = existing_query.filter_by(asset_id=asset_id)
    existing_rows = existing_query.all()
    existing = {
        (row.asset_id, row.cve_id, row.package_name): row
        for row in existing_rows
        if row.active
    }
    seen: set[tuple[int, str, str]] = set()
    now = datetime.now(timezone.utc)
    processed = 0

    for asset in assets:
        if (asset.distribution or "").lower() == "openwrt":
            from app.services.iot_devices import match_openwrt
            keys = match_openwrt(db, asset, target_cves)
            seen.update(keys)
            processed += len(keys)
            continue
        packages = {pkg.package_name: pkg for pkg in asset.packages}
        for vulnerability in vulnerabilities:
            if vulnerability.source == "openwrt_operator_advisory":
                continue  # OpenWrt-specific evidence cannot establish Linux distro applicability.
            if not _applies_to_asset(asset, vulnerability.cve_id):
                continue
            package_name = vulnerability.affected_package
            distribution = (asset.distribution or "").lower()
            # 发行版源对其包/release 组合是权威的：Ubuntu 看 Canonical，
            # 麒麟看 NVD CPE 映射出的 kylin 记录（最终以麒麟官方公告为准）。
            canonical = None
            if distribution == "ubuntu":
                canonical = canonical_applicability(
                    db, vulnerability.cve_id, _asset_codename(asset), package_name
                )
            elif is_kylin_distribution(distribution):
                canonical = kylin_applicability(
                    db, vulnerability.cve_id, _asset_codename(asset), package_name
                )
            # 发行版事实存在时压制通用 NVD 上游行，包括已修复与不受影响的事实。
            if canonical and ":" not in vulnerability.cve_id:
                continue
            key = (asset.id, vulnerability.cve_id, package_name)
            seen.add(key)
            values = _evaluate_match(asset, vulnerability, packages.get(package_name), canonical)
            if distribution == "ubuntu" and canonical is None:
                _annotate_unverified_upstream(values, package_name, values["installed_version"])
            values["evidence_fingerprint"] = _fingerprint({
                "asset_id": asset.id,
                "cve_id": vulnerability.cve_id,
                "package_name": package_name,
                "installed_version": values["installed_version"],
                "fixed_version": values["fixed_version"],
                "match_status": values["match_status"],
                "vulnerability_modified": vulnerability.last_modified_date or "",
                "intelligence_fingerprint": intelligence_fingerprint(db, vulnerability.cve_id),
                "canonical": canonical or {},
            })

            row = existing.get(key)
            if row is None:
                row = models.VulnerabilityMatch(
                    asset_id=asset.id,
                    cve_id=vulnerability.cve_id,
                    package_name=package_name,
                    active=True,
                    **values,
                )
                db.add(row)
            elif row.evidence_fingerprint != values["evidence_fingerprint"] or not row.active:
                for name, value in values.items():
                    setattr(row, name, value)
                row.active = True
                row.updated_at = now
            processed += 1

    for key, row in existing.items():
        if target_cves and base_cve_id(row.cve_id) not in target_cves:
            continue
        if key in seen:
            continue
        row.active = False
        row.affected = False
        row.match_status = "no_longer_affected"
        row.reason_code = "not_seen_in_latest_recalculation"
        row.match_reason = "本轮匹配不再命中；历史记录保留用于审计。"
        row.updated_at = now

    db.commit()
    return processed
