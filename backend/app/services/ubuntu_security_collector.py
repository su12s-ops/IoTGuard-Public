from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from app import models
from app.services.real_intel_collector import _http_json, fetch_cisa_kev, fetch_epss, fetch_nvd_by_cve
from app.services.vulnerability_intelligence.base import classify_error
from app.services.vulnerability_intelligence.canonical_provider import CanonicalProvider
from app.services.vulnerability_intelligence.cisa_kev_provider import CisaKevProvider
from app.services.vulnerability_intelligence.epss_provider import EpssProvider
from app.services.vulnerability_intelligence.nvd_provider import NvdProvider
from app.services.vulnerability_intelligence.service import (
    apply_fused_intelligence,
    cves_needing_refresh,
    mark_provider_failure,
    source_rows,
)


UBUNTU_CVE_API = "https://ubuntu.com/security/cves.json"
UBUNTU_CVE_DETAIL = "https://ubuntu.com/security/cves/{cve_id}.json"

RELEASE_CODENAMES = {
    "14.04": "trusty",
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "25.10": "questing",
    "26.04": "resolute",
}

DEFAULT_PACKAGE_ALLOWLIST = {
    "apache2",
    "bash",
    "curl",
    "libcurl4",
    "libssl3",
    "nginx",
    "nginx-common",
    "openssh-client",
    "openssh-server",
    "openssl",
    "redis-server",
    "redis-tools",
    "sudo",
    "systemd",
    "systemd-sysv",
}

TRACKED_NON_RELEASED_STATUSES = {"needed", "needs-triage", "deferred"}


@dataclass
class UbuntuSyncResult:
    assets_checked: int = 0
    packages_checked: int = 0
    saved: int = 0
    affected_matches: int = 0
    epss_enriched: int = 0
    kev_marked: int = 0
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    changed_cve_ids: list[str] = field(default_factory=list)


def _report_progress(progress, message: str, current: int | None = None, total: int | None = None) -> None:
    if progress:
        progress(message, current, total)


def _release_codename(asset: models.LinuxAsset) -> str:
    version = (asset.os_version or "").strip()
    if version in RELEASE_CODENAMES:
        return RELEASE_CODENAMES[version]
    for prefix, codename in RELEASE_CODENAMES.items():
        if version.startswith(prefix):
            return codename
    return ""


def _ubuntu_package_candidates(asset: models.LinuxAsset, max_packages: int) -> list[str]:
    installed = {pkg.package_name for pkg in asset.packages}
    service_names = {svc.service_name for svc in asset.services if svc.service_name}
    candidates = set(installed & DEFAULT_PACKAGE_ALLOWLIST)
    for name in service_names:
        if name in installed:
            candidates.add(name)
        if name == "sshd" and "openssh-server" in installed:
            candidates.add("openssh-server")
    return sorted(candidates)[:max_packages]


def _fetch_ubuntu_cves_for_package(package_name: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    results: list[dict[str, Any]] = []
    warning = ""
    offset = 0
    while len(results) < limit:
        page = min(20, limit - len(results))
        params = {"package": package_name, "limit": page, "offset": offset}
        try:
            data = _http_json(
                f"{UBUNTU_CVE_API}?{urlencode(params)}",
                headers={"User-Agent": "LinuxGuard/0.1"},
                timeout=20,
            )
        except Exception as exc:
            warning = f"Ubuntu Security API 请求失败 ({package_name}): {exc}"
            break
        cves = data.get("cves", []) or []
        if not cves:
            break
        results.extend(cves)
        if len(cves) < page:
            break
        offset += page
        time.sleep(1.0)
    return results[:limit], warning


def _status_for_package(cve: dict[str, Any], package_name: str, codename: str) -> dict[str, Any] | None:
    for package in cve.get("packages", []) or []:
        if package.get("name") != package_name:
            continue
        for status in package.get("statuses", []) or []:
            if status.get("release_codename") != codename:
                continue
            return status
    return None


def _has_supported_non_released_status(cve: dict[str, Any], package_name: str, codename: str) -> bool:
    for package in cve.get("packages", []) or []:
        if package.get("name") != package_name:
            continue
        for status in package.get("statuses", []) or []:
            if status.get("release_codename") != codename:
                continue
            if status.get("status") in TRACKED_NON_RELEASED_STATUSES:
                return True
    return False


def _severity_from_priority(priority: str | None, cvss: float) -> str:
    priority = (priority or "").lower()
    if priority in {"critical", "high", "medium", "low"}:
        return priority.title()
    if cvss >= 9:
        return "Critical"
    if cvss >= 7:
        return "High"
    if cvss >= 4:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Unknown"


def _upsert_ubuntu_vulnerability(
    db: Session,
    cve: dict[str, Any],
    package_name: str,
    fixed_version: str,
    codename: str,
    canonical_status: str,
) -> bool:
    base_cve_id = cve.get("id", "")
    if not base_cve_id:
        return False
    # Package is part of the record identity because one CVE can affect more
    # than one Ubuntu source package in the same release.
    record_id = f"{base_cve_id}:{codename}:{package_name}"
    cvss_score = float(cve.get("cvss3") or 0)
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=record_id).first()
    if not vuln:
        vuln = models.VulnerabilityInfo(cve_id=record_id, affected_package=package_name)
        db.add(vuln)
    title = (cve.get("ubuntu_description") or cve.get("description") or base_cve_id).strip()
    vuln.title = f"{base_cve_id} / Ubuntu {codename}: {title}"[:240]
    vuln.description = (cve.get("ubuntu_description") or cve.get("description") or "").strip()
    vuln.cvss_score = cvss_score
    vuln.cvss_severity = _severity_from_priority(cve.get("priority"), cvss_score)
    vuln.cwe_id = ""
    vuln.affected_product = f"Ubuntu {codename}"
    vuln.affected_package = package_name
    vuln.fixed_version = fixed_version
    vuln.published_date = cve.get("published", "")
    vuln.last_modified_date = cve.get("updated_at", "")
    vuln.source = "Ubuntu Security API"
    vuln.references = "\n".join(cve.get("references", []) or [f"https://ubuntu.com/security/cves/{base_cve_id}"])
    if fixed_version:
        vuln.remediation = (
            f"Ubuntu {codename} fixed {package_name} in {fixed_version}. "
            f"Run apt update and upgrade {package_name}."
        )
    elif canonical_status in {"needed", "deferred"}:
        vuln.remediation = f"Canonical marks {package_name} on Ubuntu {codename} as affected; no fixed package is published yet."
    else:
        vuln.remediation = f"Follow Canonical status for {package_name} on Ubuntu {codename}: {canonical_status}."
    threat = db.query(models.ThreatIntelSource).filter_by(cve_id=record_id).first()
    if not threat:
        threat = models.ThreatIntelSource(cve_id=record_id)
        db.add(threat)
    threat.source_detail = json.dumps(
        {
            "ubuntu_security_api": UBUNTU_CVE_API,
            "base_cve_id": base_cve_id,
            "release_codename": codename,
            "package": package_name,
            "notices": cve.get("notices_ids", []),
            "canonical_status": canonical_status,
        },
        ensure_ascii=False,
    )
    return True


def _restore_cached_canonical_package(db: Session, package_name: str, codename: str, error: str) -> set[str]:
    """Materialize applicability from the global cache when Canonical is offline."""
    restored: set[str] = set()
    rows = db.query(models.VulnerabilityIntelligenceSource).filter_by(source="canonical").all()
    for row in rows:
        try:
            records = json.loads(row.normalized_data or "{}").get("records", [])
        except (TypeError, ValueError):
            records = []
        for record in records:
            if record.get("package") != package_name or record.get("release") != codename:
                continue
            raw_status = record.get("canonical_status") or record.get("status") or "needs-triage"
            fixed_version = record.get("fixed_version") or ""
            cve = {
                "id": row.cve_id,
                "priority": record.get("priority", "unknown"),
                "updated_at": row.source_updated_at,
                "notices_ids": record.get("notices", []),
            }
            if _upsert_ubuntu_vulnerability(
                db, cve, package_name, fixed_version, codename, raw_status
            ):
                restored.add(f"{row.cve_id}:{codename}:{package_name}")
            row.fetch_status = "cached"
            row.error_message = error
    return restored


def _enrich_intel(db: Session, cve_ids: list[str], force: bool = False) -> tuple[int, int]:
    base_ids = sorted({cve_id.split(":", 1)[0] for cve_id in cve_ids})
    kev_count = epss_count = 0

    nvd_ids = base_ids if force else cves_needing_refresh(db, base_ids, "nvd")
    # NVD API 限流：无 Key 时 5 请求/30s，有 Key 时 50 请求/30s。逐条请求必须主动节流，
    # 否则连续快速请求会触发 Cloudflare 429 (error 1015) 导致出口 IP 被临时封禁。
    nvd_sleep = 0.7 if os.getenv("NVD_API_KEY", "").strip() else 6.0
    try:
        nvd_items: list[dict[str, Any]] = []
        for index, cve_id in enumerate(nvd_ids):
            nvd_items.extend(fetch_nvd_by_cve(cve_id))
            if index < len(nvd_ids) - 1:
                time.sleep(nvd_sleep)
        NvdProvider().store_items(db, nvd_items)
    except Exception as exc:
        mark_provider_failure(db, nvd_ids, "nvd", classify_error(exc), str(exc))

    kev_ids = base_ids if force else cves_needing_refresh(db, base_ids, "cisa_kev")
    try:
        if kev_ids:
            kev_map = fetch_cisa_kev()
            CisaKevProvider().store_catalog(db, kev_ids, {"vulnerabilities": list(kev_map.values())})
    except Exception as exc:
        mark_provider_failure(db, kev_ids, "cisa_kev", classify_error(exc), str(exc))

    epss_ids = base_ids if force else cves_needing_refresh(db, base_ids, "epss")
    try:
        if epss_ids:
            epss_map = fetch_epss(epss_ids)
            EpssProvider().store_rows(
                db,
                epss_ids,
                {"data": [
                    {"cve": cve_id, "epss": row.get("epss_score", 0), "percentile": row.get("epss_percentile", 0), "date": row.get("score_date", "")}
                    for cve_id, row in epss_map.items()
                ]},
            )
    except Exception as exc:
        mark_provider_failure(db, epss_ids, "epss", classify_error(exc), str(exc))

    apply_fused_intelligence(db, base_ids)
    for cve_id in base_ids:
        sources = source_rows(db, cve_id)
        if sources.get("cisa_kev"):
            try:
                kev_count += 1 if json.loads(sources["cisa_kev"].normalized_data).get("is_kev") else 0
            except (TypeError, ValueError):
                pass
        if sources.get("epss"):
            try:
                epss_count += 1 if json.loads(sources["epss"].normalized_data).get("score") is not None else 0
            except (TypeError, ValueError):
                pass
    return kev_count, epss_count


def sync_ubuntu_asset_intelligence(
    db: Session,
    max_packages_per_asset: int = 24,
    limit_per_package: int = 40,
    replace: bool = False,
    progress=None,
) -> UbuntuSyncResult:
    if replace:
        _report_progress(progress, "Refreshing selected Canonical records; preserving all risk and audit history")

    result = UbuntuSyncResult()
    saved_cves: set[str] = set()
    changed_cves: set[str] = set()
    skipped_non_released = 0
    skipped_missing_fixed_version = 0

    assets = db.query(models.LinuxAsset).filter(models.LinuxAsset.distribution == "ubuntu").all()
    result.assets_checked = len(assets)
    total_packages = 0
    fetch_cache: dict[tuple[str, str], tuple[list[dict[str, Any]], str]] = {}
    canonical_provider = CanonicalProvider()
    for asset in assets:
        if _release_codename(asset):
            total_packages += len(_ubuntu_package_candidates(asset, max_packages=max_packages_per_asset))

    processed_packages = 0
    for asset in assets:
        codename = _release_codename(asset)
        if not codename:
            continue
        _report_progress(progress, f"Scanning packages on {asset.hostname}")
        for package_name in _ubuntu_package_candidates(asset, max_packages=max_packages_per_asset):
            result.packages_checked += 1
            processed_packages += 1
            cache_key = (package_name, codename)
            if cache_key not in fetch_cache:
                fetch_cache[cache_key] = _fetch_ubuntu_cves_for_package(package_name, limit=limit_per_package)
            cve_list, fetch_warning = fetch_cache[cache_key]
            if fetch_warning:
                result.warnings.append(fetch_warning)
                saved_cves.update(
                    _restore_cached_canonical_package(db, package_name, codename, fetch_warning)
                )
            for cve in cve_list:
                status = _status_for_package(cve, package_name, codename)
                if not status:
                    continue
                raw_status = (status.get("status") or "").strip().lower()
                fixed_version = (status.get("description") or "").strip() if raw_status == "released" else ""
                if raw_status == "released" and not fixed_version:
                    skipped_missing_fixed_version += 1
                    continue
                if canonical_provider.store(db, cve, package_name, codename, raw_status, fixed_version):
                    changed_cves.add(cve["id"])
                if _upsert_ubuntu_vulnerability(db, cve, package_name, fixed_version, codename, raw_status):
                    saved_cves.add(f"{cve['id']}:{codename}:{package_name}")
            db.commit()
            _report_progress(
                progress,
                f"Synced {package_name} on {asset.hostname} ({processed_packages}/{max(total_packages, 1)})",
                processed_packages,
                total_packages or 1,
            )
            time.sleep(1.0)

    result.saved = len(saved_cves)
    result.changed_cve_ids = sorted({item.split(":", 1)[0] for item in saved_cves} | changed_cves)
    if saved_cves:
        try:
            _report_progress(progress, "Fetching KEV and EPSS enrichment")
            result.kev_marked, result.epss_enriched = _enrich_intel(db, sorted(saved_cves), force=replace)
            db.commit()
        except Exception as exc:
            warning = f"Ubuntu KEV/EPSS enrichment skipped: {exc}"
            result.warnings.append(warning)
            print(f"[ubuntu_collector] {warning}")

    if skipped_non_released:
        result.notices.append(
            f"Skipped {skipped_non_released} Ubuntu package advisories without a released fix version."
        )
    if skipped_missing_fixed_version:
        result.notices.append(
            f"Skipped {skipped_missing_fixed_version} released Ubuntu advisories with an empty fixed version."
        )

    return result
