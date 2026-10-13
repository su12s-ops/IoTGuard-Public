"""麒麟（银河麒麟 / openKylin）资产的漏洞情报同步。

链路与 ubuntu_security_collector 同构：资产包名 -> 外部 CVE 源 ->
KylinProvider 记录 -> VulnerabilityInfo(CVE:v10:package) -> 匹配引擎。
麒麟官方暂无公开 CVE JSON 接口，因此按包名查询 NVD 并用 CPE 命中做包级映射；
NVD 给出的修复版本只是上游边界，最终结论以麒麟软件官方安全公告为准。
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.services.real_intel_collector import (
    NVD_CVE_API,
    _cvss,
    _cwe,
    _first_english,
    _http_json,
    _normalize_package,
    _parse_cpe,
    _references,
    _walk_cpe_matches,
)
from app.services.ubuntu_security_collector import _enrich_intel, _ubuntu_package_candidates
from app.services.vulnerability_intelligence.kylin_provider import (
    KYLIN_DATA_ORIGIN,
    KylinProvider,
    kylin_release_token,
)


KYLIN_ADVISORY_REFERENCE = "https://www.kylinos.cn"


@dataclass
class KylinSyncResult:
    assets_checked: int = 0
    packages_checked: int = 0
    saved: int = 0
    kev_marked: int = 0
    epss_enriched: int = 0
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    changed_cve_ids: list[str] = field(default_factory=list)


def _report_progress(progress, message: str, current: int | None = None, total: int | None = None) -> None:
    if progress:
        progress(message, current, total)


def _assert_public_http_url(url: str) -> None:
    """只允许 http/https 且目标必须是公网地址（拒绝环回/私有/保留段）。"""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"blocked url scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("blocked url without host")
    candidates = {host}
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP):
            candidates.add(info[4][0])
    except socket.gaierror:
        pass  # 解析失败交给 HTTP 层报错；这里只负责拦截已知非公网目标
    for candidate in candidates:
        if not candidate:
            continue
        if candidate == "localhost":
            raise ValueError("blocked non-public host: localhost")
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"blocked non-public address: {candidate}")


def _safe_http_json(url: str, headers: dict[str, str] | None = None, timeout: int = 30, retries: int = 1) -> dict[str, Any]:
    _assert_public_http_url(url)
    return _http_json(url, headers=headers, timeout=timeout, retries=retries)


def _nvd_headers() -> dict[str, str]:
    headers = {"User-Agent": "LinuxGuard/0.1"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _fetch_nvd_cves_for_package(package_name: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    params = {
        "keywordSearch": package_name,
        "resultsPerPage": min(max(limit, 1), 2000),
        "startIndex": 0,
    }
    try:
        data = _safe_http_json(f"{NVD_CVE_API}?{urlencode(params)}", headers=_nvd_headers(), timeout=30)
    except Exception as exc:
        return [], f"NVD 查询失败 ({package_name}): {exc}"
    return (data.get("vulnerabilities", []) or [])[:limit], ""


def _package_status_from_nvd(cve: dict[str, Any], package_name: str) -> tuple[str, str]:
    """从 NVD CPE 里找该包的命中情况。

    返回 (raw_status, 上游修复边界)。CPE 未点名该包时返回 ("", "")，
    说明 keyword 命中只是描述文本噪音，不能作为包级证据。
    """
    fixed_candidates: list[str] = []
    seen = False
    for match in _walk_cpe_matches(cve.get("configurations", [])):
        if match.get("vulnerable") is False:
            continue
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        part, _vendor, product = _parse_cpe(criteria)
        if part not in {"a", "o"}:
            continue
        if not product or _normalize_package(product) != package_name:
            continue
        seen = True
        boundary = (match.get("versionEndExcluding") or "").strip()
        if boundary:
            fixed_candidates.append(boundary)
    if not seen:
        return "", ""
    if fixed_candidates:
        return "released", fixed_candidates[0]
    return "under_investigation", ""


def _severity_from_cvss(score: float, severity: str) -> str:
    if severity and severity.lower() in {"critical", "high", "medium", "low"}:
        return severity.title()
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _upsert_kylin_vulnerability(
    db: Session,
    cve: dict[str, Any],
    package_name: str,
    fixed_version: str,
    release: str,
    kylin_status: str,
) -> bool:
    base_cve_id = cve.get("id", "")
    if not base_cve_id:
        return False
    # Package 是记录身份的一部分：同一 CVE 可影响同一 release 的多个包。
    record_id = f"{base_cve_id}:{release}:{package_name}"
    cvss_score, severity = _cvss(cve)
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=record_id).first()
    if not vuln:
        vuln = models.VulnerabilityInfo(cve_id=record_id, affected_package=package_name)
        db.add(vuln)
    description = _first_english(cve.get("descriptions", []))
    vuln.title = f"{base_cve_id} / Kylin {release}: {description[:120] or base_cve_id}".strip()[:240]
    vuln.description = description
    vuln.cvss_score = cvss_score
    vuln.cvss_severity = _severity_from_cvss(cvss_score, severity)
    vuln.cwe_id = _cwe(cve)
    vuln.affected_product = f"Kylin {release}"
    vuln.affected_package = package_name
    vuln.fixed_version = fixed_version
    vuln.published_date = cve.get("published", "")
    vuln.last_modified_date = cve.get("lastModified", "")
    vuln.source = "NVD CVE API (Kylin 映射)"
    vuln.references = _references(cve) or f"https://nvd.nist.gov/vuln/detail/{base_cve_id}"
    if fixed_version:
        vuln.remediation = (
            f"NVD CPE 显示上游 {package_name} 在 {fixed_version} 前受影响；"
            f"请以麒麟官方安全公告（{KYLIN_ADVISORY_REFERENCE}）确认麒麟修复包版本后升级。"
        )
    else:
        vuln.remediation = (
            f"NVD 未给出 {package_name} 的修复版本边界；"
            f"请对照麒麟官方安全公告（{KYLIN_ADVISORY_REFERENCE}）确认受影响情况与修复版本。"
        )
    threat = db.query(models.ThreatIntelSource).filter_by(cve_id=record_id).first()
    if not threat:
        threat = models.ThreatIntelSource(cve_id=record_id)
        db.add(threat)
    threat.source_detail = json.dumps(
        {
            "data_origin": KYLIN_DATA_ORIGIN,
            "nvd_api": NVD_CVE_API,
            "kylin_advisory_reference": KYLIN_ADVISORY_REFERENCE,
            "base_cve_id": base_cve_id,
            "release": release,
            "package": package_name,
            "kylin_status": kylin_status,
        },
        ensure_ascii=False,
    )
    return True


def _restore_cached_kylin_package(db: Session, package_name: str, release: str, error: str) -> set[str]:
    """NVD 不可用时，从全局缓存还原麒麟适用性记录。"""
    restored: set[str] = set()
    rows = db.query(models.VulnerabilityIntelligenceSource).filter_by(source="kylin").all()
    for row in rows:
        try:
            records = json.loads(row.normalized_data or "{}").get("records", [])
        except (TypeError, ValueError):
            records = []
        for record in records:
            if record.get("package") != package_name or record.get("release") != release:
                continue
            raw_status = record.get("kylin_status") or record.get("status") or "under_investigation"
            fixed_version = record.get("fixed_version") or ""
            cve = {
                "id": row.cve_id,
                "priority": record.get("priority", "unknown"),
                "updated_at": row.source_updated_at,
            }
            if _upsert_kylin_vulnerability(db, cve, package_name, fixed_version, release, raw_status):
                restored.add(f"{row.cve_id}:{release}:{package_name}")
            row.fetch_status = "cached"
            row.error_message = error
    return restored


def sync_kylin_asset_intelligence(
    db: Session,
    max_packages_per_asset: int = 24,
    limit_per_package: int = 40,
    replace: bool = False,
    progress=None,
) -> KylinSyncResult:
    if replace:
        _report_progress(progress, "Refreshing selected Kylin records; preserving all risk and audit history")

    result = KylinSyncResult()
    saved_cves: set[str] = set()
    changed_cves: set[str] = set()
    skipped_keyword_only = 0

    assets = db.query(models.LinuxAsset).filter(
        func.lower(models.LinuxAsset.distribution).in_(("kylin", "openkylin"))
    ).all()
    result.assets_checked = len(assets)
    total_packages = 0
    fetch_cache: dict[str, tuple[list[dict[str, Any]], str]] = {}
    provider = KylinProvider()
    # 与 _enrich_intel 相同的 NVD 限流节奏：无 Key 5 请求/30s，有 Key 50 请求/30s
    package_sleep = 0.7 if os.getenv("NVD_API_KEY", "").strip() else 6.0
    for asset in assets:
        if kylin_release_token(asset.os_version):
            total_packages += len(_ubuntu_package_candidates(asset, max_packages=max_packages_per_asset))

    processed_packages = 0
    for asset in assets:
        release = kylin_release_token(asset.os_version)
        if not release:
            result.notices.append(
                f"资产 {asset.hostname} 的麒麟版本（{asset.os_version or '未知'}）无法识别，已跳过。"
            )
            continue
        _report_progress(progress, f"Scanning packages on {asset.hostname}")
        for package_name in _ubuntu_package_candidates(asset, max_packages=max_packages_per_asset):
            result.packages_checked += 1
            processed_packages += 1
            if package_name not in fetch_cache:
                fetch_cache[package_name] = _fetch_nvd_cves_for_package(package_name, limit=limit_per_package)
            cve_items, fetch_warning = fetch_cache[package_name]
            if fetch_warning:
                result.warnings.append(fetch_warning)
                saved_cves.update(
                    _restore_cached_kylin_package(db, package_name, release, fetch_warning)
                )
            for item in cve_items:
                cve = item.get("cve", {}) or {}
                cve_id = (cve.get("id") or "").upper()
                if not cve_id:
                    continue
                raw_status, fixed_version = _package_status_from_nvd(cve, package_name)
                if not raw_status:
                    skipped_keyword_only += 1
                    continue
                cvss_score, severity = _cvss(cve)
                meta = {
                    "id": cve_id,
                    "priority": _severity_from_cvss(cvss_score, severity).lower(),
                    "updated_at": cve.get("lastModified", ""),
                }
                if provider.store(db, meta, package_name, release, raw_status, fixed_version):
                    changed_cves.add(cve_id)
                if _upsert_kylin_vulnerability(db, cve, package_name, fixed_version, release, raw_status):
                    saved_cves.add(f"{cve_id}:{release}:{package_name}")
            db.commit()
            _report_progress(
                progress,
                f"Synced {package_name} on {asset.hostname} ({processed_packages}/{max(total_packages, 1)})",
                processed_packages,
                total_packages or 1,
            )
            time.sleep(package_sleep)

    result.saved = len(saved_cves)
    result.changed_cve_ids = sorted({item.split(":", 1)[0] for item in saved_cves} | changed_cves)
    if saved_cves:
        try:
            _report_progress(progress, "Fetching KEV and EPSS enrichment")
            result.kev_marked, result.epss_enriched = _enrich_intel(db, sorted(saved_cves), force=replace)
            db.commit()
        except Exception as exc:
            warning = f"Kylin KEV/EPSS enrichment skipped: {exc}"
            result.warnings.append(warning)
            print(f"[kylin_collector] {warning}")

    if skipped_keyword_only:
        result.notices.append(
            f"Skipped {skipped_keyword_only} NVD keyword hits whose CPE did not name the package."
        )

    return result
