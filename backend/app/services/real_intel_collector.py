from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, ProxyHandler, build_opener, urlopen

from sqlalchemy.orm import Session

from app import models
from app.services.nvd_package_mapping import UNMAPPED_PACKAGE
from app.services.vulnerability_intelligence.base import classify_error
from app.services.vulnerability_intelligence.cisa_kev_provider import CisaKevProvider
from app.services.vulnerability_intelligence.epss_provider import EpssProvider
from app.services.vulnerability_intelligence.nvd_provider import NvdProvider
from app.services.vulnerability_intelligence.service import apply_fused_intelligence, mark_provider_failure


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

PACKAGE_ALIASES = {
    "linux_kernel": "linux-kernel",
    "kernel": "linux-kernel",
    "openssh": "openssh-server",
    "mysql": "mysql-server",
    "mariadb": "mariadb-server",
    "apache_http_server": "apache2",
    "http_server": "apache2",
}


@dataclass
class SyncResult:
    total_from_nvd: int = 0
    saved: int = 0
    kev_marked: int = 0
    epss_enriched: int = 0
    warnings: list[str] = field(default_factory=list)
    changed_cve_ids: list[str] = field(default_factory=list)

ProgressCallback = Callable[[str, int | None, int | None], None]


_HTTP_OPENER = None


def _get_http_opener() -> object:
    global _HTTP_OPENER
    if _HTTP_OPENER is not None:
        return _HTTP_OPENER
    proxy_url = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
        or ""
    ).strip()
    if proxy_url:
        _HTTP_OPENER = build_opener(ProxyHandler({"https": proxy_url, "http": proxy_url}))
    else:
        _HTTP_OPENER = build_opener()
    return _HTTP_OPENER


def _http_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    retries: int = 3,
    retry_delay: float = 2.0,
) -> dict[str, Any]:
    request = Request(url, headers=headers or {})
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            opener = _get_http_opener()
            with opener.open(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            retriable = exc.code in {408, 425, 429, 500, 502, 503, 504}
            last_error = RuntimeError(f"HTTP {exc.code} while requesting {url}: {body[:300]}")
            if not retriable or attempt >= retries:
                raise last_error from exc
            # 429 限流需要更长的退避时间
            if exc.code == 429:
                wait = retry_delay * (2 ** attempt)
            else:
                wait = retry_delay * (attempt + 1)
        except URLError as exc:
            last_error = RuntimeError(f"Network error while requesting {url}: {exc.reason}")
            if attempt >= retries:
                raise last_error from exc
            wait = retry_delay * (attempt + 1)
        except Exception as exc:
            last_error = RuntimeError(f"Unexpected error while requesting {url}: {exc}")
            if attempt >= retries:
                raise last_error from exc
            wait = retry_delay * (attempt + 1)
        time.sleep(wait)
    raise last_error or RuntimeError(f"Request failed for {url}")


def _report_progress(
    progress: ProgressCallback | None,
    message: str,
    current: int | None = None,
    total: int | None = None,
) -> None:
    if progress:
        progress(message, current, total)


def _nvd_date(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _first_english(items: list[dict[str, Any]], key: str = "value") -> str:
    for item in items or []:
        if item.get("lang") == "en":
            return item.get(key, "")
    return items[0].get(key, "") if items else ""


def _cvss(cve: dict[str, Any]) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvssData", {})
            score = float(data.get("baseScore") or 0)
            severity = values[0].get("baseSeverity") or data.get("baseSeverity") or _severity_from_score(score)
            return score, str(severity).title()
    return 0, "Unknown"


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _cwe(cve: dict[str, Any]) -> str:
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                return value
    return ""


def _references(cve: dict[str, Any]) -> str:
    references = cve.get("references", [])
    if isinstance(references, dict):
        references = references.get("referenceData", [])
    urls = [ref.get("url", "") for ref in references]
    return "\n".join(url for url in urls if url)


def _normalize_package(product: str) -> str:
    """CPE product → 发行版包名；只使用显式别名表，不做文本猜测。"""
    product = (product or "").strip().lower().replace(" ", "_")
    return PACKAGE_ALIASES.get(product, product.replace("_", "-"))


def _parse_cpe(cpe: str) -> tuple[str, str, str]:
    # cpe:2.3:part:vendor:product:version:... -> (part, vendor, product)
    parts = cpe.split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[2], parts[3], parts[4]
    return "", "", ""


def _walk_cpe_matches(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    def walk_node(node: dict[str, Any]) -> None:
        matches.extend(node.get("cpeMatch", []) or [])
        for child in node.get("children", []) or []:
            walk_node(child)

    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            walk_node(node)
    return matches


def _affected_from_nvd(cve: dict[str, Any]) -> tuple[str, str, str]:
    """从 NVD CVE 载荷提取（受影响产品, 发行版包名, 修复版本）。

    包名只来自 CPE 的 vendor/product 精确映射（经 ``PACKAGE_ALIASES`` 显式
    发行版别名表归一）。**没有 CPE 产品时返回 ``UNMAPPED_PACKAGE``（空串）**，
    绝不使用描述/引用文本里的包名子串猜测——历史上 vm2、WordPress SAML 插件、
    OpenSSH-for-Windows、openssl_encrypt 等公告因此被误映射到
    openssl/openssh-server，进而产生虚假的 affected 风险。调用方（matching）
    对未映射包名给出显式 not_applicable/unmapped 结论，不生成受影响候选。
    """
    counts: dict[str, int] = {}
    fixed_candidates: list[str] = []
    affected_products: list[str] = []
    for match in _walk_cpe_matches(cve.get("configurations", [])):
        if match.get("vulnerable") is False:
            continue
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        part, vendor, product = _parse_cpe(criteria)
        if not product or product in {"*", "-"}:
            continue
        package = _normalize_package(product)
        if part in {"a", "o"}:
            counts[package] = counts.get(package, 0) + 1
            affected_products.append(f"{vendor}:{product}")
        if match.get("versionEndExcluding"):
            fixed_candidates.append(match["versionEndExcluding"])
    if counts:
        affected_package = sorted(counts.items(), key=lambda item: item[1], reverse=True)[0][0]
    else:
        # 无 CPE：明确的「未映射」语义，由调用方决定不生成受影响候选。
        affected_package = UNMAPPED_PACKAGE
    affected_product = ", ".join(sorted(set(affected_products))[:5])
    fixed_version = fixed_candidates[0] if fixed_candidates else ""
    return affected_product, affected_package, fixed_version


def fetch_nvd(keyword: str = "linux", days: int = 30, limit: int = 100) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(days, 1))
    page_size = min(max(limit, 1), 2000)
    params = {
        "keywordSearch": keyword,
        "pubStartDate": _nvd_date(start),
        "pubEndDate": _nvd_date(now),
        "resultsPerPage": page_size,
        "startIndex": 0,
    }
    headers = {"User-Agent": "LinuxGuard/0.1"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    data = _http_json(f"{NVD_CVE_API}?{urlencode(params)}", headers=headers, timeout=60)
    return data.get("vulnerabilities", [])[:limit]


def fetch_nvd_by_cve(cve_id: str) -> list[dict[str, Any]]:
    headers = {"User-Agent": "LinuxGuard/0.1"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    data = _http_json(
        f"{NVD_CVE_API}?{urlencode({'cveId': cve_id})}",
        headers=headers,
        timeout=30,
        retries=1,
    )
    return data.get("vulnerabilities", [])


def fetch_cisa_kev(timeout: int = 20, retries: int = 1) -> dict[str, dict[str, Any]]:
    data = _http_json(
        CISA_KEV_JSON,
        headers={"User-Agent": "LinuxGuard/0.1"},
        timeout=timeout,
        retries=retries,
    )
    rows = data.get("vulnerabilities", [])
    return {row.get("cveID", ""): row for row in rows if row.get("cveID")}


def fetch_epss(cve_ids: list[str], timeout: int = 20, retries: int = 1) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index in range(0, len(cve_ids), 100):
        batch = cve_ids[index : index + 100]
        if not batch:
            continue
        url = f"{EPSS_API}?{urlencode({'cve': ','.join(batch)})}"
        data = _http_json(
            url,
            headers={"User-Agent": "LinuxGuard/0.1"},
            timeout=timeout,
            retries=retries,
        )
        for row in data.get("data", []):
            result[row["cve"]] = {
                "epss_score": float(row.get("epss") or 0),
                "epss_percentile": float(row.get("percentile") or 0),
                "score_date": row.get("date", ""),
            }
        time.sleep(0.25)
    return result


def _upsert_vulnerability(db: Session, item: dict[str, Any], kev: dict[str, Any] | None, epss: dict[str, float] | None) -> None:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return
    cvss_score, severity = _cvss(cve)
    affected_product, affected_package, fixed_version = _affected_from_nvd(cve)
    description = _first_english(cve.get("descriptions", []))
    title = kev.get("vulnerabilityName") if kev else description[:120]
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).first()
    if not vuln:
        vuln = models.VulnerabilityInfo(cve_id=cve_id, affected_package=affected_package)
        db.add(vuln)
    vuln.title = title or cve_id
    vuln.description = description
    vuln.cvss_score = cvss_score
    vuln.cvss_severity = severity
    vuln.cwe_id = _cwe(cve)
    vuln.affected_product = affected_product
    vuln.affected_package = affected_package
    vuln.fixed_version = fixed_version
    vuln.published_date = cve.get("published", "")
    vuln.last_modified_date = cve.get("lastModified", "")
    vuln.source = "NVD CVE API"
    vuln.references = _references(cve)
    if affected_package == UNMAPPED_PACKAGE:
        vuln.remediation = (
            "NVD 未提供可精确映射到发行版包名的 CPE vendor/product；不得依据描述或"
            "引用文本子串猜测包名。需以发行版官方公告补充适用性记录后再做匹配。"
        )
    elif fixed_version:
        vuln.remediation = (
            f"NVD CPE versionEndExcluding={fixed_version}，请结合发行版安全公告确认修复包版本。"
        )
    else:
        vuln.remediation = "请结合发行版安全公告确认受影响软件包和修复版本。"
    db.flush()

    threat = db.query(models.ThreatIntelSource).filter_by(cve_id=cve_id).first()
    if not threat:
        threat = models.ThreatIntelSource(cve_id=cve_id)
        db.add(threat)
        db.flush()   # autoflush=False：让同会话后续查找（如多源富集）立即可见，防重复建行
    threat.is_kev = bool(kev)
    threat.kev_due_date = kev.get("dueDate", "") if kev else ""
    threat.epss_score = (epss or {}).get("epss_score", 0)
    threat.epss_percentile = (epss or {}).get("epss_percentile", 0)
    threat.exploit_status = "known-exploited" if kev else "unknown"
    threat.poc_available = False
    threat.source_detail = json.dumps(
        {
            "nvd": NVD_CVE_API,
            "cisa_kev": CISA_KEV_JSON if kev else "",
            "epss": EPSS_API if epss else "",
            "kev": kev or {},
        },
        ensure_ascii=False,
    )


def clear_vulnerability_pipeline(db: Session) -> None:
    """Compatibility reset: retire derived rows without deleting audit history."""
    db.query(models.VulnerabilityMatch).filter_by(active=True).update(
        {"active": False, "affected": False, "match_status": "inactive", "reason_code": "intel_refresh"},
        synchronize_session=False,
    )
    db.query(models.RiskAssessment).filter_by(active=True).update(
        {"active": False, "review_status": "inactive", "review_reason": "情报刷新后等待增量重算"},
        synchronize_session=False,
    )
    db.query(models.RemediationTask).filter(
        models.RemediationTask.status.in_(["pending", "blocked"])
    ).update({"status": "blocked"}, synchronize_session=False)
    db.commit()


def sync_real_vulnerabilities(
    db: Session,
    keyword: str = "linux",
    days: int = 30,
    limit: int = 100,
    replace: bool = False,
    progress=None,
) -> SyncResult:
    if replace:
        _report_progress(progress, "Refreshing selected providers; preserving all matches, risks, and audit history")
    _report_progress(progress, "Fetching NVD vulnerabilities")
    warnings: list[str] = []
    try:
        nvd_items = fetch_nvd(keyword=keyword, days=days, limit=limit)
    except Exception as exc:
        # NVD is an enrichment source.  An outage must not retire Canonical
        # matches, risks, or audit history.
        warnings.append(f"NVD unavailable: {exc}")
        return SyncResult(warnings=warnings)
    cve_ids = [item.get("cve", {}).get("id", "") for item in nvd_items]
    cve_ids = [cve_id for cve_id in cve_ids if cve_id]
    changed_cves = NvdProvider().store_items(db, nvd_items)
    try:
        _report_progress(progress, "Fetching CISA KEV enrichment")
        kev_map = fetch_cisa_kev()
    except Exception as exc:
        kev_map = {}
        warnings.append(f"CISA KEV unavailable: {exc}")
        mark_provider_failure(db, cve_ids, "cisa_kev", classify_error(exc), str(exc))
    else:
        changed_cves.update(
            CisaKevProvider().store_catalog(db, cve_ids, {"vulnerabilities": list(kev_map.values())})
        )
    try:
        _report_progress(progress, "Fetching EPSS enrichment")
        epss_map = fetch_epss(cve_ids)
    except Exception as exc:
        epss_map = {}
        warnings.append(f"EPSS unavailable: {exc}")
        mark_provider_failure(db, cve_ids, "epss", classify_error(exc), str(exc))
    else:
        changed_cves.update(EpssProvider().store_rows(
            db,
            cve_ids,
            {"data": [
                {"cve": cve_id, "epss": row.get("epss_score", 0), "percentile": row.get("epss_percentile", 0), "date": row.get("score_date", "")}
                for cve_id, row in epss_map.items()
            ]},
        ))
    saved = 0
    kev_marked = 0
    epss_enriched = 0
    total = len(nvd_items)
    for index, item in enumerate(nvd_items, 1):
        cve_id = item.get("cve", {}).get("id", "")
        if not cve_id:
            continue
        kev = kev_map.get(cve_id)
        epss = epss_map.get(cve_id)
        _upsert_vulnerability(db, item, kev, epss)
        saved += 1
        kev_marked += 1 if kev else 0
        epss_enriched += 1 if epss else 0
        if index == total or index == 1 or index % 10 == 0:
            _report_progress(progress, f"Saving vulnerabilities ({index}/{total})", index, total)
    apply_fused_intelligence(db, cve_ids)
    db.commit()
    return SyncResult(
        total_from_nvd=len(nvd_items),
        saved=saved,
        kev_marked=kev_marked,
        epss_enriched=epss_enriched,
        warnings=warnings,
        changed_cve_ids=sorted(changed_cves),
    )
