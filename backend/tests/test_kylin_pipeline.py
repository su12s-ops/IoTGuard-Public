import json
from pathlib import Path

from app import models
from app.services import kylin_security_collector as kylin_collector
from app.services.asset_parser import parse_asset_text
from app.services.matching_engine import run_matching
from app.services.vulnerability_intelligence.kylin_provider import KylinProvider, kylin_release_token
from app.services.vulnerability_intelligence.service import get_source_bundle, kylin_applicability


SAMPLE_ASSET = Path(__file__).parent / "fixtures" / "kylin_asset_synthetic.txt"


def _nvd_item(cve_id: str, package: str, fixed: str = "") -> dict:
    match = {
        "criteria": f"cpe:2.3:a:vendor:{package}:*:*:*:*:*:*:*:*",
        "vulnerable": True,
    }
    if fixed:
        match["versionEndExcluding"] = fixed
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-01-10T00:00:00.000Z",
            "lastModified": "2026-02-01T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": f"Test vulnerability in {package}."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L",
            }}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": "https://example.com/advisory"}],
            "configurations": [{"nodes": [{"cpeMatch": [match]}]}],
        }
    }


def _seed_kylin_asset(db, package="openssl", installed="1.0.2"):
    asset = models.LinuxAsset(
        hostname="kylin-vm-test",
        distribution="kylin",
        os_name="Kylin Linux Desktop",
        os_version="V10",
        exposure_level="dmz",
        business_level="core",
    )
    db.add(asset)
    db.flush()
    db.add(models.AssetPackage(
        asset_id=asset.id,
        package_name=package,
        package_version=installed,
        package_manager="dpkg",
    ))
    db.commit()
    return asset


def _fake_fetch(items_by_package: dict, warnings: dict | None = None):
    warnings = warnings or {}

    def fetch(package_name, limit):
        return items_by_package.get(package_name, [])[:limit], warnings.get(package_name, "")

    return fetch


def test_parse_kylin_asset_sample():
    parsed = parse_asset_text(SAMPLE_ASSET.read_text(encoding="utf-8"))
    assert parsed.distribution == "kylin"
    assert parsed.os_version == "V10"
    assert parsed.hostname == "kylin-vm-01"
    assert any(pkg["package_name"] == "openssl" for pkg in parsed.packages)
    assert any(svc["port"] == 22 for svc in parsed.services)


def test_kylin_release_token_normalization():
    assert kylin_release_token("V10") == "v10"
    assert kylin_release_token("v10") == "v10"
    assert kylin_release_token("V10 SP1") == "v10"
    assert kylin_release_token("10") == "v10"
    assert kylin_release_token("") == ""


def test_ssrf_guard_blocks_non_public_targets():
    for url in (
        "http://127.0.0.1/api",
        "http://localhost/api",
        "https://192.168.1.5/api",
        "https://10.0.0.8/api",
        "https://172.16.2.3/api",
        "https://169.254.1.1/api",
        "ftp://services.nvd.nist.gov/api",
    ):
        try:
            kylin_collector._assert_public_http_url(url)
        except ValueError:
            continue
        raise AssertionError(f"URL should have been blocked: {url}")
    # 公网 https 目标应放行（DNS 解析失败也放行，交给 HTTP 层报错）
    kylin_collector._assert_public_http_url("https://services.nvd.nist.gov/rest/json/cves/2.0")


def test_kylin_provider_store_and_applicability(session_factory):
    db = session_factory()
    try:
        KylinProvider().store(
            db,
            {"id": "CVE-2026-3001", "priority": "high", "updated_at": "2026-02-01T00:00:00Z"},
            "openssl",
            "v10",
            "under_investigation",
            "",
        )
        db.commit()
        record = kylin_applicability(db, "CVE-2026-3001", "v10", "openssl")
        assert record is not None
        assert record["source"] == "kylin"
        assert record["data_origin"] == "nvd_cpe"
        assert record["status"] == "under_investigation"
        bundle = get_source_bundle(db, "CVE-2026-3001", release="v10", package_name="openssl")
        assert bundle["kylin"]["status"] == "available"
        assert bundle["kylin"]["value"]["package"] == "openssl"
    finally:
        db.close()


def test_kylin_sync_creates_records_and_released_match(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_kylin_asset(db, installed="1.0.2")
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            _fake_fetch({"openssl": [_nvd_item("CVE-2026-3002", "openssl", fixed="1.1.1")]}),
        )
        monkeypatch.setattr(kylin_collector, "_enrich_intel", lambda db, ids, **kwargs: (0, 0))
        monkeypatch.setattr(kylin_collector.time, "sleep", lambda _: None)
        result = kylin_collector.sync_kylin_asset_intelligence(db, max_packages_per_asset=10, limit_per_package=10)
        assert result.saved == 1
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id="CVE-2026-3002:v10:openssl").one()
        assert vuln.source == "NVD CVE API (Kylin 映射)"
        assert vuln.fixed_version == "1.1.1"
        threat = db.query(models.ThreatIntelSource).filter_by(cve_id="CVE-2026-3002:v10:openssl").one()
        assert json.loads(threat.source_detail)["data_origin"] == "nvd_cpe"
        source = db.query(models.VulnerabilityIntelligenceSource).filter_by(
            cve_id="CVE-2026-3002", source="kylin"
        ).one()
        assert json.loads(source.normalized_data)["records"][0]["status"] == "released"
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(cve_id="CVE-2026-3002:v10:openssl").one()
        assert match.affected is True
        assert match.reason_code == "installed_version_below_fixed"
    finally:
        db.close()


def test_kylin_under_investigation_status_marks_affected(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_kylin_asset(db, installed="1.1.1f-1kord1")
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            _fake_fetch({"openssl": [_nvd_item("CVE-2026-3003", "openssl")]}),
        )
        monkeypatch.setattr(kylin_collector, "_enrich_intel", lambda db, ids, **kwargs: (0, 0))
        monkeypatch.setattr(kylin_collector.time, "sleep", lambda _: None)
        kylin_collector.sync_kylin_asset_intelligence(db, max_packages_per_asset=10, limit_per_package=10)
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(cve_id="CVE-2026-3003:v10:openssl").one()
        assert match.affected is True
        assert match.reason_code == "kylin_under_investigation"
        assert match.confidence == 0.65
    finally:
        db.close()


def test_kylin_fact_suppresses_generic_nvd_row(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_kylin_asset(db, installed="1.0.2")
        db.add(models.VulnerabilityInfo(
            cve_id="CVE-2026-3004",
            title="upstream",
            affected_package="openssl",
            fixed_version="99.0",
            source="NVD CVE API",
        ))
        db.commit()
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            _fake_fetch({"openssl": [_nvd_item("CVE-2026-3004", "openssl", fixed="1.1.1")]}),
        )
        monkeypatch.setattr(kylin_collector, "_enrich_intel", lambda db, ids, **kwargs: (0, 0))
        monkeypatch.setattr(kylin_collector.time, "sleep", lambda _: None)
        kylin_collector.sync_kylin_asset_intelligence(db, max_packages_per_asset=10, limit_per_package=10)
        run_matching(db)
        rows = db.query(models.VulnerabilityMatch).all()
        assert len(rows) == 1
        assert rows[0].cve_id == "CVE-2026-3004:v10:openssl"
    finally:
        db.close()


def test_kylin_keyword_only_hits_without_cpe_are_skipped(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_kylin_asset(db, package="nginx")
        # CPE 只点名 bash，keyword 命中的 nginx 视为描述噪音
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            _fake_fetch({"nginx": [_nvd_item("CVE-2026-3005", "bash")]}),
        )
        monkeypatch.setattr(kylin_collector, "_enrich_intel", lambda db, ids, **kwargs: (0, 0))
        monkeypatch.setattr(kylin_collector.time, "sleep", lambda _: None)
        result = kylin_collector.sync_kylin_asset_intelligence(db, max_packages_per_asset=10, limit_per_package=10)
        assert result.saved == 0
        assert db.query(models.VulnerabilityInfo).count() == 0
        assert any("CPE" in notice for notice in result.notices)
    finally:
        db.close()


def test_kylin_network_failure_restores_cached_applicability(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_kylin_asset(db, installed="1.0.2")
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            _fake_fetch({"openssl": [_nvd_item("CVE-2026-3006", "openssl", fixed="1.1.1")]}),
        )
        monkeypatch.setattr(kylin_collector, "_enrich_intel", lambda db, ids, **kwargs: (0, 0))
        monkeypatch.setattr(kylin_collector.time, "sleep", lambda _: None)
        kylin_collector.sync_kylin_asset_intelligence(db, max_packages_per_asset=10, limit_per_package=10)
        db.query(models.ThreatIntelSource).delete()
        db.query(models.VulnerabilityInfo).delete()
        db.commit()
        monkeypatch.setattr(
            kylin_collector,
            "_fetch_nvd_cves_for_package",
            lambda package, limit: ([], "NVD timeout"),
        )
        result = kylin_collector.sync_kylin_asset_intelligence(db)
        assert result.saved == 1
        assert db.query(models.VulnerabilityInfo).count() == 1
        source = db.query(models.VulnerabilityIntelligenceSource).filter_by(
            cve_id="CVE-2026-3006", source="kylin"
        ).one()
        assert source.fetch_status == "cached"
        run_matching(db)
        assert db.query(models.VulnerabilityMatch).filter_by(affected=True).count() == 1
    finally:
        db.close()
