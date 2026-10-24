"""任务 B2/B3 回归：NVD 无 CPE 时禁止包名子串猜测 + 隔离脚本语义。

覆盖：
- vm2、WordPress SAML 插件、OpenSSH-for-Windows、openssl_encrypt 四类公告
  即使描述/引用文本出现 openssl/openssh，也不会被映射成 openssl/openssh-server；
- CPE vendor/product 精确映射（含显式发行版别名表）仍然可用；
- matching_engine 对空/未映射包名给出显式 not_applicable +
  affected_package_unmapped，不生成 affected 匹配或风险；
- 已映射包的既有语义（缺修复版本 → unknown/affected）不被误伤；
- 隔离维护脚本默认 dry-run 只读，--apply 才置 reanalysis_required 并写治理事件，
  不删除记录、不修改历史报告。

仅使用合成 NVD 载荷与隔离 SQLite，不触网、不写真实库。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import models
from app.services.matching_engine import _evaluate_match, run_matching
from app.services.nvd_package_mapping import (
    QUARANTINED_MAPPING_STATUS,
    UNMAPPED_PACKAGE,
    cpe_package_names,
    cpe_package_names_from_configurations,
    is_unmapped_package,
)
from app.services.real_intel_collector import _affected_from_nvd, _upsert_vulnerability

GUARDED_PACKAGES = {"openssl", "openssh", "openssh-server"}


def _nvd_cve(description: str, references: list[str] | None = None,
             configurations: list[dict] | None = None,
             cve_id: str = "CVE-2099-9001") -> dict:
    payload = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "references": [{"url": item} for item in (references or [])],
    }
    if configurations:
        payload["configurations"] = configurations
    return payload


def _cpe_config(product: str, vendor: str = "openssl",
                version_end: str | None = None) -> list[dict]:
    match = {
        "vulnerable": True,
        "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
    }
    if version_end:
        match["versionEndExcluding"] = version_end
    return [{"nodes": [{"cpeMatch": [match]}]}]


# ── B2：无 CPE 时的三类（含第四类）误映射反例 ─────────────────────────────────


@pytest.mark.parametrize("label, description, references", [
    ("vm2",
     "vm2 is a Node.js sandbox. A sandbox escape allows code execution. "
     "Unrelated projects such as openssl and openssh-server are not affected by this vm2 issue.",
     ["https://github.com/patriksimek/vm2/security/advisories/GHSA-vm2-demo"]),
    ("wordpress-saml",
     "The WordPress SAML Single Sign-On plugin mishandles assertion signatures. "
     "The plugin ships an openssl_encrypt compatibility helper.",
     ["https://wordpress.org/plugins/saml-sso-demo/"]),
    ("openssh-for-windows",
     "OpenSSH for Windows before 9.5 fails to validate forwarded agent restrictions.",
     ["https://github.com/PowerShell/Win32-OpenSSH/releases"]),
    ("openssl_encrypt",
     "openssl_encrypt is a PHP library that implements symmetric encryption wrappers.",
     ["https://github.com/openssl-encrypt/openssl-encrypt"]),
])
def test_no_cpe_never_guesses_distro_package_from_text(label, description, references):
    """描述里的 openssl/openssh 字样不得再驱动包映射（历史误映射回归）。"""
    affected_product, affected_package, fixed_version = _affected_from_nvd(
        _nvd_cve(description, references))

    assert is_unmapped_package(affected_package), (label, affected_package)
    assert affected_package == UNMAPPED_PACKAGE
    assert affected_package not in GUARDED_PACKAGES
    assert affected_product == ""
    assert fixed_version == ""


def test_exact_cpe_product_mapping_still_works():
    affected_product, affected_package, fixed_version = _affected_from_nvd(
        _nvd_cve("Buffer overread in OpenSSL X.509 parsing.",
                 configurations=_cpe_config("openssl", version_end="3.0.3")))

    assert affected_product == "openssl:openssl"
    assert affected_package == "openssl"
    assert fixed_version == "3.0.3"


def test_explicit_distro_alias_table_still_maps_exact_cpe_products():
    # 只有显式别名表（http_server → apache2）可做归一；这不是文本猜测。
    _, package, _ = _affected_from_nvd(
        _nvd_cve("HTTP server request smuggling.",
                 configurations=_cpe_config("http_server", vendor="apache")))
    assert package == "apache2"

    _, openssh_package, _ = _affected_from_nvd(
        _nvd_cve("OpenSSH pre-auth issue.",
                 configurations=_cpe_config("openssh", vendor="openbsd")))
    assert openssh_package == "openssh-server"


def test_cpe_helpers_expose_exact_mapping_set():
    assert cpe_package_names("openssl:openssl, openbsd:openssh") == {
        "openssl", "openssh-server"}
    assert cpe_package_names("") == set()


# ── B2：matching_engine 的显式未映射语义 ──────────────────────────────────────


def _values_for_package(package_name: str, *, fixed: str = "3.0.3",
                        package=None, canonical=None) -> dict:
    asset = SimpleNamespace(hostname="guard-host")
    vulnerability = SimpleNamespace(cve_id="CVE-2099-9100",
                                    affected_package=package_name,
                                    fixed_version=fixed)
    return _evaluate_match(asset, vulnerability, package, canonical)


@pytest.mark.parametrize("package_name", ["", "unknown", "unmapped", "unmapped_nvd"])
def test_unmapped_package_is_explicit_not_applicable(package_name):
    installed = SimpleNamespace(package_version="3.0.2")
    values = _values_for_package(package_name, package=installed)
    assert values["affected"] is False
    assert values["match_status"] == "not_applicable"
    assert values["reason_code"] == "affected_package_unmapped"
    assert "未提供可精确" in values["match_reason"]
    assert "不做包匹配" in values["match_reason"]


def test_unmapped_guard_precedes_missing_package_and_vendor_override():
    # 即使包未安装、即使误传了厂商 affected 记录，也不得变回 affected。
    canonical = {"status": "affected", "release": "jammy", "fixed_version": "3.0.3"}
    values = _values_for_package("", package=None, canonical=canonical)
    assert values["match_status"] == "not_applicable"
    assert values["reason_code"] == "affected_package_unmapped"
    assert values["affected"] is False


def test_mapped_package_semantics_are_unchanged():
    installed = SimpleNamespace(package_version="3.0.2")
    values = _values_for_package("openssl", package=installed)
    assert values["affected"] is True
    assert values["match_status"] == "potentially_affected"

    # 既有保守语义：包已映射但缺修复版本 → unknown/affected，仍保留。
    missing_fixed = _values_for_package("openssl", fixed="", package=installed)
    assert missing_fixed["affected"] is True
    assert missing_fixed["match_status"] == "unknown"
    assert missing_fixed["reason_code"] == "fixed_version_missing"


def test_run_matching_creates_no_affected_rows_or_risks_for_unmapped(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="guard-host", distribution="ubuntu",
                                  os_version="22.04", inventory_complete=True)
        db.add(asset)
        db.flush()
        db.add(models.AssetPackage(asset_id=asset.id, package_name="openssl",
                                   package_version="3.0.2", package_manager="deb"))
        for index, package_name in enumerate(("", "unknown", "unmapped"), start=1):
            db.add(models.VulnerabilityInfo(
                cve_id=f"CVE-2099-920{index}", title="synthetic",
                affected_package=package_name, fixed_version="",
                source="NVD CVE API", affected_product=""))
        db.commit()

        run_matching(db)

        rows = db.query(models.VulnerabilityMatch).all()
        assert len(rows) == 3
        for row in rows:
            assert row.affected is False
            assert row.match_status == "not_applicable"
            assert row.reason_code == "affected_package_unmapped"
        assert db.query(models.RiskAssessment).count() == 0


def test_upsert_records_unmapped_package_with_explicit_remediation(session_factory):
    item = {"cve": {
        "id": "CVE-2099-9300",
        "descriptions": [{"lang": "en", "value": "OpenSSL and OpenSSH text only."}],
        "references": [{"url": "https://example.invalid/openssl"}],
        "metrics": {},
    }}
    with session_factory() as db:
        _upsert_vulnerability(db, item, None, None)
        db.commit()
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id="CVE-2099-9300").one()
        assert vuln.source == "NVD CVE API"
        assert vuln.affected_package == UNMAPPED_PACKAGE
        assert "未映射" in vuln.remediation or "不得依据描述" in vuln.remediation


# ── B3：隔离维护脚本（默认 dry-run / --apply 显式） ───────────────────────────

SCRIPT_PATH = (Path(__file__).resolve().parents[1]
               / "scripts" / "quarantine_unmapped_nvd_risks.py")


def _load_quarantine_script():
    spec = importlib.util.spec_from_file_location(
        "quarantine_unmapped_nvd_risks_under_test", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _add_nvd_cache(db, cve_id: str, *, configurations=None,
                   fetch_status: str = "available") -> None:
    """镜像真实库：NVD 缓存只有描述/CVSS，通常没有 CPE configurations。"""
    data = {
        "description": "synthetic NVD description",
        "cvss": {"score": 5.0, "severity": "Medium", "vector": ""},
        "cwe": [], "references": [], "published": "", "modified": "",
    }
    if configurations is not None:
        data["configurations"] = configurations
    db.add(models.VulnerabilityIntelligenceSource(
        cve_id=cve_id.split(":")[0], source="nvd", fetch_status=fetch_status,
        normalized_data=json.dumps(data), content_fingerprint=""))
    db.flush()


def _add_risk(db, asset_id: int, *, cve_id: str, package: str, source: str,
              affected_product: str, affected_package: str,
              active: bool = True, review_status: str = "candidate",
              nvd_configurations=None,
              nvd_cache: bool = True) -> models.RiskAssessment:
    vuln = models.VulnerabilityInfo(
        cve_id=cve_id, title="synthetic", affected_package=affected_package,
        affected_product=affected_product, fixed_version="", source=source)
    db.add(vuln)
    db.flush()
    match = models.VulnerabilityMatch(
        asset_id=asset_id, cve_id=cve_id, package_name=package,
        affected=True, match_status="unknown",
        reason_code="fixed_version_missing", active=active)
    db.add(match)
    db.flush()
    risk = models.RiskAssessment(
        asset_id=asset_id, cve_id=cve_id, package_name=package, match_id=match.id,
        active=active, review_status=review_status, affected_status="unknown")
    db.add(risk)
    db.flush()
    if nvd_cache and source.strip().lower().startswith("nvd"):
        _add_nvd_cache(db, cve_id, configurations=nvd_configurations)
    return risk


def _seed_audit_db(db) -> dict:
    asset = models.LinuxAsset(hostname="audit-host", distribution="ubuntu",
                              os_version="22.04", inventory_complete=True)
    db.add(asset)
    db.flush()
    unmapped = _add_risk(db, asset.id, cve_id="CVE-2099-9401", package="openssl",
                         source="NVD CVE API", affected_product="",
                         affected_package="openssl")
    inactive = _add_risk(db, asset.id, cve_id="CVE-2099-9402", package="openssh-server",
                         source="NVD CVE API", affected_product="",
                         affected_package="openssh-server", active=False,
                         review_status="completed")
    # 只有 NVD 缓存中确实保有 CPE configurations 时才算“可精确复核”。
    mapped = _add_risk(db, asset.id, cve_id="CVE-2099-9403", package="openssl",
                       source="NVD CVE API", affected_product="openssl:openssl",
                       affected_package="openssl",
                       nvd_configurations=_cpe_config("openssl"))
    distro = _add_risk(db, asset.id, cve_id="CVE-2099-9404:jammy", package="openssl",
                       source="Ubuntu Security API", affected_product="",
                       affected_package="openssl")
    db.commit()
    return {"unmapped": unmapped.id, "inactive": inactive.id,
            "mapped": mapped.id, "distro": distro.id}


def test_quarantine_audit_is_read_only_and_targets_only_unverifiable_nvd(session_factory):
    module = _load_quarantine_script()
    with session_factory() as db:
        ids = _seed_audit_db(db)
        findings = module.collect_candidates(db)

        assert {item["risk_id"] for item in findings} == {ids["unmapped"], ids["inactive"]}
        unmapped = next(item for item in findings if item["risk_id"] == ids["unmapped"])
        # NVD 缓存无 CPE provenance：即使派生列看起来有值，也不能证明精确映射。
        assert unmapped["basis"] == "nvd_source_without_cpe_provenance"
        assert unmapped["action"] == "will_quarantine"
        assert unmapped["active"] is True
        inactive = next(item for item in findings if item["risk_id"] == ids["inactive"])
        assert inactive["active"] is False
        assert inactive["action"] == "inactive_skipped"

        # 只读：dry-run 收集不改变状态、不写治理事件
        assert db.query(models.RiskGovernanceEvent).count() == 0
        for risk_id in ids.values():
            assert db.get(models.RiskAssessment, risk_id).review_status in {
                "candidate", "completed"}

        applied = module.apply_quarantine(db, findings)
        assert applied == [ids["unmapped"]]

        db.expire_all()
        assert db.get(models.RiskAssessment, ids["unmapped"]).review_status == QUARANTINED_MAPPING_STATUS
        assert db.get(models.RiskAssessment, ids["unmapped"]).active is True
        assert db.get(models.RiskAssessment, ids["inactive"]).review_status == "completed"
        assert db.get(models.RiskAssessment, ids["mapped"]).review_status == "candidate"
        assert db.get(models.RiskAssessment, ids["distro"]).review_status == "candidate"

        event = db.query(models.RiskGovernanceEvent).filter_by(
            risk_id=ids["unmapped"]).one()
        assert event.kind == "nvd_mapping_quarantine"
        assert event.actor == "nvd_mapping_policy"
        assert '"records_deleted": false' in event.payload_json
        assert '"historical_reports_modified": false' in event.payload_json
        assert '"scores_unchanged": true' in event.payload_json
        # 不删除记录：风险、匹配、漏洞行都保留
        assert db.query(models.RiskAssessment).count() == 4
        assert db.query(models.VulnerabilityMatch).count() == 4
        assert db.query(models.VulnerabilityInfo).count() == 4

        # 幂等：第二次 apply 不再改状态、不再追加事件
        second = module.apply_quarantine(db, module.collect_candidates(db))
        assert second == []
        assert db.query(models.RiskGovernanceEvent).count() == 1


def test_quarantine_audit_marks_empty_affected_package_as_unmapped(session_factory):
    module = _load_quarantine_script()
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="audit-empty", distribution="ubuntu",
                                  os_version="22.04", inventory_complete=True)
        db.add(asset)
        db.flush()
        risk = _add_risk(db, asset.id, cve_id="CVE-2099-9405", package="",
                         source="NVD CVE API", affected_product="",
                         affected_package="")
        db.commit()

        findings = module.collect_candidates(db)
        assert [item["risk_id"] for item in findings] == [risk.id]
        assert findings[0]["basis"] == "nvd_affected_package_unmapped"
        assert findings[0]["package"] == ""


def test_risk_141_candidate_without_nvd_cpe_provenance_is_quarantined(session_factory):
    """真实 risk=141 形态回归：NVD/unknown/candidate，派生 affected_product 有值，
    但 NVD 缓存没有 configurations；必须判定为应隔离而不是被别名表放行。"""
    module = _load_quarantine_script()
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="audit-141", distribution="ubuntu",
                                  os_version="22.04", inventory_complete=True)
        db.add(asset)
        db.flush()
        risk = _add_risk(db, asset.id, cve_id="CVE-2026-106585",
                         package="openssh-server", source="NVD CVE API",
                         affected_product="openbsd:openssh",
                         affected_package="openssh-server",
                         review_status="candidate", nvd_cache=True)
        db.commit()

        findings = module.collect_candidates(db)
        item = next(row for row in findings if row["risk_id"] == risk.id)
        assert item["basis"] == "nvd_source_without_cpe_provenance"
        assert item["action"] == "will_quarantine"
        assert item["match_status"] == "unknown"
        assert item["claimed_cpe_products"] == ["openssh-server"]
        assert item["cpe_provenance_products"] == []
        assert item["nvd_cache_present"] is True


def test_cpe_provenance_helper_requires_configurations():
    assert cpe_package_names_from_configurations(_cpe_config("openssl")) == {"openssl"}
    # 只有派生 affected_product 字符串、没有 configurations → 无 provenance。
    assert cpe_package_names_from_configurations([]) == set()


def test_quarantine_changes_only_status_and_keeps_counts_scores(session_factory):
    module = _load_quarantine_script()
    with session_factory() as db:
        ids = _seed_audit_db(db)
        risk = db.get(models.RiskAssessment, ids["unmapped"])
        risk.preliminary_score = 77.5
        risk.final_score = 70.0
        risk.risk_level = "High"
        risk.reason = "历史分数与结论保持不变"
        risk.review_reason = "历史研判理由保持不变"
        risk.reanalysis_count = 3
        db.add(models.RemediationTask(
            risk_id=risk.id, asset_id=risk.asset_id, cve_id=risk.cve_id,
            package_name=risk.package_name, status="pending"))
        db.commit()

        before = {
            "risks": db.query(models.RiskAssessment).count(),
            "matches": db.query(models.VulnerabilityMatch).count(),
            "vulns": db.query(models.VulnerabilityInfo).count(),
            "tasks": db.query(models.RemediationTask).count(),
            "reports": db.query(models.AnalysisReport).count(),
            "events": db.query(models.RiskGovernanceEvent).count(),
        }
        applied = module.apply_quarantine(db, module.collect_candidates(db))
        assert applied == [ids["unmapped"]]
        db.expire_all()
        risk = db.get(models.RiskAssessment, ids["unmapped"])

        after = {
            "risks": db.query(models.RiskAssessment).count(),
            "matches": db.query(models.VulnerabilityMatch).count(),
            "vulns": db.query(models.VulnerabilityInfo).count(),
            "tasks": db.query(models.RemediationTask).count(),
            "reports": db.query(models.AnalysisReport).count(),
            "events": db.query(models.RiskGovernanceEvent).count(),
        }
        for key in ("risks", "matches", "vulns", "tasks", "reports"):
            assert after[key] == before[key], key
        assert after["events"] == before["events"] + 1  # 只追加治理事件

        # 只有 review_status 改变：active、分数、理由、再研判计数都不动。
        assert risk.review_status == QUARANTINED_MAPPING_STATUS
        assert risk.active is True
        assert risk.preliminary_score == 77.5
        assert risk.final_score == 70.0
        assert risk.risk_level == "High"
        assert risk.reason == "历史分数与结论保持不变"
        assert risk.review_reason == "历史研判理由保持不变"
        assert risk.reanalysis_count == 3


def test_quarantine_script_requires_explicit_apply_and_is_idempotent(
        session_factory, monkeypatch, capsys):
    module = _load_quarantine_script()
    from app import database
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    with session_factory() as db:
        ids = _seed_audit_db(db)
        db.close()

    assert module.main([]) == 0
    dry_output = capsys.readouterr().out
    assert "DRY-RUN" in dry_output
    assert "action=will_quarantine" in dry_output
    assert "no rows modified" in dry_output
    assert "counts:" in dry_output
    assert "active_pending=1" in dry_output
    assert "active_already_quarantined=0" in dry_output
    assert "active_pending_from_candidate=1" in dry_output
    with session_factory() as db:
        assert db.get(models.RiskAssessment, ids["unmapped"]).review_status == "candidate"
        assert db.query(models.RiskGovernanceEvent).count() == 0

    assert module.main(["--apply"]) == 0
    apply_output = capsys.readouterr().out
    assert f"applied=1 risk(s) set to {QUARANTINED_MAPPING_STATUS}" in apply_output
    with session_factory() as db:
        assert db.get(models.RiskAssessment, ids["unmapped"]).review_status == QUARANTINED_MAPPING_STATUS
        assert db.query(models.RiskGovernanceEvent).count() == 1

    # 再次 dry-run：区分“已隔离”，不再是 will_quarantine。
    assert module.main([]) == 0
    rerun_output = capsys.readouterr().out
    assert "action=already_quarantined" in rerun_output
    assert "active_pending=0" in rerun_output
    assert "active_already_quarantined=1" in rerun_output

    # 再次 --apply：幂等，不追加事件。
    assert module.main(["--apply"]) == 0
    assert "applied=0 risk(s)" in capsys.readouterr().out
    with session_factory() as db:
        assert db.query(models.RiskGovernanceEvent).count() == 1

