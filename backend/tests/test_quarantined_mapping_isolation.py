"""隔离状态回归：quarantined_mapping 不得进入正式研判，但必须可见且原因明确。

覆盖：
- 选择器白名单/显式隔离分支：candidate、reanalysis_required 可选，
  quarantined_mapping 与 inactive 跳过并给出可核验原因；
- preflight 在只有隔离行时返回 no_candidates；
- POST /api/analysis/runs 的 create_run 核心路径不会选中隔离行、不会新建任务；
- /api/risk/ranking 仍返回隔离行，且 legacy_status 不伪装成可研判状态、
  review_status_reason 给出“未映射/隔离”原因。

仅使用隔离 SQLite；不触网、不调用模型、不写真实库。
"""
from __future__ import annotations

import pytest

from app import config, models
from app.routers import analysis, risk as risk_router
from app.services.nvd_package_mapping import QUARANTINED_MAPPING_STATUS
from app.services.review_common.selection import (
    QUARANTINED_STATUSES,
    REVIEWABLE_STATUSES,
    preflight_check,
    select_candidates,
)


def _add_risk(db, asset_id: int, *, cve_id: str, status: str,
              active: bool = True, package: str = "openssl",
              priority: int = 0) -> models.RiskAssessment:
    vuln = models.VulnerabilityInfo(
        cve_id=cve_id, title="synthetic", affected_package=package,
        affected_product="", fixed_version="", source="NVD CVE API")
    db.add(vuln)
    db.flush()
    match = models.VulnerabilityMatch(
        asset_id=asset_id, cve_id=cve_id, package_name=package,
        affected=True, match_status="unknown", reason_code="fixed_version_missing",
        active=active)
    db.add(match)
    db.flush()
    risk = models.RiskAssessment(
        asset_id=asset_id, cve_id=cve_id, package_name=package, match_id=match.id,
        active=active, review_status=status, affected_status="unknown",
        priority_rank=priority)
    db.add(risk)
    db.flush()
    return risk


def _seed(db) -> dict:
    asset = models.LinuxAsset(hostname="isolation-host", distribution="ubuntu",
                              os_version="22.04", inventory_complete=True)
    db.add(asset)
    db.flush()
    ids = {
        "candidate": _add_risk(db, asset.id, cve_id="CVE-2099-9501",
                               status="candidate", priority=1).id,
        "reanalysis": _add_risk(db, asset.id, cve_id="CVE-2099-9502",
                                status="reanalysis_required", priority=2).id,
        "quarantined": _add_risk(db, asset.id, cve_id="CVE-2099-9503",
                                 status=QUARANTINED_MAPPING_STATUS, priority=3).id,
        "inactive": _add_risk(db, asset.id, cve_id="CVE-2099-9504",
                              status="completed", active=False, priority=4).id,
        "asset": asset.id,
    }
    db.commit()
    return ids


def test_status_sets_make_quarantine_explicit_and_unreviewable():
    assert QUARANTINED_MAPPING_STATUS in QUARANTINED_STATUSES
    assert QUARANTINED_MAPPING_STATUS not in REVIEWABLE_STATUSES
    assert REVIEWABLE_STATUSES == {"candidate", "reanalysis_required"}


def test_selection_excludes_quarantined_mapping_and_counts_it(session_factory):
    with session_factory() as db:
        ids = _seed(db)
        result = select_candidates(db)

        assert set(result["selected_object_ids"]) == {
            f"risk-{ids['candidate']}", f"risk-{ids['reanalysis']}"}
        assert result["candidate_count"] == 2
        assert result["quarantined_count"] == 1
        skipped = {item["object_id"]: item["reason"]
                   for item in result["skipped_objects"]}
        assert skipped[f"risk-{ids['quarantined']}"] == "nvd_package_mapping_quarantined"
        assert skipped[f"risk-{ids['inactive']}"] == "inactive"


def test_preflight_is_no_candidates_when_only_quarantined(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="only-quarantined", distribution="ubuntu",
                                  os_version="22.04")
        db.add(asset)
        db.flush()
        _add_risk(db, asset.id, cve_id="CVE-2099-9601",
                  status=QUARANTINED_MAPPING_STATUS)
        db.commit()

        result = preflight_check(db, "test-pipeline")
        assert result["status"] == "no_candidates"
        assert result["candidate_count"] == 0
        assert result["quarantined_count"] == 1
        assert result["selected_object_count"] == 0


def _seed_only_quarantined(db) -> int:
    asset = models.LinuxAsset(hostname="only-quarantined-run", distribution="ubuntu",
                              os_version="22.04")
    db.add(asset)
    db.flush()
    risk = _add_risk(db, asset.id, cve_id="CVE-2099-9601",
                     status=QUARANTINED_MAPPING_STATUS)
    db.commit()
    return risk.id


def test_create_run_does_not_select_quarantined(session_factory, monkeypatch):
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        risk_id = _seed_only_quarantined(db)
        result = analysis.create_run(db=db)

        assert result["status"] == "no_candidates"
        assert result["selected_object_count"] == 0
        assert result["selected_object_ids"] == []
        assert db.get(models.RiskAssessment, risk_id).review_status == \
            QUARANTINED_MAPPING_STATUS
        assert db.query(models.AnalysisReport).count() == 0
        assert db.query(models.UnifiedAnalysisRun).count() == 0


def test_analysis_create_run_cannot_force_quarantined_by_risk_id(
        session_factory, monkeypatch):
    monkeypatch.setattr(config, "UNIFIED_PIPELINE_MODE", "on")
    with session_factory() as db:
        risk_id = _seed_only_quarantined(db)

        result = analysis.create_run(db=db, risk_id=risk_id)
        assert result["status"] == "no_candidates"
        assert result["selected_object_count"] == 0
        assert db.get(models.RiskAssessment, risk_id).review_status == \
            QUARANTINED_MAPPING_STATUS


def test_risk_ranking_keeps_quarantined_visible_with_reason(
        client, session_factory):
    with session_factory() as db:
        ids = _seed(db)
    response = client.get("/api/risk/ranking")
    assert response.status_code == 200
    rows = {row["risk_id"]: row for row in response.json()}
    row = rows[ids["quarantined"]]
    assert row["review_status"] == QUARANTINED_MAPPING_STATUS
    # legacy_status 不得把它伪装成候选或研判中。
    assert row["legacy_review_status"] == QUARANTINED_MAPPING_STATUS
    assert "未映射" in row["review_status_reason"] or "隔离" in row["review_status_reason"]
    # 其他正常候选的 legacy 映射保持原样。
    assert rows[ids["candidate"]]["legacy_review_status"] == "candidate"
    assert rows[ids["candidate"]]["review_status_reason"] == ""


def test_risk_recalculation_preserves_mapping_quarantine(session_factory):
    """事实指纹变化触发重算时，隔离状态不得被重置回 reanalysis_required。"""
    from app.services.risk_engine import calculate_risk

    with session_factory() as db:
        asset = models.LinuxAsset(hostname="recalc-quarantined", distribution="ubuntu",
                                  os_version="22.04", exposure_level="internal",
                                  business_level="normal")
        db.add(asset)
        db.flush()
        risk = _add_risk(db, asset.id, cve_id="CVE-2099-9604",
                         status=QUARANTINED_MAPPING_STATUS)
        risk.candidate_fingerprint = "stale-fingerprint"
        risk.reanalysis_count = 2
        db.commit()
        risk_id = risk.id

        calculate_risk(db)

        db.expire_all()
        risk = db.get(models.RiskAssessment, risk_id)
        assert risk.review_status == QUARANTINED_MAPPING_STATUS
        assert risk.reanalysis_count == 2
        assert db.query(models.RiskGovernanceEvent).filter_by(
            risk_id=risk_id, kind="quarantine_preserved_on_fact_change").count() == 1


def test_execution_is_not_allowed_for_quarantined(session_factory):
    from app.services.review_common.governance import execution_allowed

    with session_factory() as db:
        asset = models.LinuxAsset(hostname="exec-quarantined", distribution="ubuntu",
                                  os_version="22.04")
        db.add(asset)
        db.flush()
        risk = _add_risk(db, asset.id, cve_id="CVE-2099-9605",
                         status=QUARANTINED_MAPPING_STATUS)
        db.commit()
        assert execution_allowed(db, risk) is False


def test_human_review_rejects_quarantined(session_factory):
    from app.services.review_common.human_review import apply_human_review

    with session_factory() as db:
        asset = models.LinuxAsset(hostname="human-gate", distribution="ubuntu",
                                  os_version="22.04")
        db.add(asset)
        db.flush()
        risk = _add_risk(db, asset.id, cve_id="CVE-2099-9603",
                         status=QUARANTINED_MAPPING_STATUS)
        db.commit()

        with pytest.raises(ValueError, match="risk_not_awaiting_review"):
            apply_human_review(db, risk.id, "begin", "review", "operator",
                               QUARANTINED_MAPPING_STATUS)
        db.expire_all()
        assert db.get(models.RiskAssessment, risk.id).review_status == \
            QUARANTINED_MAPPING_STATUS
