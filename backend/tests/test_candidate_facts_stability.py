"""新清单触发重评的判据：事实变化 vs 采集时间/原始文本变化（2026-10-24）。

回归对象：资产 #4 两次清单（INV-a16623… → INV-ff201e2f…）实际对比——
182 个包完全一致、OS/内核/板卡/端口（忽略 PID）/DHCP 一致，差异仅为
采集时间、进程 PID（设备重启）与 boot_id；但 risk-130/131/132 全部因
候选指纹失配被重置为 reanalysis_required。根因：旧指纹把 asset.updated_at
（每次清单写入必变）与 runtime 事件 ID/权重（持续遥测下必然轮换）混入
事实载荷，采集周期性变化被当成了事实变化。

新判据：
- 事实载荷只含组件版本/配置/情报/覆盖事实（runtime 覆盖等级保留）；
- 采集时间戳与运行时事件增长不再触发重置；
- 旧算法行按行上事实字段做一次性迁移比对，仍一致则保留结论并留痕；
- 事实未变但存在当期结论时记录 candidate_facts_unchanged（来源追溯）。
"""
import json

import pytest

from app import models
from app.services.risk_engine import _candidate_facts, _facts_hash, calculate_risk


def _seed(db, installed="3.0.2-0ubuntu1.10"):
    vuln = models.VulnerabilityInfo(cve_id="CVE-2099-0701", title="Facts", description="facts",
        affected_package="openssl", fixed_version="3.0.0-0ubuntu1.1", cvss_score=8.0)
    asset = models.LinuxAsset(hostname="facts-target", distribution="ubuntu", os_version="24.04",
        inventory_complete=True, inventory_sha256="aa" * 32)
    db.add_all([vuln, asset]); db.flush()
    db.add(models.AssetPackage(asset_id=asset.id, package_name="openssl", package_version=installed))
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=vuln.cve_id,
        package_name="openssl", installed_version=installed,
        fixed_version=vuln.fixed_version, affected=True, active=True,
        match_status="potentially_affected")
    db.add(match); db.commit()
    return asset, match


def _events(db, risk_id):
    return db.query(models.RiskGovernanceEvent).filter_by(risk_id=risk_id).order_by(
        models.RiskGovernanceEvent.id).all()


def _concluded(risk, verdict="confirmed_affected"):
    risk.review_status = "pending_human_review"
    risk.review_verdict = verdict
    risk.review_confidence = 0.7
    db_id = risk.id
    return db_id


def test_recollect_without_fact_change_preserves_conclusion(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        assert calculate_risk(db) == 1
        risk = db.query(models.RiskAssessment).one()
        _concluded(risk)
        db.commit()
        first_hash, first_facts = risk.candidate_fingerprint, risk.candidate_facts_json

        # 模拟一次「事实完全一致」的重新采集：清单哈希变化、资产行更新时间
        # 前进、清单采集时间前进——组件版本/配置/情报/覆盖均不变。
        asset.inventory_sha256 = "bb" * 32
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        asset.updated_at = (asset.updated_at or now) + timedelta(hours=1)
        asset.inventory_collected_at = now
        db.commit()

        assert calculate_risk(db) == 1
        db.refresh(risk)
        assert risk.review_status == "pending_human_review"
        assert risk.review_verdict == "confirmed_affected"
        assert risk.candidate_fingerprint == first_hash
        assert risk.candidate_facts_json == first_facts

        kinds = [e.kind for e in _events(db, risk.id)]
        assert "risk_reanalysis_reset" not in kinds
        assert "candidate_facts_unchanged" in kinds
        payload = json.loads(_events(db, risk.id)[-1].payload_json)
        assert payload["inventory_sha256"] == "bb" * 32
        assert payload["facts"]["installed_version"] == "3.0.2-0ubuntu1.10"


def test_component_version_change_resets_conclusion(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        assert calculate_risk(db) == 1
        risk = db.query(models.RiskAssessment).one()
        _concluded(risk)
        db.commit()

        match.installed_version = "3.0.2-0ubuntu1.9"
        db.get(models.AssetPackage, db.query(models.AssetPackage).first().id).package_version = \
            "3.0.2-0ubuntu1.9"
        db.commit()

        assert calculate_risk(db) == 1
        db.refresh(risk)
        assert risk.review_status == "reanalysis_required"
        assert risk.review_verdict == ""
        assert risk.reanalysis_count == 1
        reset = [e for e in _events(db, risk.id) if e.kind == "risk_reanalysis_reset"]
        assert reset and json.loads(reset[-1].payload_json)["facts"]["installed_version"] == \
            "3.0.2-0ubuntu1.9"


def test_runtime_event_growth_and_strength_do_not_enter_facts(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        quiet = {"status": "contextual", "strength_score": 2.0,
                 "matched_events": [{"id": 101}, {"id": 102}]}
        grown = {"status": "contextual", "strength_score": 41.7,
                 "matched_events": [{"id": 901}, {"id": 902}, {"id": 903}]}
        first = _facts_hash(_candidate_facts(match, asset, quiet, "src-1"))
        second = _facts_hash(_candidate_facts(match, asset, grown, "src-1"))
        assert first == second

        # 覆盖等级跃迁（无证据 → 上下文证据）仍是事实变化。
        none = _facts_hash(_candidate_facts(match, asset, {"status": "not_observed"}, "src-1"))
        assert none != first


def test_legacy_row_migration_preserves_identical_conclusion(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        assert calculate_risk(db) == 1
        risk = db.query(models.RiskAssessment).one()
        _concluded(risk)
        # 模拟旧算法行：只有哈希、没有事实载荷。
        risk.candidate_facts_json = ""
        db.commit()

        assert calculate_risk(db) == 1
        db.refresh(risk)
        assert risk.review_status == "pending_human_review"
        assert risk.candidate_facts_json  # 基线已按事实载荷重建
        kinds = [e.kind for e in _events(db, risk.id)]
        assert "risk_reanalysis_reset" not in kinds
        assert "candidate_facts_rebaseline" in kinds

        # 二次计算进入精确比较，不再产生迁移事件。
        assert calculate_risk(db) == 1
        kinds = [e.kind for e in _events(db, risk.id)]
        assert kinds.count("candidate_facts_rebaseline") == 1


def test_legacy_row_row_fact_drift_resets(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        assert calculate_risk(db) == 1
        risk = db.query(models.RiskAssessment).one()
        _concluded(risk)
        risk.candidate_facts_json = ""
        risk.runtime_status = "contextual"  # 行上覆盖等级与本次计算（waiting）漂移
        db.commit()

        assert calculate_risk(db) == 1
        db.refresh(risk)
        assert risk.review_status == "reanalysis_required"


def test_fresh_candidate_rows_record_no_unchanged_event(session_factory):
    with session_factory() as db:
        asset, match = _seed(db)
        assert calculate_risk(db) == 1
        risk = db.query(models.RiskAssessment).one()
        assert risk.review_status == "candidate"
        assert calculate_risk(db) == 1
        kinds = [e.kind for e in _events(db, risk.id)]
        assert "candidate_facts_unchanged" not in kinds
        assert "candidate_facts_rebaseline" not in kinds
        assert "risk_reanalysis_reset" not in kinds
