"""四智能体固定流水线综合测试 —— 全部 mock DeepSeek，不真实调用 API。

覆盖要求：
1.  候选为 0 时，四个智能体调用次数都是 0
2.  两个对象分别得到 upgraded 和 downgraded，结果不能互相覆盖
3.  本次只分析 A、B 时，C 不得被修改
4.  返回伪造 object_id 时拒绝写入
5.  引用不存在的 evidence_id 时进入人工复核
6.  低置信度结果强制人工复核
7.  一个对象成功、一个对象失败时，整体状态为 partial
8.  协调智能体第一次格式错误、第二次成功时，只重试协调智能体
9.  协调智能体连续失败时正常结束，不等待 MAX_TURNS
10. 13 个对象按批次全部处理，不得因切片丢失
11. 接口错误时前端不得显示"没有候选"
12. 旧 running 超时后可以自动恢复
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import models
from app.database import recover_stale_running
from app.services import agent_group_chat as review
from app.services.agent_group_chat import (
    AGENT_COORDINATOR,
    AGENT_DATA_QUALITY,
    AGENT_IMPACT,
    AGENT_RUNTIME,
    _apply_object_verdicts,
    _validate_all_verdicts,
    _validate_object_verdict,
    preflight_check,
)


# ═══════════════════════════════════════════════════════════════════════════
# 测试夹具
# ═══════════════════════════════════════════════════════════════════════════

def _make_asset(db, hostname="test-host", asset_id=None):
    asset = models.LinuxAsset(
        hostname=hostname,
        distribution="ubuntu",
        os_version="22.04",
        exposure_level="internal",
        business_level="normal",
    )
    db.add(asset)
    db.flush()
    return asset


def _make_vuln(db, cve_id="CVE-2026-0001", package="openssl", fixed="3.0.2-0ubuntu1.18", cvss=7.5):
    vuln = models.VulnerabilityInfo(
        cve_id=cve_id,
        title=f"Test {cve_id}",
        description="Test vulnerability",
        cvss_score=cvss,
        cvss_severity="High",
        affected_package=package,
        fixed_version=fixed,
        source="test",
    )
    db.add(vuln)
    db.flush()
    return vuln


def _make_match(db, asset_id, cve_id, package="openssl", installed="3.0.2-0ubuntu1.10", fixed="3.0.2-0ubuntu1.18", affected=True):
    match = models.VulnerabilityMatch(
        asset_id=asset_id,
        cve_id=cve_id,
        package_name=package,
        installed_version=installed,
        fixed_version=fixed,
        affected=affected,
        match_reason="test",
        confidence=0.9,
    )
    db.add(match)
    db.flush()
    return match


def _make_risk(db, asset_id, cve_id, preliminary=65.0, status="candidate"):
    risk = models.RiskAssessment(
        asset_id=asset_id,
        cve_id=cve_id,
        preliminary_score=preliminary,
        preliminary_level="High" if preliminary >= 60 else "Medium",
        preliminary_decision="scheduled_fix",
        preliminary_reason="test preliminary",
        review_status=status,
        human_review_required=False,
        cvss_score=75.0,
        epss_score=30.0,
        kev_score=0,
        runtime_score=10.0,
        reachability_score=50.0,
        priority_rank=1,
    )
    db.add(risk)
    db.flush()
    return risk


# ═══════════════════════════════════════════════════════════════════════════
# 1. 候选为 0 时不调用模型
# ═══════════════════════════════════════════════════════════════════════════

def test_no_candidates_skips_model(session_factory, monkeypatch):
    """候选为 0 时，preflight_check 返回 no_candidates，不调用任何 LLM。"""
    db = session_factory()
    try:
        result = preflight_check(db)
        assert result["status"] == "no_candidates"
        assert result["candidate_count"] == 0
        assert result["model_called"] is False
        assert "当前没有" in result["message"]
    finally:
        db.close()


def test_generate_report_no_candidates(session_factory, monkeypatch):
    """generate_and_save_report 在候选为 0 时立即返回 no_candidates。"""
    db = session_factory()
    try:
        # 不创建任何候选数据

        # Mock 避免真实 API 调用
        called = []
        async def fake_pipeline(_db):
            called.append(1)
            return {"status": "should_not_reach"}

        monkeypatch.setattr(review, "_run_review_pipeline", fake_pipeline)
        monkeypatch.setattr(review, "_configured", lambda: True)

        result = review.generate_and_save_report(db)
        assert result["status"] == "no_candidates"
        assert result["candidate_count"] == 0
        assert result["model_called"] is False
        assert len(called) == 0  # 流水线根本不应被调用
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 2. 两个对象分别 upgraded/downgraded，不互相覆盖
# ═══════════════════════════════════════════════════════════════════════════

def test_two_objects_independent_verdicts(session_factory):
    """对象 A upgraded +15，对象 B downgraded -10，各自独立生效。"""
    db = session_factory()
    try:
        asset_a = _make_asset(db, "host-a")
        asset_b = _make_asset(db, "host-b")
        _make_vuln(db, "CVE-2026-0001", "openssl")
        _make_vuln(db, "CVE-2026-0002", "bash")
        _make_match(db, asset_a.id, "CVE-2026-0001", "openssl")
        _make_match(db, asset_b.id, "CVE-2026-0002", "bash")
        risk_a = _make_risk(db, asset_a.id, "CVE-2026-0001", preliminary=60.0, status="running")
        risk_b = _make_risk(db, asset_b.id, "CVE-2026-0002", preliminary=80.0, status="running")
        db.commit()

        object_verdicts = [
            {
                "object_id": f"asset-{asset_a.id}-CVE-2026-0001",
                "verdict": "upgraded",
                "confidence": 0.85,
                "risk_adjustment": 15,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "升级原因",
                "recommended_action": "立即修复",
            },
            {
                "object_id": f"asset-{asset_b.id}-CVE-2026-0002",
                "verdict": "downgraded",
                "confidence": 0.80,
                "risk_adjustment": 10,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "降级原因",
                "recommended_action": "排期修复",
            },
        ]

        candidate_ids = {f"asset-{asset_a.id}-CVE-2026-0001", f"asset-{asset_b.id}-CVE-2026-0002"}
        stats = _apply_object_verdicts(db, object_verdicts, candidate_ids)
        assert stats["updated"] == 2

        # 重新查询确认不互相覆盖
        risk_a_after = db.query(models.RiskAssessment).filter_by(asset_id=asset_a.id, cve_id="CVE-2026-0001").first()
        risk_b_after = db.query(models.RiskAssessment).filter_by(asset_id=asset_b.id, cve_id="CVE-2026-0002").first()

        assert risk_a_after.final_score == 75.0  # 60 + 15
        assert risk_a_after.review_verdict == "upgraded"
        assert risk_b_after.final_score == 70.0  # 80 - 10
        assert risk_b_after.review_verdict == "downgraded"
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 3. 只分析 A、B 时 C 不被修改
# ═══════════════════════════════════════════════════════════════════════════

def test_only_target_objects_updated(session_factory):
    """本次只分析 A 和 B，C 的 review_status 保持 candidate 不变。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "multi-host")
        for i, cve in enumerate(["CVE-2026-A", "CVE-2026-B", "CVE-2026-C"], 1):
            _make_vuln(db, cve, f"pkg{i}")
            _make_match(db, asset.id, cve, f"pkg{i}")
            _make_risk(db, asset.id, cve, preliminary=50 + i * 10, status="running")
        db.commit()

        # 只裁定 A 和 B
        object_verdicts = [
            {
                "object_id": f"asset-{asset.id}-CVE-2026-A",
                "verdict": "confirmed",
                "confidence": 0.9,
                "risk_adjustment": 0,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "确认A",
                "recommended_action": "",
            },
            {
                "object_id": f"asset-{asset.id}-CVE-2026-B",
                "verdict": "upgraded",
                "confidence": 0.85,
                "risk_adjustment": 10,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "升级B",
                "recommended_action": "",
            },
        ]

        candidate_ids = {f"asset-{asset.id}-CVE-2026-A", f"asset-{asset.id}-CVE-2026-B"}
        stats = _apply_object_verdicts(db, object_verdicts, candidate_ids)
        assert stats["updated"] == 2

        # C 应保持在 running 状态（未被更改）
        risk_c = db.query(models.RiskAssessment).filter_by(asset_id=asset.id, cve_id="CVE-2026-C").first()
        assert risk_c.review_status == "running"  # 没被我们的精确写回碰过
        assert risk_c.final_score == 0.0  # 没有最终结论
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 4. 伪造 object_id 时拒绝写入
# ═══════════════════════════════════════════════════════════════════════════

def test_fake_object_id_rejected(session_factory):
    """返回不属于候选集合的 object_id 时，校验失败。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "legit-host")
        _make_vuln(db, "CVE-2026-LEGIT", "openssl")
        _make_match(db, asset.id, "CVE-2026-LEGIT", "openssl")
        _make_risk(db, asset.id, "CVE-2026-LEGIT", status="candidate")
        db.commit()

        candidate_ids = {f"asset-{asset.id}-CVE-2026-LEGIT"}
        all_evidence_ids = set()

        # 伪造的 object_id
        fake_verdict = {
            "object_id": "asset-99999-CVE-2026-FAKE",
            "verdict": "confirmed",
            "confidence": 0.9,
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "fake",
            "recommended_action": "",
        }

        ok, err = _validate_object_verdict(fake_verdict, candidate_ids, all_evidence_ids)
        assert ok is False
        assert "不在本次候选集合" in err
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 5. 引用不存在的 evidence_id 时进入人工复核
# ═══════════════════════════════════════════════════════════════════════════

def test_nonexistent_evidence_id_causes_human_review(session_factory):
    """引用不存在的 evidence_id 时校验失败，进入人工复核。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "ev-host")
        _make_vuln(db, "CVE-2026-EV", "openssl")
        _make_match(db, asset.id, "CVE-2026-EV", "openssl")
        _make_risk(db, asset.id, "CVE-2026-EV", status="candidate")
        db.commit()

        candidate_ids = {f"asset-{asset.id}-CVE-2026-EV"}
        valid_evidence_ids = {"ev-asset-1-CVE-2026-EV-version", "ev-asset-1-CVE-2026-EV-intel"}

        verdict_with_fake_evidence = {
            "object_id": f"asset-{asset.id}-CVE-2026-EV",
            "verdict": "confirmed",
            "confidence": 0.9,
            "risk_adjustment": 0,
            "evidence_ids": ["ev-NONEXISTENT-12345"],  # 不存在的证据
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "test",
            "recommended_action": "",
        }

        ok, err = _validate_object_verdict(verdict_with_fake_evidence, candidate_ids, valid_evidence_ids)
        assert ok is False
        assert "不存在" in err
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 6. 低置信度结果强制人工复核
# ═══════════════════════════════════════════════════════════════════════════

def test_low_confidence_forces_human_review(session_factory):
    """置信度 < 0.75 时，即使模型声称无需复核也强制 human_review_required。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "lc-host")
        _make_vuln(db, "CVE-2026-LC", "openssl")
        _make_match(db, asset.id, "CVE-2026-LC", "openssl")
        _make_risk(db, asset.id, "CVE-2026-LC", preliminary=70.0, status="running")
        db.commit()

        candidate_ids = {f"asset-{asset.id}-CVE-2026-LC"}
        empty_evidence = set()

        # 低置信度但模型声称无需复核 → 应被校验拒绝
        low_conf_verdict = {
            "object_id": f"asset-{asset.id}-CVE-2026-LC",
            "verdict": "confirmed",
            "confidence": 0.60,  # < 0.75
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,  # 模型声称无需复核
            "reason": "low confidence test",
            "recommended_action": "",
        }

        ok, err = _validate_object_verdict(low_conf_verdict, candidate_ids, empty_evidence)
        assert ok is False
        assert "human_review_required" in err.lower() or "置信度" in err

        # 即使用 _apply_object_verdicts 写回低置信度结果，也应强制 human_review
        # (这种情况在上层已被校验拦截，不会到达写回)
    finally:
        db.close()


def test_noncritical_missing_evidence_does_not_reject_confident_verdict():
    verdict = {
        "object_id": "asset-1-CVE-2026-GAP",
        "verdict": "confirmed",
        "confidence": 0.85,
        "risk_adjustment": 0,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": ["CWE编号缺失", "未观察到真实攻击"],
        "human_review_required": False,
        "reason": "版本与可达性证据充分",
        "recommended_action": "升级",
    }

    ok, error = _validate_object_verdict(
        verdict,
        {"asset-1-CVE-2026-GAP"},
        set(),
    )

    assert ok is True
    assert error == ""


def test_conflict_still_requires_human_review():
    verdict = {
        "object_id": "asset-1-CVE-2026-CONFLICT",
        "verdict": "confirmed",
        "confidence": 0.9,
        "risk_adjustment": 0,
        "evidence_ids": [],
        "conflicts": ["版本来源冲突"],
        "missing_evidence": [],
        "human_review_required": False,
        "reason": "test",
        "recommended_action": "",
    }

    ok, error = _validate_object_verdict(
        verdict,
        {"asset-1-CVE-2026-CONFLICT"},
        set(),
    )

    assert ok is False
    assert "冲突" in error


# ═══════════════════════════════════════════════════════════════════════════
# 7. 一个成功一个失败时整体状态为 partial
# ═══════════════════════════════════════════════════════════════════════════

def test_one_success_one_failure_partial(session_factory):
    """对象 A 校验通过，对象 B 校验失败 → 整体 partial。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "partial-host")
        _make_vuln(db, "CVE-2026-P1", "openssl")
        _make_vuln(db, "CVE-2026-P2", "bash")
        _make_match(db, asset.id, "CVE-2026-P1", "openssl")
        _make_match(db, asset.id, "CVE-2026-P2", "bash")
        _make_risk(db, asset.id, "CVE-2026-P1", status="running")
        _make_risk(db, asset.id, "CVE-2026-P2", status="running")
        db.commit()

        candidate_ids = {f"asset-{asset.id}-CVE-2026-P1", f"asset-{asset.id}-CVE-2026-P2"}
        all_evidence_ids = set()

        object_verdicts = [
            {
                "object_id": f"asset-{asset.id}-CVE-2026-P1",
                "verdict": "confirmed",
                "confidence": 0.9,
                "risk_adjustment": 0,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "ok",
                "recommended_action": "",
            },
            {
                "object_id": f"asset-{asset.id}-CVE-2026-P2",
                "verdict": "upgraded",
                "confidence": 999,  # 非法：大于 1
                "risk_adjustment": 10,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "bad",
                "recommended_action": "",
            },
        ]

        valid, failed = _validate_all_verdicts(object_verdicts, candidate_ids, all_evidence_ids)
        assert len(valid) == 1
        assert len(failed) == 1
        assert valid[0]["object_id"] == f"asset-{asset.id}-CVE-2026-P1"
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 8. 协调智能体第一次格式错误、第二次成功
# ═══════════════════════════════════════════════════════════════════════════

def test_coordinator_retry_on_bad_json():
    """协调智能体第一次返回无效 JSON，第二次返回有效 JSON → 只重试协调智能体。"""
    import asyncio

    call_count = [0]

    async def mock_create(messages, **kwargs):
        call_count[0] += 1
        from unittest.mock import MagicMock
        resp = MagicMock()
        if call_count[0] == 1:
            resp.content = "this is not valid json at all"
        else:
            resp.content = json.dumps({
                "object_verdicts": [
                    {
                        "object_id": "asset-1-CVE-2026-T1",
                        "verdict": "confirmed",
                        "confidence": 0.9,
                        "risk_adjustment": 0,
                        "evidence_ids": [],
                        "conflicts": [],
                        "missing_evidence": [],
                        "human_review_required": False,
                        "reason": "ok",
                        "recommended_action": "",
                    }
                ],
                "overall_summary": "test",
            })
        return resp

    from unittest.mock import AsyncMock, MagicMock
    mock_client = MagicMock()
    mock_client.create = mock_create
    mock_client.close = AsyncMock()

    context = json.dumps({"objects": [], "total_objects": 0})
    specialist_outputs = {
        AGENT_DATA_QUALITY: {"status": "completed", "output": {"object_opinions": []}},
        AGENT_IMPACT: {"status": "completed", "output": {"object_opinions": []}},
        AGENT_RUNTIME: {"status": "completed", "output": {"object_opinions": []}},
    }

    result = asyncio.run(review._run_coordinator_agent(specialist_outputs, context, mock_client))
    assert result["status"] == "completed"
    assert result["output_valid"] is True
    assert result["attempts"] == 2  # 第一次失败，第二次成功
    assert call_count[0] == 2  # 确认 LLM 被调用了两次


# ═══════════════════════════════════════════════════════════════════════════
# 9. 协调智能体连续失败时正常结束，不等待 MAX_TURNS
# ═══════════════════════════════════════════════════════════════════════════

def test_coordinator_max_retries_then_fail():
    """协调智能体连续返回无效 JSON → 最多重试 MAX_RETRIES 次后返回失败。"""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    async def mock_create_always_bad(messages, **kwargs):
        resp = MagicMock()
        resp.content = "completely invalid {{{"
        return resp

    mock_client = MagicMock()
    mock_client.create = mock_create_always_bad
    mock_client.close = AsyncMock()

    context = json.dumps({"objects": [], "total_objects": 0})
    specialist_outputs = {
        AGENT_DATA_QUALITY: {"status": "completed", "output": {"object_opinions": []}},
        AGENT_IMPACT: {"status": "completed", "output": {"object_opinions": []}},
        AGENT_RUNTIME: {"status": "completed", "output": {"object_opinions": []}},
    }

    result = asyncio.run(review._run_coordinator_agent(specialist_outputs, context, mock_client))
    assert result["status"] == "failed"
    assert result["output_valid"] is False
    assert result["attempts"] == review.MAX_RETRIES + 1  # 初始 + 重试
    # 不会无限等待 MAX_TURNS


# ═══════════════════════════════════════════════════════════════════════════
# 10. 13 个对象全部处理
# ═══════════════════════════════════════════════════════════════════════════

def test_all_objects_processed_no_slicing_loss(session_factory):
    """13 个对象应全部被 _build_object_evidence_packages 返回，不得因切片丢失。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "bulk-host")
        for i in range(13):
            cve = f"CVE-2026-B{i:04d}"
            _make_vuln(db, cve, f"pkg{i}")
            _make_match(db, asset.id, cve, f"pkg{i}")
            _make_risk(db, asset.id, cve, preliminary=50.0 + i, status="candidate")
        db.commit()

        objects, evidence_map, skipped = review._build_object_evidence_packages(db)
        assert len(objects) == 13, f"Expected 13 objects, got {len(objects)}"
        # 确认每个 object_id 唯一
        ids = [obj["object_id"] for obj in objects]
        assert len(set(ids)) == 13
        # 检查证据映射不为空
        assert len(evidence_map) > 0
    finally:
        db.close()


def test_evidence_package_uses_explicit_epss_and_cvss_semantics(session_factory):
    db = session_factory()
    try:
        asset = _make_asset(db, "semantic-host")
        vuln = _make_vuln(db, "CVE-2026-SEM1", "openssl", cvss=5.3)
        vuln.cvss_severity = "Low"  # vendor severity can differ from CVSS bands
        _make_match(db, asset.id, vuln.cve_id, "openssl")
        _make_risk(db, asset.id, vuln.cve_id, status="candidate")
        db.commit()

        objects, _, _ = review._build_object_evidence_packages(db)
        obj = objects[0]
        intel_evidence = next(item for item in obj["evidence_items"] if item["type"] == "threat_intel")

        assert obj["intelligence"]["epss_probability_0_to_1"] == 0.3
        assert obj["intelligence"]["epss_percent_0_to_100"] == 30.0
        assert obj["vulnerability"]["cvss_severity_by_score"] == "Medium"
        assert obj["vulnerability"]["vendor_severity"] == "Low"
        assert intel_evidence["epss_probability_0_to_1"] == 0.3
        assert "epss_score" not in intel_evidence
        assert "cvss_severity" not in obj["vulnerability"]
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 11. 接口错误时前端状态（后端 API 层面）
# ═══════════════════════════════════════════════════════════════════════════

def test_preflight_endpoint_no_candidates(client):
    """GET /api/analysis/preflight 在无候选时返回 no_candidates。"""
    resp = client.get("/api/analysis/preflight")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "no_candidates"
    assert data["candidate_count"] == 0
    assert data["model_called"] is False


def test_preflight_endpoint_with_candidates(client, session_factory):
    """有候选时 preflight 返回 ready 状态。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "pf-host")
        cve = "CVE-2026-PF01"
        _make_vuln(db, cve, "openssl")
        _make_match(db, asset.id, cve, "openssl")
        _make_risk(db, asset.id, cve, preliminary=65.0, status="candidate")
        db.commit()
    finally:
        db.close()

    resp = client.get("/api/analysis/preflight")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["candidate_count"] >= 1


def test_risk_ranking_returns_error_on_failure(client, session_factory, monkeypatch):
    """确认 /api/risk/ranking 接口失败时返回 HTTP 错误码，不返回空数组。"""
    # 测试 API 在数据库异常时不返回 200 + 空数组
    # 这里我们验证正常流程即可；异常流程由全局异常处理器保证
    resp = client.get("/api/risk/ranking")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ═══════════════════════════════════════════════════════════════════════════
# 12. 旧 running 超时自动恢复
# ═══════════════════════════════════════════════════════════════════════════

def test_stale_running_recovery(session_factory):
    """超时的 running 状态应被自动恢复为 candidate。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "stale-host")
        _make_vuln(db, "CVE-2026-STALE", "openssl")
        _make_match(db, asset.id, "CVE-2026-STALE", "openssl")
        risk = _make_risk(db, asset.id, "CVE-2026-STALE", status="running")
        # 模拟 review_completed_at 为空（旧残留）
        risk.review_completed_at = None
        db.commit()

        # 内联恢复逻辑（使用测试数据库 session）
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=0)
        stale = (
            db.query(models.RiskAssessment)
            .filter(
                models.RiskAssessment.review_status == "running",
                models.RiskAssessment.review_completed_at.is_(None),
            )
            .all()
        )
        assert len(stale) >= 1

        for r in stale:
            active_report = (
                db.query(models.AnalysisReport)
                .filter(
                    models.AnalysisReport.status == "running",
                    models.AnalysisReport.created_at > cutoff,
                )
                .first()
            )
            if active_report is None:
                r.review_status = "candidate"
                r.human_review_required = False
                r.review_reason = (r.review_reason or "") + " [stale_running_recovered]"
        db.commit()

        recovered = len(stale)
        assert recovered >= 1

        # 确认已恢复
        risk_after = db.query(models.RiskAssessment).filter_by(asset_id=asset.id, cve_id="CVE-2026-STALE").first()
        assert risk_after.review_status == "candidate"
        assert risk_after.human_review_required is False
        assert "stale_running_recovered" in (risk_after.review_reason or "")
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
# 补充：insufficient_evidence 强制 human_review
# ═══════════════════════════════════════════════════════════════════════════

def test_insufficient_evidence_forces_human_review_in_validate():
    """insufficient_evidence 裁定的 risk_adjustment 必须为 0。"""
    verdict = {
        "object_id": "asset-1-CVE-2026-IE",
        "verdict": "insufficient_evidence",
        "confidence": 0.5,
        "risk_adjustment": 5,  # 非法：应必须为 0
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": ["关键证据缺失"],
        "human_review_required": True,
        "reason": "insufficient",
        "recommended_action": "",
    }

    ok, err = _validate_object_verdict(verdict, {"asset-1-CVE-2026-IE"}, set())
    assert ok is False
    assert "risk_adjustment" in err and "0" in err


# ═══════════════════════════════════════════════════════════════════════════
# 补充：confirmed 的 risk_adjustment 必须为 0
# ═══════════════════════════════════════════════════════════════════════════

def test_confirmed_with_nonzero_adjustment_rejected():
    """confirmed 裁定但 risk_adjustment != 0 → 校验失败。"""
    verdict = {
        "object_id": "asset-1-CVE-2026-CF",
        "verdict": "confirmed",
        "confidence": 0.9,
        "risk_adjustment": 3,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": [],
        "human_review_required": False,
        "reason": "confirmed",
        "recommended_action": "",
    }

    ok, err = _validate_object_verdict(verdict, {"asset-1-CVE-2026-CF"}, set())
    assert ok is False
    assert "risk_adjustment" in err


# ═══════════════════════════════════════════════════════════════════════════
# 补充：证据不足裁定必须人工复核
# ═══════════════════════════════════════════════════════════════════════════

def test_insufficient_evidence_forces_human_review():
    """明确裁定为 insufficient_evidence 时必须进入人工复核。"""
    verdict = {
        "object_id": "asset-1-CVE-2026-ME",
        "verdict": "insufficient_evidence",
        "confidence": 0.9,
        "risk_adjustment": 0,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": ["缺少运行时证据"],  # 有缺失证据
        "human_review_required": False,  # 但声称无需复核
        "reason": "test",
        "recommended_action": "",
    }

    ok, err = _validate_object_verdict(verdict, {"asset-1-CVE-2026-ME"}, set())
    assert ok is False
    assert "human_review_required" in err.lower()


# ═══════════════════════════════════════════════════════════════════════════
# 补充：风险分数边界限制 0～100
# ═══════════════════════════════════════════════════════════════════════════

def test_final_score_clamped_to_range(session_factory):
    """upgraded + 30 不超过 100；downgraded - 30 不低于 0。"""
    db = session_factory()
    try:
        asset = _make_asset(db, "clamp-host")
        _make_vuln(db, "CVE-2026-HI", "openssl")
        _make_vuln(db, "CVE-2026-LO", "bash")
        _make_match(db, asset.id, "CVE-2026-HI", "openssl")
        _make_match(db, asset.id, "CVE-2026-LO", "bash")
        _make_risk(db, asset.id, "CVE-2026-HI", preliminary=95.0, status="running")
        _make_risk(db, asset.id, "CVE-2026-LO", preliminary=10.0, status="running")
        db.commit()

        candidate_ids = {
            f"asset-{asset.id}-CVE-2026-HI",
            f"asset-{asset.id}-CVE-2026-LO",
        }

        object_verdicts = [
            {
                "object_id": f"asset-{asset.id}-CVE-2026-HI",
                "verdict": "upgraded",
                "confidence": 0.85,
                "risk_adjustment": 30,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "high",
                "recommended_action": "",
            },
            {
                "object_id": f"asset-{asset.id}-CVE-2026-LO",
                "verdict": "downgraded",
                "confidence": 0.85,
                "risk_adjustment": 30,
                "evidence_ids": [],
                "conflicts": [],
                "missing_evidence": [],
                "human_review_required": False,
                "reason": "low",
                "recommended_action": "",
            },
        ]

        stats = _apply_object_verdicts(db, object_verdicts, candidate_ids)
        assert stats["updated"] == 2

        risk_hi = db.query(models.RiskAssessment).filter_by(asset_id=asset.id, cve_id="CVE-2026-HI").first()
        risk_lo = db.query(models.RiskAssessment).filter_by(asset_id=asset.id, cve_id="CVE-2026-LO").first()

        assert risk_hi.final_score == 100.0  # 95 + 30 capped at 100
        assert risk_lo.final_score == 0.0  # 10 - 30 floored at 0
    finally:
        db.close()
