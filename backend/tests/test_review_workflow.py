"""四智能体协同复核系统测试：校验、写回、报告持久化（兼容 v2 流水线 API）。"""
import json
import threading
import time

from app import models
from app.services import agent_group_chat as review
from app.services import event_review_pipeline as pipeline
from app.services.remediation_engine import generate_remediation_tasks


def seed_risk(session_factory, hostname="review-host", preliminary=70.0, cve_id="CVE-2099-0010"):
    db = session_factory()
    try:
        asset = models.LinuxAsset(
            hostname=hostname,
            distribution="ubuntu",
            os_version="22.04",
            exposure_level="public",
            business_level="core",
        )
        db.add(asset)
        db.flush()
        db.add(
            models.VulnerabilityInfo(
                cve_id=cve_id,
                title="Sample",
                description="Sample vuln",
                cvss_score=8.0,
                cvss_severity="High",
                affected_package="openssl",
                fixed_version="3.0.2-0ubuntu1.18",
            )
        )
        db.add(
            models.VulnerabilityMatch(
                asset_id=asset.id,
                cve_id=cve_id,
                package_name="openssl",
                installed_version="3.0.2-0ubuntu1.10",
                fixed_version="3.0.2-0ubuntu1.18",
                affected=True,
            )
        )
        risk = models.RiskAssessment(
            asset_id=asset.id,
            cve_id=cve_id,
            final_score=preliminary,
            risk_level="High",
            decision="scheduled_fix",
            preliminary_score=preliminary,
            preliminary_level="High",
            preliminary_decision="scheduled_fix",
            review_status="candidate",
            human_review_required=False,
        )
        db.add(risk)
        db.commit()
    finally:
        db.close()


# ── 逐对象裁定校验 ──────────────────────────────────────────────────────

def test_validate_object_verdict_accepts_valid():
    payload = {
        "object_id": "asset-1-CVE-2099-0010",
        "verdict": "confirmed",
        "confidence": 0.85,
        "risk_adjustment": 0,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": [],
        "human_review_required": False,
        "reason": "证据充分",
        "recommended_action": "按初步结论执行",
    }
    ok, err = review._validate_object_verdict(payload, {"asset-1-CVE-2099-0010"}, set())
    assert ok is True
    assert err == ""


def test_validate_object_verdict_rejects_invalid():
    payload = {
        "object_id": "asset-1-CVE-2099-0010",
        "verdict": "maybe",
        "confidence": 0.5,
        "risk_adjustment": 0,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": [],
        "human_review_required": False,
        "reason": "x",
        "recommended_action": "",
    }
    ok, err = review._validate_object_verdict(payload, {"asset-1-CVE-2099-0010"}, set())
    assert ok is False
    assert "verdict" in err


def test_validate_object_verdict_rejects_excessive_adjustment():
    payload = {
        "object_id": "asset-1-CVE-2099-0010",
        "verdict": "upgraded",
        "confidence": 0.5,
        "risk_adjustment": 999,
        "evidence_ids": [],
        "conflicts": [],
        "missing_evidence": [],
        "human_review_required": False,
        "reason": "x",
        "recommended_action": "",
    }
    ok, err = review._validate_object_verdict(payload, {"asset-1-CVE-2099-0010"}, set())
    assert ok is False
    assert "risk_adjustment" in err


def test_insufficient_evidence_forces_human_review_in_apply(session_factory):
    """insufficient_evidence 裁定的对象在写回时强制 human_review。"""
    seed_risk(session_factory)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "insufficient_evidence",
            "confidence": 0.4,
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": ["缺少 eBPF 证据"],
            "human_review_required": True,  # 模型已正确标记
            "reason": "证据不足",
            "recommended_action": "",
        }]

        stats = review._apply_object_verdicts(db, object_verdicts, candidate_ids)
        assert stats["human_review"] == 1

        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.human_review_required is True
        assert risk_after.review_status == "human_review"
    finally:
        db.close()


# ── 逐对象写回（固定规则）────────────────────────────────────────────

def test_apply_object_verdict_confirmed(session_factory):
    seed_risk(session_factory, preliminary=70.0)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "confirmed",
            "confidence": 0.9,
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "确认",
            "recommended_action": "",
        }]

        stats = review._apply_object_verdicts(db, object_verdicts, candidate_ids)
        assert stats["updated"] == 1

        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.final_score == 70.0
        assert risk_after.review_status == "completed"
        assert risk_after.review_verdict == "confirmed"
        assert risk_after.human_review_required is False
    finally:
        db.close()


def test_apply_object_verdict_upgraded(session_factory):
    seed_risk(session_factory, preliminary=60.0)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "upgraded",
            "confidence": 0.85,
            "risk_adjustment": 20,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "升级",
            "recommended_action": "",
        }]

        review._apply_object_verdicts(db, object_verdicts, candidate_ids)
        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.final_score == 80.0
        assert risk_after.risk_level == "Critical"
    finally:
        db.close()


def test_apply_object_verdict_downgraded(session_factory):
    seed_risk(session_factory, preliminary=80.0)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "downgraded",
            "confidence": 0.8,
            "risk_adjustment": 25,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "降级",
            "recommended_action": "",
        }]

        review._apply_object_verdicts(db, object_verdicts, candidate_ids)
        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.final_score == 55.0
        assert risk_after.risk_level == "Medium"
    finally:
        db.close()


def test_human_review_status_no_final_conclusion(session_factory):
    """human_review 时不产生最终结论（final 保持 0）。"""
    seed_risk(session_factory, preliminary=70.0)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "insufficient_evidence",
            "confidence": 0.5,
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": ["无运行时证据"],
            "human_review_required": True,
            "reason": "证据不足",
            "recommended_action": "",
        }]

        review._apply_object_verdicts(db, object_verdicts, candidate_ids)
        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.human_review_required is True
        assert risk_after.review_status == "human_review"
        # 无最终结论；None 与真实低风险 0 分明确区分。
        assert risk_after.final_score is None
        assert risk_after.preliminary_score == 70.0  # 候选基线保留
    finally:
        db.close()


# ── 修复任务准入 ────────────────────────────────────────────────────────

def test_remediation_blocked_without_completed_review(session_factory):
    seed_risk(session_factory)
    db = session_factory()
    try:
        count = generate_remediation_tasks(db)
        assert count == 0
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


def test_remediation_generated_after_completed_review(session_factory):
    seed_risk(session_factory)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "running"
        db.commit()

        candidate_ids = {f"asset-{risk.asset_id}-{risk.cve_id}"}
        object_verdicts = [{
            "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
            "verdict": "confirmed",
            "confidence": 0.9,
            "risk_adjustment": 0,
            "evidence_ids": [],
            "conflicts": [],
            "missing_evidence": [],
            "human_review_required": False,
            "reason": "确认",
            "recommended_action": "",
        }]
        review._apply_object_verdicts(db, object_verdicts, candidate_ids)

        count = generate_remediation_tasks(db)
        assert count == 1
        task = db.query(models.RemediationTask).one()
        assert task.status == "pending"
        assert "sudo apt" in task.remediation_command
    finally:
        db.close()


def test_remediation_human_override_cannot_bypass_review(session_factory):
    seed_risk(session_factory)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "human_review"
        risk.human_review_required = True
        db.commit()

        count = generate_remediation_tasks(db, allow_human_override=True)
        assert count == 0
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


# ── 报告持久化 ──────────────────────────────────────────────────────────

def test_generate_report_with_mocked_review(session_factory, monkeypatch):
    seed_risk(session_factory)
    db = session_factory()
    try:
        risk = db.query(models.RiskAssessment).first()
        risk.review_status = "candidate"
        db.commit()

        def fake_review(_db, *_args, **_kwargs):
            stored = _db.get(models.RiskAssessment, risk.id)
            stored.review_status = "auto_confirmed"
            stored.review_verdict = "confirmed_affected"
            stored.review_confidence = 0.9
            stored.final_score = stored.preliminary_score
            stored.risk_level = "High"
            stored.decision = "scheduled_fix"
            _db.commit()
            return {
                "status": "completed",
                "error": "",
                "answer": "确认",
                "transcript": [],
                "verdict": {
                    "object_verdicts": [{
                        "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
                        "verdict": "confirmed",
                        "confidence": 0.9,
                        "risk_adjustment": 0,
                        "evidence_ids": [],
                        "conflicts": [],
                        "missing_evidence": [],
                        "human_review_required": False,
                        "reason": "确认",
                        "recommended_action": "",
                    }],
                },
                "object_verdicts": [{
                    "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
                    "verdict": "confirmed",
                    "confidence": 0.9,
                    "risk_adjustment": 0,
                    "evidence_ids": [],
                    "conflicts": [],
                    "missing_evidence": [],
                    "human_review_required": False,
                    "reason": "确认",
                    "recommended_action": "",
                }],
                "valid_verdicts": [{
                    "object_id": f"asset-{risk.asset_id}-{risk.cve_id}",
                    "verdict": "confirmed",
                    "confidence": 0.9,
                    "risk_adjustment": 0,
                    "evidence_ids": [],
                    "conflicts": [],
                    "missing_evidence": [],
                    "human_review_required": False,
                    "reason": "确认",
                    "recommended_action": "",
                }],
                "failed_verdicts": [],
                "candidate_count": 1,
                "selected_object_count": 1,
                "completed_object_count": 1,
                "human_review_object_count": 0,
                "agent_executions": {},
                "review_run_id": "test123",
                "termination_reason": "pipeline_completed",
                "stats": {"total_objects": 1, "valid_count": 1, "updated_count": 1},
                "skipped_reasons": [],
            }

        monkeypatch.setattr("app.services.event_review_pipeline.run_review_analysis", fake_review)

        result = review.generate_and_save_report(db)

        assert result["status"] == "completed"
        assert result["candidate_count"] == 1

        report = db.query(models.AnalysisReport).one()
        assert report.status == "completed"
        verdict = json.loads(report.verdict_json)
        assert "object_verdicts" in verdict

        risk_after = db.query(models.RiskAssessment).first()
        assert risk_after.review_status == "auto_confirmed"
    finally:
        db.close()


def test_live_progress_is_persisted_for_polling(session_factory, monkeypatch):
    db = session_factory()
    try:
        db.add(models.AnalysisReport(
            review_run_id="progress123",
            status="running",
            current_stage="candidate_preflight",
            agent_executions_json="{}",
        ))
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr("app.database.SessionLocal", session_factory)
    executions = {
        review.AGENT_DATA_QUALITY: {
            "status": "running",
            "attempts": 1,
            "duration_ms": 0,
            "output_valid": False,
            "opinion_count": 0,
            "error": "",
        }
    }
    review._persist_run_progress(
        "progress123", review.AGENT_DATA_QUALITY, executions, 1,
        current_object_id="risk-1",
        progress_message="Evidence agent is reviewing risk-1",
        progress_percent=42,
    )

    db = session_factory()
    try:
        report = db.query(models.AnalysisReport).filter_by(review_run_id="progress123").one()
        assert report.current_stage == review.AGENT_DATA_QUALITY
        assert report.processed_object_count == 1
        assert json.loads(report.agent_executions_json)[review.AGENT_DATA_QUALITY]["status"] == "running"
        assert report.progress_percent == 42
        assert report.current_object_id == "risk-1"
        assert report.progress_message == "Evidence agent is reviewing risk-1"
        assert report.progress_sequence == 1
        assert report.progress_updated_at is not None
    finally:
        db.close()


def test_run_progress_tracker_emits_monotonic_real_agent_updates():
    updates = []
    tracker = pipeline._RunProgressTracker(1, lambda **payload: updates.append(payload))

    tracker.emit(
        "evidence_preparing", object_id="risk-1", percent=10,
        message="Building evidence packet 1/1",
    )
    tracker.emit(
        "agent_reviewing", object_id="risk-1", agent_name=pipeline.AGENT_EVIDENCE,
        agent_status="running", percent=25, message="Evidence agent running",
    )
    tracker.emit(
        "agent_reviewing", object_id="risk-1", agent_name=pipeline.AGENT_EVIDENCE,
        agent_status="completed", percent=55, message="Evidence agent completed",
        execution={
            "status": "completed", "attempts": 1, "duration_ms": 123,
            "output_valid": True, "error": "",
        },
    )
    tracker.emit(
        "audit_policy", object_id="risk-1", processed_events=1,
        percent=98, message="Backend audit policy applied",
    )

    percentages = [item["progress_percent"] for item in updates]
    assert percentages == sorted(percentages)
    assert updates[1]["agent_executions"][pipeline.AGENT_EVIDENCE]["status"] == "running"
    assert updates[2]["agent_executions"][pipeline.AGENT_EVIDENCE]["status"] == "completed"
    assert updates[-1]["processed_object_count"] == 1
    assert updates[-1]["progress_percent"] == 98


def test_background_review_exposes_intermediate_progress_before_completion(session_factory, monkeypatch):
    seed_risk(session_factory, hostname="background-progress-host", cve_id="CVE-2099-0099")
    progress_written = threading.Event()
    allow_completion = threading.Event()

    def fake_review(db, run_id, selected_risks, selection_result=None, progress_callback=None):
        assert progress_callback is not None
        progress_callback(
            current_stage="agent_reviewing",
            agent_executions={
                pipeline.AGENT_EVIDENCE: {
                    "status": "running", "attempts": 1, "duration_ms": 0,
                    "output_valid": False, "opinion_count": 0, "error": "",
                }
            },
            processed_object_count=0,
            current_object_id=f"risk-{selected_risks[0].id}",
            progress_message="Evidence agent is running",
            progress_percent=37,
        )
        progress_written.set()
        assert allow_completion.wait(5)
        return {
            "status": "completed", "answer": "done", "valid_verdicts": [],
            "event_results": [], "agent_executions": {},
            "candidate_count": 1, "selected_object_count": 1,
            "completed_object_count": 1, "human_review_object_count": 0,
            "termination_reason": "pipeline_completed", "current_stage": "audit_policy",
        }

    monkeypatch.setattr("app.database.SessionLocal", session_factory)
    monkeypatch.setattr(pipeline, "run_review_analysis", fake_review)
    monkeypatch.setattr(pipeline, "_configured", lambda: True)

    db = session_factory()
    try:
        kickoff = pipeline.generate_and_save_report(db, run_id="live-progress-run", background=True)
        assert kickoff["status"] == "running"
    finally:
        db.close()

    assert progress_written.wait(5)
    db = session_factory()
    try:
        report = db.query(models.AnalysisReport).filter_by(review_run_id="live-progress-run").one()
        assert report.status == "running"
        assert report.current_stage == "agent_reviewing"
        assert report.progress_percent == 37
        assert report.progress_message == "Evidence agent is running"
        assert json.loads(report.agent_executions_json)[pipeline.AGENT_EVIDENCE]["status"] == "running"
    finally:
        db.close()

    allow_completion.set()
    deadline = time.time() + 5
    while time.time() < deadline:
        db = session_factory()
        try:
            report = db.query(models.AnalysisReport).filter_by(review_run_id="live-progress-run").one()
            if report.status == "completed":
                assert report.progress_percent == 100
                break
        finally:
            db.close()
        time.sleep(0.05)
    else:
        raise AssertionError("background review did not complete")


# ── JSON 提取兼容性 ─────────────────────────────────────────────────────

def test_extract_json_with_marker():
    """_extract_json 应从带标记的文本中提取 JSON。"""
    content = '[[MARKER]]\n{"verdict": "upgraded", "confidence": 0.9, "risk_adjustment": 15, "reason": "test"}'
    parsed = review._extract_json(content)
    assert parsed is not None
    assert parsed["verdict"] == "upgraded"


def test_extract_json_with_code_fence():
    """_extract_json 应从代码块中提取 JSON。"""
    content = '```json\n{"verdict": "confirmed", "confidence": 0.7, "risk_adjustment": 0, "reason": "ok"}\n```'
    parsed = review._extract_json(content)
    assert parsed is not None
    assert parsed["verdict"] == "confirmed"
