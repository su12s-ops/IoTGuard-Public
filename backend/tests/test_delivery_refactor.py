"""Final-delivery acceptance tests for per-risk expert audit refactor."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, text

from app import models
from app.services import event_review_pipeline as pipeline
from app.services.matching_engine import run_matching
from app.services.remediation_engine import generate_remediation_tasks
from app.services.risk_engine import calculate_risk


def seed_asset_vuln(
    db,
    *,
    hostname="delivery-host",
    package="openssl",
    installed="3.0.2-0ubuntu1.10",
    fixed="3.0.2-0ubuntu1.18",
    exposure="internal",
    business="normal",
    public_service=False,
):
    asset = models.LinuxAsset(
        hostname=hostname,
        distribution="ubuntu",
        os_name="Ubuntu",
        os_version="22.04",
        exposure_level=exposure,
        business_level=business,
    )
    db.add(asset)
    db.flush()
    db.add(models.AssetPackage(
        asset_id=asset.id,
        package_name=package,
        package_version=installed,
        package_manager="dpkg",
    ))
    if public_service:
        db.add(models.AssetService(
            asset_id=asset.id,
            service_name="nginx",
            port=443,
            protocol="tcp",
            listen_address="0.0.0.0",
            process_name="nginx",
            is_public_exposed=True,
        ))
    vuln = models.VulnerabilityInfo(
        cve_id=f"CVE-2099-{asset.id:04d}",
        title="Delivery acceptance vulnerability",
        description="test",
        cvss_score=7.5,
        cvss_severity="High",
        affected_package=package,
        fixed_version=fixed,
        source="Ubuntu Security API",
    )
    db.add(vuln)
    db.commit()
    return asset, vuln


def make_packet(
    *,
    installed="1.0",
    fixed="2.0",
    match_status="potentially_affected",
    business="normal",
    public=False,
):
    evidence = pipeline.EvidenceItem(
        evidence_id="EV-1-PKG",
        evidence_type="package_version",
        source="asset_collector",
        timestamp="2026-08-07T00:00:00Z",
        reliability="direct",
        content={"installed_version": installed, "fixed_version": fixed},
    )
    return pipeline.EvidencePacket(
        object_id="risk-1",
        risk_id=1,
        match_id=1,
        asset={"business_level": business, "exposure_level": "public" if public else "internal"},
        vulnerability={"cve_id": "CVE-2099-0001"},
        package_match={
            "installed_version": installed,
            "fixed_version": fixed,
            "match_status": match_status,
            "affected": match_status != "fixed",
        },
        service_context={"services": [{"public": public, "listen_address": "0.0.0.0" if public else "127.0.0.1"}]},
        network_exposure={"status": "internet_exposed" if public else "none"},
        runtime_evidence=[],
        threat_intelligence={},
        data_quality={},
        baseline={"preliminary_score": 50, "preliminary_level": "Medium", "preliminary_decision": "scheduled_fix"},
        evidence_items=[evidence],
    )


def specialist_results(packet, *, quality="sufficient", impact_status="confirmed_affected", exposure="internal_reachable", runtime="not_observed", confidence=0.9):
    evidence = pipeline.EvidenceAuditResult(
        object_id=packet.object_id,
        evidence_quality=quality,
        confidence=confidence,
        valid_evidence_ids=["EV-1-PKG"],
        conflicting_evidence_ids=[],
        missing_evidence=[],
        reason="evidence reviewed",
    )
    impact = pipeline.ImpactAssessmentResult(
        object_id=packet.object_id,
        impact_status=impact_status,
        confidence=confidence,
        supporting_evidence_ids=["EV-1-PKG"],
        counter_evidence_ids=[],
        required_conditions=[],
        conditions_met=[],
        missing_evidence=[],
        reason="impact reviewed",
    )
    exposure_result = pipeline.ExposureRuntimeResult(
        object_id=packet.object_id,
        exposure_status=exposure,
        runtime_status=runtime,
        confidence=confidence,
        supporting_evidence_ids=[],
        contradictions=[],
        missing_evidence=[],
        reason="runtime reviewed",
    )
    return evidence, impact, exposure_result


def coordinator(packet, *, direction="maintain", priority="low", action="monitor", confidence=0.9):
    return pipeline.CoordinatorResult(
        object_id=packet.object_id,
        impact_status="confirmed_affected",
        risk_direction=direction,
        recommended_priority=priority,
        recommended_action=action,
        confidence=confidence,
        supporting_evidence_ids=["EV-1-PKG"],
        conflicts=[],
        missing_evidence=[],
        reason="coordinated",
    )


def test_case_a_fixed_version_is_excluded_and_matching_is_idempotent(session_factory):
    db = session_factory()
    try:
        seed_asset_vuln(db, installed="3.0.2-0ubuntu1.18", fixed="3.0.2-0ubuntu1.18")
        assert run_matching(db) == 1
        assert run_matching(db) == 1
        match = db.query(models.VulnerabilityMatch).one()
        assert match.match_status == "fixed"
        assert match.reason_code == "installed_version_fixed"
        assert match.affected is False
        assert calculate_risk(db) == 0
        assert db.query(models.RiskAssessment).count() == 0
    finally:
        db.close()


def test_candidate_exact_match_dedup_reanalysis_and_multi_package(session_factory):
    db = session_factory()
    try:
        asset, vuln = seed_asset_vuln(db)
        run_matching(db)
        match_one = db.query(models.VulnerabilityMatch).one()
        match_two = models.VulnerabilityMatch(
            asset_id=asset.id,
            cve_id=vuln.cve_id,
            package_name="libssl3",
            installed_version="3.0.2-0ubuntu1.10",
            fixed_version="3.0.2-0ubuntu1.18",
            affected=True,
            match_status="potentially_affected",
            reason_code="installed_version_below_fixed",
            evidence_fingerprint="second-package",
            active=True,
        )
        db.add(match_two)
        db.commit()

        assert calculate_risk(db) == 2
        risks = db.query(models.RiskAssessment).order_by(models.RiskAssessment.match_id).all()
        assert len(risks) == 2
        assert {risk.match_id for risk in risks} == {match_one.id, match_two.id}
        assert {risk.package_name for risk in risks} == {"openssl", "libssl3"}

        risks[0].review_status = "auto_confirmed"
        db.commit()
        calculate_risk(db)
        assert db.get(models.RiskAssessment, risks[0].id).review_status == "auto_confirmed"
        assert generate_remediation_tasks(db) == 1
        remediation = db.query(models.RemediationTask).filter_by(risk_id=risks[0].id).one()
        assert remediation.status == "pending"

        match_one.fixed_version = "3.0.2-0ubuntu1.20"
        match_one.evidence_fingerprint = "fixed-version-changed"
        db.commit()
        calculate_risk(db)
        changed = db.query(models.RiskAssessment).filter_by(match_id=match_one.id).one()
        assert changed.review_status == "reanalysis_required"
        assert changed.reanalysis_count == 1
        assert remediation.status == "blocked"
    finally:
        db.close()


def test_evidence_packet_is_exact_typed_and_traceable(session_factory):
    db = session_factory()
    try:
        seed_asset_vuln(db)
        run_matching(db)
        calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()
        packet = pipeline.build_evidence_packet(db, risk)
        assert packet.object_id == f"risk-{risk.id}"
        assert packet.match_id == risk.match_id
        assert packet.package_match["package_name"] == "openssl"
        assert all(item.evidence_id for item in packet.evidence_items)
        assert all(item.source and item.timestamp and item.reliability for item in packet.evidence_items)
    finally:
        db.close()


def test_all_agent_schemas_reject_invalid_json_shape():
    with pytest.raises(ValidationError):
        pipeline.EvidenceAuditResult.model_validate({"object_id": "risk-1", "evidence_quality": "maybe"})
    with pytest.raises(ValidationError):
        pipeline.ImpactAssessmentResult.model_validate({"object_id": "risk-1", "impact_status": "yes", "confidence": 2, "reason": "x"})
    with pytest.raises(ValidationError):
        pipeline.ExposureRuntimeResult.model_validate({"object_id": "risk-1", "exposure_status": "public", "runtime_status": "none", "confidence": 1, "reason": "x"})
    with pytest.raises(ValidationError):
        pipeline.CoordinatorResult.model_validate({"object_id": "risk-1", "risk_direction": "plus_17"})


def test_case_b_runtime_not_observed_does_not_negate_impact_or_create_conflict():
    packet = make_packet()
    evidence, impact, runtime = specialist_results(packet, runtime="not_observed")
    conflict = pipeline.detect_conflicts(packet, evidence, impact, runtime)
    assert impact.impact_status == "confirmed_affected"
    assert runtime.runtime_status == "not_observed"
    assert conflict.has_major_conflict is False


def test_case_c_public_contextual_raises_priority_but_never_claims_exploitation():
    packet = make_packet(public=True)
    evidence, impact, runtime = specialist_results(
        packet, exposure="internet_reachable", runtime="contextual"
    )
    result = coordinator(packet, direction="upgrade_major", priority="high", action="immediate_fix")
    policy = pipeline.apply_audit_policy(
        packet, evidence, impact, runtime, result, pipeline.ConflictResult()
    )
    assert result.risk_direction == "upgrade_major"
    assert runtime.runtime_status == "contextual"
    assert "verified" not in runtime.reason.lower()
    assert policy.status == "pending_human_review"


def test_case_d_missing_version_is_insufficient_and_never_auto_confirmed():
    packet = make_packet(installed="", fixed="2.0", match_status="insufficient_data")
    evidence, impact, runtime = specialist_results(packet, quality="insufficient", impact_status="insufficient_evidence")
    policy = pipeline.apply_audit_policy(
        packet, evidence, impact, runtime,
        coordinator(packet, action="collect_more_evidence"),
        pipeline.ConflictResult(),
    )
    assert policy.status == "pending_human_review"
    assert policy.final_score is None
    assert "installed_version_missing" in policy.reasons


def test_case_e_conflict_is_detected_rereviewed_once_then_human():
    packet = make_packet(public=True)
    evidence, impact, runtime = specialist_results(
        packet, quality="conflicting", exposure="unreachable"
    )
    first = pipeline.detect_conflicts(packet, evidence, impact, runtime)
    assert first.has_major_conflict is True
    second = pipeline.detect_conflicts(packet, evidence, impact, runtime, rereview_count=1)
    assert second.rereview_count == 1
    assert second.unresolved is True
    policy = pipeline.apply_audit_policy(
        packet, evidence, impact, runtime, coordinator(packet), second
    )
    assert policy.status == "pending_human_review"
    assert "unresolved_major_conflict" in policy.reasons


@pytest.mark.parametrize(
    ("direction", "expected", "expected_status"),
    [
        ("maintain", 50, "auto_confirmed"),
        ("upgrade_minor", 60, "pending_human_review"),
        ("upgrade_major", 70, "pending_human_review"),
        ("downgrade_minor", 40, "auto_confirmed"),
        ("downgrade_major", 30, "auto_confirmed"),
    ],
)
def test_llm_direction_maps_to_backend_controlled_score(direction, expected, expected_status):
    packet = make_packet()
    evidence, impact, runtime = specialist_results(packet)
    policy = pipeline.apply_audit_policy(
        packet, evidence, impact, runtime,
        coordinator(packet, direction=direction),
        pipeline.ConflictResult(),
    )
    assert policy.status == expected_status
    assert policy.final_score == (expected if expected_status == "auto_confirmed" else None)
    assert policy.adjustment == pipeline.DIRECTION_ADJUSTMENTS[direction]
    if expected_status == "pending_human_review":
        assert "high_or_critical_final_score" in policy.reasons


def test_low_confidence_and_agent_failure_are_fail_safe():
    packet = make_packet()
    evidence, impact, runtime = specialist_results(packet, confidence=0.69)
    low = pipeline.apply_audit_policy(
        packet, evidence, impact, runtime, coordinator(packet), pipeline.ConflictResult()
    )
    failed = pipeline.apply_audit_policy(
        packet, None, None, None, None, pipeline.ConflictResult(), [pipeline.AGENT_IMPACT]
    )
    assert low.status == "pending_human_review"
    assert failed.status == "pending_human_review"
    assert failed.final_score is None


def test_real_batch_size_chunks_every_event_without_aggregate_verdict():
    items = list(range(13))
    batches = list(pipeline._batches(items))
    assert [len(batch) for batch in batches] == [5, 5, 3]
    assert [item for batch in batches for item in batch] == items


def test_remediation_requires_explicit_confirmation_and_exact_risk(session_factory):
    db = session_factory()
    try:
        seed_asset_vuln(db)
        run_matching(db)
        calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()

        risk.review_status = "candidate"
        db.commit()
        assert generate_remediation_tasks(db) == 0

        risk.review_status = "pending_human_review"
        risk.human_review_required = True
        db.commit()
        assert generate_remediation_tasks(db, allow_human_override=True) == 0

        risk.risk_direction = "maintain"
        risk.recommended_action = "scheduled_fix"
        pipeline.apply_human_review(db, risk.id, "confirm", "maintenance window approved")
        assert risk.review_status == "human_confirmed"
        assert generate_remediation_tasks(db) == 1
        task = db.query(models.RemediationTask).one()
        assert task.risk_id == risk.id
        assert task.package_name == "openssl"
    finally:
        db.close()


def test_agent_audit_record_model_has_per_event_fields():
    fields = models.AgentAuditRecord.__table__.columns.keys()
    for field in (
        "run_id", "risk_id", "object_id", "agent_name", "model", "evidence_ids_json",
        "structured_output_json", "parse_status", "retry_count", "latency_ms", "error",
    ):
        assert field in fields


def test_analysis_report_model_has_realtime_progress_fields():
    fields = models.AnalysisReport.__table__.columns.keys()
    for field in (
        "progress_percent", "current_object_id", "progress_message",
        "progress_sequence", "progress_updated_at",
    ):
        assert field in fields


def test_workflow_overview_reads_new_per_event_opinion_list():
    from app.services.agent_intelligence import _review_agent_status

    event_result = {
        "object_id": "risk-1",
        "evidence_audit": {
            "object_id": "risk-1",
            "evidence_quality": "sufficient",
            "confidence": 0.9,
            "reason": "版本证据可靠",
        },
        "impact_assessment": {
            "object_id": "risk-1",
            "impact_status": "potentially_affected",
            "confidence": 0.8,
            "reason": "版本低于修复版本",
        },
        "exposure_runtime": {
            "object_id": "risk-1",
            "exposure_status": "internet_reachable",
            "runtime_status": "contextual",
            "confidence": 0.75,
            "reason": "公网服务存在但未证明利用",
        },
        "coordinator": {
            "object_id": "risk-1",
            "risk_direction": "maintain",
            "confidence": 0.78,
            "reason": "转人工确认",
        },
    }
    executions = {
        agent: {"status": "completed", "duration_ms": 100, "event_results": []}
        for agent in pipeline.ALL_AGENTS
    }
    report = SimpleNamespace(
        status="human_review",
        error="",
        human_review_object_count=1,
        verdict_json=json.dumps({"event_results": [event_result]}),
        opinions_json=json.dumps([event_result], ensure_ascii=False),
        agent_executions_json=json.dumps(executions),
    )

    result = _review_agent_status(report)
    assert result["agents"]["evidence_audit"]["status"] == "completed"
    assert "版本证据可靠" in result["agents"]["evidence_audit"]["output"]
    assert "公网服务存在但未证明利用" in result["agents"]["exposure_runtime"]["output"]
    assert "转人工确认" in result["agents"]["decision_coordinator"]["output"]


def test_migrated_high_risk_auto_confirmation_is_revoked_fail_closed(session_factory):
    from app import database

    db = session_factory()
    try:
        seed_asset_vuln(db)
        run_matching(db)
        calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()
        risk.review_status = "auto_confirmed"
        risk.human_review_required = False
        risk.preliminary_level = "High"
        risk.risk_level = "High"
        risk.final_score = 80
        risk.decision = "immediate_fix"
        db.add(models.RemediationTask(
            risk_id=risk.id,
            asset_id=risk.asset_id,
            cve_id=risk.cve_id,
            package_name=risk.package_name,
            status="pending",
        ))
        db.commit()

        with db.bind.begin() as conn:
            database._backfill_targeted_refactor(conn)
        db.expire_all()

        assert risk.review_status == "pending_human_review"
        assert risk.human_review_required is True
        assert risk.final_score is None
        assert risk.risk_level is None
        assert risk.decision is None
        assert db.query(models.RemediationTask).one().status == "blocked"
    finally:
        db.close()


def test_additive_sqlite_migration_backfills_only_unambiguous_match(tmp_path, monkeypatch):
    from app import database

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE vulnerability_match (
            id INTEGER PRIMARY KEY, asset_id INTEGER, cve_id VARCHAR(32), package_name VARCHAR(128),
            installed_version VARCHAR(128), fixed_version VARCHAR(128), affected BOOLEAN,
            match_reason TEXT, confidence FLOAT, created_at DATETIME
        )"""))
        conn.execute(text("""CREATE TABLE risk_assessment (
            id INTEGER PRIMARY KEY, asset_id INTEGER, cve_id VARCHAR(32), created_at DATETIME
        )"""))
        conn.execute(text("""CREATE TABLE remediation_task (
            id INTEGER PRIMARY KEY, asset_id INTEGER, cve_id VARCHAR(32), package_name VARCHAR(128)
        )"""))
        conn.execute(text("CREATE TABLE analysis_report (id INTEGER PRIMARY KEY)"))
        conn.execute(text("""INSERT INTO vulnerability_match
            (id, asset_id, cve_id, package_name, installed_version, fixed_version, affected)
            VALUES (7, 1, 'CVE-2099-7777', 'openssl', '1.0', '2.0', 1)
        """))
        conn.execute(text("""INSERT INTO risk_assessment (id, asset_id, cve_id)
            VALUES (9, 1, 'CVE-2099-7777')
        """))
    models.AgentAuditRecord.__table__.create(bind=engine)
    monkeypatch.setattr(database, "engine", engine)

    added = database._migrate_sqlite_schema()
    assert "risk_assessment.match_id" in added
    with engine.begin() as conn:
        row = conn.execute(text("SELECT match_id, package_name FROM risk_assessment WHERE id=9")).one()
        assert row.match_id == 7
        assert row.package_name == "openssl"
        audit_columns = {item[1] for item in conn.execute(text("PRAGMA table_info('agent_audit_record')"))}
        assert "structured_output_json" in audit_columns
    engine.dispose()
