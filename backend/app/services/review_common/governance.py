"""M5 object-level evidence, historical correction and execution eligibility.

Events are append-only. A correction never edits the original risk or approval
evidence and never counts as an operator decision.
"""
import hashlib
import json

from app import models

CONTRACT = "m5-native-review-v2"
DIRECTION_ADJUSTMENTS = {"maintain": 0, "upgrade_minor": 10, "upgrade_major": 20,
                         "downgrade_minor": -10, "downgrade_major": -20}
DIRECTION_MEANING = "new_evidence_relative_to_explicit_risk_baseline"


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def snapshot(row):
    return {c.name: getattr(row, c.name) for c in row.__table__.columns}


def record(db, risk, kind, actor, payload):
    event = models.RiskGovernanceEvent(risk_id=risk.id, kind=kind, actor=actor,
        contract_version=CONTRACT, payload_json=encode(payload))
    db.add(event)
    db.flush()
    return event


def correction(db, risk):
    return db.query(models.RiskGovernanceEvent).filter_by(risk_id=risk.id,
        kind="official_applicability_correction").order_by(models.RiskGovernanceEvent.id.desc()).first()


def execution_allowed(db, risk):
    from app.services.nvd_package_mapping import QUARANTINED_MAPPING_STATUS
    return bool(risk and risk.active and risk.review_status != QUARANTINED_MAPPING_STATUS
                and not correction(db, risk))


def assert_execution_allowed(db, risk):
    if not execution_allowed(db, risk):
        raise ValueError("risk_inactive_or_officially_corrected_requires_new_eligible_object")


def apply_official_correction(db, risk, proof):
    """Caller supplies an integrity-checked precise official release/package row.

    This blocks future execution under the superseded match, including plans
    approved before correction. It does not close or reactivate the risk.
    """
    if proof.get("status") != "not_affected" or not all(proof.get(k) for k in
            ("evidence_id", "sha256", "release", "package", "url")):
        raise ValueError("precise_official_not_affected_proof_required")
    if correction(db, risk):
        return correction(db, risk)
    payload = {"original_risk": snapshot(risk), "correction": proof,
        "current_explanation": "官方精确发行版/源包不受影响；历史风险保留，归档待操作员裁定。该 CVE 无专属修复版本。",
        "operator_confirmed": False, "affected_candidates": []}
    for task in db.query(models.RemediationTask).filter_by(risk_id=risk.id):
        payload["affected_candidates"].append({"type": "remediation_task", "original": snapshot(task)})
        task.status = "invalidated"
    for run in db.query(models.HarnessRun).filter_by(risk_id=risk.id):
        plan = json.loads(run.plan_json or "{}")
        if plan.get("goal") != "repair":
            continue
        payload["affected_candidates"].append({"type": "harness_run", "original": snapshot(run)})
        # Preserve the exact plan/hash/actor; a tombstone, not a new approval.
        run.status = "invalidated"
        run.error = "official_applicability_correction: prior match and authorization superseded"
        run.approval_hash = ""
    return record(db, risk, "official_applicability_correction", "official_evidence_policy", payload)


def reconcile_official_record(db, official):
    """Apply only an exact, integrity-checked Canonical tuple, including history."""
    from app.services import canonical_official
    from app.services.matching_engine import _asset_codename
    data = json.loads(official.raw_json)
    if official.evidence_status != "available" or official.source_url != canonical_official.official_record_url(official.cve_id):
        raise ValueError("official_source_invalid")
    if hashlib.sha256(encode(data).encode()).hexdigest() != official.content_sha256:
        raise ValueError("official_evidence_integrity_failed")
    entries = canonical_official.record_statuses(official.cve_id, data)
    results = []
    for risk in db.query(models.RiskAssessment).all():
        if risk.cve_id.split(":")[0] != official.cve_id:
            continue
        asset = db.get(models.LinuxAsset, risk.asset_id)
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        if not asset or asset.distribution != "ubuntu":
            continue
        package = risk.package_name or (match.package_name if match else "")
        exact = [e for e in entries if e["release"] == _asset_codename(asset) and e["package"] == package
                 and e["raw_status"] in {"not-affected", "not_affected"}]
        if len(exact) == 1:
            event = apply_official_correction(db, risk, {"status": "not_affected",
                "evidence_id": official.evidence_id, "sha256": official.content_sha256,
                "url": official.source_url, "release": exact[0]["release"], "package": package,
                "fixed_version": "", "notice_fixes_are_not_cve_specific": exact[0]["notice_fixes"]})
            results.append(event.id)
    return results


def explanation(db, risk):
    from app.services.remediation_engine import _authorized
    events = db.query(models.RiskGovernanceEvent).filter_by(risk_id=risk.id).order_by(models.RiskGovernanceEvent.id).all()
    native = [e for e in events if e.kind == "native_assessment"]
    adjudications = [e for e in events if e.kind == "historical_adjudication"]
    run_id = json.loads(risk.device_context_json or "{}").get("unified_run_id")
    current = db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id, risk_id=risk.id, mode="formal").first() if run_id else None
    return {"contract_version": CONTRACT, "risk_direction_semantics": DIRECTION_MEANING if native else "legacy_unverified",
        "raw_risk_direction": risk.risk_direction,
        "current_formal_run_id": current.run_id if current else None,
        "current_plan": json.loads(current.plan_json or "{}") if current else {},
        "historical_review_state": json.loads(adjudications[-1].payload_json)["decision"] if adjudications else "awaiting_operator",
        "execution_eligible": execution_allowed(db, risk) and _authorized(risk),
        "events": [{"id": e.id, "kind": e.kind, "actor": e.actor, "created_at": e.created_at,
                    "payload": json.loads(e.payload_json)} for e in events]}


def assessment_record(db, risk, run, state):
    previous = snapshot(risk)
    prep = state.evidence_prep or {}
    # Facts, not the receipt id or model output, identify repeated reasoning.
    from app.services.unified.investigation import evidence_view
    identity = {"asset_facts": evidence_view(db, risk.asset_id),
        "candidate": {key: (state.baseline or {}).get(key) for key in
            ("preliminary_score", "preliminary_level", "match_status", "installed_version", "fixed_version")}}
    facts_hash = hashlib.sha256(encode(identity).encode()).hexdigest()
    return record(db, risk, "native_assessment", "unified_policy", {
        "run_id": run.run_id, "previous": previous,
        "risk_direction_semantics": DIRECTION_MEANING, "baseline": state.baseline,
        "facts_hash": facts_hash, "model_outputs_preserved": True,
        "facts_schema": "m5-facts-v2", "facts": identity,
        "confidence_dimensions": {"static_applicability": state.vulnerability,
            "runtime_quality": state.runtime or state.runtime_program_fallback,
            "official_coverage": [c.get("source_bundle") for c in prep.get("candidates", [])],
            "model_variance": "Independent reasoning is not new evidence or a risk change."}})


def invalidate_prior_authorizations(db, risk, reason):
    affected = []
    for run in db.query(models.HarnessRun).filter_by(risk_id=risk.id):
        if json.loads(run.plan_json or "{}").get("goal") == "repair" and run.approval_hash:
            affected.append(snapshot(run))
            run.approval_hash = ""
            if run.status not in {"completed", "resolved", "invalidated"}:
                run.status = "invalidated"
                run.error = reason
    if affected:
        record(db, risk, "authorization_invalidated", "evidence_policy", {"reason": reason, "original_plans": affected})


def historical_draft_sink(db, run, state):
    risk = db.get(models.RiskAssessment, run.risk_id)
    if run.mode != "historical" or state.mode != "historical" or not risk or risk.active or not correction(db, risk):
        raise ValueError("inactive_corrected_historical_source_required")
    record(db, risk, "historical_assessment_draft", "unified_four_agent", {
        "run_id": run.run_id, "trace_id": run.trace_id, "original_risk": snapshot(risk),
        "correction_event_id": correction(db, risk).id, "decision": state.decision,
        "confidence_dimensions": {"static": state.vulnerability,
            "runtime": state.runtime or state.runtime_program_fallback,
            "model_variance": "Raw independent outputs are preserved; repeats do not create new facts."},
        "policy": state.final.get("policy"), "operator_confirmed": False, "repair_authorization": False})
    db.commit()
