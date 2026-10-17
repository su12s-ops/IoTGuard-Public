"""Authorized object review; history adjudication never reactivates a risk."""
from datetime import datetime, timezone
from sqlalchemy import update
from app import models
from app.services.risk_engine import risk_level
from app.services.review_common.governance import DIRECTION_ADJUSTMENTS, record, snapshot, correction


def apply_human_review(db, risk_id, decision, reason, actor="", expected_status=""):
    risk = db.get(models.RiskAssessment, risk_id)
    if not risk or not risk.active:
        raise ValueError("active_risk_required_use_historical_adjudication_for_inactive")
    if not actor.strip() or not reason.strip() or expected_status != risk.review_status:
        raise ValueError("actor_reason_and_current_expected_status_required")
    if risk.review_status not in {"pending_human_review", "human_reviewing", "reanalysis_required"}:
        raise ValueError("risk_not_awaiting_review")
    before = snapshot(risk)
    target = {"begin": "human_reviewing", "request_reanalysis": "reanalysis_required",
              "reject": "rejected", "confirm": "human_confirmed", "accept_risk": "risk_accepted"}.get(decision)
    if not target:
        raise ValueError("invalid_review_decision")
    if decision in {"confirm", "accept_risk"}:
        if expected_status == "reanalysis_required" or not risk.review_verdict or correction(db, risk):
            raise ValueError("current_native_assessment_required_before_final_decision")
        from app.services.review_common.governance import CONTRACT
        if not db.query(models.RiskGovernanceEvent).filter_by(risk_id=risk.id, kind="native_assessment",
                                                            contract_version=CONTRACT).first():
            raise ValueError("legacy_direction_semantics_require_native_reanalysis")
    changed = db.execute(update(models.RiskAssessment).where(models.RiskAssessment.id == risk_id,
        models.RiskAssessment.active.is_(True), models.RiskAssessment.review_status == expected_status).values(review_status=target))
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("review_state_changed")
    db.refresh(risk)
    risk.human_review_required = decision in {"begin", "request_reanalysis"}
    if decision == "confirm":
        final = max(0, min(100, float(risk.preliminary_score or 0) + DIRECTION_ADJUSTMENTS.get(risk.risk_direction, 0)))
        risk.final_score, risk.risk_level = round(final, 2), risk_level(final)
        risk.decision = risk.recommended_action or risk.preliminary_decision
    elif decision != "begin":
        risk.final_score = risk.risk_level = risk.decision = None
    if decision == "request_reanalysis":
        risk.review_verdict = ""
    risk.review_completed_at = datetime.now(timezone.utc)
    event_kind = "reanalysis_request" if decision == "request_reanalysis" else "human_review"
    risk.review_reason = f"{risk.review_reason or ''}\n[{event_kind}] {actor}: {reason}".strip()
    record(db, risk, event_kind, actor, {"decision": decision, "reason": reason,
        "before": before, "after": snapshot(risk), "repair_authorization": False})
    db.commit()
    return risk


def adjudicate_history(db, risk_id, decision, actor, reason, correction_event_id):
    risk = db.get(models.RiskAssessment, risk_id)
    event = db.get(models.RiskGovernanceEvent, correction_event_id)
    if not risk or risk.active or not event or event.risk_id != risk_id or event.kind != "official_applicability_correction":
        raise ValueError("inactive_risk_and_exact_correction_required")
    if not actor.strip() or not reason.strip() or decision not in {"confirm_archive", "retain_for_review", "reject_correction"}:
        raise ValueError("operator_decision_reason_required")
    record(db, risk, "historical_adjudication", actor, {"decision": decision, "reason": reason,
        "correction_event_id": event.id, "original_risk": snapshot(risk), "reactivated": False,
        "repair_authorization": False})
    db.commit()
    return risk
