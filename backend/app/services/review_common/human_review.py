"""人工门禁裁定落库（Q1-Q8 正式裁定机制）。

从旧 System B 迁出的人工复核语义：只有处于待人工审核状态的风险事件
可被裁定；confirm 沿用既有方向调整表由程序计算最终分数；模型不得代签。
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.services.risk_engine import risk_level

DIRECTION_ADJUSTMENTS = {
    "maintain": 0,
    "upgrade_minor": 10,
    "upgrade_major": 20,
    "downgrade_minor": -10,
    "downgrade_major": -20,
}


def apply_human_review(db: Session, risk_id: int, decision: str, reason: str) -> models.RiskAssessment:
    risk = db.get(models.RiskAssessment, risk_id)
    if risk is None:
        raise ValueError("risk event not found")
    if risk.review_status not in {"pending_human_review", "human_reviewing"}:
        raise ValueError(f"risk event status {risk.review_status} is not awaiting human review")
    if decision == "reject":
        risk.review_status = "rejected"
        risk.human_review_required = False
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
    elif decision == "confirm":
        adjustment = DIRECTION_ADJUSTMENTS.get(risk.risk_direction or "maintain", 0)
        final = max(0.0, min(100.0, float(risk.preliminary_score or 0) + adjustment))
        risk.review_status = "human_confirmed"
        risk.human_review_required = False
        risk.final_score = round(final, 2)
        risk.risk_level = risk_level(final)
        risk.decision = risk.recommended_action or risk.preliminary_decision
    else:
        raise ValueError("decision must be confirm or reject")
    risk.review_reason = f"{risk.review_reason}\n[human_review] {reason}".strip()
    risk.review_completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(risk)
    return risk
