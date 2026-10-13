import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.services.risk_engine import calculate_risk

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.post("/calculate")
def calculate(db: Session = Depends(get_db)):
    count = calculate_risk(db)
    return {"message": "Risk calculated", "count": count}


@router.get("/ranking")
def ranking(db: Session = Depends(get_db)):
    rows = []
    for item in db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all():
        asset = db.get(models.LinuxAsset, item.asset_id)
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=item.cve_id).first()
        match = db.get(models.VulnerabilityMatch, item.match_id) if item.match_id else None
        legacy_status = {
            "auto_confirmed": "completed",
            "human_confirmed": "completed",
            "pending_human_review": "human_review",
            "human_reviewing": "human_review",
            "evidence_preparing": "running",
            "agent_reviewing": "running",
            "conflict_review": "running",
            "coordinator_review": "running",
        }.get(item.review_status, item.review_status)
        rows.append(
            {
                "id": item.id,
                "risk_id": item.id,
                "object_id": f"risk-{item.id}",
                "match_id": item.match_id,
                "rank": item.priority_rank,
                "asset_id": item.asset_id,
                "hostname": asset.hostname if asset else "",
                "cve_id": item.cve_id,
                "package_name": match.package_name if match else (vuln.affected_package if vuln else ""),
                "cvss_score": item.cvss_score,
                "epss_score": item.epss_score,
                "kev_score": item.kev_score,
                "exposure_score": item.exposure_score,
                "business_score": item.business_score,
                "patch_score": item.patch_score,
                "static_score": item.static_score,
                "runtime_score": item.runtime_score,
                "environment_score": item.environment_score,
                "actionability_score": item.actionability_score,
                "reachability_score": item.reachability_score,
                "path_count": item.path_count,
                "exposed_service_count": item.exposed_service_count,
                "affected_status": item.affected_status,
                "reachable_status": item.reachable_status,
                "runtime_status": item.runtime_status,
                "exploitability_status": item.exploitability_status,
                "decision": item.decision,
                "decision_confidence": item.decision_confidence,
                "reachability_reason": item.reachability_reason,
                "decision_reason": item.decision_reason,
                # 候选/基线结果（版本匹配后，四智能体研判前）
                "preliminary_score": item.preliminary_score,
                "preliminary_level": item.preliminary_level,
                "preliminary_decision": item.preliminary_decision,
                "preliminary_reason": item.preliminary_reason,
                # 研判状态：candidate / running / completed / human_review / failed / skipped
                "review_status": item.review_status,
                "legacy_review_status": legacy_status,
                "review_verdict": item.review_verdict,
                "review_confidence": item.review_confidence,
                "review_adjustment": item.review_adjustment,
                "review_reason": item.review_reason,
                "human_review_required": item.human_review_required,
                "review_failed_agents": json.loads(item.review_failed_agents or "[]"),
                "review_missing_evidence": json.loads(item.review_missing_evidence or "[]"),
                "review_conflicts": json.loads(item.review_conflicts or "[]"),
                "audit_policy_reasons": json.loads(item.audit_policy_reasons or "[]"),
                "recommended_priority": item.recommended_priority,
                "recommended_action": item.recommended_action,
                "risk_direction": item.risk_direction,
                "evidence_packet": json.loads(item.evidence_packet_json or "{}"),
                "agent_results": json.loads(item.agent_results_json or "{}"),
                "conflict_result": json.loads(item.conflict_result_json or "{}"),
                # 最终结论（仅研判完成并校验通过后有效；人工复核为 null）
                "final_score": item.final_score,
                "risk_level": item.risk_level,
                "reason": item.reason,
                "applicability_source": item.applicability_source,
                "ubuntu_priority": item.ubuntu_priority,
                "technical_severity": item.technical_severity,
                "likelihood_level": item.likelihood_level,
                "known_exploited": bool(item.known_exploited),
                "risk_factors": json.loads(item.risk_factors_json or "{}"),
                # 便捷标志：review_status=completed 且 final_score 非空
                "has_final_conclusion": bool(
                    item.review_status in {"auto_confirmed", "human_confirmed", "remediation_ready", "remediation_in_progress", "verification", "resolved"}
                    and item.final_score is not None
                ),
            }
        )
    return rows
