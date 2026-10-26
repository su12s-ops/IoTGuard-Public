import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, defer

from app import models
from app.database import get_db
from app.services.device_access import require_control
from app.services.nvd_package_mapping import QUARANTINED_MAPPING_STATUS
from app.services.risk_engine import calculate_risk
from app.services.review_common.governance import explanation

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.post("/calculate", dependencies=[Depends(require_control)])
def calculate(asset_id: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    """Recalculate candidate risks; ``asset_id`` keeps the mutation scoped.

    Without an explicit asset the historical fleet-wide calculation is
    retained for operators, but the browser asset flow always passes its own
    asset_id so one device cannot rewrite another device's statuses/ranking.
    """
    if asset_id and db.get(models.LinuxAsset, asset_id) is None:
        raise HTTPException(404, "资产不存在")
    count = calculate_risk(db, asset_id=asset_id or None)
    return {"message": "Risk calculated", "count": count, "asset_id": asset_id or None}


@router.get("/ranking")
def ranking(asset_id: int = Query(default=0, ge=0),
            include_details: bool = True,
            db: Session = Depends(get_db)):
    rows = []
    query = db.query(models.RiskAssessment)
    if not include_details:
        query = query.options(defer(models.RiskAssessment.evidence_packet_json),
                              defer(models.RiskAssessment.agent_results_json),
                              defer(models.RiskAssessment.conflict_result_json))
    if asset_id:
        query = query.filter(models.RiskAssessment.asset_id == asset_id)
    for item in query.order_by(models.RiskAssessment.priority_rank, models.RiskAssessment.id).all():
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
            # 隔离状态没有旧的研判语义：显式保留为自身，绝不映射成候选/研判中。
            "quarantined_mapping": "quarantined_mapping",
        }.get(item.review_status, item.review_status)
        rows.append(
            {
                "id": item.id,
                "risk_id": item.id,
                "active": item.active,
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
                "review_status_reason": (
                    "NVD 包名无法精确复核，已隔离，不进入正式研判"
                    if item.review_status == QUARANTINED_MAPPING_STATUS else ""
                ),
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
                "governance": explanation(db, item, include_payloads=False),
                "details_included": include_details,
                **({"evidence_packet": json.loads(item.evidence_packet_json or "{}"),
                    "agent_results": json.loads(item.agent_results_json or "{}"),
                    "conflict_result": json.loads(item.conflict_result_json or "{}")} if include_details else {}),
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
