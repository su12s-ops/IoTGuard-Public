"""正式研判候选选择与预检（确定性规则，无 LLM）。

从旧 System B 迁出的候选选择语义：按优先级序遍历活跃风险，只放行
处于可研判状态、且能唯一定位精确版本命中的事件；跳过对象必须给出
可核验原因。消费方：/api/analysis 正式入口、统一适配层、preflight。
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.nvd_package_mapping import QUARANTINED_MAPPING_STATUS

# 正式研判白名单：只有这两类可进入四智能体研判。
REVIEWABLE_STATUSES = frozenset({"candidate", "reanalysis_required"})
# 隔离状态：NVD 包名来源无法精确复核，保留在风险列表但绝不进入正式研判。
# 即使未来误把该状态加入白名单，下面的显式分支也会拦截。
QUARANTINED_STATUSES = frozenset({QUARANTINED_MAPPING_STATUS})


def object_id_for(risk: models.RiskAssessment) -> str:
    return f"risk-{risk.id}"


def select_candidates(db: Session, asset_id: int = 0) -> dict[str, Any]:
    query = db.query(models.RiskAssessment)
    if asset_id:
        query = query.filter(models.RiskAssessment.asset_id == asset_id)
    risks = query.order_by(models.RiskAssessment.priority_rank).all()
    selected: list[models.RiskAssessment] = []
    skipped: list[dict[str, Any]] = []
    for risk in risks:
        oid = object_id_for(risk)
        reason = ""
        if not risk.active:
            reason = "inactive"
        elif risk.review_status in QUARANTINED_STATUSES:
            # 显式隔离：不进入候选，且与普通“状态不可研判”区分，便于审计。
            reason = "nvd_package_mapping_quarantined"
        elif risk.review_status not in REVIEWABLE_STATUSES:
            reason = "status_not_reviewable"
        elif not risk.match_id:
            matches = db.query(models.VulnerabilityMatch).filter_by(
                asset_id=risk.asset_id, cve_id=risk.cve_id, active=True
            ).all()
            if len(matches) == 1:
                risk.match_id = matches[0].id
                risk.package_name = matches[0].package_name
            else:
                reason = "exact_match_missing" if not matches else "exact_match_ambiguous"
        elif db.get(models.VulnerabilityMatch, risk.match_id) is None:
            reason = "match_not_found"
        if reason:
            skipped.append({"object_id": oid, "reason": reason, "detail": risk.review_status})
        else:
            selected.append(risk)
    db.flush()
    return {
        "total_risks_in_db": len(risks),
        "candidate_count": sum(r.review_status in REVIEWABLE_STATUSES for r in risks),
        "quarantined_count": sum(r.review_status in QUARANTINED_STATUSES for r in risks),
        "selected_object_count": len(selected),
        "selected_object_ids": [object_id_for(risk) for risk in selected],
        "unselected_count": len(skipped),
        "skipped_objects": skipped,
        "_selected_risks": selected,
    }


def explain_candidate_selection(db: Session, asset_id: int = 0) -> dict[str, Any]:
    return select_candidates(db, asset_id=asset_id)


def preflight_check(db: Session, pipeline_version: str) -> dict[str, Any]:
    selection = select_candidates(db)
    result = {
        "asset_count": db.query(models.LinuxAsset).count(),
        "package_count": db.query(models.AssetPackage).count(),
        "vulnerability_count": db.query(models.VulnerabilityInfo).count(),
        "match_count": db.query(models.VulnerabilityMatch).filter_by(active=True).count(),
        "affected_match_count": db.query(models.VulnerabilityMatch).filter_by(active=True, affected=True).count(),
        "risk_assessment_count": selection["total_risks_in_db"],
        **{key: value for key, value in selection.items() if key != "_selected_risks"},
        "pipeline_version": pipeline_version,
    }
    if not selection["selected_object_count"]:
        result.update(status="no_candidates", model_called=False, message="当前没有可进入智能研判的候选对象")
    else:
        result["status"] = "ready"
    return result
