import csv
import io
import json
import os
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.services.vulnerability_intelligence.service import get_source_bundle


FINAL_REVIEW_STATES = {
    "auto_confirmed",
    "human_confirmed",
    "remediation_ready",
    "remediation_in_progress",
    "verification",
    "resolved",
}


def _has_final_conclusion(risk: models.RiskAssessment) -> bool:
    return risk.review_status in FINAL_REVIEW_STATES and risk.final_score is not None


def _effective_risk_level(risk: models.RiskAssessment) -> str:
    return (risk.risk_level if _has_final_conclusion(risk) else risk.preliminary_level) or "Low"


def _effective_risk_score(risk: models.RiskAssessment) -> float:
    value = risk.final_score if _has_final_conclusion(risk) else risk.preliminary_score
    return float(value or 0)


def _risk_sources(db: Session, risk: models.RiskAssessment) -> dict:
    parts = (risk.cve_id or "").split(":")
    return get_source_bundle(
        db,
        risk.cve_id,
        release=parts[1] if len(parts) > 1 else "",
        package_name=risk.package_name or "",
    )


def build_summary(db: Session) -> dict:
    vulnerabilities = db.query(models.VulnerabilityInfo).all()
    assets = db.query(models.LinuxAsset).all()
    affected_matches = db.query(models.VulnerabilityMatch).filter_by(affected=True).all()
    risks = db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all()
    tasks = db.query(models.RemediationTask).all()
    high_count = sum(1 for item in risks if _effective_risk_level(item) in {"Critical", "High"})
    kev_vulnerability_count = db.query(models.ThreatIntelSource).filter_by(is_kev=True).count()
    pending_task_count = sum(1 for task in tasks if task.status == "pending")
    blocked_task_count = sum(1 for task in tasks if task.status == "blocked")
    human_review_count = sum(1 for item in risks if item.human_review_required)
    review_completed_count = sum(
        1 for item in risks
        if item.review_status in {"auto_confirmed", "human_confirmed", "remediation_ready", "remediation_in_progress", "verification", "resolved"}
    )
    return {
        "vulnerability_count": len(vulnerabilities),
        "asset_count": len(assets),
        "affected_match_count": len(affected_matches),
        "high_risk_count": high_count,
        "kev_vulnerability_count": kev_vulnerability_count,
        "remediation_task_count": len(tasks),
        "pending_remediation_task_count": pending_task_count,
        "blocked_remediation_task_count": blocked_task_count,
        "human_review_required_count": human_review_count,
        "review_completed_count": review_completed_count,
        "top_risks": risks[:5],
        "tasks": tasks,
    }


def _latest_review(db: Session) -> dict:
    """读取最近一次四智能体联合研判报告摘要。"""
    report = (
        db.query(models.AnalysisReport)
        .order_by(models.AnalysisReport.id.desc())
        .first()
    )
    if not report:
        return {"status": "none"}
    verdict = {}
    opinions = {}
    try:
        verdict = json.loads(report.verdict_json or "{}")
    except json.JSONDecodeError:
        pass
    try:
        opinions = json.loads(report.opinions_json or "{}")
    except json.JSONDecodeError:
        pass
    return {
        "status": report.status,
        "model": report.model,
        "verdict": verdict,
        "opinions": opinions,
        "error": report.error or "",
        "created_at": report.created_at.isoformat() if report.created_at else "",
    }


def markdown_report(db: Session) -> str:
    summary = build_summary(db)
    review = _latest_review(db)
    lines = [
        "# LinuxGuard 风险报告",
        "",
        "## 总览",
        f"- 漏洞情报数: {summary['vulnerability_count']}",
        f"- 资产数: {summary['asset_count']}",
        f"- 资产级命中: {summary['affected_match_count']}",
        f"- 高危与严重风险: {summary['high_risk_count']}",
        f"- 修复任务数: {summary['remediation_task_count']}",
        f"- 待修复任务: {summary['pending_remediation_task_count']}",
        f"- 受阻任务: {summary['blocked_remediation_task_count']}",
        f"- 需人工复核: {summary['human_review_required_count']}",
        f"- 已完成智能研判: {summary['review_completed_count']}",
        "",
    ]

    if review.get("status") and review["status"] != "none":
        verdict = review.get("verdict") or {}
        lines.extend(
            [
                "## 四智能体联合研判",
                f"- 状态: {review['status']}",
                f"- 模型: {review.get('model', '')}",
                f"- 最终裁定: {verdict.get('verdict', '') or '无'}",
                f"- 置信度: {verdict.get('confidence', 0)}",
                f"- 风险调整: {verdict.get('risk_adjustment', 0)}",
                f"- 需人工复核: {verdict.get('human_review_required', False)}",
                f"- 裁定理由: {verdict.get('reason', '') or ''}",
                "",
                "### 各智能体意见",
            ]
        )
        opinions = review.get("opinions") or {}
        agent_labels = {
            "data_quality_agent": "数据质量审核",
            "impact_assessment_agent": "漏洞影响研判",
            "runtime_attribution_agent": "运行时归因验证",
            "decision_coordinator_agent": "处置决策协调",
        }
        if opinions:
            for agent_id, content in opinions.items():
                label = agent_labels.get(agent_id, agent_id)
                lines.append(f"- **{label}**: {str(content).strip()[:400]}")
        else:
            lines.append("- （无智能体意见记录）")
        lines.extend(
            [
                "",
                "### 证据与冲突",
                f"- 引用证据: {', '.join(verdict.get('evidence_ids', []) or []) or '无'}",
                f"- 意见冲突: {len(verdict.get('conflicts', []) or [])} 项",
                f"- 缺失证据: {', '.join(verdict.get('missing_evidence', []) or []) or '无'}",
                "",
            ]
        )
        if review.get("error"):
            lines.extend([f"- 研判异常: {review['error']}", ""])
    else:
        lines.extend(["## 四智能体联合研判", "- 状态: 未执行", ""])

    lines.extend(["## 候选风险与最终研判", ""])
    for risk in summary["top_risks"]:
        asset = db.get(models.LinuxAsset, risk.asset_id)
        host = asset.hostname if asset else str(risk.asset_id)
        preliminary = risk.preliminary_score if risk.preliminary_score is not None else 0
        final = risk.final_score
        has_final = _has_final_conclusion(risk)
        if has_final:
            change = ""
            if abs(preliminary - final) > 0.01:
                change = f"，风险变化: 基线 {preliminary} → 最终 {final}"
            review_flag = "，需人工复核" if risk.human_review_required else ""
            score_line = f"最终分数={final}, 等级={risk.risk_level}, 决策={risk.decision}{change}{review_flag}"
        else:
            score_line = f"候选基线分数={preliminary}, 候选等级={risk.preliminary_level}（待四智能体研判，未生成最终结论）"
        lines.append(
            f"- #{risk.priority_rank} {host} {risk.cve_id}: {score_line}, 依据={risk.reason or ''}"
        )
    lines.extend(["", "## 整改建议（不自动执行修复）"])
    for task in summary["tasks"][:10]:
        asset = db.get(models.LinuxAsset, task.asset_id)
        risk = db.get(models.RiskAssessment, task.risk_id) if task.risk_id else None
        host = asset.hostname if asset else str(task.asset_id)
        decision = risk.decision if risk else "monitor"
        lines.append(
            f"- {host} {task.cve_id} [{decision}/{task.status}] 整改命令=`{task.remediation_command}` 验证命令=`{task.verification_command}` 前置说明={task.mitigation}"
        )
    return "\n".join(lines) + "\n"


def json_report(db: Session) -> dict:
    summary = build_summary(db)
    review = _latest_review(db)
    return {
        "overview": {k: v for k, v in summary.items() if not isinstance(v, list)},
        "review": review,
        "top_risks": [
            {
                "rank": risk.priority_rank,
                "asset_id": risk.asset_id,
                "cve_id": risk.cve_id,
                "preliminary_score": risk.preliminary_score,
                "preliminary_level": risk.preliminary_level,
                "preliminary_decision": risk.preliminary_decision,
                "final_score": risk.final_score,
                "risk_level": risk.risk_level,
                "decision": risk.decision,
                "decision_reason": risk.decision_reason,
                "review_status": risk.review_status,
                "review_verdict": risk.review_verdict,
                "review_confidence": risk.review_confidence,
                "review_adjustment": risk.review_adjustment,
                "human_review_required": risk.human_review_required,
                "has_final_conclusion": _has_final_conclusion(risk),
                "reason": risk.reason if _has_final_conclusion(risk) else risk.preliminary_reason,
                "risk_factors": json.loads(risk.risk_factors_json or "{}"),
                "intelligence_sources": _risk_sources(db, risk),
            }
            for risk in summary["top_risks"]
        ],
    }


def csv_report(db: Session) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["rank", "asset", "cve_id", "score", "risk_level", "decision", "reason"])
    for risk in db.query(models.RiskAssessment).order_by(models.RiskAssessment.priority_rank).all():
        asset = db.get(models.LinuxAsset, risk.asset_id)
        writer.writerow(
            [
                risk.priority_rank,
                asset.hostname if asset else risk.asset_id,
                risk.cve_id,
                _effective_risk_score(risk),
                _effective_risk_level(risk),
                risk.decision if _has_final_conclusion(risk) else risk.preliminary_decision,
                risk.reason if _has_final_conclusion(risk) else risk.preliminary_reason,
            ]
        )
    return output.getvalue()


def get_archive_dir() -> Path:
    return Path(os.getenv("REPORT_ARCHIVE_DIR", "/app/data/archives"))


def _archive_path(filename: str) -> Path:
    safe_name = os.path.basename(filename)
    path = get_archive_dir() / safe_name
    if safe_name != filename or path.suffix.lower() != ".json" or not path.is_file():
        raise HTTPException(status_code=404, detail="Archive not found")
    return path


def read_archive(filename: str) -> dict:
    path = _archive_path(filename)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return redact_archive_credentials(payload)


def redact_archive_credentials(value):
    """Sanitize historical archive responses without rewriting the original files."""
    if isinstance(value, dict):
        return {key: redact_archive_credentials(item) for key, item in value.items()
                if key.lower() not in {"password", "passphrase", "private_key", "api_key", "token", "secret"}}
    if isinstance(value, list):
        return [redact_archive_credentials(item) for item in value]
    return value


def list_archives() -> list[dict]:
    archive_dir = get_archive_dir()
    if not archive_dir.exists():
        return []

    archives = []
    for path in archive_dir.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue

        summary = payload.get("summary") or {}
        archived_risks = payload.get("risks") or []
        archived_high_risks = summary.get("high_risks")
        if archived_high_risks is None:
            archived_high_risks = sum(
                1
                for risk in archived_risks
                if (
                    risk.get("risk_level")
                    if risk.get("review_status") in FINAL_REVIEW_STATES and risk.get("final_score") is not None
                    else risk.get("preliminary_level")
                ) in {"Critical", "High"}
            )
        archived_at = payload.get("archived_at")
        archives.append(
            {
                "filename": path.name,
                "archived_at": archived_at,
                "size_bytes": path.stat().st_size,
                "summary": {
                    "assets": summary.get("assets", 0),
                    "vulnerabilities": summary.get("vulnerabilities", 0),
                    "matches": summary.get("matches", 0),
                    "risks": summary.get("risks", 0),
                    "high_risks": archived_high_risks,
                    "tasks": summary.get("tasks", 0),
                    "events": summary.get("events", 0),
                },
            }
        )

    archives.sort(key=lambda item: (item.get("archived_at") or "", item["filename"]), reverse=True)
    return archives
