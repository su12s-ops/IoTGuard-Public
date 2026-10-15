"""任务分类与路由策略（不是每个任务都调用全部四个 Agent）。

判据全部为程序规则并写入 Trace（可审计）：
- simple 层：单一低/中危候选、证据充分、无情报冲突 → 0 次 LLM，纯规则维持
  基线（审计 R8 成本分层；该层结论由规则产生，不经 LLM）；
- 运行时能力不支持（Zephyr 等 capability_marks）或该目标无任何运行时证据源
  → 跳过 Agent 3，由程序填充 unavailable + 覆盖缺口；
- 无 CVE 候选 → 跳过 Agent 2；
- 困难候选（High/Critical、KEV、运行时告警、证据不足/冲突）→ 全量评审。
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.unified import schemas as S
from app.services.unified.state import (
    TASK_DEVICE_SURFACE,
    TASK_RISK_REVIEW,
    RoutingDecision,
)

SIMPLE_ALLOWED_LEVELS = {"Low", "Medium"}
DIFFICULT_LEVELS = {"High", "Critical"}


def _runtime_capability_unsupported(capability_marks: dict[str, Any]) -> bool:
    unsupported = capability_marks.get("unsupported") or {}
    if isinstance(unsupported, dict):
        return bool(unsupported.get("ebpf"))
    if isinstance(unsupported, list):
        return "ebpf" in unsupported
    return False


def _has_runtime_evidence(db: Session, target_ref: str, target_type: str) -> bool:
    """目标是否存在任何 SecurityEvidence（多标识键解析，与工具语义一致）。"""
    from app.services.agents.tools import _evidence_keys

    keys = _evidence_keys(db, target_ref)
    if not keys:
        return False
    return db.query(models.SecurityEvidence).filter(
        models.SecurityEvidence.device_id.in_(keys)
    ).first() is not None


def _count_intelligence_conflicts(db: Session, candidates: list[dict[str, Any]]) -> int:
    """候选 CVE 的多源情报是否已存在结构化冲突记录（廉价预检，不调 LLM）。"""
    conflicts = 0
    for candidate in candidates:
        cve_id = candidate.get("cve_id", "")
        if not cve_id:
            continue
        rows = db.query(models.VulnerabilityIntelligenceSource).filter_by(cve_id=cve_id).all()
        statuses = {row.source: (row.fetch_status or "") for row in rows}
        if any(status in {"error", "conflict"} for status in statuses.values()):
            conflicts += 1
    return conflicts


def decide_routing(db: Session, task_type: str, target_ref: str, target_type: str,
                   risk: models.RiskAssessment | None = None,
                   capability_marks: dict[str, Any] | None = None,
                   candidates: list[dict[str, Any]] | None = None) -> RoutingDecision:
    candidates = list(candidates or [])
    marks = capability_marks or {}

    if task_type == TASK_DEVICE_SURFACE:
        include_vulnerability = bool(candidates)
        include_runtime = not _runtime_capability_unsupported(marks) and _has_runtime_evidence(db, target_ref, target_type)
        skipped = [S.AGENT_VULNERABILITY] if not include_vulnerability else []
        if not include_runtime:
            skipped.append(S.AGENT_RUNTIME)
        return RoutingDecision(
            tier="standard", include_asset=True,
            include_vulnerability=include_vulnerability,
            include_runtime=include_runtime, include_decision=bool(candidates) or include_runtime,
            skipped_agents=skipped,
            reason="device_surface：资产巡检；按候选与证据源裁剪角色")

    # risk_review / focused_review：单事件语义
    preliminary_level = (risk.preliminary_level if risk else "") or ""
    has_kev = bool(risk and risk.known_exploited)
    hard = (
        preliminary_level in DIFFICULT_LEVELS
        or has_kev
        or _count_intelligence_conflicts(db, candidates) > 0
    )
    if not hard and preliminary_level in SIMPLE_ALLOWED_LEVELS:
        return RoutingDecision(
            tier="simple", include_asset=False, include_vulnerability=False,
            include_runtime=False, include_decision=False,
            skipped_agents=list(S.ALL_AGENT_IDS),
            reason=(f"simple 分层：候选等级 {preliminary_level or 'unknown'}、无 KEV/冲突；"
                    "规则基线维持，不经 LLM（成本分层）"))

    include_runtime = not _runtime_capability_unsupported(marks)
    runtime_reason = ""
    if not include_runtime:
        runtime_reason = "运行时能力不支持（capability_marks）"
    elif not _has_runtime_evidence(db, target_ref, target_type):
        include_runtime = False
        runtime_reason = "目标无任何运行时证据源"

    include_vulnerability = bool(candidates)
    skipped = []
    if not include_vulnerability:
        skipped.append(S.AGENT_VULNERABILITY)
    if not include_runtime:
        skipped.append(S.AGENT_RUNTIME)
    reason = "标准评审：困难候选全量四角色"
    if runtime_reason:
        reason += f"；Agent 3 跳过（{runtime_reason}，程序填充 unavailable）"
    if not include_vulnerability:
        reason += "；Agent 2 跳过（无 CVE 候选）"
    return RoutingDecision(
        tier="standard", include_asset=True,
        include_vulnerability=include_vulnerability,
        include_runtime=include_runtime, include_decision=True,
        skipped_agents=skipped, reason=reason)
