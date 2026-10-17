"""正式研判共用确定性组件（M5 中立模块）。

从退役的旧 System B（event_review_pipeline.py）迁出的通用业务能力，
不含任何 LLM 调用或编排流程：
- evidence_packet：逐风险事件证据包构建（供统一编排器证据准备与设备 Harness 复核）；
- selection：正式研判候选选择与预检（供 /api/analysis 正式入口与统一适配层）；
- human_review：人工门禁裁定落库（Q1-Q8 正式裁定机制，模型不得代签）。
"""
from app.services.review_common.evidence_packet import (
    EvidenceItem,
    EvidencePacket,
    StrictModel,
    build_evidence_packet,
)
from app.services.review_common.human_review import DIRECTION_ADJUSTMENTS, apply_human_review
from app.services.review_common.selection import (
    REVIEWABLE_STATUSES,
    explain_candidate_selection,
    object_id_for,
    preflight_check,
    select_candidates,
)

__all__ = [
    "EvidenceItem", "EvidencePacket", "StrictModel", "build_evidence_packet",
    "DIRECTION_ADJUSTMENTS", "apply_human_review",
    "REVIEWABLE_STATUSES", "explain_candidate_selection", "object_id_for",
    "preflight_check", "select_candidates",
]
