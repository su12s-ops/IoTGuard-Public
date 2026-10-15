"""统一编排器的有状态工作流状态（LangGraph StateGraph 的 state schema）。"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def merge_dict(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """并行节点并发写字典时的合并 reducer（右值覆盖同键）。"""
    return {**left, **right}


def merge_unique(left: list[str], right: list[str]) -> list[str]:
    """并行节点并发写列表时的去重合并 reducer。"""
    return list(dict.fromkeys(list(left) + list(right)))

from app.services.unified.schemas import (
    AGENT_ASSET,
    AGENT_DECISION,
    AGENT_RUNTIME,
    AGENT_VULNERABILITY,
    ALL_AGENT_IDS,
    AuditPolicyDecisionRecord,
    ConflictResultRecord,
)

TASK_RISK_REVIEW = "risk_review"
TASK_DEVICE_SURFACE = "device_surface"
TASK_FOCUSED_REVIEW = "focused_review"
TASK_TYPES = (TASK_RISK_REVIEW, TASK_DEVICE_SURFACE, TASK_FOCUSED_REVIEW)

PIPELINE_STAGE_ORDER = [
    "prepare",
    "prepare_evidence",
    "investigate_asset",
    "analyze_vulnerability",
    "analyze_runtime",
    "detect_conflicts",
    "directed_rereview",
    "decide",
    "execute_follow_ups",
    "finalize",
]


class RoutingDecision(BaseModel):
    model_config = ConfigDict(extra="ignore")
    tier: Literal["simple", "standard", "focused"] = "standard"
    include_asset: bool = True
    include_vulnerability: bool = True
    include_runtime: bool = True
    include_decision: bool = True
    skipped_agents: list[str] = Field(default_factory=list)
    reason: str = ""

    def active_agents(self) -> list[str]:
        """本次编排实际会调用（或程序降级填充）的 LLM 角色。"""
        return [
            agent_id
            for agent_id, include in (
                (AGENT_ASSET, self.include_asset),
                (AGENT_VULNERABILITY, self.include_vulnerability),
                (AGENT_RUNTIME, self.include_runtime),
                (AGENT_DECISION, self.include_decision),
            )
            if include
        ]


class BudgetState(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_llm_calls: int = 40
    agent_deadline_s: float = 150.0
    run_deadline_s: float = 900.0
    follow_up_rounds: int = 1
    rereview_rounds: int = 1


class UnifiedAnalysisState(BaseModel):
    """LangGraph 图的完整状态；每个节点返回增量 dict，由框架合并。

    所有字段可被 JSON 序列化（快照落库 UnifiedAnalysisRun.state_json）。
    Agent 输出以 model_dump() 的 dict 形态保存，保持状态层无类型耦合。
    """

    model_config = ConfigDict(extra="ignore")

    run_id: str
    task_type: str = TASK_RISK_REVIEW
    target_ref: str = ""
    target_type: str = "linux_host"
    mode: Literal["shadow", "formal"] = "shadow"

    routing: RoutingDecision = Field(default_factory=RoutingDecision)
    capability_marks: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)       # 规则基线（只读引用）
    object_id: str = ""                                           # risk_review 的事件标识
    candidate_context: list[dict[str, Any]] = Field(default_factory=list)
    # M4.1：确定性证据预取包（非 Agent 产物；无 LLM；运行内只读复用）
    evidence_prep: dict[str, Any] | None = None

    investigation: dict[str, Any] | None = None                   # Agent 1 输出
    vulnerability: dict[str, Any] | None = None                   # Agent 2 输出
    runtime: dict[str, Any] | None = None                         # Agent 3 输出
    runtime_program_fallback: dict[str, Any] | None = None        # Agent 3 被跳过/失败时的程序填充
    conflict_result: ConflictResultRecord = Field(default_factory=ConflictResultRecord)
    decision: dict[str, Any] | None = None                        # Agent 4 输出
    follow_up_results: list[dict[str, Any]] = Field(default_factory=list)

    follow_ups_used: int = 0
    rereview_used: int = 0
    # 以下三键会被并行分支（Agent 2 ∥ Agent 3）并发写入，必须用 reducer 合并
    # （注意：error 只能定义一次；重复定义会让普通注解覆盖 Annotated reducer，
    #  并行写错误时触发 LangGraph InvalidUpdateError——最终验收实验实测）
    degraded_roles: Annotated[list[str], merge_unique] = Field(default_factory=list)
    stage_status: Annotated[dict[str, str], merge_dict] = Field(default_factory=dict)
    error: Annotated[str, lambda left, right: "; ".join(x for x in (left, right) if x)] = ""
    final: dict[str, Any] = Field(default_factory=dict)           # finalize 产物（policy/aggregate/plan）
    budgets: BudgetState = Field(default_factory=BudgetState)

    def record_stage(self, stage: str, status: str) -> dict[str, str]:
        return {**self.stage_status, stage: status}

    def known_evidence_ids(self) -> set[str]:
        """状态中真实存在的证据引用全集（程序校验 Agent 引用的依据）。"""
        ids: set[str] = set(self.baseline.get("packet_evidence_ids") or [])
        investigation = self.investigation or {}
        inventory = investigation.get("evidence_inventory") or {}
        for source in inventory.get("sources") or []:
            if isinstance(source, str):
                ids.add(source)
        runtime = self.runtime or {}
        ids.update(runtime.get("evidence_ids") or [])
        for finding in runtime.get("findings") or []:
            if isinstance(finding, dict):
                ids.add(finding.get("evidence_id", ""))
        ids.discard("")
        vulnerability = self.vulnerability or {}
        for finding in vulnerability.get("findings") or []:
            if isinstance(finding, dict):
                ids.update(finding.get("supporting_evidence_ids") or [])
        return ids

    def failed_or_missing_roles(self) -> list[str]:
        return list(dict.fromkeys(self.degraded_roles))


def empty_state(run_id: str, task_type: str, target_ref: str, target_type: str,
                mode: str) -> UnifiedAnalysisState:
    return UnifiedAnalysisState(
        run_id=run_id, task_type=task_type, target_ref=target_ref,
        target_type=target_type, mode=mode,   # type: ignore[arg-type]
    )
