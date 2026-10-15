"""统一四智能体（Stage 9B）的结构化输入/输出 Schema。

设计约束（见 IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md §3）：
- 每个 Agent 有唯一命名、明确输出 Schema、只读工具边界；
- 顶层多余字段由程序「预分拣」进 notes（CF6 修复：Zephyr 场景不再因
  多余说明字段整体失败），必填字段/类型/枚举仍然强制校验；
- 引用类字段（evidence_id）的存在性由编排器节点做程序校验（防幻觉），
  不在 Schema 内完成（需要数据库事实）。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.services.agents.agents import RemediationActionPlan, VerificationStep

AGENT_ASSET = "asset_investigator"
AGENT_VULNERABILITY = "vulnerability_analyst"
AGENT_RUNTIME = "runtime_analyst"
AGENT_DECISION = "decision_planner"
ALL_AGENT_IDS = [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_RUNTIME, AGENT_DECISION]

AGENT_TITLES = {
    AGENT_ASSET: "Asset & Evidence Investigator（资产与证据调查员）",
    AGENT_VULNERABILITY: "Vulnerability Analyst（漏洞分析师）",
    AGENT_RUNTIME: "Runtime Analyst（运行时分析师）",
    AGENT_DECISION: "Decision & Response Planner（研判与处置规划师）",
}

PIPELINE_VERSION = "unified-four-agent-v1"

Freshness = Literal["fresh", "stale", "mixed", "none"]


class UnifiedAgentOutput(BaseModel):
    """四个智能体输出的公共底座。

    extra=ignore：顶层未知键在程序预分拣中转入 notes 后再校验（见 agent_base）；
    嵌套未知键由 pydantic 忽略。这是对 CF6（extra=forbid 全败）的根因修复，
    同时保留「结构化输出必须过校验」的语义。
    """

    model_config = ConfigDict(extra="ignore")
    notes: list[str] = Field(default_factory=list, description="程序注入的预分拣记录或模型补充说明")
    data_gaps: list[str] = Field(default_factory=list, description="工具未能覆盖的信息缺口（如实声明，不得编造）")
    confidence: float = Field(ge=0, le=1, default=0.5)


# ── Agent 1：Asset & Evidence Investigator ───────────────────────────────────

class ServiceObservation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    port: int
    service_type: str
    product: str = ""


class ComponentObservation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    version: str = ""
    type: str = "software"


class EvidenceInventory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    runtime_evidence_present: bool = False
    evidence_freshness: Freshness = "none"
    coverage_status: str = "unknown"
    dropped_events: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)


class AssetEvidenceReport(UnifiedAgentOutput):
    device_id: str
    device_type: str = "unknown"
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    os: str = ""
    services: list[ServiceObservation] = Field(default_factory=list)
    components: list[ComponentObservation] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    evidence_inventory: EvidenceInventory = Field(default_factory=EvidenceInventory)
    evidence_quality: Literal["sufficient", "partial", "insufficient", "conflicting"] = "insufficient"
    missing_evidence: list[str] = Field(default_factory=list)
    exposure_summary: str = ""


# ── Agent 2：Vulnerability Analyst ───────────────────────────────────────────

class IntelligenceConflict(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sources: list[str] = Field(default_factory=list)
    description: str
    evidence_ids: list[str] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    package_name: str = ""
    cvss_score: float = 0
    kev: bool = False
    epss_score: float = 0
    installed_version: str = ""
    fixed_version: str = ""
    version_impact: Literal["affected", "fixed", "not_affected", "unknown"] = "unknown"
    applicability: Literal[
        "confirmed_affected", "potentially_affected", "not_affected", "insufficient_evidence"
    ] = "insufficient_evidence"
    confidence: float = Field(ge=0, le=1, default=0.5)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    rationale: str = ""


_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


class VulnerabilityAnalysisReport(UnifiedAgentOutput):
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    max_observed_severity: Literal["critical", "high", "medium", "low", "none"] = "none"
    intelligence_conflicts: list[IntelligenceConflict] = Field(default_factory=list)

    @model_validator(mode="after")
    def severity_consistent(self):
        """继承 System A 纪律：严重度不得高于证据支持的上限（防夸大）。"""
        implied = "none"
        for finding in self.findings:
            score = finding.cvss_score
            level = ("critical" if score >= 9 else "high" if score >= 7
                     else "medium" if score >= 4 else "low" if score > 0 else "none")
            if _SEVERITY_ORDER.index(level) > _SEVERITY_ORDER.index(implied):
                implied = level
        if _SEVERITY_ORDER.index(self.max_observed_severity) > _SEVERITY_ORDER.index(implied):
            raise ValueError(
                f"max_observed_severity={self.max_observed_severity} 高于证据支持的 {implied}；不得夸大严重度")
        return self


# ── Agent 3：Runtime Analyst ─────────────────────────────────────────────────

class RuntimeFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    aspect: Literal["process", "network", "file"]
    evidence_id: str
    description: str


class RuntimeAnalysisReport(UnifiedAgentOutput):
    behavior_level: Literal["NORMAL", "SUSPICIOUS", "ACTIVE", "BLOCKED"] = "NORMAL"
    # F6 修复：freshness 参与状态语义——stale_verified 取代跨期「仍算 verified」
    runtime_status: Literal[
        "verified", "stale_verified", "contextual", "not_observed", "waiting", "unavailable"
    ] = "not_observed"
    evidence_freshness: Freshness = "none"
    exposure_status: Literal[
        "internet_reachable", "internal_reachable", "local_only", "unreachable", "unknown"
    ] = "unknown"
    evidence_ids: list[str] = Field(default_factory=list)
    findings: list[RuntimeFinding] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    scope: str = ""

    @model_validator(mode="after")
    def evidence_and_freshness_semantics(self):
        """继承 System A 证据纪律 + F6 新鲜度语义（保守方向）。"""
        if self.behavior_level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"}:
            if not self.evidence_ids or not self.findings:
                raise ValueError(
                    f"behavior_level={self.behavior_level} 必须引用真实 evidence_id 并给出 findings；"
                    "没有证据不得判断为可疑或攻击中")
            if self.evidence_freshness not in {"fresh", "mixed"}:
                raise ValueError(
                    f"behavior_level={self.behavior_level} 不能只依据过期证据"
                    f"（freshness={self.evidence_freshness}）；请降级或声明 data_gaps")
        for finding in self.findings:
            if finding.evidence_id not in self.evidence_ids:
                raise ValueError(f"finding 引用的 {finding.evidence_id} 未列入 evidence_ids")
        if self.runtime_status == "verified" and self.evidence_freshness != "fresh":
            raise ValueError(
                f"runtime_status=verified 要求 freshness=fresh（当前 {self.evidence_freshness}）；"
                "证据过期时请使用 stale_verified 并说明")
        if self.runtime_status == "stale_verified" and self.evidence_freshness not in {"stale", "mixed"}:
            raise ValueError(
                f"runtime_status=stale_verified 要求 freshness 为 stale/mixed（当前 {self.evidence_freshness}）")
        if self.evidence_ids and self.behavior_level == "NORMAL" and not self.findings:
            raise ValueError("引用了证据却没有任何 finding，请补充观察说明")
        return self


# ── Agent 4：Decision & Response Planner ─────────────────────────────────────

ImpactStatus = Literal[
    "confirmed_affected", "potentially_affected", "not_affected", "insufficient_evidence"
]
RiskDirection = Literal[
    "maintain", "upgrade_minor", "upgrade_major", "downgrade_minor", "downgrade_major"
]
RecommendedAction = Literal[
    "immediate_fix", "scheduled_fix", "mitigate", "monitor", "collect_more_evidence", "defer"
]
FOLLOW_UP_TARGETS = (AGENT_ASSET, AGENT_VULNERABILITY, AGENT_RUNTIME)


class FollowUpRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_agent: Literal["asset_investigator", "vulnerability_analyst", "runtime_analyst"]
    question: str = Field(min_length=1)
    evidence_hint: str = ""


class KeyEvidenceCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    evidence_id: str
    check: str
    passed: bool


class VerdictItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    object_id: str
    impact_status: ImpactStatus = "insufficient_evidence"
    risk_direction: RiskDirection = "maintain"
    recommended_action: RecommendedAction = "monitor"
    recommended_priority: Literal["critical", "high", "medium", "low"] = "medium"
    confidence: float = Field(ge=0, le=1, default=0.5)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason: str = ""


class ResponsePlan(BaseModel):
    """候选修复计划（F4 修复的载体）。

    actions 复用 System A 的 RemediationActionPlan（白名单动作枚举 +
    params 禁止 shell 键的 validator），VerificationStep 同样复用；
    requires_approval 由程序在 finalize 阶段强制覆写为 True。
    """

    model_config = ConfigDict(extra="ignore")
    risk_ref: str = ""
    actions: list[RemediationActionPlan] = Field(default_factory=list)
    verification_plan: list[VerificationStep] = Field(default_factory=list)
    rollback_plan: list[str] = Field(default_factory=list)
    requires_approval: bool = True


class DecisionResponseReport(UnifiedAgentOutput):
    verdicts: list[VerdictItem] = Field(default_factory=list)
    key_evidence_checks: list[KeyEvidenceCheck] = Field(default_factory=list)
    follow_up_requests: list[FollowUpRequest] = Field(default_factory=list, max_length=2)
    response_plan: ResponsePlan = Field(default_factory=ResponsePlan)
    degraded_roles: list[str] = Field(default_factory=list)
    reason: str = ""

    @model_validator(mode="after")
    def follow_up_targets_valid(self):
        for request in self.follow_up_requests:
            if request.target_agent not in FOLLOW_UP_TARGETS:
                raise ValueError(f"follow_up target_agent={request.target_agent} 非法")
        return self


# ── 节点间/编排层结构 ─────────────────────────────────────────────────────────

class ConflictItemRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    code: str
    description: str
    involved_agents: list[str] = Field(default_factory=list)


class ConflictResultRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    has_major_conflict: bool = False
    conflicts: list[ConflictItemRecord] = Field(default_factory=list)
    rereview_count: int = Field(default=0, ge=0, le=1)
    unresolved: bool = False


class AuditPolicyDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: Literal["auto_confirmed", "pending_human_review"]
    reasons: list[str] = Field(default_factory=list)
    adjustment: int = 0
    final_score: float | None = None
    final_level: str | None = None


AGENT_OUTPUT_MODELS = {
    AGENT_ASSET: AssetEvidenceReport,
    AGENT_VULNERABILITY: VulnerabilityAnalysisReport,
    AGENT_RUNTIME: RuntimeAnalysisReport,
    AGENT_DECISION: DecisionResponseReport,
}
