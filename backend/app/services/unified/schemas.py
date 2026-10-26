"""统一四智能体（Stage 9B）的结构化输入/输出 Schema。

设计约束（见 docs/reference/security-model.md）：
- 每个 Agent 有唯一命名、明确输出 Schema、只读工具边界；
- 顶层多余字段由程序「预分拣」进 notes（CF6 修复：Zephyr 场景不再因
  多余说明字段整体失败），必填字段/类型/枚举仍然强制校验；
- 引用类字段（evidence_id）的存在性由编排器节点做程序校验（防幻觉），
  不在 Schema 内完成（需要数据库事实）。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

# 白名单修复动作 Schema（M5 自旧 System A agents.py 迁入：统一编排器是唯一消费方）
RemediationAction = Literal[
    "change_config", "restart_service", "disable_service", "enable_authentication",
    "update_package", "backup_file", "restore_file",
]


class RemediationActionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: RemediationAction
    target: str = Field(description="动作对象：包名/服务名/配置路径")
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1)
    expected_verification: str = ""
    requires_approval: bool = True

    @field_validator("params")
    @classmethod
    def no_shell_in_params(cls, value: dict[str, Any]):
        banned = {"command", "shell", "cmd", "script", "exec"}
        if banned & set(value):
            raise ValueError(f"params 禁止包含 {banned & set(value)}；修复动作由平台白名单执行器执行")
        return value


class VerificationStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: str
    evidence_source: str = ""


class CollaborationMessageDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receiver: Literal["asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner", "all"]
    message_type: Literal["FINDING", "QUESTION", "CHALLENGE", "EVIDENCE_REQUEST",
                          "EVIDENCE_UPDATE", "CONFLICT", "RESOLUTION", "PLAN_FEEDBACK"]
    claim: str = Field(min_length=1, max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    requested_action: str = Field(default="", max_length=800)
    reply_to: str = ""
    finding_id: str = ""


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
    messages: list[CollaborationMessageDraft] = Field(default_factory=list, max_length=6)


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


# M4.2 深化（任务书第二部分）：资产结论必须区分证据等级——已核实事实 /
# 来源不明确数据 / 冲突事实，不得把三者混同陈述。
class VerifiedFact(BaseModel):
    """已核实事实：来自当前运行内真实工具返回且来源明确。"""

    model_config = ConfigDict(extra="ignore")
    fact: str
    source: str = ""
    as_of: str = ""


class UnverifiedObservation(BaseModel):
    """来源不明确或未经交叉核实的数据（如实标注，不得当作已核实事实使用）。"""

    model_config = ConfigDict(extra="ignore")
    item: str
    reason: Literal["source_unclear", "single_source", "stale", "unconfirmed", "other"] = "unconfirmed"
    note: str = ""


class ConflictingFact(BaseModel):
    """不同来源互相矛盾的事实（列出双方来源，交由决策端冲突处理）。"""

    model_config = ConfigDict(extra="ignore")
    description: str
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
    verified_facts: list[VerifiedFact] = Field(default_factory=list)
    unverified_observations: list[UnverifiedObservation] = Field(default_factory=list)
    conflicting_facts: list[ConflictingFact] = Field(default_factory=list)


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
    # M4.2 深化（任务书第二部分）：CVE 适用性研判的专业维度——
    # 安装版本与受影响版本区间的关系（独立于 fixed_version 单点比较）；
    # 装机分支与公告作用分支的关系；厂商补丁及 backport 语义；
    # 情报源精确度（厂商精确公告 vs NVD 通用候选匹配）。
    version_range_relation: Literal[
        "in_affected_range", "below_affected_range", "at_or_above_fixed_version",
        "outside_affected_range", "no_stated_range", "unknown"
    ] = "unknown"
    branch_relation: Literal[
        "vendor_branch_matches_advisory", "different_distribution_branch", "unknown"
    ] = "unknown"
    patch_semantics: Literal[
        "vendor_fixed_in_release", "vendor_backport_applied", "backport_available_not_installed",
        "upstream_fix_only", "no_fix_available", "unknown"
    ] = "unknown"
    advisory_specificity: Literal[
        "vendor_precise_match", "nvd_candidate_only", "sources_conflict", "no_advisory"
    ] = "unknown"
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

# M4.2 深化（任务书第二部分）：单条运行时证据与候选漏洞的关系语义——
# 组件存在/服务活跃/攻击前置条件/可疑行为/CVE 相关动态证据/已确认利用/无关。
# 「可疑」不等于「与该 CVE 相关」，「无关活跃」不得作为该 CVE 的紧迫依据。
EvidenceRelation = Literal[
    "component_present", "service_active", "attack_precondition", "suspicious_behavior",
    "cve_related_evidence", "confirmed_exploitation", "unrelated",
]


class RuntimeFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    aspect: Literal["process", "network", "file"]
    evidence_id: str
    description: str
    relation: EvidenceRelation = "unrelated"
    observed_at: str = Field(default="", description="证据真实发生时间（来自工具返回，不得编造）")
    source_quality: Literal["sensor_verified", "single_source", "aggregated", "unknown"] = "unknown"


# 报告级总结：动态证据整体与候选 CVE 的关联程度（禁止把异常直接等同已利用）
ExploitationRelation = Literal[
    "confirmed_exploitation", "cve_related_evidence", "suspicious_unlinked",
    "service_active_only", "component_present_only", "not_observed",
    "monitoring_unavailable", "monitoring_missing",
]


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
    exploitation_relation: ExploitationRelation = "not_observed"
    exploitation_relation_rationale: str = Field(
        default="", description="关联程度判定的依据（引用真实证据 ID 与时间；缺失≠不存在，异常≠已利用）")

    @model_validator(mode="after")
    def evidence_and_freshness_semantics(self):
        """继承 System A 证据纪律 + F6 新鲜度语义（保守方向）+ M4.2 关联语义纪律。"""
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
        # 已确认利用必须由明确标注 confirmed_exploitation 的真实证据支撑（防跳级）
        if self.exploitation_relation == "confirmed_exploitation":
            supporting = [f for f in self.findings
                          if f.relation in {"confirmed_exploitation", "cve_related_evidence"}]
            if not supporting:
                raise ValueError(
                    "exploitation_relation=confirmed_exploitation 必须由 relation="
                    "confirmed_exploitation/cve_related_evidence 的具体证据条目支撑；"
                    "仅有可疑或无关行为时不得宣称已确认利用")
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
    collection_capability: Literal["database", "inventory"] = "database"
    expected_effect: str = Field(default="", description="该补查预期消除哪个具体证据缺口、"
                                                         "以及结果会如何改变研判（防止无边界索证）")


class KeyEvidenceCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    evidence_id: str
    check: str
    passed: bool


# M4.2 分层研判模型（任务书第三部分）：四个研判维度（非新增 Agent）——
# 适用性 / 运行时证据 / 暴露与利用条件各自独立表达结论、置信与证据不足，
# 处置维度由 VerdictItem 的 action/priority/urgency_basis 承载。
DimensionStatus = Literal[
    "established", "partial", "absent", "insufficient_evidence", "unknown"
]


class DimensionAssessment(BaseModel):
    """单个研判维度的独立评估：结论状态、置信、支撑证据与缺口。

    纪律：运行时维度 absent/insufficient 不得反推适用性不存在；
    适用性维度结论不得由运行时异常单独支撑。
    """

    model_config = ConfigDict(extra="ignore")
    status: DimensionStatus = "unknown"
    conclusion: str = ""
    confidence: float = Field(ge=0, le=1, default=0.5)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class VerdictItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    object_id: str
    impact_status: ImpactStatus = "insufficient_evidence"
    risk_direction: RiskDirection = Field(default="maintain", description="风险相对于输入 baseline 的变化；upgrade=风险上升，downgrade=风险下降，与软件包升级无关")
    risk_baseline_ref: str = Field(default="input.baseline", description="风险变化比较的明确基线")
    risk_change_basis: str = Field(default="", description="新事实及其相对于基线的影响；同事实重跑差异是模型方差")
    package_change: Literal["none", "upgrade", "downgrade", "replace", "undetermined"] = "undetermined"
    confidence_explanation: dict[str, str] = Field(default_factory=dict, description="分别解释 static_applicability/runtime_quality/official_coverage/model_variance")
    recommended_action: RecommendedAction = "monitor"
    recommended_priority: Literal["critical", "high", "medium", "low"] = "medium"
    confidence: float = Field(ge=0, le=1, default=0.5)
    # M4.1 校准（E5/X3）：适用性、运行时证据有效性、处置紧迫度三类字段强制分离。
    # runtime_evidence_validity 只描述「运行时证据现在的有效性」；
    # urgency_basis 说明紧迫度结论的证据来源（stale_verified 不得作为当前活跃
    # 利用的充分依据；静态证据独立支撑的紧急建议必须显式声明并转人工）。
    runtime_evidence_validity: Literal[
        "fresh_verified", "stale_verified", "unavailable", "not_observed", "unknown"
    ] = "unknown"
    urgency_basis: Literal[
        "fresh_runtime_evidence", "static_evidence_only", "no_urgency_evidence", "unknown"
    ] = "unknown"
    # M4.2 分层研判：各维度独立表达（证据不足与不确定性逐维度声明）。
    applicability_dimension: DimensionAssessment = Field(default_factory=DimensionAssessment)
    runtime_dimension: DimensionAssessment = Field(default_factory=DimensionAssessment)
    exposure_dimension: DimensionAssessment = Field(default_factory=DimensionAssessment)
    # 处置前置条件中仍不满足的项（如：冲突未消解、补丁不可用、触发条件不满足）
    unsatisfied_conditions: list[str] = Field(default_factory=list)
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
    # M4.2 协作深化：冲突消解状态显式声明（哪些已消解及依据、哪些仍存在）。
    resolved_conflicts: list[str] = Field(default_factory=list)
    unresolved_conflicts: list[str] = Field(default_factory=list)
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
    category: Literal["dimension_difference", "fact_version", "substantive_judgment",
                      "plan_feasibility", "safety_block"] = "substantive_judgment"
    evidence_ids: list[str] = Field(default_factory=list)


class ConflictResultRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    has_major_conflict: bool = False
    conflicts: list[ConflictItemRecord] = Field(default_factory=list)
    rereview_count: int = Field(default=0, ge=0)
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
