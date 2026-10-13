"""四个智能体定义：职责 + 专属工具 + 结构化输出模型。

差异来源是「工具集 + 输出模型」，系统消息由基座统一生成，不写四份长提示词。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.agents.base import AgentSpec, AgentTool
from app.services.agents import tools as T


class StructuredAgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data_gaps: list[str] = Field(default_factory=list, description="工具未能覆盖的信息缺口")
    confidence: float = Field(ge=0, le=1, default=0.5)


# ── Agent 1：Device Intelligence Agent ────────────────────────────────────────

class ServiceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    port: int
    service_type: str
    product: str = ""


class ComponentEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str = ""
    type: str = "software"


class DeviceProfileReport(StructuredAgentOutput):
    device_id: str
    device_type: str
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    services: list[ServiceEntry] = Field(default_factory=list)
    components: list[ComponentEntry] = Field(default_factory=list)
    exposure_summary: str = ""


DEVICE_INTELLIGENCE_SPEC = AgentSpec(
    name="device_intelligence_agent",
    role="设备情报智能体，负责识别设备类型、端口、协议、服务、固件与软件组件",
    output_model=DeviceProfileReport,
    tools=[
        AgentTool(
            name="query_device_profile",
            description="按 device_id 或 IP 查询设备画像：类型/厂商/型号/固件/服务/组件",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}, "host": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_device_profile,
        ),
        AgentTool(
            name="list_devices",
            description="列出全部已登记智能设备与 Linux 主机",
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
            handler=T.tool_list_devices,
        ),
        AgentTool(
            name="query_network_surface",
            description="查询设备网络暴露面：开放端口、协议、匿名可接入服务、暴露基线",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}, "host": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_network_surface,
        ),
    ],
)


# ── Agent 2：Vulnerability Intelligence Agent ─────────────────────────────────

class VulnerabilityFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    cvss_score: float = 0
    kev: bool = False
    epss_score: float = 0
    installed_version: str = ""
    fixed_version: str = ""
    version_impact: Literal["affected", "fixed", "not_affected", "unknown"] = "unknown"
    confidence: float = Field(ge=0, le=1, default=0.5)
    sources: list[str] = Field(default_factory=list)


class VulnerabilityReport(StructuredAgentOutput):
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    max_severity: Literal["critical", "high", "medium", "low", "none"] = "none"

    @model_validator(mode="after")
    def severity_consistent(self):
        order = ["none", "low", "medium", "high", "critical"]
        implied = "none"
        for finding in self.findings:
            score = finding.cvss_score
            level = ("critical" if score >= 9 else "high" if score >= 7
                     else "medium" if score >= 4 else "low" if score > 0 else "none")
            if order.index(level) > order.index(implied):
                implied = level
        if order.index(self.max_severity) > order.index(implied):
            raise ValueError(f"max_severity={self.max_severity} 高于证据支持的 {implied}；不得夸大严重度")
        return self


VULNERABILITY_INTELLIGENCE_SPEC = AgentSpec(
    name="vulnerability_intelligence_agent",
    role="漏洞情报智能体，负责 CVE/CVSS/KEV/EPSS、版本影响判断与修复版本",
    output_model=VulnerabilityReport,
    tools=[
        AgentTool(
            name="query_cve_intelligence",
            description="查询 CVE 情报：CVSS、CISA KEV、EPSS、多源情报状态、修复版本",
            parameters={"type": "object",
                        "properties": {"cve_id": {"type": "string"},
                                       "package_name": {"type": "string"},
                                       "limit": {"type": "integer", "maximum": 20}},
                        "additionalProperties": False},
            handler=T.tool_query_cve_intelligence,
        ),
        AgentTool(
            name="query_version_impact",
            description="真实版本比较：装机版本是否低于修复版本",
            parameters={"type": "object",
                        "properties": {"cve_id": {"type": "string"},
                                       "installed_version": {"type": "string"},
                                       "fixed_version": {"type": "string"}},
                        "required": ["cve_id", "installed_version"],
                        "additionalProperties": False},
            handler=T.tool_query_version_impact,
        ),
        AgentTool(
            name="query_matched_vulnerabilities",
            description="查询已入库的资产×CVE 版本命中（主机 + 智能设备组件）",
            parameters={"type": "object",
                        "properties": {"host": {"type": "string"},
                                       "cve_id": {"type": "string"},
                                       "device_id": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_matched_vulnerabilities,
        ),
    ],
)


# ── Agent 3：Runtime Behavior Agent ──────────────────────────────────────────

class RuntimeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aspect: Literal["process", "network", "file"]
    evidence_id: str
    description: str


class RuntimeBehaviorReport(StructuredAgentOutput):
    behavior_level: Literal["NORMAL", "SUSPICIOUS", "ACTIVE", "BLOCKED"]
    evidence_ids: list[str] = Field(default_factory=list)
    findings: list[RuntimeFinding] = Field(default_factory=list)
    scope: str = "本设备全部运行时证据"

    @model_validator(mode="after")
    def evidence_required_for_alert(self):
        if self.behavior_level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"}:
            if not self.evidence_ids or not self.findings:
                raise ValueError(
                    f"behavior_level={self.behavior_level} 必须引用真实 evidence_id 并给出 findings；"
                    "没有证据不得判断为可疑或攻击中")
        for finding in self.findings:
            if finding.evidence_id not in self.evidence_ids:
                raise ValueError(f"finding 引用的 {finding.evidence_id} 未列入 evidence_ids")
        if self.evidence_ids and self.behavior_level == "NORMAL":
            if not self.findings:
                raise ValueError("引用了证据却没有任何 finding，请补充观察说明")
        return self


RUNTIME_BEHAVIOR_SPEC = AgentSpec(
    name="runtime_behavior_agent",
    role="运行时行为智能体，读取 eBPF/Falco 的 SecurityEvidence（进程/网络/文件/进程树）并判定 NORMAL/SUSPICIOUS/ACTIVE/BLOCKED",
    output_model=RuntimeBehaviorReport,
    tools=[
        AgentTool(
            name="query_process_evidence",
            description="进程类 eBPF 证据（execve：PID/PPID/用户/命令）",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"},
                                       "limit": {"type": "integer", "maximum": 100}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_process_evidence,
        ),
        AgentTool(
            name="query_network_evidence",
            description="网络类 eBPF 证据（进程→IP:端口）",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"},
                                       "limit": {"type": "integer", "maximum": 100}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_network_evidence,
        ),
        AgentTool(
            name="query_file_evidence",
            description="文件类 eBPF 证据（受控路径读/写）",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"},
                                       "limit": {"type": "integer", "maximum": 100},
                                       "watched_only": {"type": "boolean"}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_file_evidence,
        ),
        AgentTool(
            name="query_process_tree",
            description="设备进程树与「服务→shell→下载器」链分析",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_process_tree,
        ),
    ],
)


# ── Agent 4：Remediation & Verification Agent ────────────────────────────────

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


class RemediationPlan(StructuredAgentOutput):
    risk_ref: str = Field(default="", description="针对的 CVE 或风险标识")
    actions: list[RemediationActionPlan] = Field(default_factory=list)
    verification_plan: list[VerificationStep] = Field(default_factory=list)
    rollback_plan: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def actions_need_rationale_and_rollback(self):
        if self.actions and not self.rollback_plan:
            raise ValueError("包含修复动作的方案必须给出回滚计划")
        return self


REMEDIATION_VERIFICATION_SPEC = AgentSpec(
    name="remediation_verification_agent",
    role="修复与验证智能体，负责生成白名单动作修复方案、重新检测与验证计划、失败回滚计划；不执行 shell",
    output_model=RemediationPlan,
    tools=[
        AgentTool(
            name="query_remediation_targets",
            description="查询可修复目标：已授权风险事件与智能设备 CVE 命中（设备须经 Harness 审批）",
            parameters={"type": "object",
                        "properties": {"host": {"type": "string"},
                                       "cve_id": {"type": "string"},
                                       "device_id": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_remediation_targets,
        ),
        AgentTool(
            name="query_remediation_options",
            description="查询修复动作白名单与发行版包管理器命令模板（只读参考）",
            parameters={"type": "object",
                        "properties": {"cve_id": {"type": "string"},
                                       "package_name": {"type": "string"},
                                       "host": {"type": "string"}},
                        "required": ["cve_id"],
                        "additionalProperties": False},
            handler=T.tool_query_remediation_options,
        ),
        AgentTool(
            name="query_verification_status",
            description="查询修复任务状态与可用验证手段",
            parameters={"type": "object",
                        "properties": {"cve_id": {"type": "string"}, "host": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_verification_status,
        ),
    ],
)


ALL_SPECS: list[AgentSpec] = [
    DEVICE_INTELLIGENCE_SPEC,
    VULNERABILITY_INTELLIGENCE_SPEC,
    RUNTIME_BEHAVIOR_SPEC,
    REMEDIATION_VERIFICATION_SPEC,
]


def specs_summary() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "role": spec.role,
            "tools": [tool.name for tool in spec.tools],
            "output_model": spec.output_model.__name__,
        }
        for spec in ALL_SPECS
    ]
