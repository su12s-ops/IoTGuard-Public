"""统一四智能体定义：职责 + 只读工具 + 输出模型（唯一命名）。

工具全部复用 System A `agents/tools.py` 的既有只读实现（零改动），
新增 `query_intelligence_sources`（只读封装 vulnerability_intelligence
多源状态包——Agent 2 做厂商公告语义理解与情报冲突核查的事实基础）。
能力边界 = 注册的工具集合，四组互不重叠。
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app import models
from app.services.agents import tools as T
from app.services.agents.base import AgentSpec, AgentTool
from app.services.unified import schemas as S
from app.services.unified.schemas import (
    AGENT_ASSET,
    AGENT_DECISION,
    AGENT_RUNTIME,
    AGENT_VULNERABILITY,
)


class IntelligenceSourceQuery(BaseModel):
    model_config = ConfigDict(extra="ignore")


def tool_query_intelligence_sources(db: Session, cve_id: str = "", release: str = "",
                                    package_name: str = "") -> dict[str, Any]:
    """查询 CVE 多源情报状态包（Canonical/NVD/CISA KEV/EPSS/Kylin，只读）。

    供漏洞分析师做「厂商公告语义理解 + 情报冲突核查」（E3/E4 类案例的
    事实基础）。来源数据与 System B 证据包同源（get_source_bundle），
    不引入新的情报能力，只把它开放为 Agent 2 的专属工具。
    """
    from app.services.vulnerability_intelligence.service import get_source_bundle

    if not cve_id:
        return {"error": "缺少 cve_id"}
    vulnerability = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).one_or_none()
    bundle = get_source_bundle(db, cve_id, release=release, package_name=package_name)
    return {
        "cve_id": cve_id,
        "known_in_library": vulnerability is not None,
        "title": vulnerability.title if vulnerability else "",
        "cvss_score": vulnerability.cvss_score if vulnerability else 0,
        "count": len(bundle),
        "sources": bundle,
        "note": "各来源状态可能是 unavailable；unavailable 表示该源当前不可用，不代表无冲突。",
    }


ASSET_INVESTIGATOR_SPEC = AgentSpec(
    name=AGENT_ASSET,
    role="资产与证据调查员（Asset & Evidence Investigator），负责识别设备类型/固件/服务/组件、"
         "网络暴露面，以及运行时证据的存在性/新鲜度/覆盖/丢失，并如实列出缺失项",
    output_model=S.AssetEvidenceReport,
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
            name="query_network_surface",
            description="查询设备网络暴露面：开放端口、协议、匿名可接入服务、暴露基线",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}, "host": {"type": "string"}},
                        "additionalProperties": False},
            handler=T.tool_query_network_surface,
        ),
        AgentTool(
            name="query_runtime_data_quality",
            description="查询运行时数据质量：采集覆盖/心跳、真实丢失计数（unavailable≠0）、证据新鲜度、数据缺口",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_runtime_data_quality,
        ),
        AgentTool(
            name="list_devices",
            description="列出全部已登记智能设备与 Linux 主机（用于核对目标身份）",
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
            handler=T.tool_list_devices,
        ),
    ],
)


VULNERABILITY_ANALYST_SPEC = AgentSpec(
    name=AGENT_VULNERABILITY,
    role="漏洞分析师（Vulnerability Analyst），负责 CVE 适用性分析：真实版本比较、"
         "厂商公告（Canonical/NVD/KEV/EPSS 等）语义理解、补丁状态与多源情报冲突核查",
    output_model=S.VulnerabilityAnalysisReport,
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
            description="真实版本比较：装机版本是否低于修复版本（确定性比较函数）",
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
        AgentTool(
            name="query_intelligence_sources",
            description="查询 CVE 多源情报状态包：Canonical 适用性/NVD 严重度/KEV/EPSS/Kylin 的"
                        "原始状态、更新时间与错误信息（用于识别来源之间的矛盾）",
            parameters={"type": "object",
                        "properties": {"cve_id": {"type": "string"},
                                       "release": {"type": "string"},
                                       "package_name": {"type": "string"}},
                        "required": ["cve_id"],
                        "additionalProperties": False},
            handler=tool_query_intelligence_sources,
        ),
    ],
)


RUNTIME_ANALYST_SPEC = AgentSpec(
    name=AGENT_RUNTIME,
    role="运行时分析师（Runtime Analyst），读取 eBPF/Falco/syslog 的 SecurityEvidence"
         "（进程/网络/文件/进程树）与遥测数据质量，判定行为等级与运行时状态。"
         "语义边界：运行时证据只影响紧迫度与证据强度；包活动不等于漏洞被利用；"
         "证据过期时必须使用 stale_verified 而不是 verified",
    output_model=S.RuntimeAnalysisReport,
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
        AgentTool(
            name="query_runtime_data_quality",
            description="查询运行时数据质量：采集覆盖/心跳、真实丢失计数（unavailable≠0）、证据新鲜度、数据缺口",
            parameters={"type": "object",
                        "properties": {"device_id": {"type": "string"}},
                        "required": ["device_id"],
                        "additionalProperties": False},
            handler=T.tool_query_runtime_data_quality,
        ),
    ],
)


DECISION_PLANNER_SPEC = AgentSpec(
    name=AGENT_DECISION,
    role="研判与处置规划师（Decision & Response Planner），综合资产/漏洞/运行时三个专家的"
         "结构化结果与确定性基线、冲突结果，给出离散裁定与待审批处置计划。"
         "你只给出离散 risk_direction 与处置建议，不能给自由数值、不能决定自动确认、"
         "不能授予修复权限、不能生成 shell 命令；证据不足时用 follow_up_requests "
         "申请定向补充调查（有界）",
    output_model=S.DecisionResponseReport,
    tools=[],
)


ALL_SPECS: list[AgentSpec] = [
    ASSET_INVESTIGATOR_SPEC,
    VULNERABILITY_ANALYST_SPEC,
    RUNTIME_ANALYST_SPEC,
    DECISION_PLANNER_SPEC,
]

SPEC_BY_NAME = {spec.name: spec for spec in ALL_SPECS}


def specs_summary() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "title": S.AGENT_TITLES[spec.name],
            "role": spec.role,
            "tools": [tool.name for tool in spec.tools],
            "output_model": spec.output_model.__name__,
        }
        for spec in ALL_SPECS
    ]
