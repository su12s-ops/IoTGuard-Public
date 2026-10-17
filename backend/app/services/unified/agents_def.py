"""统一四智能体定义：职责 + 只读工具 + 输出模型（唯一命名）。

工具全部复用中立模块 `services/agent_tools.py` 的只读实现（零改动），
新增 `query_intelligence_sources`（只读封装 vulnerability_intelligence
多源状态包——Agent 2 做厂商公告语义理解与情报冲突核查的事实基础）。
能力边界 = 注册的工具集合，四组互不重叠。
"""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app import models
from app.services import agent_tools as T
from app.services.agent_infra import AgentSpec, AgentTool
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
    """查询 CVE 多源情报状态包（Canonical/NVD/CISA KEV/EPSS/Kylin/OpenWrt，只读）。

    供漏洞分析师做「厂商公告语义理解 + 情报冲突核查」（E3/E4/E5 类案例的
    事实基础）。来源数据与 System B 证据包同源（get_source_bundle），并补充
    操作员登记的 OpenWrt 厂商公告（与 System B 证据包的 OPENWRT 项同源）——
    不引入新的情报能力，只把它开放为 Agent 2 的专属工具。
    """
    from app.services.vulnerability_intelligence.service import get_source_bundle

    if not cve_id:
        return {"error": "缺少 cve_id"}
    parts = cve_id.split(":")
    if len(parts) > 1 and not release:
        release = parts[1]
    if len(parts) > 2 and not package_name:
        package_name = parts[2]
    vulnerability = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).one_or_none()
    bundle = get_source_bundle(db, cve_id, release=release, package_name=package_name)
    advisories = db.query(models.OpenWrtAdvisory).filter_by(cve_id=cve_id).all()
    if advisories:
        bundle["openwrt_advisory"] = {
            "status": "operator_supplied",
            "records": [{
                "package_name": item.package_name,
                "release": item.release,
                "affected_versions": json.loads(item.affected_versions_json or "[]"),
                "fixed_versions": json.loads(item.fixed_versions_json or "[]"),
                "source_url": item.source_url,
                "note": "操作员依据官方公告人工登记，需结合原文核对；仅适用于对应 release。",
            } for item in advisories],
        }
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
         "网络暴露面，以及运行时证据的存在性/新鲜度/覆盖/丢失，并如实列出缺失项。"
         "证据质量纪律（M4.2）：输出必须区分已核实事实（verified_facts，注明来源）、"
         "来源不明确的数据（unverified_observations，注明原因）与相互冲突的事实"
         "（conflicting_facts，列出双方来源）——「清单里没有」不等于「不存在」，"
         "清单不完整时必须声明",
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
         "厂商公告（Canonical/NVD/KEV/EPSS 等）语义理解、补丁状态与多源情报冲突核查。"
         "适用性专业维度（M4.2）：安装版本与受影响版本区间的关系（独立于 fixed_version "
         "单点比较）；装机发行分支与公告作用分支；厂商补丁及 backport 回移植语义"
         "（发行版回移植后「装机<上游修复版本」不等于受影响）；NVD 通用候选匹配与"
         "厂商精确公告的差异及冲突。适用性只有四种结论：已修复/不受影响/可能受影响/"
         "证据不足，以及已证实静态受影响（confirmed_affected）。"
         "M5：软件包/发行版静态适用性、实际触发条件、运行时相关活动、已证实利用必须分开。"
         "精确官方发行版、源包、版本范围与授权清单足够时可以确认静态受影响；缺少利用痕迹不能否定静态适用性。"
         "branch_check 与模型不一致须明确保留分歧，不能提高置信度消除冲突。"
         "not_affected 不是已安装某修复版本；综合 USN 其他 CVE 的版本不得归为本 CVE 专属修复。",
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
         "证据过期时必须使用 stale_verified 而不是 verified。"
         "动态证据关联语义（M4.2）：逐条证据区分组件存在/服务活跃/攻击前置条件/"
         "可疑行为/与候选 CVE 直接相关/已确认利用/无关（配真实时间与来源质量）；"
         "报告级 exploitation_relation 总结整体关联程度——可疑但与该 CVE 无关≠CVE 相关；"
         "监控缺失/能力受限≠漏洞不存在",
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
         "分层研判模型（M4.2）：适用性/运行时证据/暴露与利用条件/处置四个维度各自独立评估、"
         "各自表达证据不足与不确定性；处置结论必须综合全部维度，不以单一 CVSS/KEV/公网"
         "暴露/运行时异常字段为无条件充分依据；冲突必须显式声明消解状态。"
         "你只给出离散 risk_direction 与处置建议，不能给自由数值、不能决定自动确认、"
         "不能授予修复权限、不能生成 shell 命令；证据不足时用 follow_up_requests "
         "申请定向补充调查（有界）；补查返回更多信息本身不构成提高置信度的依据。"
         "M5 risk_direction 仅表示新证据相对于输入 baseline 的风险变化（upgrade 为风险上升，downgrade 为下降），"
         "软件包升级必须使用独立 package_change 字段。priority 综合官方优先级、静态适用性、"
         "实际触发入口、证据相关性、运行时覆盖质量；public 标签不是 CVE 公网入口，"
         "KEV/EPSS 不可用不是低风险。分别解释静态、运行时、官方覆盖与模型方差。"
         "相同事实重跑的输出差异仅为模型方差，不得声称发现新事实或风险改变。",
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
