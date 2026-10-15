"""确定性设备级风险聚合（System A aggregate_risk 的 F5 修复版）。

F5 修复：`version_impact ∈ {fixed, not_affected}` 的 finding 不计入基线分——
已修复/不受影响的组件不得按 CVSS 计分；扣减在 rationale 中显式说明。
其余权重语义与 System A 保持一致（severity 基线 / KEV +10 / 运行时等级权重 /
暴露面 ≤10），优先级阈值不变——保证与历史数据可比。
"""
from __future__ import annotations

from typing import Any

RUNTIME_LEVEL_WEIGHT = {"NORMAL": 0, "SUSPICIOUS": 4, "ACTIVE": 8, "BLOCKED": 10}
SEVERITY_BASE = {"critical": 40, "high": 30, "medium": 18, "low": 8, "none": 0}


def _score_to_severity(score: float) -> str:
    return ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 4 else "low" if score > 0 else "none")


def aggregate_device_risk(investigation: dict[str, Any] | None,
                          vulnerability: dict[str, Any] | None,
                          runtime: dict[str, Any] | None) -> dict[str, Any]:
    """设备级确定性聚合。LLM 输出只作为 finding/等级输入，分数由本函数计算。"""
    investigation = investigation or {}
    vulnerability = vulnerability or {}
    runtime = runtime or {}

    counted, excluded = [], []
    kev_on_counted = False
    for finding in vulnerability.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        impact = finding.get("version_impact")
        if impact in {"fixed", "not_affected"}:
            excluded.append(finding)
        else:
            counted.append(finding)
            kev_on_counted = kev_on_counted or bool(finding.get("kev"))

    severity = "none"
    for finding in counted:
        level = _score_to_severity(float(finding.get("cvss_score") or 0))
        if SEVERITY_BASE.get(level, 0) > SEVERITY_BASE.get(severity, 0):
            severity = level
    base = SEVERITY_BASE.get(severity, 0)
    if kev_on_counted:
        base += 10

    level = runtime.get("behavior_level", "NORMAL")
    runtime_weight = RUNTIME_LEVEL_WEIGHT.get(level, 0)

    services = investigation.get("services") or []
    open_ports = len(services) or len(investigation.get("open_ports") or [])
    exposure = min(10, open_ports * 2)
    score = min(100, base + runtime_weight + exposure)
    priority = ("critical" if score >= 80 else "high" if score >= 60
                else "medium" if score >= 35 else "low")

    rationale = (f"漏洞基线 {base}（{severity}{'，KEV' if kev_on_counted else ''}；"
                 f"计入 {len(counted)} 条，剔除已修复/不受影响 {len(excluded)} 条——F5）+ "
                 f"运行时权重 {runtime_weight}（{level}）+ 暴露面 {exposure}"
                 f"（{open_ports} 个开放服务）= {score}，优先级 {priority}")
    if excluded:
        excluded_ids = ", ".join(str(f.get("cve_id", "?")) for f in excluded[:5])
        rationale += f"；剔除项：{excluded_ids}（version_impact=fixed/not_affected 不计分）"

    return {
        "risk_score": score,
        "priority": priority,
        "severity": severity,
        "kev": kev_on_counted,
        "runtime_level": level,
        "runtime_status": runtime.get("runtime_status", "not_observed"),
        "runtime_evidence_ids": (runtime.get("evidence_ids") or [])[:20],
        "findings_counted": len(counted),
        "findings_excluded_f5": [f.get("cve_id", "") for f in excluded],
        "rationale": rationale,
    }
