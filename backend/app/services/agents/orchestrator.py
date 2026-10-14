"""重构后的四智能体编排（阶段三）。

程序负责：执行顺序、状态、超时、失败、重试、数据校验；
智能体负责：基于专属工具的分析。流程：

    DEVICE → VULNERABILITY → RUNTIME → RISK → REMEDIATION → VERIFY

RISK 与 VERIFY 是纯程序步骤（确定性），不调用 LLM。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from app import models
from app.database import SessionLocal
from app.services import trace_service as tracing
from app.services.agents import agents as A
from app.services.agents.base import AgentResult, ChatClient, ToolLoopAgent

STAGES = ["DEVICE", "VULNERABILITY", "RUNTIME", "RISK", "REMEDIATION", "VERIFY"]

RUNTIME_LEVEL_WEIGHT = {"NORMAL": 0, "SUSPICIOUS": 4, "ACTIVE": 8, "BLOCKED": 10}
SEVERITY_BASE = {"critical": 40, "high": 30, "medium": 18, "low": 8, "none": 0}

ClientFactory = Callable[[], ChatClient]


def default_client_factory() -> ChatClient:
    from app.config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
    if not DEEPSEEK_API_KEY:
        raise RuntimeError("未配置 DEEPSEEK_API_KEY，无法调用智能体 LLM")
    from app.services.agents.base import DeepSeekChatClient
    return DeepSeekChatClient(model=DEEPSEEK_MODEL, api_key=DEEPSEEK_API_KEY,
                              base_url=DEEPSEEK_BASE_URL)


def new_run_id() -> str:
    return "AG-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunState:
    """阶段状态机：绑定编排线程会话，每次变更即提交，供 API 轮询。

    begin/finish 同时是统一追踪的事件挂钩点（第八阶段）：trace_id 为空时
    tracing.emit 静默跳过，直接调用 run_orchestration 的既有测试零影响。
    """

    def __init__(self, db: Session, row: models.AgentOrchestrationRun):
        self.db = db
        self.row = row
        self.stages: dict[str, Any] = json.loads(row.stages_json or "{}")

    def begin(self, stage: str) -> None:
        previous = next((name for name in reversed(list(self.stages))
                         if self.stages[name].get("status") in {"succeeded", "failed"}), "")
        self.stages[stage] = {"status": "running", "started_at": _now_iso()}
        self._flush()
        if previous:
            tracing.emit(self.db, self.row.trace_id, "handoff", actor="orchestrator",
                         status="succeeded",
                         payload={"from": previous, "to": stage},
                         started_at=self.row.updated_at)
        tracing.emit(self.db, self.row.trace_id, "stage_started", actor="orchestrator",
                     status="running", payload={"stage": stage},
                     started_at=self.row.updated_at)

    def finish(self, stage: str, status: str, **fields: Any) -> None:
        entry = self.stages.get(stage, {})
        started = entry.get("started_at")
        entry.update({"status": status, "finished_at": _now_iso(), **fields})
        self.stages[stage] = entry
        self._flush()
        payload = {"stage": stage}
        if status == "failed":
            payload["error"] = str(fields.get("error", ""))[:800]
        tracing.emit(self.db, self.row.trace_id, "stage_finished", actor="orchestrator",
                     status=status, payload=payload)

    def output(self, stage: str) -> dict[str, Any]:
        return self.stages.get(stage, {}).get("output") or {}

    def _flush(self) -> None:
        self.row.stages_json = json.dumps(self.stages, ensure_ascii=False, default=str)
        self.row.updated_at = models.utcnow()
        self.db.commit()


# ── 事实校验（程序负责数据校验） ─────────────────────────────────────────────

def validate_runtime_report(db: Session, report: dict[str, Any]) -> list[str]:
    """Runtime 结论的事实校验：引用的 evidence_id 必须真实存在于库。"""
    errors: list[str] = []
    ids = set(report.get("evidence_ids") or [])
    level = report.get("behavior_level")
    if level in {"SUSPICIOUS", "ACTIVE", "BLOCKED"} and not ids:
        errors.append(f"{level} 结论没有任何 evidence_id")
    if ids:
        existing = {
            row.evidence_id
            for row in db.query(models.SecurityEvidence)
            .filter(models.SecurityEvidence.evidence_id.in_(ids)).all()
        }
        fabricated = sorted(ids - existing)
        if fabricated:
            errors.append(f"引用了不存在的 evidence_id: {fabricated[:5]}")
    return errors


def aggregate_risk(device: dict[str, Any], vulnerability: dict[str, Any],
                   runtime: dict[str, Any]) -> dict[str, Any]:
    """RISK 阶段（纯程序）：确定性聚合，不调用 LLM。"""
    severity = vulnerability.get("max_severity", "none")
    base = SEVERITY_BASE.get(severity, 0)
    kev = any(finding.get("kev") for finding in vulnerability.get("findings", []))
    if kev:
        base += 10
    level = runtime.get("behavior_level", "NORMAL")
    runtime_weight = RUNTIME_LEVEL_WEIGHT.get(level, 0)
    open_ports = len(device.get("services", []))
    exposure = min(10, open_ports * 2)
    score = min(100, base + runtime_weight + exposure)
    priority = ("critical" if score >= 80 else "high" if score >= 60
                else "medium" if score >= 35 else "low")
    return {
        "risk_score": score,
        "priority": priority,
        "severity": severity,
        "kev": kev,
        "runtime_level": level,
        "runtime_evidence_ids": runtime.get("evidence_ids", [])[:20],
        "rationale": (f"漏洞基线 {base}（{severity}{'，KEV' if kev else ''}）+ "
                      f"运行时权重 {runtime_weight}（{level}）+ 暴露面 {exposure}"
                      f"（{open_ports} 个开放服务）= {score}，优先级 {priority}"),
    }


def _installed_version(db: Session, risk: models.RiskAssessment) -> str:
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    return match.installed_version if match else ""


def _fixed_version(db: Session, risk: models.RiskAssessment) -> str:
    match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
    if match and match.fixed_version:
        return match.fixed_version
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=risk.cve_id).first()
    return vuln.fixed_version if vuln else ""


def execute_remediation_plan(db: Session, plan: dict[str, Any]) -> dict[str, Any]:
    """REMEDIATION 执行子步骤（程序）：白名单动作进入真实修复流程。

    - update_package 且存在已授权风险 → 创建真实 RemediationTask（复用现有授权语义与命令模板）；
    - 其余动作 → 登记 pending_approval，交由现有审批/设备 Harness 流程，不擅自执行。
    """
    from app.services.remediation_engine import _authorized, _package_command

    executed, pending = [], []
    for action in plan.get("actions", []):
        kind, target = action.get("action"), action.get("target", "")
        if kind == "update_package" and plan.get("risk_ref"):
            risk = db.query(models.RiskAssessment).filter(
                models.RiskAssessment.cve_id == plan["risk_ref"],
                models.RiskAssessment.active.is_(True),
            ).order_by(models.RiskAssessment.priority_rank).first()
            if risk is None:
                pending.append({"action": kind, "target": target,
                                "reason": "未找到对应风险事件，不能创建修复任务"})
                continue
            if not _authorized(risk):
                pending.append({"action": kind, "target": target, "risk_id": risk.id,
                                "reason": "风险事件未获修复授权（需人工确认），已登记待审批"})
                continue
            existing = db.query(models.RemediationTask).filter_by(risk_id=risk.id).first()
            if existing:
                executed.append({"action": kind, "target": target, "task_id": existing.id,
                                 "status": existing.status, "note": "修复任务已存在"})
                continue
            asset = db.get(models.LinuxAsset, risk.asset_id)
            task = models.RemediationTask(
                risk_id=risk.id, asset_id=risk.asset_id, cve_id=risk.cve_id,
                package_name=risk.package_name,
                current_version=_installed_version(db, risk),
                target_version=_fixed_version(db, risk),
                remediation_command=_package_command(asset.distribution if asset else "",
                                                     risk.package_name),
                mitigation=action.get("rationale", ""),
                verification_command=f"dpkg -s {risk.package_name} | grep Version",
                status="pending",
            )
            db.add(task)
            db.commit()
            executed.append({"action": kind, "target": target, "task_id": task.id,
                             "status": "created"})
        else:
            pending.append({"action": kind, "target": target,
                            "reason": "动作需要平台审批/设备 Harness 执行，LLM 无执行权"})
    return {"executed": executed, "pending_approval": pending}


def build_verify_plan(db: Session, target_host: str, remediation: dict[str, Any]) -> dict[str, Any]:
    """VERIFY 阶段（纯程序）：生成并执行只读验证检查。"""
    checks: list[dict[str, Any]] = []
    for entry in remediation.get("execution", {}).get("executed", []):
        task = db.get(models.RemediationTask, entry.get("task_id")) if entry.get("task_id") else None
        checks.append({
            "check": f"修复任务 #{entry.get('task_id')} 状态流转",
            "result": task.status if task else "missing",
            "pass": bool(task and task.status in {"pending", "in_progress", "completed", "verified"}),
        })
    checks.append({
        "check": "重新探测设备服务与组件（更新清单后复核版本）",
        "result": "planned: POST /api/devices/{device_id}/refresh",
        "pass": None,
    })
    checks.append({
        "check": "复查 eBPF 运行时证据窗口（修复前后对比）",
        "result": f"planned: GET /api/runtime/evidence/summary?device_id={target_host}",
        "pass": None,
    })
    return {"checks": checks, "rollback_hint": "修复失败时按回滚计划执行 restore_file/disable_service 还原"}


# ── 主编排 ───────────────────────────────────────────────────────────────────

def _context_for(spec: A.AgentSpec, host: str, device: dict[str, Any] | None = None,
                 feedback: list[str] | None = None) -> str:
    base = f"分析目标设备: {host}。请先调用你的工具获取真实数据再下结论。"
    if spec is A.VULNERABILITY_INTELLIGENCE_SPEC and device:
        base += (f"\n设备画像摘要: type={device.get('device_type')} "
                 f"firmware={device.get('firmware_version')}")
    if spec is A.RUNTIME_BEHAVIOR_SPEC:
        # 证据工具支持 device_id / IP / 主机名多键解析，这里明确提示可用的标识
        base += "\n运行时证据可按 device_id 或设备 IP 查询（工具会自动解析两者）。"
    if spec is A.REMEDIATION_VERIFICATION_SPEC:
        base += "\n只提出白名单动作与验证/回滚计划；执行由平台完成。"
    if feedback:
        base += (f"\n上一次输出未通过证据校验: {feedback}。"
                 "请只引用工具返回的真实 evidence_id，否则输出 NORMAL。")
    return base


def _output_summary(output: dict[str, Any] | None, limit: int = 12) -> dict[str, Any]:
    """结构化输出摘要（键级裁剪，完整输出仍在 stages_json；不含敏感原文）。"""
    if not isinstance(output, dict):
        return {}
    summary: dict[str, Any] = {}
    for key, value in list(output.items())[:limit]:
        if isinstance(value, list):
            summary[key] = {"count": len(value), "sample": value[:3]}
        elif isinstance(value, dict):
            summary[key] = {"keys": list(value)[:8]}
        else:
            summary[key] = value
    return summary


def run_orchestration(db: Session, run: models.AgentOrchestrationRun,
                      client_factory: ClientFactory = default_client_factory,
                      stage_budget_s: float = 150.0) -> models.AgentOrchestrationRun:
    state = RunState(db, run)
    state.stages = {stage: {"status": "pending"} for stage in STAGES}
    state._flush()
    host = run.target_ref
    agents_log: dict[str, Any] = {}

    def run_agent(spec, context: str) -> AgentResult:
        agent = ToolLoopAgent(spec, client_factory())
        tracing.emit(db, run.trace_id, "agent_started", actor=spec.name, status="running",
                     is_llm_step=True, payload={"agent": spec.name, "role": spec.role},
                     started_at=models.utcnow())
        agent_started = time.monotonic()
        result = agent.run(db, context=context, deadline_s=stage_budget_s)
        agents_log[spec.name] = {
            "status": result.status, "attempts": result.attempts,
            "latency_ms": result.latency_ms, "error": result.error,
            "tool_calls": [{"name": call["name"], "ok": call.get("ok", False)}
                           for call in result.tool_calls],
        }
        run.agents_json = json.dumps(agents_log, ensure_ascii=False, default=str)
        db.commit()
        # 智能体事件：结构化输出摘要 + 工具调用 + LLM 真实统计（无依据时 unavailable）
        refs: list[str] = list(result.output.get("evidence_ids") or []) if result.output else []
        if result.output:
            refs += [f.get("cve_id", "") for f in result.output.get("findings", [])
                     if isinstance(f, dict) and f.get("cve_id")]
        tracing.emit(db, run.trace_id,
                     "agent_finished" if result.status == "succeeded" else "agent_failed",
                     actor=spec.name, status=result.status, is_llm_step=True,
                     payload={
                         "agent": spec.name,
                         "attempts": result.attempts,
                         "latency_ms": result.latency_ms,
                         "error": (result.error or "")[:800],
                         "tool_calls": [{"name": c["name"], "ok": c.get("ok", False)}
                                        for c in result.tool_calls],
                         "llm": {"calls": result.llm_calls,
                                 "model": result.llm_model or "unavailable",
                                 "llm_tokens": result.llm_usage or "unavailable"},
                         "output_summary": _output_summary(result.output),
                     },
                     evidence_refs=refs,
                     duration_ms=result.latency_ms)
        return result


    # DEVICE
    state.begin("DEVICE")
    result = run_agent(A.DEVICE_INTELLIGENCE_SPEC, _context_for(A.DEVICE_INTELLIGENCE_SPEC, host))
    if result.status != "succeeded":
        state.finish("DEVICE", "failed", error=result.error)
        return _complete(db, run, "failed", f"DEVICE 阶段失败: {result.error}")
    state.finish("DEVICE", "succeeded", output=result.output)

    # VULNERABILITY
    state.begin("VULNERABILITY")
    result = run_agent(A.VULNERABILITY_INTELLIGENCE_SPEC,
                       _context_for(A.VULNERABILITY_INTELLIGENCE_SPEC, host, device=result.output))
    if result.status == "succeeded":
        state.finish("VULNERABILITY", "succeeded", output=result.output)
    else:
        state.finish("VULNERABILITY", "failed", error=result.error)

    # RUNTIME：证据事实校验 + 一次带反馈重试（程序负责校验与重试）
    state.begin("RUNTIME")
    runtime_output = None
    feedback: list[str] | None = None
    for attempt in range(2):
        result = run_agent(A.RUNTIME_BEHAVIOR_SPEC,
                           _context_for(A.RUNTIME_BEHAVIOR_SPEC, host, feedback=feedback))
        if result.status != "succeeded":
            state.finish("RUNTIME", "failed", error=result.error)
            break
        errors = validate_runtime_report(db, result.output)
        if not errors:
            runtime_output = result.output
            state.finish("RUNTIME", "succeeded", output=runtime_output)
            break
        agents_log.setdefault(A.RUNTIME_BEHAVIOR_SPEC.name, {})["evidence_validation_errors"] = errors
        run.agents_json = json.dumps(agents_log, ensure_ascii=False, default=str)
        db.commit()
        feedback = errors
    if runtime_output is None:
        runtime_output = {"behavior_level": "NORMAL", "evidence_ids": [], "findings": [],
                          "degraded": True,
                          "note": "运行时智能体输出未通过证据校验，按无证据处理（不升级风险）"}
        if "RUNTIME" not in state.stages or state.stages["RUNTIME"].get("status") == "running":
            state.finish("RUNTIME", "failed", error="; ".join(feedback or []))

    # RISK（纯程序）
    state.begin("RISK")
    risk = aggregate_risk(state.output("DEVICE"), state.output("VULNERABILITY"), runtime_output)
    run.risk_json = json.dumps(risk, ensure_ascii=False, default=str)
    state.finish("RISK", "succeeded", output=risk)

    # REMEDIATION
    state.begin("REMEDIATION")
    result = run_agent(A.REMEDIATION_VERIFICATION_SPEC,
                       _context_for(A.REMEDIATION_VERIFICATION_SPEC, host))
    if result.status != "succeeded":
        plan = {"actions": [], "note": "修复方案生成失败，不执行任何动作"}
        state.finish("REMEDIATION", "failed", error=result.error)
    else:
        plan = result.output
        plan["execution"] = execute_remediation_plan(db, plan)
        state.finish("REMEDIATION", "succeeded", output=plan)
    run.remediation_json = json.dumps(plan, ensure_ascii=False, default=str)
    db.commit()

    # VERIFY（纯程序）
    state.begin("VERIFY")
    verify = build_verify_plan(db, host, plan)
    run.verify_json = json.dumps(verify, ensure_ascii=False, default=str)
    state.finish("VERIFY", "succeeded", output=verify)

    return _complete(db, run, "completed", "")


def _complete(db: Session, run: models.AgentOrchestrationRun, status: str, error: str) -> models.AgentOrchestrationRun:
    run.status = status
    run.error = error
    run.completed_at = models.utcnow()
    db.commit()
    stages = json.loads(run.stages_json or "{}")
    risk = json.loads(run.risk_json or "{}")
    tracing.finish_trace(db, run.trace_id, status, error=error, summary={
        "stages": {name: entry.get("status") for name, entry in stages.items()},
        "risk_score": risk.get("risk_score"), "priority": risk.get("priority"),
        "runtime_level": risk.get("runtime_level"),
        "agents": sorted(json.loads(run.agents_json or "{}").keys()),
    })
    return run


def _target_capability_marks(db: Session, target_type: str, target_ref: str) -> dict[str, Any] | None:
    """目标设备能力边界（如实标注）：Zephyr 等嵌入式 OS 的 unsupported 项。"""
    if target_type != "device":
        return None
    device = db.query(models.IotDevice).filter_by(device_id=target_ref).one_or_none()
    if device is None:
        return None
    from app.services.discovery_pipeline import _capability_marks
    return _capability_marks(device)


def start_analysis(target_ref: str, target_type: str = "device",
                   client_factory: ClientFactory = default_client_factory) -> models.AgentOrchestrationRun:
    """创建运行记录并在后台线程执行编排（API 入口）。

    第八阶段：每次分析生成统一 trace_id（唯一），编排内全部智能体步骤、
    阶段与交接事件共享该 trace_id；目标能力边界（如 Zephyr unsupported）如实记录。
    """
    db = SessionLocal()
    try:
        marks = _target_capability_marks(db, target_type, target_ref)
        trace = tracing.start_trace(
            db, task_type="four_agent_analysis", target_type=target_type, target_ref=target_ref,
            run_ref_type="agent_orchestration", run_ref_id="pending",
            metadata={"capability_marks": marks} if marks else {})
        run = models.AgentOrchestrationRun(
            run_id=new_run_id(), target_type=target_type, target_ref=target_ref,
            status="running", trace_id=trace.trace_id,
            stages_json=json.dumps({stage: {"status": "pending"} for stage in STAGES}),
        )
        db.add(run)
        db.commit()
        trace.run_ref_id = run.run_id
        db.commit()
        if marks:
            tracing.emit(db, trace.trace_id, "capability_marks", actor="pipeline",
                         status="unsupported", payload={"target": target_ref, "capabilities": marks})

        def worker() -> None:
            worker_db = SessionLocal()
            try:
                row = worker_db.query(models.AgentOrchestrationRun).filter_by(run_id=run.run_id).one()
                run_orchestration(worker_db, row, client_factory=client_factory)
            except Exception as exc:  # 编排级异常：整体失败并保留阶段状态
                try:
                    row.status = "failed"
                    row.error = f"orchestrator: {type(exc).__name__}: {exc}"
                    row.completed_at = models.utcnow()
                    worker_db.commit()
                    tracing.finish_trace(worker_db, row.trace_id, "failed",
                                         error=row.error, summary={"stage": "orchestrator_crash"})
                except Exception:
                    pass
            finally:
                worker_db.close()

        threading.Thread(target=worker, daemon=True).start()
        time.sleep(0.2)
        return run
    finally:
        db.close()
