"""整链黑盒回归：Harness 是否真的嵌在四智能体研判里，并能否闭环。

本模块只用"外部契约"做断言，与 scripts/agent_blackbox.py（真环境 HTTP 检测器）
对应，区别是这里跑在隔离 SQLite + 假模型客户端上，不触网、不碰真实库：

1. `test_pipeline_harness_precheck_gates_plan`：四角色图跑完后，
   `harness_precheck` 必须是真实阶段；候选意图来自模型计划、绑定确定性身份、
   永不携带执行权；计划恒为 requires_approval，且编排期不得创建任何 HarnessRun。
2. `test_write_switch_off_blocks_plan_terminally`：写开关关闭时预检终止
   （policy_denied），计划执行方式为 blocked，且不产生计划反馈轮次。
3. `test_harness_task_links_shadow_candidate_and_closes`：影子研判 → Harness 计划
   （绑定影子候选）→ 执行 → 结果与工具调用无副作用 → 反向链接出现在运行详情与
   Trace 事件里；只读任务不得走审批路径。
4. `test_blocked_ubuntu_plan_execute_is_contract_error`：已阻断的 Ubuntu 修复
   计划执行时必须返回契约错误（ValueError → 409），而不是 KeyError → 500。
   —— 该缺陷由真环境黑盒检测首次暴露。
"""
from __future__ import annotations

import json
import re

import pytest

from app import models
from app.services import agent_harness as harness, ubuntu_repair
from app.services.matching_engine import run_matching
from app.services.unified import harness_bridge
from app.services.unified.agent_base import UsageMeter
from app.services.unified.graph import RunContext, build_graph
from app.services.unified.state import TASK_RISK_REVIEW, UnifiedAnalysisState, empty_state
from test_iot_upgrade import add_advisory, seed_openwrt
from test_unified_harness_bridge import bridge_rig  # noqa: F401  作为 pytest fixture 复用

ASSET_PROMPT = "资产与证据调查员"
VULN_PROMPT = "漏洞分析师"
RUNTIME_PROMPT = "运行时分析师"
DECISION_PROMPT = "研判与处置规划师"


def json_response(payload):
    return {"content": json.dumps(payload, ensure_ascii=False), "tool_calls": []}


class ScriptedClient:
    """按角色前缀匹配脚本响应的假模型客户端（线程安全，供并行分支共用）。"""

    def __init__(self, script):
        import threading
        self.script = script
        self.prompts = []
        self._lock = threading.Lock()

    def complete(self, messages, tools=None):
        system, user = messages[0]["content"], messages[-1]["content"]
        with self._lock:
            self.prompts.append(system + "||" + user)
            for key, queue in self.script.items():
                if key in system:
                    if not queue:
                        return {"content": "{}", "tool_calls": []}
                    response = queue.pop(0)
                    break
            else:
                return {"content": "{}", "tool_calls": []}
        # 脚本项可以是可调用对象：决策角色按提示词里真实出现的证据 ID 作答，
        # 模拟"只引用材料中存在的证据"的合规模型，而不是硬编码猜测 ID。
        return response(messages) if callable(response) else response


def asset_report(hostname):
    return {
        "device_id": hostname, "device_type": "iot_gateway", "os": "OpenWrt 24.10.2",
        "services": [{"port": 1883, "service_type": "mqtt", "product": "mosquitto"}],
        "evidence_inventory": {"runtime_evidence_present": False, "evidence_freshness": "stale"},
        "evidence_quality": "partial", "confidence": 0.6,
        "data_gaps": ["缺少新鲜运行时心跳"],
    }


def vulnerability_report():
    return {
        "findings": [{"cve_id": "CVE-2099-9999", "cvss_score": 7.5, "kev": False,
                      "version_impact": "affected", "applicability": "confirmed_affected",
                      "confidence": 0.7}],
        "max_observed_severity": "high", "confidence": 0.7,
    }


def runtime_report():
    return {"behavior_level": "NORMAL", "runtime_status": "unavailable",
            "evidence_freshness": "none", "exposure_status": "internal_reachable",
            "evidence_ids": [], "findings": [],
            "missing_evidence": ["采集心跳过期，运行时尚无可信事件"]}


def available_evidence_id(prompt: str) -> str:
    """从决策提示词里的 available_evidence_ids 取一个真实存在的证据 ID。"""
    match = re.search(r'"available_evidence_ids":\s*\[(.*?)\]', prompt, re.S)
    ids = re.findall(r'"([^"]+)"', match.group(1)) if match else []
    return ids[0] if ids else ""


def decision_report(risk_id):
    """模型给出的处置计划：提案可写，但执行权只能由审批链授予。"""

    def respond(messages):
        evidence = available_evidence_id(messages[-1]["content"])
        cited = [evidence] if evidence else []
        return json_response({
            "verdicts": [{
                "object_id": f"risk-{risk_id}", "impact_status": "confirmed_affected",
                "risk_direction": "maintain", "recommended_action": "scheduled_fix",
                "recommended_priority": "medium", "confidence": 0.7,
                "runtime_evidence_validity": "unavailable",
                "urgency_basis": "static_evidence_only",
                "applicability_dimension": {"status": "established",
                                            "conclusion": "官方公告版本区间命中",
                                            "supporting_evidence_ids": cited},
                "runtime_dimension": {"status": "insufficient_evidence",
                                      "conclusion": "采集心跳过期",
                                      "gaps": ["新鲜运行时证据"]},
                "exposure_dimension": {"status": "partial",
                                       "conclusion": "内网 MQTT 端口",
                                       "supporting_evidence_ids": cited},
                "supporting_evidence_ids": cited,
                "reason": "官方公告版本区间命中，等待操作员审批"}],
            "key_evidence_checks": [{"evidence_id": item, "check": "存在性", "passed": True}
                                    for item in cited],
            "response_plan": {"risk_ref": "CVE-2099-9999",
                              "actions": [{"action": "update_package", "target": "mosquitto",
                                           "rationale": "受影响的 mosquitto 版本"}],
                              "rollback_plan": ["保留回退产物"]},
            "confidence": 0.7, "reason": "证据引用完整"})

    return respond


def seed_runtime_evidence(db, asset):
    """给被测资产落一条真实运行时证据：证据注册表由此获得可引用 ID。"""
    db.add(models.SecurityEvidence(evidence_id="SE-1", device_id=asset.hostname,
                                   asset_id=asset.id, source="ebpf_bpftrace",
                                   evidence_type="process", timestamp="2026-10-20T00:00:00Z",
                                   process="mosquitto", commandline="mosquitto -c /etc/mosquitto.conf",
                                   description="隔离回归夹具：MQTT 服务进程"))
    db.commit()


def build_state(rig):
    state = empty_state("UA-BLACKBOX-1", TASK_RISK_REVIEW, rig.asset.hostname,
                        "linux_host", "shadow")
    state.object_id = f"risk-{rig.risk.id}"
    state.baseline = {
        "object_id": f"risk-{rig.risk.id}", "match_status": "affected",
        "preliminary_level": "High", "preliminary_score": 70.0,
        "installed_version": "2.0.1-1", "fixed_version": "2.0.2-1",
        "package_name": "mosquitto", "cve_id": "CVE-2099-9999",
    }
    return state


def run_full_graph(rig, session_factory, decisions):
    # 决策角色可能出现"模型自纠重试"，因此同一脚本允许重复命中。
    decision = decisions[0]
    client = ScriptedClient({
        ASSET_PROMPT: [json_response(asset_report(rig.asset.hostname))],
        VULN_PROMPT: [json_response(vulnerability_report())],
        RUNTIME_PROMPT: [json_response(runtime_report())],
        DECISION_PROMPT: [decision] * 3,
    })
    ctx = RunContext(db_factory=session_factory, trace_id="", meter=UsageMeter(),
                     client_factory=lambda: client, risk=rig.risk, force_full_review=True)
    result = build_graph(ctx).invoke(build_state(rig))
    if isinstance(result, dict):
        result = UnifiedAnalysisState.model_validate(result)
    return result, client


def test_pipeline_harness_precheck_gates_plan(bridge_rig, session_factory, monkeypatch):  # noqa: F811
    """Harness 预检是四智能体链路的一个真实阶段，且模型计划永远只是提案。"""
    rig = bridge_rig
    # 写开关打开只用于让预检进入"待审批"分支；本用例不触发任何设备写。
    monkeypatch.setattr(harness_bridge, "_write_policy", lambda asset: (True, ""))
    seed_runtime_evidence(rig.db, rig.asset)
    final, client = run_full_graph(rig, session_factory, [decision_report(rig.risk.id)])
    assert client.prompts, "四角色应至少被调用一次"

    assert final.stage_status.get("harness_precheck") == "succeeded"
    feedback = final.harness_feedback
    assert feedback.get("contract") == harness_bridge.CONTRACT
    assert feedback.get("read_only") is True
    assert feedback.get("execution_authorized") is False
    assert feedback.get("device_writes") is False
    assert feedback.get("status") == "authorization_required", (
        feedback.get("status"), feedback.get("reasons"))

    intents = final.candidate_intents
    assert intents, "模型计划的候选意图必须进入图状态"
    assert all(item["execution_authorized"] is False for item in intents)
    assert all(item["requires_approval"] is True for item in intents)
    assert intents[0]["asset_id"] == rig.asset.id
    assert intents[0]["risk_id"] == rig.risk.id

    plan = final.final["plan"]
    assert plan["requires_approval"] is True
    assert final.final["plan_execution_mode"] == "pending_approval"
    # 编排期只做元数据预检：绝不落 HarnessRun、绝不派发任务。
    assert rig.db.query(models.HarnessRun).count() == 0
    assert final.plan_feedback_used == 0


def test_write_switch_off_blocks_plan_terminally(bridge_rig, session_factory):  # noqa: F811
    """写开关关闭 → 预检终止 → 计划标为 blocked，且不消耗计划反馈轮次。"""
    rig = bridge_rig
    seed_runtime_evidence(rig.db, rig.asset)
    final, _ = run_full_graph(rig, session_factory, [decision_report(rig.risk.id)])

    assert final.stage_status.get("harness_precheck") == "succeeded"
    feedback = final.harness_feedback
    assert feedback.get("terminal") is True
    assert feedback.get("status") == "policy_denied"
    assert "production_device_write_disabled" in (feedback.get("reasons") or [])
    assert final.collaboration_stop_reason == "policy_denied"
    assert final.final["plan_execution_mode"] == "blocked"
    assert final.final["plan"]["requires_approval"] is True
    assert final.plan_feedback_used == 0
    assert rig.db.query(models.HarnessRun).count() == 0


def test_harness_task_links_shadow_candidate_and_closes(session_factory, client, control_headers):
    """影子研判 → Harness 计划绑定该候选 → 只读执行闭环 → 反向链接与 Trace 可查。"""
    with session_factory() as db:
        asset = seed_openwrt(db)
        add_advisory(db)
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).one()
        risk = models.RiskAssessment(asset_id=asset.id, match_id=match.id, cve_id=match.cve_id,
                                     package_name=match.package_name,
                                     review_status="human_confirmed", human_review_required=False)
        db.add(risk)
        db.commit()
        shadow = models.UnifiedAnalysisRun(
            run_id="UA-BLACKBOX-SHADOW", task_type="risk_review", target_type="linux_host",
            target_ref=asset.hostname, mode="shadow", status="completed", risk_id=risk.id,
            plan_json=json.dumps({"actions": [{"action": "collect_evidence",
                                               "target": match.package_name}]}))
        db.add(shadow)
        db.commit()
        asset_id, risk_id = asset.id, risk.id

    created = client.post("/api/harness/runs", headers=control_headers, json={
        "asset_id": asset_id, "risk_id": risk_id, "goal": "investigate",
        "shadow_run_id": "UA-BLACKBOX-SHADOW"})
    assert created.status_code == 200, created.text
    run = created.json()
    assert run["status"] == "pending"
    assert run["plan"]["shadow_candidate"]["run_id"] == "UA-BLACKBOX-SHADOW"
    # 影子候选只是"待审批计划的来源"，不构成任何修复授权。
    assert run["plan"]["shadow_candidate"]["authorization"] == "none"

    # 只读任务没有审批前置：审批入口必须拒绝，不能出现"假审批"。
    approved = client.post(f"/api/harness/runs/{run['id']}/approve", headers=control_headers,
                           json={"plan_hash": run["plan_hash"], "actor": "blackbox",
                                 "reason": "只读任务不应存在审批环节"})
    assert approved.status_code == 409

    executed = client.post(f"/api/harness/runs/{run['id']}/execute", headers=control_headers)
    assert executed.status_code == 200, executed.text
    detail = client.get(f"/api/harness/runs/{run['id']}").json()
    assert detail["status"] in {"completed", "needs_evidence"}, detail.get("error")
    calls = detail["tool_calls"]
    assert calls, "执行必须留下工具调用记录"
    assert not any(call["side_effect"] for call in calls)
    assert {call["tool"] for call in calls} <= {
        "collect_inventory", "inspect_inventory", "inspect_runtime", "inspect_evidence"}
    assert detail["plan_hash"] == run["plan_hash"]
    assert detail["trace_id"]

    # 反向链接：从运行详情能看到绑定到本次影子候选的 Harness 任务。
    linked = client.get("/api/unified/runs/UA-BLACKBOX-SHADOW").json()
    assert [item["id"] for item in linked["harness_checks"]] == [run["id"]]
    assert linked["harness_checks"][0]["plan"]["shadow_candidate"]["run_id"] == "UA-BLACKBOX-SHADOW"

    trace = client.get(f"/api/traces/{detail['trace_id']}").json()
    types = {event["event_type"] for event in trace["events"]}
    assert {"harness_plan", "harness_execute_started", "harness_finished"} <= types
    view = client.get(f"/api/traces/{detail['trace_id']}/harness").json()
    assert view["association"] == "linked"
    assert view["harness"]["id"] == run["id"]


def _ubuntu_asset(db):
    asset = models.LinuxAsset(hostname="blackbox-ubuntu", ip_address="192.168.50.30",
                              distribution="ubuntu", os_version="24.04",
                              inventory_complete=True)
    db.add(asset)
    db.commit()
    connection = models.DeviceConnection(asset_id=asset.id, host="192.168.50.30",
                                        key_path_env="LINUXGUARD_DEVICE_TEST",
                                        host_key_sha256="SHA256:" + "A" * 43, enabled=True)
    risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2099-0001", active=True,
                                 review_status="human_confirmed", human_review_required=False)
    db.add_all([connection, risk])
    db.commit()
    return asset, connection, risk


def test_blocked_ubuntu_plan_execute_is_contract_error(session_factory, monkeypatch):
    """已阻断/残缺的 Ubuntu 计划执行时必须是契约错误（409），不能 500。

    真环境黑盒检测（scripts/agent_blackbox.py，2026-10-20）实测到
    `POST /api/harness/runs/{id}/execute` 对 blocked 计划返回 500：
    `validate()` 用 plan["node_id"] 直接下标，阻断计划没有该键 → KeyError。
    """
    monkeypatch.setenv("LINUXGUARD_DEPLOYMENT_MODE", "standard")
    with session_factory() as db:
        asset, connection, risk = _ubuntu_asset(db)
        blocked_plan = {"adapter": "ubuntu-apt-v1", "goal": "repair",
                        "blocked_reasons": ["需要当前资产的有效 curl 风险"]}
        blocked = models.HarnessRun(
            id="bb-blocked", asset_id=asset.id, risk_id=risk.id, connection_id=connection.id,
            status="blocked", plan_json=json.dumps(blocked_plan),
            plan_hash=harness.digest(blocked_plan))
        db.add(blocked)
        db.commit()
        with pytest.raises(ValueError) as exc:
            ubuntu_repair.queue(db, blocked, "execute")
        assert "阻断" in str(exc.value)

        # 状态被改成 approved 但计划字段残缺：同样必须是 ValueError，不是 KeyError。
        broken_plan = {"adapter": "ubuntu-apt-v1", "goal": "repair"}
        broken = models.HarnessRun(
            id="bb-broken", asset_id=asset.id, risk_id=risk.id, connection_id=connection.id,
            status="approved", plan_json=json.dumps(broken_plan),
            plan_hash=harness.digest(broken_plan), approval_hash=harness.digest(broken_plan))
        db.add(broken)
        db.commit()
        with pytest.raises(ValueError) as exc:
            ubuntu_repair.queue(db, broken, "execute")
        assert "绑定已变化" in str(exc.value)
