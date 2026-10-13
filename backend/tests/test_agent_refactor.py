"""阶段三：四智能体重构测试。

用剧本化 LLM 客户端（ScriptedClient）驱动真实工具与真实项目数据：
IoT/主机资产、CVE/KEV/EPSS 情报、授权风险事件、以及阶段二真实采集的
eBPF SecurityEvidence（tests/fixtures/ebpf_real_capture.jsonl）。
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app import models
from app.services.agents import agents as A
from app.services.agents.base import ToolLoopAgent, parse_structured_output
from app.services.agents import orchestrator
from app.services.ebpf_event_collector import append_events

FIXTURE = Path(__file__).parent / "fixtures" / "ebpf_real_capture.jsonl"
HOST = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])["hostname"]
CVE = "CVE-2026-49975"

ROLE_MARKERS = {
    "device_intelligence_agent": "设备情报智能体",
    "vulnerability_intelligence_agent": "漏洞情报智能体",
    "runtime_behavior_agent": "运行时行为智能体",
    "remediation_verification_agent": "修复与验证智能体",
}


class ScriptedClient:
    """按智能体剧本推进：先真实调用专属工具，再产出结构化 JSON。

    runtime 剧本是「反应式」的：最终结论里的 evidence_id 从工具真实返回中提取，
    也可按测试需要强制伪造（fabricate_evidence=True）。
    """

    def __init__(self, *, behavior_level: str = "SUSPICIOUS",
                 fabricate_evidence: bool = False,
                 remediation_actions: list[dict] | None = None,
                 runtime_script: str = "valid"):
        self.behavior_level = behavior_level
        self.fabricate_evidence = fabricate_evidence
        self.remediation_actions = remediation_actions
        self.runtime_script = runtime_script
        self.queues: dict[str, list[dict[str, Any]]] = {
            "device_intelligence_agent": [
                {"tool_calls": [{"id": "c1", "name": "query_device_profile",
                                 "arguments": {"host": HOST}}]},
                {"final": "device"},
            ],
            "vulnerability_intelligence_agent": [
                {"tool_calls": [{"id": "c2", "name": "query_cve_intelligence",
                                 "arguments": {"cve_id": CVE}},
                                {"id": "c3", "name": "query_version_impact",
                                 "arguments": {"cve_id": CVE,
                                               "installed_version": "1.1.1-1ubuntu0.1"}}]},
                {"final": "vulnerability"},
            ],
            "runtime_behavior_agent": [
                {"tool_calls": [
                    {"id": "c4", "name": "query_process_evidence", "arguments": {"device_id": HOST}},
                    {"id": "c5", "name": "query_network_evidence", "arguments": {"device_id": HOST}},
                    {"id": "c6", "name": "query_file_evidence", "arguments": {"device_id": HOST}},
                ]},
                {"final": "runtime"},
            ],
            "remediation_verification_agent": [
                {"tool_calls": [{"id": "c7", "name": "query_remediation_targets",
                                 "arguments": {"host": HOST}},
                                {"id": "c8", "name": "query_remediation_options",
                                 "arguments": {"cve_id": CVE, "package_name": "openssl",
                                               "host": HOST}}]},
                {"final": "remediation"},
            ],
        }

    def _agent(self, messages) -> str:
        system = messages[0]["content"]
        for name, marker in ROLE_MARKERS.items():
            if marker in system:
                return name
        raise AssertionError(f"未知智能体系统消息: {system[:60]}")

    def complete(self, messages, tools=None):
        agent = self._agent(messages)
        queue = self.queues[agent]
        if queue:
            step = queue.pop(0)
            if "tool_calls" in step:
                return {"content": None, "tool_calls": step["tool_calls"]}
            self._final_key = getattr(self, "_final_key", {})
            self._final_key[agent] = step["final"]
        # 队列耗尽（编排器带反馈重试）时重复最终输出剧本
        final_key = getattr(self, "_final_key", {}).get(agent)
        if final_key is None:
            raise AssertionError(f"{agent} 没有可用的最终输出剧本")
        builder = getattr(self, f"_final_{final_key}")
        return {"content": json.dumps(builder(messages), ensure_ascii=False), "tool_calls": []}

    def _tool_results(self, messages) -> list[dict]:
        results = []
        for message in messages:
            if message.get("role") == "tool":
                try:
                    results.append(json.loads(message["content"]))
                except (json.JSONDecodeError, KeyError):
                    pass
        return results

    def _final_device(self, messages):
        profile = next((r for r in self._tool_results(messages) if r.get("found")), {})
        return {
            "device_id": profile.get("device_id", HOST), "device_type": profile.get("device_type", "linux_server"),
            "vendor": profile.get("vendor", ""), "model": profile.get("model", ""),
            "firmware_version": profile.get("firmware_version", ""),
            "services": [{"port": s["port"], "service_type": str(s.get("service_type") or s.get("product") or ""),
                          "product": str(s.get("product") or "")} for s in profile.get("services", [])],
            "components": [{"name": c["name"], "version": c.get("version", ""), "type": c.get("type", "software")}
                           for c in profile.get("components", [])],
            "exposure_summary": "管理服务暴露，SSH/MQTT 在线", "confidence": 0.9, "data_gaps": [],
        }

    def _final_vulnerability(self, messages):
        intel = next((r for r in self._tool_results(messages) if "vulnerabilities" in r), {})
        findings = []
        for item in intel.get("vulnerabilities", []):
            impact = next((r for r in self._tool_results(messages)
                           if r.get("cve_id") == item["cve_id"] and "version_impact" in r), {})
            findings.append({
                "cve_id": item["cve_id"], "cvss_score": item["cvss_score"], "kev": item["kev"],
                "epss_score": item["epss_score"],
                "installed_version": impact.get("installed_version", ""),
                "fixed_version": impact.get("fixed_version", item.get("fixed_version", "")),
                "version_impact": impact.get("version_impact", "unknown"),
                "confidence": 0.9, "sources": [item["source"]],
            })
        return {"findings": findings, "max_severity": "critical", "confidence": 0.85, "data_gaps": []}

    def _final_runtime(self, messages):
        if self.behavior_level == "NORMAL":
            return {"behavior_level": "NORMAL", "evidence_ids": [], "findings": [],
                    "scope": "全部证据", "confidence": 0.8, "data_gaps": []}
        if self.fabricate_evidence:
            return {"behavior_level": "ACTIVE",
                    "evidence_ids": ["SE-FABRICATED0001", "SE-FABRICATED0002"],
                    "findings": [{"aspect": "process", "evidence_id": "SE-FABRICATED0001",
                                  "description": "伪造的攻击判断"}],
                    "scope": "all", "confidence": 0.9, "data_gaps": []}
        picked, findings = [], []
        for aspect in ("process", "network", "file"):
            payload = next((r for r in self._tool_results(messages) if r.get("events") and
                            r["events"] and "destination_ip" in r["events"][0] or
                            (r.get("events") and aspect == "process" and "ppid" in r["events"][0]) or
                            (r.get("events") and aspect == "file" and "file_path" in r["events"][0]) or
                            (r.get("events") and aspect == "network" and "destination_ip" in r["events"][0])), None)
            if payload and payload.get("events"):
                event = payload["events"][0]
                picked.append(event["evidence_id"])
                findings.append({"aspect": aspect, "evidence_id": event["evidence_id"],
                                 "description": f"{aspect} 真实证据：{event.get('process')} {event.get('commandline', '')[:60]}"})
        level = self.behavior_level if picked else "NORMAL"
        return {"behavior_level": level, "evidence_ids": picked, "findings": findings,
                "scope": "进程/网络/文件证据", "confidence": 0.85, "data_gaps": []}

    def _final_remediation(self, messages):
        actions = self.remediation_actions if self.remediation_actions is not None else [
            {"action": "update_package", "target": "openssl",
             "params": {"package": "openssl"}, "rationale": "版本低于修复版本，升级消除命中",
             "expected_verification": "dpkg 版本变为修复版本", "requires_approval": False},
            {"action": "backup_file", "target": "/etc/ssl/openssl.cnf",
             "params": {"path": "/etc/ssl/openssl.cnf"}, "rationale": "升级前备份配置",
             "requires_approval": True},
        ]
        return {
            "risk_ref": CVE, "actions": actions,
            "verification_plan": [
                {"check": "复核软件包版本", "evidence_source": "重新探测设备清单"},
                {"check": "复查运行时证据窗口", "evidence_source": "SecurityEvidence"},
            ],
            "rollback_plan": ["restore_file /etc/ssl/openssl.cnf 备份"],
            "confidence": 0.85, "data_gaps": [],
        }


def make_factory(client: ScriptedClient):
    return lambda: client


# ── 测试数据：真实项目模型 + 阶段二真实 eBPF 采集 ────────────────────────────

@pytest.fixture()
def project_data(session_factory):
    db = session_factory()
    asset = models.LinuxAsset(hostname=HOST, ip_address="127.0.0.1", os_name="Ubuntu",
                              os_version="22.04", distribution="ubuntu")
    db.add(asset)
    db.flush()
    db.add_all([
        models.AssetService(asset_id=asset.id, service_name="sshd", port=22, process_name="sshd"),
        models.AssetService(asset_id=asset.id, service_name="mosquitto", port=1883, process_name="mosquitto"),
        models.AssetPackage(asset_id=asset.id, package_name="openssl", package_version="1.1.1-1ubuntu0.1"),
    ])
    vuln = models.VulnerabilityInfo(cve_id=CVE, title="OpenSSL 缓冲区溢出", cvss_score=9.8,
                                    cvss_severity="Critical", affected_package="openssl",
                                    fixed_version="1.1.1-1ubuntu0.2", source="nvd")
    db.add(vuln)
    db.add(models.ThreatIntelSource(cve_id=CVE, is_kev=True, epss_score=0.94, epss_percentile=0.99))
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=CVE, package_name="openssl",
                                      installed_version="1.1.1-1ubuntu0.1",
                                      fixed_version="1.1.1-1ubuntu0.2", affected=True,
                                      match_status="potentially_affected",
                                      reason_code="installed_version_below_fixed", confidence=0.92,
                                      active=True)
    db.add(match)
    db.flush()
    risk = models.RiskAssessment(match_id=match.id, asset_id=asset.id, cve_id=CVE,
                                 package_name="openssl", review_status="auto_confirmed",
                                 human_review_required=False, risk_level="Medium",
                                 active=True, final_score=55)
    db.add(risk)
    db.commit()
    events = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").strip().splitlines()]
    append_events(events, db=db)
    try:
        yield {"asset": asset, "risk": risk, "match": match}
    finally:
        db.close()


def _run(db, project_data, client: ScriptedClient):
    row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="linux_host",
                                       target_ref=HOST, status="running", stages_json="{}")
    db.add(row)
    db.commit()
    return orchestrator.run_orchestration(db, row, client_factory=make_factory(client)), row


# ── 规格：四个智能体、职责不同、工具互不重叠 ─────────────────────────────────

def test_agent_specs_distinct_roles_and_disjoint_tools():
    assert len(A.ALL_SPECS) == 4
    tool_sets = []
    for spec in A.ALL_SPECS:
        assert len(spec.tools) >= 3
        assert spec.role and spec.output_model
        tool_sets.append({tool.name for tool in spec.tools})
    for i in range(4):
        for j in range(i + 1, 4):
            assert not (tool_sets[i] & tool_sets[j]), f"{A.ALL_SPECS[i].name} 与 {A.ALL_SPECS[j].name} 工具重叠"


# ── 全流程：真实数据 + 四个智能体各自使用自己的工具 ─────────────────────────

def test_full_orchestration_with_real_data(session_factory, project_data):
    db = session_factory()
    try:
        run, _ = _run(db, project_data, ScriptedClient())
        assert run.status == "completed"
        stages = json.loads(run.stages_json)
        assert [stages[s]["status"] for s in orchestrator.STAGES] == ["succeeded"] * 6

        # 每个智能体都真实调用了自己的专属工具
        agents_log = json.loads(run.agents_json)
        spec_tools = {spec.name: {t.name for t in spec.tools} for spec in A.ALL_SPECS}
        called_tools = {}
        for name, log in agents_log.items():
            used = {call["name"] for call in log["tool_calls"]}
            assert used, f"{name} 未调用任何工具"
            assert used <= spec_tools[name], f"{name} 调用了不属于自己的工具: {used - spec_tools[name]}"
            assert all(call["ok"] for call in log["tool_calls"])
            called_tools[name] = used
        assert len(called_tools) == 4

        # DEVICE：读到真实主机画像
        assert stages["DEVICE"]["output"]["device_type"]
        assert any(s["port"] == 1883 for s in stages["DEVICE"]["output"]["services"])

        # VULNERABILITY：读到真实 CVE/KEV/EPSS/版本影响
        finding = stages["VULNERABILITY"]["output"]["findings"][0]
        assert finding["cve_id"] == CVE and finding["cvss_score"] == 9.8
        assert finding["kev"] is True and finding["version_impact"] == "affected"

        # RUNTIME：结论引用真实 eBPF evidence_id
        runtime = stages["RUNTIME"]["output"]
        assert runtime["behavior_level"] in {"SUSPICIOUS", "ACTIVE"}
        real_ids = {row.evidence_id for row in db.query(models.SecurityEvidence).all()}
        assert set(runtime["evidence_ids"]) <= real_ids

        # RISK：确定性聚合（严重度基线 + KEV + 运行时权重 + 暴露面）
        risk = json.loads(run.risk_json)
        assert risk["severity"] == "critical" and risk["kev"] is True
        assert risk["runtime_level"] == runtime["behavior_level"]
        assert risk["risk_score"] >= 50 and risk["priority"] in {"medium", "high", "critical"}

        # REMEDIATION：update_package 进入真实修复流程（创建真实任务）
        plan = stages["REMEDIATION"]["output"]
        executed = plan["execution"]["executed"]
        assert executed and executed[0]["status"] == "created"
        task = db.get(models.RemediationTask, executed[0]["task_id"])
        assert task is not None and task.cve_id == CVE
        assert "apt" in task.remediation_command and task.status == "pending"
        assert plan["execution"]["pending_approval"], "backup_file 应进入待审批而非直接执行"

        # VERIFY：验证计划引用真实任务
        verify = json.loads(run.verify_json)
        assert verify["checks"][0]["pass"] is True
    finally:
        db.close()


def test_runtime_agent_reads_real_ebpf_evidence(session_factory, project_data):
    db = session_factory()
    try:
        run, _ = _run(db, project_data, ScriptedClient(behavior_level="ACTIVE"))
        stages = json.loads(run.stages_json)
        runtime = stages["RUNTIME"]["output"]
        assert runtime["behavior_level"] == "ACTIVE"
        real_ids = {row.evidence_id for row in db.query(models.SecurityEvidence).all()}
        assert real_ids and set(runtime["evidence_ids"]) <= real_ids
        for finding in runtime["findings"]:
            assert finding["evidence_id"] in real_ids
        assert json.loads(run.risk_json)["runtime_level"] == "ACTIVE"
    finally:
        db.close()


def test_runtime_rejects_fabricated_evidence_ids(session_factory, project_data):
    db = session_factory()
    try:
        run, _ = _run(db, project_data, ScriptedClient(fabricate_evidence=True))
        stages = json.loads(run.stages_json)
        assert stages["RUNTIME"]["status"] == "failed"
        assert "不存在的 evidence_id" in stages["RUNTIME"]["error"]
        # 无证据不得升级风险：降级为 NORMAL 继续编排
        assert json.loads(run.risk_json)["runtime_level"] == "NORMAL"
        assert run.status == "completed"
        agents_log = json.loads(run.agents_json)
        assert agents_log["runtime_behavior_agent"]["evidence_validation_errors"]
    finally:
        db.close()


def test_runtime_normal_without_evidence_is_valid(session_factory, project_data):
    db = session_factory()
    try:
        run, _ = _run(db, project_data, ScriptedClient(behavior_level="NORMAL"))
        stages = json.loads(run.stages_json)
        assert stages["RUNTIME"]["status"] == "succeeded"
        assert stages["RUNTIME"]["output"]["behavior_level"] == "NORMAL"
    finally:
        db.close()


# ── 修复智能体：白名单与授权门禁 ─────────────────────────────────────────────

def test_remediation_rejects_non_whitelist_action(session_factory, project_data):
    db = session_factory()
    try:
        bad = [{"action": "run_shell", "target": "rm -rf /", "params": {},
                "rationale": "越权动作"}]
        run, _ = _run(db, project_data, ScriptedClient(remediation_actions=bad))
        stages = json.loads(run.stages_json)
        assert stages["REMEDIATION"]["status"] == "failed"
        plan = json.loads(run.remediation_json)
        assert plan["actions"] == []
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


def test_remediation_rejects_shell_params(session_factory, project_data):
    db = session_factory()
    try:
        sneaky = [{"action": "change_config", "target": "/etc/ssh/sshd_config",
                   "params": {"command": "systemctl restart sshd"}, "rationale": "夹带命令"}]
        run, _ = _run(db, project_data, ScriptedClient(remediation_actions=sneaky))
        stages = json.loads(run.stages_json)
        assert stages["REMEDIATION"]["status"] == "failed"
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


def test_remediation_unauthorized_risk_goes_to_approval(session_factory, project_data):
    db = session_factory()
    try:
        db.get(models.RiskAssessment, project_data["risk"].id).review_status = "pending_human_review"
        db.commit()
        run, _ = _run(db, project_data, ScriptedClient())
        plan = json.loads(run.remediation_json)
        pending = plan["execution"]["pending_approval"]
        assert any("未获修复授权" in item["reason"] for item in pending)
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


# ── 编排器：失败传播与超时 ────────────────────────────────────────────────────

def test_device_failure_stops_run(session_factory, project_data):
    class BrokenClient:
        def complete(self, messages, tools=None):
            raise RuntimeError("LLM 服务不可用")

    db = session_factory()
    try:
        row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="linux_host",
                                           target_ref=HOST, status="running", stages_json="{}")
        db.add(row)
        db.commit()
        run = orchestrator.run_orchestration(db, row, client_factory=lambda: BrokenClient())
        assert run.status == "failed"
        stages = json.loads(run.stages_json)
        assert stages["DEVICE"]["status"] == "failed"
        # 后续阶段保持 pending，不再执行
        assert stages["VERIFY"]["status"] == "pending"
        assert db.query(models.RemediationTask).count() == 0
    finally:
        db.close()


def test_agent_timeout_is_reported(session_factory, project_data):
    import time as _time

    class SlowClient:
        def complete(self, messages, tools=None):
            _time.sleep(0.3)
            return {"content": "{}", "tool_calls": []}

    db = session_factory()
    try:
        row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="linux_host",
                                           target_ref=HOST, status="running", stages_json="{}")
        db.add(row)
        db.commit()
        run = orchestrator.run_orchestration(db, row, client_factory=lambda: SlowClient(),
                                             stage_budget_s=0.1)
        assert run.status == "failed"
        assert "DEVICE" in run.error
    finally:
        db.close()


# ── 设备 ↔ 证据关联（阶段五：SmartCam 设备按 device_id 读到按 IP 存的证据） ──

def test_device_evidence_resolution_by_device_id(session_factory, project_data):
    from app.services.agents import tools as agent_tools

    db = session_factory()
    try:
        device = models.IotDevice(device_id="DEV-SCX1-TEST", device_name="SmartCam-X1",
                                   device_type="ip_camera", ip=HOST, status="online")
        db.add(device)
        db.commit()
        # 证据按 HOST（采集端 hostname）存储；智能体用 device_id 查询也应命中
        events = agent_tools.tool_query_process_evidence(db, device_id="DEV-SCX1-TEST")
        assert events["count"] > 0
        assert all(event["evidence_id"].startswith("SE-") for event in events["events"])
        network = agent_tools.tool_query_network_evidence(db, device_id="DEV-SCX1-TEST")
        assert network["count"] >= 3
        tree = agent_tools.tool_query_process_tree(db, device_id="DEV-SCX1-TEST")
        assert tree["process_count"] >= 10
        # 按设备 IP 查询同样命中
        by_ip = agent_tools.tool_query_file_evidence(db, device_id=HOST)
        assert by_ip["count"] >= 20
    finally:
        db.close()


def test_orchestrator_targets_iot_device_end_to_end(session_factory, project_data):
    """四智能体编排以 IotDevice 为目标：设备画像走 IoT 表，证据按 IP 自动关联。"""
    db = session_factory()
    try:
        device = models.IotDevice(device_id="DEV-SCX1-TEST", device_name="SmartCam-X1",
                                   device_type="ip_camera", vendor="SmartCam Technologies",
                                   model="SmartCam-X1", firmware_version="2.4.7", ip=HOST,
                                   status="online")
        db.add(device)
        db.flush()
        db.add(models.IotDeviceService(device_row_id=device.id, port=1883,
                                        service_type="mqtt", product="SmartCam MQTT broker",
                                        status="open", auth_state="anonymous_accepted"))
        db.commit()

        client = ScriptedClient()
        # 设备智能体按 device_id 查询（命中 IotDevice），运行时按 device_id 查询（多键解析到 IP）
        client.queues["device_intelligence_agent"] = [
            {"tool_calls": [{"id": "d1", "name": "query_device_profile",
                             "arguments": {"device_id": "DEV-SCX1-TEST"}}]},
            {"final": "device"},
        ]
        client.queues["runtime_behavior_agent"] = [
            {"tool_calls": [{"id": "r1", "name": "query_process_evidence",
                             "arguments": {"device_id": "DEV-SCX1-TEST"}}]},
            {"final": "runtime"},
        ]
        row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="device",
                                           target_ref="DEV-SCX1-TEST", status="running",
                                           stages_json="{}")
        db.add(row)
        db.commit()
        run = orchestrator.run_orchestration(db, row, client_factory=make_factory(client))
        stages = json.loads(run.stages_json)
        assert run.status == "completed"
        assert stages["DEVICE"]["output"]["device_type"] == "ip_camera"
        assert stages["DEVICE"]["output"]["device_id"] == "DEV-SCX1-TEST"
        runtime = stages["RUNTIME"]["output"]
        assert runtime["behavior_level"] in {"SUSPICIOUS", "ACTIVE"}
        real_ids = {row.evidence_id for row in db.query(models.SecurityEvidence).all()}
        assert set(runtime["evidence_ids"]) <= real_ids
    finally:
        db.close()


# ── API ──────────────────────────────────────────────────────────────────────

def test_agents_api_specs_and_orchestration(client, session_factory, project_data, monkeypatch):
    specs = client.get("/api/agents/specs").json()
    assert len(specs["agents"]) == 4
    assert specs["orchestration"] == orchestrator.STAGES

    def fake_start(target_ref, target_type, client_factory=None):
        db = session_factory()
        try:
            row = models.AgentOrchestrationRun(run_id="AG-TEST-RUN", target_type=target_type,
                                               target_ref=target_ref, status="running",
                                               stages_json="{}")
            db.add(row)
            db.commit()
            orchestrator.run_orchestration(db, row, client_factory=make_factory(ScriptedClient()))
            snapshot = SimpleNamespace(run_id=row.run_id, status=row.status, target_ref=row.target_ref)
            return snapshot
        finally:
            db.close()

    monkeypatch.setattr("app.routers.agents.orchestrator.start_analysis", fake_start)
    response = client.post("/api/agents/analyze", json={"hostname": HOST})
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]
    detail = client.get(f"/api/agents/runs/{run_id}").json()
    assert detail["status"] == "completed"
    assert set(detail["stages"].keys()) == set(orchestrator.STAGES)
    assert detail["remediation"]["execution"]["executed"][0]["task_id"] > 0
    listed = client.get("/api/agents/runs").json()
    assert any(item["run_id"] == run_id for item in listed)


def test_agents_api_rejects_unknown_target(client, project_data):
    assert client.post("/api/agents/analyze", json={"hostname": "no-such-host"}).status_code == 404
    assert client.post("/api/agents/analyze", json={}).status_code == 422


def test_parse_structured_output_tolerates_fence():
    assert parse_structured_output('说明文字\n```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_structured_output('{"a": 2}') == {"a": 2}
    with pytest.raises(ValueError):
        parse_structured_output("完全没有 JSON")
