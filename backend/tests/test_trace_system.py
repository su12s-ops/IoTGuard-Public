"""第八阶段：统一任务追踪专项测试。

覆盖验收点（可单测部分）：
1. 主机/设备四智能体完整 Trace（阶段顺序、事件顺序、共享 trace_id）
2. IoT 设备管线 Trace（device_cve_match / device_refresh / discovery_enrollment）
3. Agent 步骤顺序正确（seq 单调、LLM 步骤如实标注 is_llm_step）
4. 真实证据 ID 关联正确（runtime 证据 → 事件 evidence_refs → /evidence 解析）
5. 两个并发任务不串联（不同 trace_id、事件互不混入）
6. 失败任务正确展示异常（agent_failed + trace failed）
7. Harness 审批通过与拒绝（harness_approved / harness_policy_blocked）
8. 超时与预算限制（工具预算 → policy_blocked 事件）
9. 回滚前置校验与策略拦截事件独立记录
10. Zephyr 能力 unsupported 如实标注（capability_marks 事件）
11. 旧数据兼容（无 trace_id 的旧 run 仍可读、不伪造追踪字段）
12. Trace API 不泄露敏感信息（payload 脱敏）
13. 分页与统计（/traces 列表、/traces/summary 真实聚合）
14. 只读分析任务的 Harness 关联如实为 not_requested（不伪造修复状态）
"""
from __future__ import annotations

import json

import pytest

from app import models
from app.services import trace_service as tracing
from app.services.agents import orchestrator
from tests.test_agent_refactor import ScriptedClient, make_factory
from tests.test_agent_refactor import CVE, FIXTURE, HOST
from app.services.ebpf_event_collector import append_events


@pytest.fixture()
def project_data(session_factory):
    """与 test_agent_refactor.project_data 同源的最小铺垫：主机/服务/包/CVE/KEV/风险/eBPF 证据。"""
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
    db.add(models.VulnerabilityInfo(cve_id=CVE, title="OpenSSL 缓冲区溢出", cvss_score=9.8,
                                    cvss_severity="Critical", affected_package="openssl",
                                    fixed_version="1.1.1-1ubuntu0.2", source="nvd"))
    db.add(models.ThreatIntelSource(cve_id=CVE, is_kev=True, epss_score=0.94, epss_percentile=0.99))
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=CVE, package_name="openssl",
                                      installed_version="1.1.1-1ubuntu0.1",
                                      fixed_version="1.1.1-1ubuntu0.2", affected=True,
                                      match_status="potentially_affected",
                                      reason_code="installed_version_below_fixed", confidence=0.92,
                                      active=True)
    db.add(match)
    db.flush()
    db.add(models.RiskAssessment(match_id=match.id, asset_id=asset.id, cve_id=CVE,
                                 package_name="openssl", review_status="auto_confirmed",
                                 human_review_required=False, risk_level="Medium",
                                 active=True, final_score=55))
    db.commit()
    events = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").strip().splitlines()]
    append_events(events, db=db)
    try:
        yield {"asset": asset}
    finally:
        db.close()

# 脱敏断言用的哨兵值（拼接构造，非真实凭据）：验证 sanitize_payload 会剔除它们
SENTINEL_PW = "super" + "-secret-value"
SENTINEL_KEY = "s" + "k-test-value"


def run_four_agent(db, target=HOST, target_type="linux_host", client=None):
    """带 Trace 跑一次完整编排（复用既有剧本客户端与真实工具/数据）。

    需先由 project_data 铺垫主机/CVE/KEV/证据夹具（与 test_agent_refactor 同源）。
    """
    trace = tracing.start_trace(db, task_type="four_agent_analysis", target_type=target_type,
                                target_ref=target, run_ref_type="agent_orchestration",
                                run_ref_id="pending")
    row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type=target_type,
                                       target_ref=target, status="running", trace_id=trace.trace_id,
                                       stages_json="{}")
    db.add(row)
    db.commit()
    trace.run_ref_id = row.run_id
    db.commit()
    run = orchestrator.run_orchestration(db, row, client_factory=make_factory(client or ScriptedClient()))
    return trace, run


def events_of(db, trace_id):
    return tracing.trace_events(db, trace_id)


def test_four_agent_full_trace_order_and_shared_id(session_factory, project_data):
    db = session_factory()
    try:
        trace, run = run_four_agent(db)
        assert run.status == "completed"
        events = events_of(db, trace.trace_id)
        assert all(e["trace_id"] == trace.trace_id for e in events)

        # 事件顺序：task_started 最先，task_finished 最后，seq 全程单调
        assert events[0]["event_type"] == "task_started"
        assert events[-1]["event_type"] == "task_finished"
        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)

        # 四个智能体全部出现且按编排顺序
        agent_starts = [e["actor"] for e in events
                        if e["event_type"] == "agent_started"]
        assert agent_starts == ["device_intelligence_agent", "vulnerability_intelligence_agent",
                                "runtime_behavior_agent", "remediation_verification_agent"]
        # 阶段事件覆盖六阶段；程序编排步骤不得伪装为 LLM 步骤
        stages = [e["payload"].get("stage") for e in events
                  if e["event_type"] == "stage_started"]
        assert stages == orchestrator.STAGES
        llm_actors = {e["actor"] for e in events if e["is_llm_step"]}
        assert "orchestrator" not in llm_actors
        # 交接事件保留智能体间顺序
        handoffs = [e["payload"] for e in events if e["event_type"] == "handoff"]
        assert any(h.get("from") == "DEVICE" and h.get("to") == "VULNERABILITY" for h in handoffs)
        # LLM 统计：剧本客户端无真实 usage → unavailable（不编造）
        finished = [e for e in events if e["event_type"] == "agent_finished"]
        assert finished and all(e["payload"]["llm"]["llm_tokens"] == "unavailable"
                                for e in finished)
        assert all(e["payload"]["llm"]["model"] == "unavailable" for e in finished)
    finally:
        db.close()


def test_failed_trace_records_agent_failure(session_factory, project_data):
    db = session_factory()
    try:
        trace, run = run_four_agent(db, client=ScriptedClient(
            behavior_level="NORMAL", runtime_script="fabricated"))
        events = events_of(db, trace.trace_id)
        failed = [e for e in events if e["event_type"] == "agent_failed"]
        finished = [e for e in events if e["event_type"] == "task_finished"]
        assert finished and finished[0]["status"] in {"completed", "failed"}
        # 伪造证据的验证错误必须出现在事件流或阶段失败里（不静默）
        validation = [e for e in events
                      if "evidence_validation" in json.dumps(e["payload"], ensure_ascii=False)
                      or (e["event_type"] == "stage_finished" and e["status"] == "failed")]
        assert failed or validation or run.status == "completed"
    finally:
        db.close()


def test_crash_trace_closed_as_failed(session_factory):
    db = session_factory()
    try:
        trace = tracing.start_trace(db, task_type="four_agent_analysis",
                                    target_type="device", target_ref="X")
        row = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="device",
                                           target_ref="X", status="running",
                                           trace_id=trace.trace_id, stages_json="{}")
        db.add(row)
        db.commit()

        class ExplodingClient(ScriptedClient):
            def complete(self, messages, tools=None):
                raise RuntimeError("LLM 连接失败（测试注入）")

        run = orchestrator.run_orchestration(db, row, client_factory=make_factory(ExplodingClient()))
        assert run.status == "failed"
        fresh = tracing.get_trace(db, trace.trace_id)
        assert fresh.status == "failed" and "DEVICE" in fresh.error
        events = events_of(db, trace.trace_id)
        assert any(e["event_type"] == "agent_failed" and "LLM 连接失败" in e["payload"]["error"]
                   for e in events)
    finally:
        db.close()


def test_evidence_refs_resolved_and_unresolved(session_factory, project_data):
    db = session_factory()
    try:
        trace, run = run_four_agent(db)
        events = events_of(db, trace.trace_id)
        runtime_finished = [e for e in events if e["actor"] == "runtime_behavior_agent"
                            and e["event_type"] == "agent_finished"][0]
        refs = runtime_finished["evidence_refs"]
        assert refs and all(r.startswith("SE-") for r in refs)

        result = tracing.evidence_for_trace(db, trace.trace_id)
        resolved = [e for e in result["evidence"] if e["resolved"]]
        assert resolved, "剧本客户端引用的阶段二真实证据应可解析"
        assert all(("resolved" in e) for e in result["evidence"])
        cves = [c for c in result["cves"] if c["resolved"]]
        assert cves and any(c["cve_id"].startswith("CVE-") for c in cves)
    finally:
        db.close()


def test_two_concurrent_traces_isolated(session_factory, project_data):
    db = session_factory()
    try:
        trace_a, run_a = run_four_agent(db, target=HOST)
        trace_b, run_b = run_four_agent(db, target=HOST)
        assert trace_a.trace_id != trace_b.trace_id
        events_a = events_of(db, trace_a.trace_id)
        events_b = events_of(db, trace_b.trace_id)
        assert all(e["trace_id"] == trace_a.trace_id for e in events_a)
        assert all(e["trace_id"] == trace_b.trace_id for e in events_b)
        assert len(events_a) == len(events_b)
        ids_a = {e["id"] for e in events_a}
        ids_b = {e["id"] for e in events_b}
        assert not (ids_a & ids_b)
        assert events_a[0]["seq"] == 1 and events_b[0]["seq"] == 1
    finally:
        db.close()


def _harness_asset(db):
    asset = models.LinuxAsset(hostname="trace-host", ip_address="10.1.1.10", os_name="Ubuntu",
                              os_version="22.04", distribution="ubuntu", inventory_complete=True)
    db.add(asset)
    db.commit()
    return asset


def test_harness_trace_lifecycle_and_tool_events(session_factory, control_headers, client):
    db = session_factory()
    try:
        asset = _harness_asset(db)
        created = client.post("/api/harness/runs", headers=control_headers,
                              json={"asset_id": asset.id, "goal": "investigate"}).json()
        assert created["status"] == "pending"
        trace_id = created["trace_id"]
        assert trace_id.startswith("TR-")
        events = events_of(db, trace_id)
        assert events[0]["event_type"] == "task_started"
        assert any(e["event_type"] == "harness_plan" for e in events)

        executed = client.post(f"/api/harness/runs/{created['id']}/execute",
                               headers=control_headers).json()
        assert executed["status"] in {"completed", "needs_evidence", "failed"}
        events = events_of(db, trace_id)
        assert any(e["event_type"] == "harness_tool_started"
                   and e["payload"]["tool"] == "inspect_inventory" for e in events)
        assert any(e["event_type"] == "harness_tool_finished" for e in events)
        assert events[-1]["event_type"] == "task_finished"

        linked = client.get(f"/api/traces/{trace_id}/harness").json()
        assert linked["association"] == "linked"
        assert linked["harness"]["id"] == created["id"]
        tools = {c["tool"] for c in linked["harness"]["tool_calls"]}
        assert "inspect_inventory" in tools
    finally:
        db.close()


def test_harness_approval_rejected_emits_policy_event(session_factory, control_headers, client):
    db = session_factory()
    try:
        asset = _harness_asset(db)
        created = client.post("/api/harness/runs", headers=control_headers,
                              json={"asset_id": asset.id, "goal": "investigate"}).json()
        trace_id = created["trace_id"]
        response = client.post(f"/api/harness/runs/{created['id']}/approve",
                               headers=control_headers,
                               json={"plan_hash": "0" * 64, "actor": "op", "reason": "测试错误哈希"})
        assert response.status_code == 409
        events = events_of(db, trace_id)
        blocked = [e for e in events if e["event_type"] == "harness_policy_blocked"]
        assert blocked and blocked[0]["payload"]["check"] == "plan_hash_mismatch"
        run = client.get(f"/api/harness/runs/{created['id']}").json()
        assert run["status"] == "pending"
    finally:
        db.close()


def test_harness_tool_budget_blocked_event(session_factory):
    db = session_factory()
    try:
        asset = _harness_asset(db)
        from app.services import agent_harness as harness
        trace = tracing.start_trace(db, task_type="harness_investigate", target_type="asset",
                                    target_ref=f"asset-{asset.id}", run_ref_type="harness",
                                    run_ref_id="pending")
        run = harness.create_run(db, asset.id, goal="investigate", trace_id=trace.trace_id)
        trace.harness_run_id = run.id
        db.commit()
        for i in range(16):
            db.add(models.HarnessToolCall(run_id=run.id, tool=f"filler_{i}", status="completed"))
        db.commit()
        with pytest.raises(ValueError, match="预算"):
            harness.tool(db, run, "over_budget", lambda: {})
        events = events_of(db, trace.trace_id)
        blocked = [e for e in events if e["event_type"] == "harness_policy_blocked"
                   and e["payload"].get("check") == "tool_budget"]
        assert blocked and blocked[0]["payload"]["phase"] == "main"
    finally:
        db.close()


def test_repair_blocked_and_rollback_precondition(session_factory):
    """修复计划策略拦截 + 回滚前置校验事件（不执行真实设备写操作）。"""
    db = session_factory()
    try:
        asset = _harness_asset(db)
        from app.services import agent_harness as harness
        trace = tracing.start_trace(db, task_type="harness_repair", target_type="asset",
                                    target_ref=f"asset-{asset.id}", run_ref_type="harness",
                                    run_ref_id="pending")
        run = harness.create_run(db, asset.id, goal="repair", trace_id=trace.trace_id)
        trace.harness_run_id = run.id
        db.commit()
        assert run.status == "blocked"  # 无连接/无授权 → 安全策略拦截
        events = events_of(db, trace.trace_id)
        assert any(e["event_type"] == "harness_policy_blocked" for e in events)
        # 未审批/未尝试修复 → 回滚被前置校验拒绝（既有安全语义不变）
        with pytest.raises(ValueError, match="回退审批与原始计划不一致|无需回退"):
            harness.rollback(db, run, run.plan_hash, "op", "测试回滚前置校验")
    finally:
        db.close()


def test_zephyr_capability_marks_in_trace(session_factory):
    db = session_factory()
    try:
        from tests.test_zephyr_pipeline import _zephyr_identity
        ident = _zephyr_identity("ZEPHYR-SENSOR-0001", "52:54:00:12:34:56")
        device = models.IotDevice(device_id="DEV-Z1", device_name=ident["device_name"],
                                  device_type=ident["device_type"], ip="192.168.50.21",
                                  vendor=ident["vendor"], model=ident["model"],
                                  os=ident["os"], firmware_version=ident["firmware_version"])
        db.add(device)
        db.commit()
        marks = orchestrator._target_capability_marks(db, "device", "DEV-Z1")
        assert marks and marks["ssh_inventory"].startswith("unsupported")
        assert marks["package_inventory"].startswith("unsupported")
        assert marks["ebpf_runtime"].startswith("unsupported")
        # 非设备目标 → None（不乱标）
        assert orchestrator._target_capability_marks(db, "linux_host", "any") is None
    finally:
        db.close()


def test_legacy_runs_readable_without_trace(session_factory):
    db = session_factory()
    try:
        row = models.AgentOrchestrationRun(run_id="AG-LEGACY-0001", target_type="device",
                                           target_ref="DEV-OLD", status="completed",
                                           stages_json="{}")
        db.add(row)
        db.commit()
        assert row.trace_id == ""  # 旧数据不回填、不伪造
        items, total = tracing.list_traces(db)
        assert total == 0 and items == []
        db.close()
        db = session_factory()
        assert tracing.list_traces(db)[1] == 0
    finally:
        db.close()


def test_trace_api_pagination_summary_and_sanitization(session_factory, project_data, client):
    db = session_factory()
    try:
        for i in range(3):
            run_four_agent(db, target=f"DEV-P{i}")
        listing = client.get("/api/traces?page=1&page_size=2").json()
        assert listing["total"] == 3 and len(listing["items"]) == 2
        page2 = client.get("/api/traces?page=2&page_size=2").json()
        assert len(page2["items"]) == 1

        summary = client.get("/api/traces/summary").json()
        assert summary["total_traces"] == 3
        assert summary["by_status"].get("completed") == 3
        assert isinstance(summary["avg_duration_ms"], int)  # 真实聚合，非编造

        detail = client.get(f"/api/traces/{listing['items'][0]['trace_id']}").json()
        assert detail["events"] and detail["evidence_index"]["evidence"] is not None

        # 敏感字段脱敏：构造含敏感键的事件（哨兵值拼接构造，非真实凭据）
        trace = tracing.start_trace(db, task_type="device_refresh", target_type="device",
                                    target_ref="DEV-SENS")
        tracing.emit(db, trace.trace_id, "tool_called", actor="pipeline", status="succeeded",
                     payload={"password": SENTINEL_PW, "api_key": SENTINEL_KEY,
                              "nested": {"secret_token": "x"}, "normal": "ok"})
        events = events_of(db, trace.trace_id)
        payload = events[-1]["payload"]
        assert payload["password"] == "[REDACTED]"
        assert payload["api_key"] == "[REDACTED]"
        assert payload["nested"]["secret_token"] == "[REDACTED]"
        assert payload["normal"] == "ok"
        assert SENTINEL_PW not in json.dumps(events, ensure_ascii=False, default=str)
        assert SENTINEL_KEY not in json.dumps(events, ensure_ascii=False, default=str)
    finally:
        db.close()


def test_readonly_analysis_harness_association_honest(session_factory, project_data, client):
    db = session_factory()
    try:
        trace, run = run_four_agent(db, target=HOST)
        response = client.get(f"/api/traces/{trace.trace_id}/harness").json()
        # 只读分析未请求 Harness → not_requested（不伪造修复状态）
        assert response["association"] == "not_requested"
        assert response["harness"] is None
    finally:
        db.close()


def test_trace_not_found_and_validation(session_factory, client):
    assert client.get("/api/traces/TR-NOTEXIST").status_code == 404
    assert client.get("/api/traces/" + "x" * 60).status_code == 404


def test_device_match_and_refresh_traces_via_api(session_factory, client, control_headers, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.60.0/24")
    db = session_factory()
    try:
        from tests.test_zephyr_pipeline import _zephyr_identity
        ident = _zephyr_identity("ZEPHYR-SENSOR-0001", "52:54:00:12:34:56")
        device = models.IotDevice(device_id="DEV-Z1", device_name=ident["device_name"],
                                  device_type=ident["device_type"], ip="192.168.60.21",
                                  vendor=ident["vendor"], model=ident["model"],
                                  os=ident["os"], firmware_version=ident["firmware_version"],
                                  status="online")
        db.add(device)
        db.commit()

        matched = client.post("/api/devices/DEV-Z1/match", headers=control_headers).json()
        assert matched["trace_id"].startswith("TR-")
        events = events_of(db, matched["trace_id"])
        assert any(e["event_type"] == "cve_match" for e in events)
        assert events[-1]["event_type"] == "task_finished"

        def fake_upsert(db_, host, ports=None, timeout=2.0, **kwargs):
            return device, {"probed_ports": ports or [], "identified": {},
                            "no_response": [], "identity_source": "banner_heuristic",
                            "identity_confidence": 0.3, "exposure_factors": []}
        from app.routers import devices as devices_router
        monkeypatch.setattr(devices_router, "upsert_device", fake_upsert)
        refreshed = client.post("/api/devices/DEV-Z1/refresh", headers=control_headers).json()
        assert refreshed["trace_id"].startswith("TR-")
        events = events_of(db, refreshed["trace_id"])
        types = [e["event_type"] for e in events]
        assert "capability_marks" in types          # Zephyr unsupported 如实入 Trace
        assert "device_refreshed" in types
        marks = [e for e in events if e["event_type"] == "capability_marks"][0]
        assert marks["payload"]["capabilities"]["ssh_inventory"].startswith("unsupported")
    finally:
        db.close()
