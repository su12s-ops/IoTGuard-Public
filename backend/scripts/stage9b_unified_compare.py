"""Stage 9B：统一四智能体 vs System B 同案例对照实验（真实 LLM）。

设计（对应 IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md §9）：
- 复用 Stage 9 审计的受控 Fixture（合成 CVE-2026-81xxx / TEST-NET 地址，
  真值表先验独立定义）与计量包装（客户端真实 usage，不编造）；
- 同一 Fixture 上运行：规则基线 A / System B 原链路 / 统一四智能体（影子，
  不触碰正式字段）；
- 新增独立案例：X1 低复杂度候选（成本分层直通）、X2 KEV+厂商 affected 但装机
  已高于修复版本（版本事实优先，不因 KEV 虚高）、X3 仅过期运行时证据+直接命中
  （F6 新鲜度语义）；
- 重复运行：E1/E3/E5 各 N 次（默认 3；E3 含两个事件实例，按实例独立重复）
  观察运行间方差；
- 失败恢复：屏蔽统一链 runtime_analyst（E1）——部分失败不全丢（F7）、
  门禁强制人工；
- 断点续跑：逐运行 JSON 落盘（--out/runs/），重跑时对已完成运行去重跳过；
  --max-total-tokens 硬预算触界后剩余运行标记 skipped、续跑补齐；
- 产物：聚合指标 JSON + 逐案例明细写入 --out（reports/ 已 gitignore）。

用法：
    python scripts/stage9b_unified_compare.py --out reports/stage9b-unified
    python scripts/stage9b_unified_compare.py --dry          # 只建 Fixture 不调 LLM
    python scripts/stage9b_unified_compare.py --repeats 1    # 快速模式
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from stage9_agent_effectiveness_audit import (  # noqa: E402
    CASE_ORDER,
    CountedChatClient,
    TRUTH,
    UsageCounter,
    build_fixture,
    collect_baseline,
    fresh_session_factory,
)

UNIFIED_TRUTH = {
    # X1：低复杂度候选——simple 分层直通或评审后保守结论皆可接受
    "CVE-2026-81006": {
        "label": "X1 低复杂度候选（Low/无KEV/无运行时证据）——成本分层",
        "impact": None,
        "directions": {"maintain", "downgrade_minor", "downgrade_major"},
        "actions": {"monitor", "defer", "collect_more_evidence"},
        "needs_human": None,
    },
    # X2：KEV+厂商 affected，但装机已高于厂商修复版本——不得因 KEV 判实际受影响
    "CVE-2026-81008": {
        "label": "X2 KEV+厂商affected但装机已修复（版本事实优先，不因KEV虚高）",
        "impact": {"not_affected", "insufficient_evidence"},   # confirmed_affected 即失败
        "directions": {"maintain", "downgrade_minor", "downgrade_major"},  # 不得升级
        "actions": {"monitor", "defer", "collect_more_evidence"},
        "needs_human": None,
    },
    # X3：证据全部过期但采集器在线——不得判 verified，不得据此立即修复
    "CVE-2026-81007": {
        "label": "X3 仅过期运行时证据+直接命中（freshness 语义）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": True,   # stale 门禁/冲突 → 必须人工
    },
}
CASE_ORDER_X = ["CVE-2026-81006", "CVE-2026-81008", "CVE-2026-81007"]


def extend_fixture_for_x_cases(db) -> None:
    """在 Fixture 上追加 X1/X3 独立案例（与 E 案例同库隔离）。"""
    from app import models

    now = datetime.now(timezone.utc)

    edge04 = models.LinuxAsset(
        hostname="edge-04", ip_address="192.0.2.14", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="internal",
        business_level="normal", device_type="server", inventory_complete=True,
    )
    edge05 = models.LinuxAsset(
        hostname="edge-05", ip_address="192.0.2.15", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="dmz",
        business_level="important", device_type="server", inventory_complete=True,
    )
    db.add_all([edge04, edge05])
    db.flush()
    db.add_all([
        models.AssetPackage(asset_id=edge04.id, package_name="zlib1g",
                            package_version="1:1.2.11.dfsg-2ubuntu9", package_manager="apt"),
        models.AssetPackage(asset_id=edge05.id, package_name="sudo",
                            package_version="1.9.9-1ubuntu2", package_manager="apt"),
    ])
    db.add_all([
        models.AssetService(asset_id=edge04.id, service_name="ssh", port=22, protocol="tcp",
                            listen_address="192.0.2.14", is_public_exposed=False,
                            process_name="sshd"),
        models.AssetService(asset_id=edge05.id, service_name="sudo-local", port=0, protocol="tcp",
                            listen_address="127.0.0.1", is_public_exposed=False,
                            process_name="sudo"),
    ])
    db.add_all([
        models.VulnerabilityInfo(
            cve_id="CVE-2026-81006:jammy", title="zlib low severity miscompute (fixture)",
            description="Fixture synthetic advisory: minor inflate miscomputation.",
            cvss_score=3.5, cvss_severity="Low", affected_package="zlib1g",
            fixed_version="1:1.2.11.dfsg-2ubuntu10", source="fixture",
            published_date="2026-09-20", last_modified_date="2026-10-01"),
        models.VulnerabilityInfo(
            cve_id="CVE-2026-81007:jammy", title="sudo local privilege hint (fixture)",
            description="Fixture synthetic advisory: local privilege escalation hint in sudo.",
            cvss_score=7.8, cvss_severity="High", affected_package="sudo",
            fixed_version="1.9.9-1ubuntu3", source="fixture",
            published_date="2026-09-15", last_modified_date="2026-10-01"),
    ])
    db.flush()
    db.add(models.ThreatIntelSource(cve_id="CVE-2026-81006:jammy", is_kev=False,
                                    epss_score=0.02, epss_percentile=0.1,
                                    exploit_status="none"))
    db.add(models.ThreatIntelSource(cve_id="CVE-2026-81007:jammy", is_kev=False,
                                    epss_score=0.4, epss_percentile=0.8,
                                    exploit_status="none"))
    db.flush()

    # X2：KEV 标记 + 厂商 canonical 状态 affected（权威、压制上游），
    # 但装机版本已高于厂商修复版本——漏洞分析师必须依据版本事实给出
    # fixed/not_affected，不得因 KEV 虚高（架构 §9 X2 定义）。
    edge06 = models.LinuxAsset(
        hostname="edge-06", ip_address="192.0.2.16", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="internal",
        business_level="normal", device_type="server", inventory_complete=True,
    )
    db.add(edge06)
    db.flush()
    db.add(models.AssetPackage(asset_id=edge06.id, package_name="libxml2",
                               package_version="2.9.13-2ubuntu0.4", package_manager="apt"))
    db.add(models.AssetService(asset_id=edge06.id, service_name="ssh", port=22, protocol="tcp",
                               listen_address="192.0.2.16", is_public_exposed=False,
                               process_name="sshd"))
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-81008:jammy", title="libxml2 xpath use-after-free (fixture)",
        description="Fixture synthetic advisory: use-after-free in xpath processing.",
        cvss_score=7.5, cvss_severity="High", affected_package="libxml2",
        fixed_version="2.9.13-2ubuntu0.3", source="fixture",
        published_date="2026-09-25", last_modified_date="2026-10-01"))
    db.flush()
    db.add(models.ThreatIntelSource(cve_id="CVE-2026-81008:jammy", is_kev=True,
                                    epss_score=0.6, epss_percentile=0.9,
                                    exploit_status="known-exploited"))
    db.flush()
    from app.services.vulnerability_intelligence.service import upsert_source_record
    upsert_source_record(db, "CVE-2026-81008", "canonical",
                         {"records": [{"release": "jammy", "package": "libxml2",
                                       "status": "affected",
                                       "fixed_version": "2.9.13-2ubuntu0.3",
                                       "priority": "medium"}]},
                         source_updated_at="2026-10-01T00:00:00Z")
    upsert_source_record(db, "CVE-2026-81008", "nvd",
                         {"cvss": {"score": 7.5, "severity": "High",
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                          "description": "Use-after-free in xpath processing (fixture).",
                          "cwe": ["CWE-416"], "cpe_status": "affected"},
                         source_updated_at="2026-10-01T00:00:00Z")
    upsert_source_record(db, "CVE-2026-81008", "cisa_kev",
                         {"is_kev": True, "date_added": "2026-10-03",
                          "due_date": "2026-10-24"},
                         source_updated_at="2026-10-03T00:00:00Z")
    upsert_source_record(db, "CVE-2026-81008", "epss",
                         {"score": 0.6, "percentile": 0.9},
                         source_updated_at="2026-10-02T00:00:00Z")
    db.flush()

    # X3：直接命中 sudo 的运行时证据——但全部是 72 小时前的旧事件；采集器心跳在线
    stale_ts = (now - timedelta(hours=72)).isoformat()
    events = [
        {"hostname": "edge-05", "asset_id": edge05.id, "source": "falco",
         "event_type": "execve", "category": "privilege_activity", "severity": "warning",
         "severity_score": 55, "rule": "sudo_spawn_shell",
         "process_name": "sudo", "parent_process": "sshd",
         "commandline": "sudo -i", "file_path": "", "destination": "", "port": 0,
         "tactic": "", "technique": "", "risk_signal": "sudo_spawn_shell",
         "timestamp": stale_ts, "occurred_at": stale_ts,
         "process_id": 5100, "parent_process_id": 5000,
         "process_exec_id": "exec-edge-05-5100-x3", "parent_exec_id": "exec-edge-05-5000-x3",
         "raw": {"fixture": True}},
    ]
    for item in events:
        db.add(models.RuntimeEvent(
            asset_id=item["asset_id"], hostname=item["hostname"], source=item["source"],
            event_type=item["event_type"], category=item["category"], severity=item["severity"],
            severity_score=item["severity_score"], rule=item["rule"],
            process_name=item["process_name"], parent_process=item["parent_process"],
            commandline=item["commandline"], file_path=item["file_path"],
            destination=item["destination"], port=item["port"], risk_signal=item["risk_signal"],
            raw_json=json.dumps(item["raw"]), occurred_at=item["occurred_at"],
            process_id=item["process_id"], parent_process_id=item["parent_process_id"],
            process_exec_id=item["process_exec_id"], parent_exec_id=item["parent_exec_id"],
            sensor_id="sensor-edge-05",
            event_fingerprint=f"fp-x3-{abs(hash(str(item))) % 10**18}",
        ))
    db.flush()
    from app.services.security_evidence import persist_evidence
    persist_evidence(db, events)
    db.add(models.RuntimeSensor(
        asset_id=edge05.id, sensor_id="sensor-edge-05", source="falco", status="running",
        last_heartbeat_at=now, dropped_events=0,
        capabilities_json=json.dumps({"metrics": "dropped_events"}), detail="fixture-x3",
    ))
    db.flush()

    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk
    run_matching(db)
    calculate_risk(db)
    db.commit()


# ── 统一链执行 ───────────────────────────────────────────────────────────────


def _make_unified_client_factory(counter: UsageCounter, mask_agent: str = ""):
    from app.services.agents.base import DeepSeekChatClient
    from app.config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL

    if not DEEPSEEK_API_KEY:
        raise RuntimeError("未配置 DEEPSEEK_API_KEY；真实 LLM 实验需要密钥（.env，不入库）")

    class MaskedUnifiedClient:
        """对指定智能体持续返回非法输出（触发 F3 反馈重试 → 角色降级）。"""

        def __init__(self, inner):
            self._inner = inner

        def complete(self, messages, tools=None):
            system = messages[0]["content"] if messages else ""
            masked_names = {
                "runtime": "运行时分析师", "vulnerability": "漏洞分析师",
                "asset": "资产与证据调查员", "decision": "研判与处置规划师"}
            if mask_agent and masked_names.get(mask_agent, "") in system:
                # 带 data_gaps 的非法输出（避免被判空对象直接拒绝，走完整降级路径）
                return {"content": json.dumps({
                    "behavior_level": "ACTIVE", "evidence_ids": [],
                    "data_gaps": ["masked_by_experiment"]}), "tool_calls": []}
            return self._inner.complete(messages, tools=tools)

    def factory():
        inner = DeepSeekChatClient(model=DEEPSEEK_MODEL, api_key=DEEPSEEK_API_KEY,
                                   base_url=DEEPSEEK_BASE_URL)
        counted = CountedChatClient(inner, counter)
        return MaskedUnifiedClient(counted) if mask_agent else counted

    return factory


def _refresh_fresh_sensor_heartbeats(db) -> None:
    """消除脚手架时序竞态：覆盖阈值 120s（runtime_telemetry.coverage）。

    Fixture 只在构建时写一次心跳，而 19 连跑中绝大多数运行距构建远超 120s，
    "设计为在线"的传感器会被如实判为 stale 覆盖 → freshness mixed → 偏离案例
    设计前提。仅刷新设计语义为「在线」的传感器；wrt-node（-72h，E5）与
    X3 的事件时间戳保持不变。
    """
    import app.services.unified.runner as runner_mod
    from app import models

    fresh_sensor_ids = ["sensor-edge-01", "sensor-edge-05"]
    (db.query(models.RuntimeSensor)
       .filter(models.RuntimeSensor.sensor_id.in_(fresh_sensor_ids))
       .update({models.RuntimeSensor.last_heartbeat_at: datetime.now(timezone.utc)},
               synchronize_session=False))
    db.commit()


def run_unified_case(db, risk, factory, run_id: str) -> dict:
    """对单个风险事件执行统一编排（影子模式：sink=None，不触碰正式字段）。"""
    import app.services.unified.runner as runner_mod
    from app import models
    from sqlalchemy.orm import sessionmaker

    # 与生产 adapter 同语义：target_ref=资产 hostname（第一轮实测教训——
    # 用占位符 "fixture" 会被决策规划师如实判为「资产身份未核实」而保守降级，
    # 那是脚手架保真度缺陷，不是管线缺陷）
    asset = db.get(models.LinuxAsset, risk.asset_id) if risk.asset_id else None
    target_ref = asset.hostname if asset else ""
    # 每次运行前刷新在线传感器心跳（消除 120s 覆盖阈值的脚手架时序竞态）
    _refresh_fresh_sensor_heartbeats(db)
    # runner 的节点会话必须来自同一实验库（与单测同模式：临时覆盖，用后恢复）
    fixture_factory = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False)
    original = runner_mod.SessionLocal
    runner_mod.SessionLocal = fixture_factory
    try:
        row = models.UnifiedAnalysisRun(
            run_id=run_id, task_type="risk_review", target_type="linux_host",
            target_ref=target_ref, mode="shadow", status="running", risk_id=risk.id)
        db.add(row)
        db.commit()
        started = time.monotonic()
        runner_mod.run_unified_sync(db, row, client_factory=factory, sink=None)
        wall_s = round(time.monotonic() - started, 1)
    finally:
        runner_mod.SessionLocal = original
    state = json.loads(row.state_json or "{}")
    final = state.get("final") or {}
    decision = json.loads(row.decision_json or "{}") or state.get("decision") or {}
    verdicts = decision.get("verdicts") or []
    # 逐运行真实 usage：runner 级 UsageMeter 落库形态为
    # {"llm_calls": N, "usage": {"prompt_tokens": …, …}, "budget_exceeded": bool}
    meter_usage = json.loads(row.usage_json or "{}") or {}
    nested = meter_usage.get("usage") or {}
    agents_log = json.loads(row.agents_json or "{}") or {}
    verdict = verdicts[0] if verdicts else None
    follow_requests = (decision.get("follow_up_requests") or [])
    follow_results = state.get("follow_up_results", [])
    # 补查回灌审计：execute_follow_ups 之后 decide 是否再次执行且产出结论
    stage_status = state.get("stage_status", {})
    follow_reentered = bool(follow_results) and stage_status.get("decide") == "succeeded" and bool(verdict)
    return {
        "case": risk.cve_id.split(":")[0],
        "risk_id": risk.id,
        "run_id": row.run_id,
        "status": row.status,
        "error": row.error[:400],
        "wall_seconds": wall_s,
        "routing": json.loads(row.routing_json or "{}"),
        "stage_status": stage_status,
        "degraded_roles": state.get("degraded_roles", []),
        "tier": (json.loads(row.routing_json or "{}") or {}).get("tier"),
        "policy": final.get("policy"),
        "aggregate": final.get("aggregate"),
        "verdict": verdict,
        "decision_full": decision,
        "conflict": (state.get("conflict_result") or {}),
        "vulnerability": state.get("vulnerability"),
        "runtime": state.get("runtime") or state.get("runtime_program_fallback"),
        "investigation": state.get("investigation"),
        "agents_log": agents_log,
        "follow_up_audit": {
            "requested": len(follow_requests),
            "requests": follow_requests,
            "executed_results": len(follow_results),
            "results": follow_results,
            "reentered_decision": follow_reentered,
        },
        "usage": {
            "llm_calls": meter_usage.get("llm_calls"),
            "prompt_tokens": nested.get("prompt_tokens"),
            "completion_tokens": nested.get("completion_tokens"),
            "total_tokens": nested.get("total_tokens"),
            "budget_exceeded": meter_usage.get("budget_exceeded"),
        },
    }


def grade_unified(event: dict, truth: dict) -> dict:
    """对照真值表给统一链单案例打分（处置级/方向级/人工路由/引用完整性）。"""
    verdict = event.get("verdict") or {}
    policy = event.get("policy") or {}
    runtime = event.get("runtime") or {}
    problems: list[str] = []
    # 分层判定双通道：routing_json 的 tier + final 留痕的 rule_tier_simple
    # （simple 直通路径此前不落 routing_json，历史运行仅能从 policy 原因识别）
    is_simple = (event.get("tier") == "simple"
                 or "rule_tier_simple" in (policy.get("reasons") or []))

    impact_ok = None
    if not is_simple and truth.get("impact"):
        expected = truth["impact"]
        actual = verdict.get("impact_status")
        impact_ok = actual in expected if isinstance(expected, set) else actual == expected
        if not impact_ok:
            problems.append(f"impact {actual} 不在真值 {expected}")

    direction = verdict.get("risk_direction")
    direction_ok = (None if is_simple or not truth.get("directions")
                    else direction in truth["directions"])
    if direction_ok is False:
        problems.append(f"direction {direction} 不在允许集")

    action = verdict.get("recommended_action")
    action_ok = (None if is_simple or not truth.get("actions")
                 else action in truth["actions"])
    if action_ok is False:
        problems.append(f"action {action} 不在允许集")

    human = policy.get("status") == "pending_human_review"
    if truth.get("needs_human") and not human:
        problems.append("真值要求人工复核但未转人工")
    human_ok = None if not truth.get("needs_human") else human

    # 引用完整性：裁定引用的证据必须真实存在于统一链已知证据集合。
    # 全集与 runner 的 known_evidence_ids 对齐：事件证据包（EV-{risk_id}-*，
    # 由证据包构建器按 risk 确定性生成）+ 运行时证据 + 资产盘点源 + 漏洞
    # 分析师 finding 引用（含情报源名）。此前仅对照 runtime 集合产生假阳性。
    known = set(runtime.get("evidence_ids") or [])
    investigation = event.get("investigation") or {}
    inventory = investigation.get("evidence_inventory") or {}
    for source in inventory.get("sources") or []:
        if isinstance(source, str):
            known.add(source)
    vulnerability = event.get("vulnerability") or {}
    for finding in vulnerability.get("findings") or []:
        if isinstance(finding, dict):
            known.update(finding.get("supporting_evidence_ids") or [])
            if finding.get("evidence_id"):
                known.add(str(finding["evidence_id"]))
    cited = set(verdict.get("supporting_evidence_ids") or [])
    packet_pattern = re.compile(rf"^EV-{event.get('risk_id')}-[A-Za-z0-9._\-]+$")
    for item in cited:
        if isinstance(item, str) and packet_pattern.match(item):
            known.add(item)
    unknown = sorted(str(item) for item in cited if item not in known)
    citation_ok = not unknown

    # F6 语义：过期证据不得被判 verified
    freshness_ok = None
    if runtime.get("evidence_freshness") == "stale":
        freshness_ok = runtime.get("runtime_status") != "verified"
        if not freshness_ok:
            problems.append("过期证据被判 verified（F6 违规）")

    return {
        "case": event["case"],
        "tier": event.get("tier"),
        "impact_ok": impact_ok, "direction_ok": direction_ok, "action_ok": action_ok,
        "human_ok": human_ok, "human": human, "citation_ok": citation_ok,
        "freshness_ok": freshness_ok,
        "degraded_roles": event.get("degraded_roles", []),
        "policy_status": policy.get("status"),
        "problems": problems,
    }


def old_system_event_rows(db) -> list[dict]:
    from app import models
    rows = []
    for risk in db.query(models.RiskAssessment).all():
        rows.append({
            "case": risk.cve_id.split(":")[0],
            "review_status": risk.review_status,
            "human": risk.review_status == "pending_human_review",
            "decision": risk.decision,
            "recommended_action": risk.recommended_action,
            "risk_direction": risk.risk_direction,
            "review_verdict": risk.review_verdict,
            "review_confidence": risk.review_confidence,
            "final_score": risk.final_score,
        })
    return rows


def grade_old(event: dict, truth: dict) -> dict:
    problems = []
    expected_impact = truth.get("impact")
    actual = event.get("review_verdict")
    impact_ok = (None if not expected_impact
                 else actual in expected_impact if isinstance(expected_impact, set)
                 else actual == expected_impact)
    if impact_ok is False:
        problems.append(f"impact {actual} 不在真值 {expected_impact}")
    direction_ok = None
    if truth.get("directions"):
        direction_ok = event.get("risk_direction") in truth["directions"]
        if not direction_ok:
            problems.append(f"direction {event.get('risk_direction')} 不在允许集")
    action_ok = None
    if truth.get("actions"):
        action_ok = (event.get("recommended_action") or event.get("decision")) in truth["actions"]
        if not action_ok:
            problems.append(f"action {event.get('recommended_action') or event.get('decision')} 不在允许集")
    human = bool(event.get("human"))
    human_ok = None if not truth.get("needs_human") else human
    if truth.get("needs_human") and not human:
        problems.append("真值要求人工复核但未转人工")
    return {"case": event["case"], "impact_ok": impact_ok, "direction_ok": direction_ok,
            "action_ok": action_ok, "human_ok": human_ok, "human": human,
            "problems": problems}


def _counter_snapshot(counter: UsageCounter) -> dict:
    data = counter.as_dict()
    return {key: value for key, value in data.items()
            if isinstance(value, (int, float))}


def _counter_diff(before: dict, after: dict) -> dict:
    return {key: after.get(key, 0) - before.get(key, 0) for key in sorted(after)}


def _runs_dir(out_dir: Path) -> Path:
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    return runs_dir


def _run_file(runs_dir: Path, run_id: str) -> Path:
    return runs_dir / f"run-{run_id}.json"


def _save_run(runs_dir: Path, event: dict) -> None:
    """逐案例落盘：每个 run 一个 JSON 文件，崩溃/中断后可续跑去重。"""
    path = _run_file(runs_dir, event["run_id"])
    path.write_text(json.dumps(event, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8")


def _load_completed_runs(runs_dir: Path) -> dict[str, dict]:
    """加载历史已完成运行（断点续跑；失败运行不加载、将被重跑）。"""
    done: dict[str, dict] = {}
    if not runs_dir.exists():
        return done
    for path in sorted(runs_dir.glob("run-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("status") == "completed" and data.get("run_id"):
            done[data["run_id"]] = data
    return done


def _sum_run_usage(runs: list[dict]) -> dict:
    """跨调用聚合逐运行真实 usage（断点续跑时汇总不丢历史）。"""
    totals = {"llm_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for run in runs:
        usage = run.get("usage") or {}
        for key in totals:
            value = usage.get(key)
            if isinstance(value, (int, float)):
                totals[key] += int(value)
    return totals


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="reports/stage9b-unified")
    parser.add_argument("--dry", action="store_true", help="只构建 Fixture 与规则基线，不调用 LLM")
    parser.add_argument("--repeats", type=int, default=3,
                        help="E1/E3/E5 统一链重复运行次数（含首次）")
    parser.add_argument("--skip-old", action="store_true", help="跳过 System B 对照运行")
    parser.add_argument("--unified-only", action="store_true",
                        help="续跑模式：只运行统一链（历史 System B 结果已在上一轮 JSON 中）")
    parser.add_argument("--old-cases", default="",
                        help="补充运行 System B 的案例过滤（如 CVE-2026-81008）；空=不补充")
    parser.add_argument("--cases", default="",
                        help="逗号分隔的案例过滤（如 CVE-2026-81004,CVE-2026-81005）；空=全部")
    parser.add_argument("--fresh", action="store_true",
                        help="忽略历史逐运行文件，全部重跑（默认对已完成运行去重跳过）")
    parser.add_argument("--max-total-tokens", type=int, default=1_500_000,
                        help="本轮统一链 LLM Token 硬上限；超出后剩余运行标记 skipped 并可续跑")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root = out_dir / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    runs_dir = _runs_dir(out_dir)
    os.environ.setdefault("LINUXGUARD_DATA_DIR", str(work_root / "data"))
    os.environ["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"
    os.environ["PYTHON_DOTENV_DISABLED"] = "0"   # 允许读取本地 .env 的 DEEPSEEK 配置

    import tempfile
    tmp_root = Path(tempfile.mkdtemp(prefix="stage9b-"))
    factory, engine = fresh_session_factory(tmp_root / "db")
    db = factory()
    build_fixture(db, with_runtime=True)
    extend_fixture_for_x_cases(db)
    baseline = collect_baseline(db)

    from app import models
    risks_by_case: dict[str, list] = {}
    for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
        risks_by_case.setdefault(risk.cve_id.split(":")[0], []).append(risk)

    print("== 规则基线（A 组） ==")
    for case in CASE_ORDER + CASE_ORDER_X:
        for risk in risks_by_case.get(case, []):
            key = risk.cve_id.split(":")[0]
            info = baseline.get(key, {})
            print(f"  {key} risk#{risk.id}: score={info.get('preliminary_score')} "
                  f"level={info.get('preliminary_level')} decision={info.get('preliminary_decision')}")
    if args.dry:
        db.close()
        return

    results: dict[str, any] = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repeats": args.repeats,
            "fixture": "stage9 E1-E5 + X1/X2/X3（合成 CVE / TEST-NET）",
        },
        "baseline": {case: [baseline.get(r.cve_id.split(":")[0]) for r in rows]
                     for case, rows in risks_by_case.items()},
    }

    # ── 对照组 1：System B 原链路（全量；最终验收沿用上一轮全量结果时用 --unified-only） ──
    if not args.skip_old and not args.unified_only:
        import app.services.event_review_pipeline as erp
        counter_old = UsageCounter()

        real_factory = erp._create_model_client

        def counted_old_factory():
            from autogen_ext.models.openai import OpenAIChatCompletionClient
            from autogen_core.models import ModelInfo
            inner = OpenAIChatCompletionClient(
                model=erp.DEEPSEEK_MODEL, api_key=erp.DEEPSEEK_API_KEY,
                base_url=erp.DEEPSEEK_BASE_URL.rstrip("/"), temperature=0.1,
                model_info=ModelInfo(vision=False, function_calling=True, json_output=True,
                                     structured_output=True, family="deepseek"))
            return CountedReviewClientShim(inner, counter_old)

        erp._create_model_client = counted_old_factory
        selected = [r for r in db.query(models.RiskAssessment).filter_by(active=True).all()
                    if r.review_status in erp.REVIEWABLE_STATUSES]
        started = time.monotonic()
        try:
            old_result = erp.run_review_analysis(db, run_id="old-full", selected_risks=selected)
        finally:
            erp._create_model_client = real_factory
        wall_old = round(time.monotonic() - started, 1)
        old_events = old_system_event_rows(db)
        old_graded = []
        for event in old_events:
            truth = TRUTH.get(event["case"]) or UNIFIED_TRUTH.get(event["case"])
            if truth:
                old_graded.append(grade_old(event, truth))
        results["old_system_b"] = {
            "status": old_result.get("status"),
            "wall_seconds": wall_old,
            "usage": counter_old.as_dict(),
            "events": old_events,
            "graded": old_graded,
        }
        db.rollback()   # 旧系统已写正式字段；统一链需要 candidate 状态重新可选
        for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
            risk.review_status = "candidate"
            risk.human_review_required = False
            risk.final_score = None
            risk.risk_level = None
            risk.decision = None
        db.commit()
        print(f"== System B 完成：{wall_old}s, {counter_old.as_dict()} ==")

    # ── 对照组 1a：System B 补充运行（如新案例 X2；历史全量结果沿用上一轮 JSON） ──
    old_case_filter = {item.strip() for item in args.old_cases.split(",") if item.strip()}
    if old_case_filter:
        import app.services.event_review_pipeline as erp
        counter_old = UsageCounter()

        def counted_old_factory():
            from autogen_ext.models.openai import OpenAIChatCompletionClient
            from autogen_core.models import ModelInfo
            inner = OpenAIChatCompletionClient(
                model=erp.DEEPSEEK_MODEL, api_key=erp.DEEPSEEK_API_KEY,
                base_url=erp.DEEPSEEK_BASE_URL.rstrip("/"), temperature=0.1,
                model_info=ModelInfo(vision=False, function_calling=True, json_output=True,
                                     structured_output=True, family="deepseek"))
            return CountedReviewClientShim(inner, counter_old)

        real_factory = erp._create_model_client
        erp._create_model_client = counted_old_factory
        selected = [r for r in db.query(models.RiskAssessment).filter_by(active=True).all()
                    if r.review_status in erp.REVIEWABLE_STATUSES
                    and r.cve_id.split(":")[0] in old_case_filter]
        started = time.monotonic()
        try:
            old_result = erp.run_review_analysis(db, run_id="old-supplement",
                                                 selected_risks=selected)
        finally:
            erp._create_model_client = real_factory
        wall_old = round(time.monotonic() - started, 1)
        old_events = [e for e in old_system_event_rows(db)
                      if e["case"] in old_case_filter]
        old_graded = []
        for event in old_events:
            truth = TRUTH.get(event["case"]) or UNIFIED_TRUTH.get(event["case"])
            if truth:
                old_graded.append(grade_old(event, truth))
        results["old_system_b_supplement"] = {
            "cases": sorted(old_case_filter),
            "status": old_result.get("status"),
            "wall_seconds": wall_old,
            "usage": counter_old.as_dict(),
            "events": old_events,
            "graded": old_graded,
        }
        db.rollback()   # 旧系统已写正式字段；统一链需要 candidate 状态重新可选
        for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
            risk.review_status = "candidate"
            risk.human_review_required = False
            risk.final_score = None
            risk.risk_level = None
            risk.decision = None
        db.commit()
        print(f"== System B 补充运行完成：{wall_old}s, {counter_old.as_dict()} ==")

    # ── 对照组 2：统一四智能体（逐案例影子运行；断点续跑 + 已完成去重 + Token 预算） ──
    unified_counter = UsageCounter()
    unified_factory = _make_unified_client_factory(unified_counter)
    unified_runs: list[dict] = []
    skipped_runs: list[dict] = []
    completed_before = {} if args.fresh else _load_completed_runs(runs_dir)
    if completed_before:
        print(f"== 断点续跑：发现 {len(completed_before)} 个已完成运行，将去重跳过 ==")
    repeat_cases = ["CVE-2026-81001", "CVE-2026-81003", "CVE-2026-81005"]
    case_filter = {item.strip() for item in args.cases.split(",") if item.strip()}
    plan: list[tuple[str, any, int]] = []
    for case in CASE_ORDER + CASE_ORDER_X:
        if case_filter and case not in case_filter:
            continue
        for risk in risks_by_case.get(case, []):
            repeats = args.repeats if case in repeat_cases else 1
            for index in range(repeats):
                plan.append((case, risk, index))
    budget_exhausted = False
    for index, (case, risk, repeat) in enumerate(plan):
        run_id = f"uni-{case}-{repeat}-{risk.id}"
        if run_id in completed_before:
            print(f"== 去重跳过 [{index + 1}/{len(plan)}] {run_id}（已完成） ==")
            unified_runs.append(completed_before[run_id])
            continue
        spent_so_far = _sum_run_usage(unified_runs)["total_tokens"]
        if spent_so_far >= args.max_total_tokens:
            print(f"== 预算触界 [{index + 1}/{len(plan)}] {run_id} 标记 skipped（可续跑） ==")
            budget_exhausted = True
            skipped_runs.append({"run_id": run_id, "case": case, "repeat": repeat,
                                 "status": "skipped_budget_exhausted"})
            continue
        print(f"== 统一链 [{index + 1}/{len(plan)}] {case} #{repeat} ==")
        snapshot_before = _counter_snapshot(unified_counter)
        event = run_unified_case(db, risk, unified_factory, run_id)
        event["usage_delta_vs_counter"] = _counter_diff(
            snapshot_before, _counter_snapshot(unified_counter))
        truth = TRUTH.get(case) or UNIFIED_TRUTH.get(case)
        event["graded"] = grade_unified(event, truth) if truth else None
        _save_run(runs_dir, event)
        unified_runs.append(event)
    results["unified"] = {
        "usage": _sum_run_usage(unified_runs) or unified_counter.as_dict(),
        "usage_this_invocation": unified_counter.as_dict(),
        "runs": unified_runs,
        "skipped_budget": skipped_runs,
        "budget_exhausted": budget_exhausted,
        "max_total_tokens": args.max_total_tokens,
        "dedup_loaded": len(completed_before),
    }

    # ── 对照组 3：失败恢复（屏蔽 runtime_analyst，E1；同样参与断点续跑去重） ──
    results.setdefault("unified_mask_runtime", {"event": None, "expectation": {}})
    mask_counter = UsageCounter()
    if (not case_filter or "CVE-2026-81001" in case_filter) and not budget_exhausted:
        mask_factory = _make_unified_client_factory(mask_counter, mask_agent="runtime")
        risk_e1 = risks_by_case["CVE-2026-81001"][0]
        print("== 统一链·失败恢复（屏蔽 runtime_analyst，E1） ==")
        masked = run_unified_case(db, risk_e1, mask_factory, "uni-mask-runtime-e1")
        masked["graded"] = grade_unified(masked, TRUTH["CVE-2026-81001"])
        _save_run(runs_dir, masked)
        results["unified_mask_runtime"] = {
            "usage": mask_counter.as_dict(),
            "event": masked,
            "expectation": {
                "degraded_recorded": "runtime_analyst" in (masked.get("degraded_roles") or []),
                "human_review": (masked.get("policy") or {}).get("status") == "pending_human_review",
                "verdict_still_produced": bool(masked.get("verdict")),
            },
        }
    elif "uni-mask-runtime-e1" in completed_before:
        results["unified_mask_runtime"] = {
            "event": completed_before["uni-mask-runtime-e1"],
            "expectation": {},   # 断点续跑：期望断言以历史留档为准
        }

    # ── 汇总 ──
    summary = summarize(results)
    results["summary"] = summary
    output = out_dir / "stage9b_unified_compare.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str),
                      encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n完整结果已写入 {output}")
    if budget_exhausted:
        print("!! Token 预算触界：本轮有运行被标记 skipped_budget_exhausted；"
              "充值/额度恢复后以相同命令续跑（已完成运行自动去重）。")


def summarize(results: dict) -> dict:
    def rate(items, key):
        values = [item.get(key) for item in items if item.get(key) is not None]
        return {"correct": sum(1 for v in values if v), "total": len(values)}

    unified_runs = [run for run in results["unified"]["runs"] if run.get("graded")]
    unified_graded = [run["graded"] for run in unified_runs]
    first_pass: dict[str, dict] = {}
    for run in unified_runs:
        first_pass.setdefault(run["case"], run)
    summary = {
        "unified_repeats": len(unified_runs),
        "unified_first_pass": {
            case: run["graded"] for case, run in sorted(first_pass.items())
        },
        "unified_repeat_stability": {
            case: [run["graded"]["action_ok"] for run in unified_runs if run["case"] == case]
            for case in ("CVE-2026-81001", "CVE-2026-81003", "CVE-2026-81005")
        },
        "unified_rates": {key: rate(unified_graded, key)
                          for key in ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "unified_citation_hallucination": sum(
            0 if run["graded"]["citation_ok"] else 1 for run in unified_runs),
        "unified_completed_runs": sum(1 for run in unified_runs if run["status"] == "completed"),
        "unified_failed_runs": sum(1 for run in unified_runs if run["status"] != "completed"),
        "unified_avg_llm_calls_per_event": round(
            results["unified"]["usage"]["llm_calls"] / max(1, len(unified_runs)), 2),
        "unified_total_tokens": results["unified"]["usage"]["total_tokens"],
        "unified_total_wall_seconds": round(
            sum(run["wall_seconds"] for run in unified_runs), 1),
        "mask_recovery": results.get("unified_mask_runtime", {}).get("expectation", {}),
    }
    if "old_system_b" in results:
        old_graded = results["old_system_b"]["graded"]
        summary["old_system_b_rates"] = {key: rate(old_graded, key)
                                         for key in ("impact_ok", "direction_ok",
                                                     "action_ok", "human_ok")}
        summary["old_system_b_total_tokens"] = results["old_system_b"]["usage"]["total_tokens"]
        summary["old_system_b_wall_seconds"] = results["old_system_b"]["wall_seconds"]
        summary["old_system_b_llm_calls"] = results["old_system_b"]["usage"]["llm_calls"]
    return summary


class CountedReviewClientShim:
    """包装 System B 的 autogen 模型客户端，仅计数（与 stage9 的 CountedReviewClient 相同语义）。"""

    def __init__(self, inner, counter: UsageCounter):
        self._inner = inner
        self._counter = counter

    async def create(self, *args, **kwargs):
        response = await self._inner.create(*args, **kwargs)
        self._counter.add(getattr(response, "usage", None))
        return response

    def __getattr__(self, name):
        return getattr(self._inner, name)


if __name__ == "__main__":
    main()
