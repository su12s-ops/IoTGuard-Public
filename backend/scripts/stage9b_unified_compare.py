"""Stage 9B：统一四智能体 vs System B 同案例对照实验（真实 LLM）。

设计（对应 IOT_UNIFIED_FOUR_AGENT_ARCHITECTURE.md §9）：
- 复用 Stage 9 审计的受控 Fixture（合成 CVE-2026-81xxx / TEST-NET 地址，
  真值表先验独立定义）与计量包装（客户端真实 usage，不编造）；
- 同一 Fixture 上运行：规则基线 A / System B 原链路 / 统一四智能体（影子，
  不触碰正式字段）；
- 新增独立案例：X1 低复杂度候选（成本分层直通）、X2 设备巡检任务（F5 聚合
  + 计划产出）、X3 仅过期运行时证据+直接命中（F6 新鲜度语义）；
- 重复运行：E1/E3/E5 各 N 次（默认 3）观察运行间方差；
- 失败恢复：屏蔽统一链 runtime_analyst（E1）——部分失败不全丢（F7）、
  门禁强制人工；
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
    # X3：证据全部过期但采集器在线——不得判 verified，不得据此立即修复
    "CVE-2026-81007": {
        "label": "X3 仅过期运行时证据+直接命中（freshness 语义）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": True,   # stale 门禁/冲突 → 必须人工
    },
}
CASE_ORDER_X = ["CVE-2026-81006", "CVE-2026-81007"]


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


def run_unified_case(db, risk, factory, run_id: str) -> dict:
    """对单个风险事件执行统一编排（影子模式：sink=None，不触碰正式字段）。"""
    import app.services.unified.runner as runner_mod
    from app import models
    from sqlalchemy.orm import sessionmaker

    # runner 的节点会话必须来自同一实验库（与单测同模式：临时覆盖，用后恢复）
    fixture_factory = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False)
    original = runner_mod.SessionLocal
    runner_mod.SessionLocal = fixture_factory
    try:
        row = models.UnifiedAnalysisRun(
            run_id=run_id, task_type="risk_review", target_type="linux_host",
            target_ref="fixture", mode="shadow", status="running", risk_id=risk.id)
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
    usage = json.loads(row.usage_json or "{}")
    return {
        "case": risk.cve_id.split(":")[0],
        "risk_id": risk.id,
        "run_id": row.run_id,
        "status": row.status,
        "error": row.error[:400],
        "wall_seconds": wall_s,
        "routing": json.loads(row.routing_json or "{}"),
        "stage_status": state.get("stage_status", {}),
        "degraded_roles": state.get("degraded_roles", []),
        "tier": (json.loads(row.routing_json or "{}") or {}).get("tier"),
        "policy": final.get("policy"),
        "aggregate": final.get("aggregate"),
        "verdict": verdicts[0] if verdicts else None,
        "decision_full": decision,
        "conflict": (state.get("conflict_result") or {}),
        "vulnerability": state.get("vulnerability"),
        "runtime": state.get("runtime") or state.get("runtime_program_fallback"),
        "investigation": state.get("investigation"),
        "follow_ups": state.get("follow_up_results", []),
        "usage": usage,
    }


def grade_unified(event: dict, truth: dict) -> dict:
    """对照真值表给统一链单案例打分（处置级/方向级/人工路由/引用完整性）。"""
    verdict = event.get("verdict") or {}
    policy = event.get("policy") or {}
    runtime = event.get("runtime") or {}
    problems: list[str] = []
    is_simple = event.get("tier") == "simple"

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

    # 引用完整性：裁定引用的证据必须真实存在于统一链已知证据集合
    runtime_ids = set(runtime.get("evidence_ids") or [])
    cited = set(verdict.get("supporting_evidence_ids") or [])
    unknown = sorted(cited - runtime_ids - {f"EV-*"})   # packet ids 事件级各异，此处以运行时为准
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="reports/stage9b-unified")
    parser.add_argument("--dry", action="store_true", help="只构建 Fixture 与规则基线，不调用 LLM")
    parser.add_argument("--repeats", type=int, default=3,
                        help="E1/E3/E5 统一链重复运行次数（含首次）")
    parser.add_argument("--skip-old", action="store_true", help="跳过 System B 对照运行")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root = out_dir / "work"
    work_root.mkdir(parents=True, exist_ok=True)
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
            info = baseline.get(risk.cve_id) or baseline.get(key, {})
            print(f"  {key} risk#{risk.id}: score={info.get('preliminary_score')} "
                  f"level={info.get('preliminary_level')} decision={info.get('preliminary_decision')}")
    if args.dry:
        db.close()
        return

    results: dict[str, any] = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repeats": args.repeats,
            "fixture": "stage9 E1-E5 + X1/X3（合成 CVE / TEST-NET）",
        },
        "baseline": {case: [baseline.get(r.cve_id) for r in rows]
                     for case, rows in risks_by_case.items()},
    }

    # ── 对照组 1：System B 原链路（全量 5+2 案例 1 次） ──
    if not args.skip_old:
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

    # ── 对照组 2：统一四智能体（逐案例影子运行） ──
    unified_counter = UsageCounter()
    unified_factory = _make_unified_client_factory(unified_counter)
    unified_runs: list[dict] = []
    repeat_cases = ["CVE-2026-81001", "CVE-2026-81003", "CVE-2026-81005"]
    plan: list[tuple[str, any, int]] = []
    for case in CASE_ORDER + CASE_ORDER_X:
        for risk in risks_by_case.get(case, []):
            repeats = args.repeats if case in repeat_cases else 1
            for index in range(repeats):
                plan.append((case, risk, index))
    for index, (case, risk, repeat) in enumerate(plan):
        run_id = f"uni-{case}-{repeat}-{risk.id}"
        print(f"== 统一链 [{index + 1}/{len(plan)}] {case} #{repeat} ==")
        event = run_unified_case(db, risk, unified_factory, run_id)
        truth = TRUTH.get(case) or UNIFIED_TRUTH.get(case)
        event["graded"] = grade_unified(event, truth) if truth else None
        unified_runs.append(event)
    results["unified"] = {"usage": unified_counter.as_dict(), "runs": unified_runs}

    # ── 对照组 3：失败恢复（屏蔽 runtime_analyst，E1） ──
    mask_counter = UsageCounter()
    mask_factory = _make_unified_client_factory(mask_counter, mask_agent="runtime")
    risk_e1 = risks_by_case["CVE-2026-81001"][0]
    print("== 统一链·失败恢复（屏蔽 runtime_analyst，E1） ==")
    masked = run_unified_case(db, risk_e1, mask_factory, "uni-mask-runtime-e1")
    masked["graded"] = grade_unified(masked, TRUTH["CVE-2026-81001"])
    results["unified_mask_runtime"] = {
        "usage": mask_counter.as_dict(),
        "event": masked,
        "expectation": {
            "degraded_recorded": "runtime_analyst" in (masked.get("degraded_roles") or []),
            "human_review": (masked.get("policy") or {}).get("status") == "pending_human_review",
            "verdict_still_produced": bool(masked.get("verdict")),
        },
    }

    # ── 汇总 ──
    summary = summarize(results)
    results["summary"] = summary
    output = out_dir / "stage9b_unified_compare.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str),
                      encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n完整结果已写入 {output}")


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
        "unified_avg_llm_calls_per_event": round(
            results["unified"]["usage"]["llm_calls"] / max(1, len(unified_runs)), 2),
        "unified_total_tokens": results["unified"]["usage"]["total_tokens"],
        "unified_total_wall_seconds": round(
            sum(run["wall_seconds"] for run in unified_runs), 1),
        "mask_recovery": results["unified_mask_runtime"]["expectation"],
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
