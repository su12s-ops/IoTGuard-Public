"""Stage 9B M4.2：研判质量专项实验（真实 LLM）。

设计（对应 M4.2 任务书第五/六/七部分）：
- Fixture = 既有 E1–E5/X1–X3 + 新增独立案例 Y1–Y10（真值表先验固定于
  stage9b_quality_cases.Y_TRUTH，先于任何模型运行入库）；
- 三方对照：确定性规则基线（免费）/ System B 原链路（Y 案例）/ 统一四智能体；
- 统一链运行矩阵：Y1–Y10 首跑 + E/X 复验（新语义下不回归）+ 稳定性重复
  （E1/E2/E3a 追加 + Y1/Y6 追加）；
- 语义消融：asset/vulnerability/runtime 三角色报告分别从决策输入中隐藏
  （角色照常执行；graph.ablation_mask 钩子），度量各角色独立分析贡献；
- 反事实：Y6 去除 KEV（--counterfactual，独立库）——验证 urgency_amplifiers
  机制真实驱动决策；
- 统计纪律：全运行口径（不挑选首次判断正确的运行）；程序兜底/消融/反事实
  与主统计分离；逐 Agent 真实计量。

用法：
    python scripts/stage9b_quality_experiment.py --out reports/stage9b-quality
    python scripts/stage9b_quality_experiment.py --dry
    python scripts/stage9b_quality_experiment.py --counterfactual \
        --out reports/stage9b-quality-cf
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(BACKEND_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR / "scripts"))

from stage9_agent_effectiveness_audit import (  # noqa: E402
    CASE_ORDER,
    CountedChatClient,
    TRUTH,
    UsageCounter,
    build_fixture,
    collect_baseline,
    fresh_session_factory,
)
from stage9b_unified_compare import (  # noqa: E402
    CASE_ORDER_X,
    UNIFIED_TRUTH,
    _load_completed_runs,
    _run_file,
    _save_run,
    _sum_run_usage,
    classify_run,
    grade_old,
    grade_unified,
    per_agent_cost_rollup,
)
from stage9b_quality_cases import (  # noqa: E402
    Y6_COUNTERFACTUAL_CVE,
    Y6_COUNTERFACTUAL_TRUTH,
    Y_CASE_ORDER,
    Y_TRUTH,
    extend_fixture_for_y_cases,
)

ALL_TRUTH = {**TRUTH, **UNIFIED_TRUTH, **Y_TRUTH}

# 主矩阵：E/X 复验 + Y 首跑；稳定性追加（E1/E2/E3a + Y1/Y6）
REVERIFY_CASES = ["CVE-2026-81001", "CVE-2026-81002", "CVE-2026-81003",
                  "CVE-2026-81004", "CVE-2026-81005", "CVE-2026-81008",
                  "CVE-2026-81007"]
STABILITY_REPEATS = {"CVE-2026-81001": 1, "CVE-2026-81002": 1, "CVE-2026-81003": 2,
                     "CVE-2026-81010": 1, "CVE-2026-81015": 1}

# 语义消融矩阵：角色 × 案例（案例选择该角色专业输出为承重证据的实例）
ABLATION_PLAN = [
    ("vulnerability_analyst", "CVE-2026-81010"),   # Y1 backport 判定承重
    ("vulnerability_analyst", "CVE-2026-81003"),   # E3 分支排除判定承重
    ("runtime_analyst", "CVE-2026-81018"),         # Y9 无关证据辨析承重
    ("runtime_analyst", "CVE-2026-81001"),         # E1 直接利用证据承重
    ("asset_investigator", "CVE-2026-81013"),      # Y4 清单完整性承重
    ("asset_investigator", "CVE-2026-81019"),      # Y10 缓解绑定（暴露面）承重
]

# 运行内保持「设计在线」的 Y 传感器（Y5/Y6/Y8 设计为无监控，不在其列）
Y_FRESH_SENSORS = ["sensor-edge-10", "sensor-edge-11", "sensor-edge-12",
                   "sensor-edge-13", "sensor-edge-16", "sensor-edge-18",
                   "sensor-edge-19"]


def _refresh_y_sensor_heartbeats(db) -> None:
    """消除脚手架时序竞态：E 案例沿用既有刷新，Y 案例刷新设计在线传感器。

    Y5（edge-14）/Y6（edge-15）无传感器、Y8（wrt2-node）无 eBPF 证据源——
    保持「监控缺失/能力受限」设计语义不变。
    """
    from app import models

    (db.query(models.RuntimeSensor)
       .filter(models.RuntimeSensor.sensor_id.in_(Y_FRESH_SENSORS))
       .update({models.RuntimeSensor.last_heartbeat_at: datetime.now(timezone.utc)},
               synchronize_session=False))
    db.commit()


def run_case(db, risk, factory, run_id: str, ablation_mask: frozenset[str] = frozenset()) -> dict:
    """统一链单事件运行（影子模式；支持语义消融注入）。"""
    import app.services.unified.runner as runner_mod
    from app import models
    from sqlalchemy.orm import sessionmaker

    asset = db.get(models.LinuxAsset, risk.asset_id) if risk.asset_id else None
    target_ref = asset.hostname if asset else ""
    _refresh_y_sensor_heartbeats(db)
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
        runner_mod.run_unified_sync(db, row, client_factory=factory, sink=None,
                                    ablation_mask=ablation_mask)
        wall_s = round(time.monotonic() - started, 1)
    finally:
        runner_mod.SessionLocal = original
    state = json.loads(row.state_json or "{}")
    final = state.get("final") or {}
    decision = json.loads(row.decision_json or "{}") or state.get("decision") or {}
    verdicts = decision.get("verdicts") or []
    meter_usage = json.loads(row.usage_json or "{}") or {}
    nested = meter_usage.get("usage") or {}
    agents_log = json.loads(row.agents_json or "{}") or {}
    verdict = verdicts[0] if verdicts else None
    runtime = state.get("runtime") or state.get("runtime_program_fallback") or {}
    return {
        "case": risk.cve_id.split(":")[0],
        "risk_id": risk.id,
        "run_id": row.run_id,
        "ablation_mask": sorted(ablation_mask),
        "status": row.status,
        "error": (row.error or "")[:400],
        "wall_seconds": wall_s,
        "routing": json.loads(row.routing_json or "{}"),
        "tier": (json.loads(row.routing_json or "{}") or {}).get("tier"),
        "stage_status": state.get("stage_status", {}),
        "degraded_roles": state.get("degraded_roles", []),
        "policy": final.get("policy"),
        "verdict": verdict,
        "decision_full": decision,
        "conflict": (state.get("conflict_result") or {}),
        "vulnerability": state.get("vulnerability"),
        "runtime": runtime,
        "investigation": state.get("investigation"),
        "evidence_prep": {
            "available": bool(state.get("evidence_prep")),
            "branch_check": (((state.get("evidence_prep") or {}).get("candidates") or [{}])[0]
                             .get("branch_check") or {}).get("result", ""),
            "version_compare": (((state.get("evidence_prep") or {}).get("candidates") or [{}])[0]
                                .get("version_compare") or {}).get("result", ""),
            "vendor_patch": (((state.get("evidence_prep") or {}).get("candidates") or [{}])[0]
                             .get("vendor_patch") or {}),
            "vendor_conflict_unresolved": bool((((state.get("evidence_prep") or {})
                                                 .get("candidates") or [{}])[0]
                                                .get("vendor_conflict") or {}).get("unresolved")),
            "urgency_amplifiers": (((state.get("evidence_prep") or {}).get("candidates") or [{}])[0]
                                   .get("urgency_amplifiers") or {}),
            "runtime_evidence_ids": (state.get("evidence_prep") or {}).get(
                "runtime_facts", {}).get("evidence_ids") or [],
        },
        "agents_log": agents_log,
        "follow_up_audit": {
            "requested": len(decision.get("follow_up_requests") or []),
            "requests": decision.get("follow_up_requests") or [],
            "executed_results": len(state.get("follow_up_results", [])),
            "reentered_decision": bool(state.get("follow_up_results"))
            and state.get("stage_status", {}).get("decide") == "succeeded" and bool(verdict),
        },
        "usage": {
            "llm_calls": meter_usage.get("llm_calls"),
            "prompt_tokens": nested.get("prompt_tokens"),
            "completion_tokens": nested.get("completion_tokens"),
            "total_tokens": nested.get("total_tokens"),
            "budget_exceeded": meter_usage.get("budget_exceeded"),
        },
    }


def _make_unified_factory(counter: UsageCounter):
    from app.services.agents.base import DeepSeekChatClient
    from app.config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL

    if not DEEPSEEK_API_KEY:
        raise RuntimeError("未配置 DEEPSEEK_API_KEY；真实 LLM 实验需要密钥（.env，不入库）")

    def factory():
        inner = DeepSeekChatClient(model=DEEPSEEK_MODEL, api_key=DEEPSEEK_API_KEY,
                                   base_url=DEEPSEEK_BASE_URL)
        return CountedChatClient(inner, counter)

    return factory


def run_system_b_y(db, y_risks) -> dict:
    """System B 对照（仅 Y 案例；沿用 stage9b_unified_compare 的计量包装）。"""
    from stage9b_unified_compare import CountedReviewClientShim, old_system_event_rows
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
    selected = [risk for risk in y_risks
                if risk.review_status in erp.REVIEWABLE_STATUSES]
    started = time.monotonic()
    try:
        result = erp.run_review_analysis(db, run_id="old-quality-y", selected_risks=selected)
    finally:
        erp._create_model_client = real_factory
    wall = round(time.monotonic() - started, 1)
    events = [event for event in old_system_event_rows(db)
              if event["case"] in set(Y_CASE_ORDER)]
    graded = [grade_old(event, Y_TRUTH[event["case"]]) for event in events]
    return {"status": result.get("status"), "wall_seconds": wall,
            "usage": counter_old.as_dict(), "events": events, "graded": graded}


def _reset_review_fields(db) -> None:
    db.rollback()
    from app import models
    for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
        risk.review_status = "candidate"
        risk.human_review_required = False
        risk.final_score = None
        risk.risk_level = None
        risk.decision = None
    db.commit()


def summarize(results: dict) -> dict:
    """全运行口径汇总（任务书第七部分：不挑选首次判断正确的运行）。"""
    def rate(items, key):
        values = [item.get(key) for item in items if item.get(key) is not None]
        return {"correct": sum(1 for value in values if value),
                "total": len(values)}

    main_runs = [run for run in results["unified"]["runs"]
                 if not run.get("ablation_mask")]
    ablation_runs = [run for run in results["unified"]["runs"]
                     if run.get("ablation_mask")]
    main_graded = [run["graded"] for run in main_runs if run.get("graded")]
    llm_graded = [graded for graded in main_graded
                  if graded.get("category") == "llm_full_chain"]

    by_case: dict[str, list[dict]] = {}
    for run in main_runs:
        by_case.setdefault(run["case"], []).append(run)

    per_case = {}
    for case, runs in sorted(by_case.items()):
        truth = ALL_TRUTH.get(case) or {}
        verdicts = [run.get("verdict") or {} for run in runs]
        impacts = [verdict.get("impact_status") for verdict in verdicts]
        actions = [verdict.get("recommended_action") for verdict in verdicts]
        directions = [verdict.get("risk_direction") for verdict in verdicts]
        expected_impact = truth.get("impact")
        impact_ok = ([value in expected_impact if isinstance(expected_impact, set)
                      else value == expected_impact for value in impacts]
                     if expected_impact else [])
        expected_actions = truth.get("actions")
        action_ok = ([value in expected_actions for value in actions]
                     if expected_actions else [])
        expected_directions = truth.get("directions")
        direction_ok = ([value in expected_directions for value in directions]
                        if expected_directions else [])
        per_case[case] = {
            "label": truth.get("label", ""),
            "runs": len(runs),
            "impacts": impacts, "actions": actions, "directions": directions,
            "impact_ok": impact_ok, "action_ok": action_ok, "direction_ok": direction_ok,
            "impact_all_ok": all(impact_ok) if impact_ok else None,
            "action_all_ok": all(action_ok) if action_ok else None,
            "direction_all_ok": all(direction_ok) if direction_ok else None,
            "human": [(run.get("policy") or {}).get("status") == "pending_human_review"
                      for run in runs],
        }

    ablation_summary = {}
    for run in ablation_runs:
        key = f"{'+'.join(run['ablation_mask'])}@{run['case']}"
        graded = run.get("graded") or {}
        ablation_summary[key] = {
            "masked": run["ablation_mask"],
            "case": run["case"],
            "impact": (run.get("verdict") or {}).get("impact_status"),
            "action": (run.get("verdict") or {}).get("recommended_action"),
            "direction": (run.get("verdict") or {}).get("risk_direction"),
            "impact_ok": graded.get("impact_ok"),
            "action_ok": graded.get("action_ok"),
            "reason_excerpt": ((run.get("verdict") or {}).get("reason") or "")[:300],
        }

    counterfactual = results.get("counterfactual") or None

    return {
        "matrix_runs": len(main_runs),
        "matrix_llm_full_chain": len(llm_graded),
        "llm_only_rates_all_runs": {key: rate(llm_graded, key)
                                    for key in ("impact_ok", "direction_ok", "action_ok",
                                                "human_ok", "citation_ok")},
        "y_cases_all_runs": {case: view for case, view in per_case.items()
                             if case in set(Y_CASE_ORDER)},
        "e_x_reverify_all_runs": {case: view for case, view in per_case.items()
                                  if case in set(CASE_ORDER + CASE_ORDER_X)},
        "per_case": per_case,
        "ablation": ablation_summary,
        "counterfactual": counterfactual,
        "citation_hallucination": sum(0 if graded.get("citation_ok") else 1
                                      for graded in main_graded),
        "program_fallback_runs": sum(1 for run in main_runs
                                     if classify_run(run) == "program_fallback"),
        "failed_runs": [run["run_id"] for run in results["unified"]["runs"]
                        if run.get("status") != "completed"],
        "usage": results["unified"]["usage"],
        "usage_this_invocation": results["unified"].get("usage_this_invocation"),
        "per_agent_cost": per_agent_cost_rollup(
            [run for run in results["unified"]["runs"]]),
        "wall_seconds_total": round(sum(run.get("wall_seconds", 0)
                                        for run in results["unified"]["runs"]), 1),
        "system_b_y": ({case: graded for case, graded in
                        ((graded["case"], graded) for graded in
                         (results.get("system_b") or {}).get("graded", []))}
                       if results.get("system_b") else None),
    }


def _plan_matrix(risks_by_case, repeats_enabled: bool) -> list[tuple[str, object, int, str]]:
    """(case, risk, repeat_index, run_id)；E3 多实例逐实例评审。"""
    plan: list[tuple[str, object, int, str]] = []
    for case in REVERIFY_CASES + Y_CASE_ORDER:
        for risk in risks_by_case.get(case, []):
            plan.append((case, risk, 0, f"q-{case}-0-{risk.id}"))
    if repeats_enabled:
        for case, extra in STABILITY_REPEATS.items():
            for risk in risks_by_case.get(case, []):
                for index in range(1, extra + 1):
                    plan.append((case, risk, index, f"q-{case}-{index}-{risk.id}"))
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="reports/stage9b-quality")
    parser.add_argument("--dry", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--cases", default="", help="逗号分隔案例过滤；空=全部")
    parser.add_argument("--skip-old", action="store_true", help="跳过 System B 对照")
    parser.add_argument("--skip-ablation", action="store_true")
    parser.add_argument("--no-repeats", action="store_true")
    parser.add_argument("--counterfactual", action="store_true",
                        help="反事实库：Y6 去除 KEV，仅运行 Y6")
    parser.add_argument("--max-total-tokens", type=int, default=3_500_000)
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root = out_dir / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("LINUXGUARD_DATA_DIR", str(work_root / "data"))
    os.environ["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"
    os.environ["PYTHON_DOTENV_DISABLED"] = "0"

    import tempfile
    tmp_root = Path(tempfile.mkdtemp(prefix="stage9b-quality-"))
    factory_db, engine = fresh_session_factory(tmp_root / "db")
    db = factory_db()
    build_fixture(db, with_runtime=True)
    extend_fixture_for_y_cases(db, y6_kev=not args.counterfactual)
    baseline = collect_baseline(db)

    from app import models
    risks_by_case: dict[str, list] = {}
    for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
        risks_by_case.setdefault(risk.cve_id.split(":")[0], []).append(risk)

    print("== 规则基线（对照组 A：确定性规则） ==")
    for case in Y_CASE_ORDER:
        for risk in risks_by_case.get(case, []):
            info = baseline.get(case, {})
            print(f"  {case} risk#{risk.id}: score={info.get('preliminary_score')} "
                  f"level={info.get('preliminary_level')} "
                  f"decision={info.get('preliminary_decision')}")
    if args.dry:
        db.close()
        return

    results: dict = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "counterfactual(y6-no-kev)" if args.counterfactual else "main",
            "truth_tables": "E/X（沿用固定版本） + Y_TRUTH（先验固定于"
                            "stage9b_quality_cases.py，先于本实验入库）",
        },
        "rules_baseline": {case: [baseline.get(r.cve_id.split(":")[0]) for r in rows]
                           for case, rows in risks_by_case.items()},
    }

    if args.counterfactual:
        # 反事实：仅 Y6（无 KEV），对照 Y6_COUNTERFACTUAL_TRUTH
        unified_counter = UsageCounter()
        unified_factory = _make_unified_factory(unified_counter)
        completed = {} if args.fresh else _load_completed_runs(runs_dir)
        cf_runs: list[dict] = []
        for risk in risks_by_case.get(Y6_COUNTERFACTUAL_CVE, []):
            run_id = f"cf-{Y6_COUNTERFACTUAL_CVE}-0-{risk.id}"
            if run_id in completed:
                cf_runs.append(completed[run_id])
                continue
            print(f"== 反事实统一链 {run_id} ==")
            event = run_case(db, risk, unified_factory, run_id)
            event["graded"] = grade_unified(event, Y6_COUNTERFACTUAL_TRUTH)
            _save_run(runs_dir, event)
            cf_runs.append(event)
        results["counterfactual"] = {
            "truth": Y6_COUNTERFACTUAL_TRUTH,
            "runs": [{key: run.get(key) for key in
                      ("run_id", "status", "verdict", "policy", "usage", "graded",
                       "evidence_prep")} for run in cf_runs],
            "usage": _sum_run_usage(cf_runs),
        }
        output = out_dir / "stage9b_quality_experiment.json"
        output.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str),
                          encoding="utf-8")
        print(json.dumps(results["counterfactual"]["runs"][0].get("verdict"),
                         ensure_ascii=False, indent=2))
        print(f"反事实结果已写入 {output}")
        db.close()
        return

    # ── 对照组 B：System B（Y 案例） ──
    if not args.skip_old:
        print("== System B 对照（Y1–Y10） ==")
        y_risks = [risk for case in Y_CASE_ORDER for risk in risks_by_case.get(case, [])]
        old_result = run_system_b_y(db, y_risks)
        results["system_b"] = old_result
        print(f"== System B 完成：{old_result['wall_seconds']}s, "
              f"{old_result['usage']} ==")
        _reset_review_fields(db)

    # ── 对照组 C：统一四智能体（主矩阵 + 稳定性重复） ──
    unified_counter = UsageCounter()
    unified_factory = _make_unified_factory(unified_counter)
    completed_before = {} if args.fresh else _load_completed_runs(runs_dir)
    if completed_before:
        print(f"== 断点续跑：发现 {len(completed_before)} 个已完成运行，将去重跳过 ==")
    case_filter = {item.strip() for item in args.cases.split(",") if item.strip()}
    plan = [item for item in _plan_matrix(risks_by_case, not args.no_repeats)
            if not case_filter or item[0] in case_filter]
    unified_runs: list[dict] = []
    skipped: list[dict] = []
    budget_exhausted = False
    for index, (case, risk, repeat, run_id) in enumerate(plan):
        if run_id in completed_before:
            print(f"== 去重跳过 [{index + 1}/{len(plan)}] {run_id} ==")
            unified_runs.append(completed_before[run_id])
            continue
        if _sum_run_usage(unified_runs)["total_tokens"] >= args.max_total_tokens:
            budget_exhausted = True
            skipped.append({"run_id": run_id, "case": case, "status": "skipped_budget"})
            continue
        print(f"== 统一链 [{index + 1}/{len(plan)}] {case} #{repeat} ==")
        event = run_case(db, risk, unified_factory, run_id)
        truth = ALL_TRUTH.get(case)
        event["graded"] = grade_unified(event, truth) if truth else None
        _save_run(runs_dir, event)
        unified_runs.append(event)

    # ── 语义消融（独立预算段；失败不影响主矩阵） ──
    if not args.skip_ablation and not budget_exhausted:
        ablation_counter = UsageCounter()
        for role, case in ABLATION_PLAN:
            run_id = f"abl-{role.split('_')[0]}-{case}"
            if run_id in completed_before:
                unified_runs.append(completed_before[run_id])
                continue
            if _sum_run_usage(unified_runs)["total_tokens"] >= args.max_total_tokens:
                budget_exhausted = True
                skipped.append({"run_id": run_id, "case": case, "status": "skipped_budget"})
                continue
            risks = risks_by_case.get(case, [])
            if not risks:
                continue
            print(f"== 语义消融：隐藏 {role} → {case} ==")
            ablation_factory = _make_unified_factory(ablation_counter)
            event = run_case(db, risks[0], ablation_factory, run_id,
                             ablation_mask=frozenset({role}))
            truth = ALL_TRUTH.get(case)
            event["graded"] = grade_unified(event, truth) if truth else None
            _save_run(runs_dir, event)
            unified_runs.append(event)

    results["unified"] = {
        "usage": _sum_run_usage(unified_runs),
        "usage_this_invocation": unified_counter.as_dict(),
        "runs": unified_runs,
        "skipped_budget": skipped,
        "budget_exhausted": budget_exhausted,
        "max_total_tokens": args.max_total_tokens,
        "dedup_loaded": len(completed_before),
    }

    summary = summarize(results)
    results["summary"] = summary
    output = out_dir / "stage9b_quality_experiment.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str),
                      encoding="utf-8")
    compact = {key: summary[key] for key in
               ("matrix_runs", "matrix_llm_full_chain", "llm_only_rates_all_runs",
                "program_fallback_runs", "citation_hallucination", "usage",
                "wall_seconds_total")}
    print(json.dumps(compact, ensure_ascii=False, indent=2))
    print(f"完整结果已写入 {output}")
    if budget_exhausted:
        print("!! Token 预算触界：有运行被标记 skipped_budget；可用相同命令续跑。")
    db.close()


if __name__ == "__main__":
    main()
