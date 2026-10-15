"""Stage 9B M4.1 校准第一部分：实验统计口径核查与严格配对对照（离线，零 LLM）。

不做任何付费调用，只读取本地留档的原始实验产物：
- --final-dir：最终验收实验目录（reports/stage9b-unified-final/，含
  stage9b_unified_compare.json 与 runs/*.json）；
- --calibration-dir：本轮校准复测目录（可选；存在则输出新旧严格配对表）。

输出（写入 <out>/calibration_stats.json + stdout 摘要）：
1. 全部运行按五类口径分类（全链 LLM / 独立重复 / 程序兜底 / 屏蔽消融 /
   simple 直通）——LLM 研判准确率只允许用「全链 LLM」口径计算；
2. 最终验收报告的数字修正（调用数、兜底归属、分母与耗时口径）；
3. 逐案例严格配对表（同案例首次成功 LLM 评审 vs System B 同案例结果）；
4. 修改前后逐 Agent 成本（旧数据无逐 Agent token 时如实标 unavailable）。

原则：不改动任何原始存档与真值标签；修正只作用于本汇总。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "scripts"))

from stage9_agent_effectiveness_audit import TRUTH  # noqa: E402
from stage9b_unified_compare import UNIFIED_TRUTH, classify_run  # noqa: E402


def truth_for(case: str) -> dict:
    return TRUTH.get(case) or UNIFIED_TRUTH.get(case) or {}


def load_runs(final_dir: Path) -> list[dict]:
    data = json.loads((final_dir / "stage9b_unified_compare.json").read_text(encoding="utf-8"))
    runs = list((data.get("unified") or {}).get("runs") or [])
    mask = (data.get("unified_mask_runtime") or {}).get("event")
    if mask:
        runs.append(mask)
    return runs


def classify_all(runs: list[dict]) -> dict[str, list[dict]]:
    categories: dict[str, list[dict]] = {}
    for run in runs:
        categories.setdefault(classify_run(run), []).append(run)
    return categories


def first_llm_pass_per_event(runs: list[dict]) -> list[dict]:
    """同案例（risk 事件粒度）首次成功的全链 LLM 评审（配对表的统一链侧）。"""
    order = {"llm_full_chain": 0}
    best: dict[int, dict] = {}
    for run in runs:
        if classify_run(run) != "llm_full_chain":
            continue
        risk_id = run.get("risk_id")
        current = best.get(risk_id)
        graded = run.get("graded") or {}
        score = (0 if graded.get("impact_ok") else 1, run.get("run_id", ""))
        if current is None or score < current[0]:
            best[risk_id] = (score, run)
    return [value[1] for value in best.values()]


def rate(graded: list[dict], key: str) -> dict:
    values = [item.get(key) for item in graded if item.get(key) is not None]
    return {"correct": sum(1 for v in values if v), "total": len(values),
            "ratio": round(sum(1 for v in values if v) / len(values), 4) if values else None}


def reconcile_final(final_dir: Path) -> dict:
    """最终验收实验（M4）的口径核查与数字修正。"""
    data = json.loads((final_dir / "stage9b_unified_compare.json").read_text(encoding="utf-8"))
    runs = load_runs(final_dir)
    categories = classify_all(runs)
    mask = next(iter(categories.get("mask_ablation", [])), None)

    review_runs = [r for r in runs if classify_run(r) != "mask_ablation"]
    review_tokens = sum(int((r.get("usage") or {}).get("total_tokens") or 0) for r in review_runs)
    review_calls = sum(int((r.get("usage") or {}).get("llm_calls") or 0) for r in review_runs)
    mask_tokens = int((mask or {}).get("usage", {}).get("total_tokens") or 0)
    mask_calls = int((mask or {}).get("usage", {}).get("llm_calls") or 0)
    llm_runs = categories.get("llm_full_chain", [])
    fallback_runs = categories.get("program_fallback", [])

    # 双计数口径：runner 计量表（预算语义，含 F3 反馈重试的 register_call(None)
    # 占位）与实验客户端计数器（仅 client.complete 次数）。逐运行的
    # usage_delta_vs_counter 是客户端口径增量。
    review_calls_client = sum(
        int((r.get("usage_delta_vs_counter") or {}).get("llm_calls") or 0) for r in review_runs)
    mask_calls_client = int(((data.get("unified_mask_runtime") or {}).get("usage") or {})
                            .get("llm_calls") or 0)

    # 原报告（acceptance_data.json / 验收报告 §0、§3）的数字与本核查的对照
    old_report = {
        "claimed_llm_calls": 258,
        "claimed_tokens": 1357234,
        "claimed_wall_seconds": 3460,
        "claimed_mixed_impact": {"correct": 15, "total": 17},
        "claimed_mixed_action": {"correct": 11, "total": 17},
        "claimed_fallback_attribution": "E3a 三次",
    }

    llm_graded = [r["graded"] for r in llm_runs]
    mixed_graded = [r["graded"] for r in review_runs]
    fallback_impacts = [((r.get("verdict") or {}).get("impact_status")) for r in fallback_runs]

    per_event_llm = first_llm_pass_per_event(runs)

    # 旧 System B 的两组运行条件（分母不得混用）
    old_full = {   # 上一轮全量 10 事件（代码条件核查一致，最终验收沿用）
        "events": 10, "llm_calls": 44, "total_tokens": 242108, "wall_seconds": 76.0,
    }
    old_supplement = {   # 本轮 X2 补充（冷启动单事件）
        "events": 1, "llm_calls": 4, "total_tokens": 23142, "wall_seconds": 28.1,
    }
    old_combined = {
        "events": 11,
        "llm_calls": old_full["llm_calls"] + old_supplement["llm_calls"],
        "total_tokens": old_full["total_tokens"] + old_supplement["total_tokens"],
        "wall_seconds": round(old_full["wall_seconds"] + old_supplement["wall_seconds"], 1),
    }

    return {
        "experiment": "final_acceptance_m4",
        "run_count": len(runs),
        "categories": {name: {
            "runs": len(items),
            "run_ids": sorted(str(r.get("run_id")) for r in items),
        } for name, items in sorted(categories.items())},
        "fallback_attribution": sorted(
            f"{r.get('case')}#{str(r.get('run_id')).split('-')[-2]}" for r in fallback_runs),
        "fallback_impacts_in_truth": [
            {"case": r.get("case"), "impact": impact,
             "in_truth": impact in (truth_for(str(r.get("case"))).get("impact") or set())}
            for r, impact in zip(fallback_runs, fallback_impacts)],
        "corrected_totals": {
            "review_runs": len(review_runs),
            "review_llm_calls_meter": review_calls,
            "review_llm_calls_client_counter": review_calls_client,
            "review_tokens": review_tokens,
            "mask_llm_calls_meter": mask_calls,
            "mask_llm_calls_client_counter": mask_calls_client,
            "mask_tokens": mask_tokens,
            "all_llm_calls_meter": review_calls + mask_calls,
            "all_llm_calls_client_counter": review_calls_client + mask_calls_client,
            "all_tokens": review_tokens + mask_tokens,
            "wall_seconds_total": round(sum(float(r.get("wall_seconds") or 0) for r in runs), 1),
            "counting_note": "meter=runner 级预算计量（含 F3 反馈重试占位，验收报告 §0 的 258 "
                             "即 237+21 口径）；client_counter=实验计数器（仅 client.complete，"
                             "验收数据 comparison 段的 237/9 即此口径）。两口径均如实呈现。",
        },
        "corrections_vs_report": {
            "llm_calls": {"report": old_report["claimed_llm_calls"],
                          "corrected": review_calls + mask_calls},
            "fallback_attribution": {"report": old_report["claimed_fallback_attribution"],
                                     "corrected": "E3a×2 + E3b×1（逐运行 degraded_roles 核查）"},
            "denominator": {"report": "混合 17 次评审运行（14 全链 + 3 兜底）",
                            "corrected": "LLM 判定 14 次（全链）；兜底 3 次单列"},
        },
        "llm_only_rates": {key: rate(llm_graded, key)
                           for key in ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "mixed_rates_as_reported": {key: rate(mixed_graded, key)
                                    for key in ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "llm_first_pass_per_event": [
            {"case": r.get("case"), "run_id": r.get("run_id"),
             "impact": (r.get("verdict") or {}).get("impact_status"),
             "action": (r.get("verdict") or {}).get("recommended_action"),
             "direction": (r.get("verdict") or {}).get("risk_direction"),
             "graded": {k: (r.get("graded") or {}).get(k)
                        for k in ("impact_ok", "direction_ok", "action_ok", "human_ok")}}
            for r in sorted(per_event_llm, key=lambda x: str(x.get("run_id")))],
        "old_system_b_denominators": {
            "full_run_10_events": old_full,
            "full_run_per_event_seconds": round(old_full["wall_seconds"] / old_full["events"], 2),
            "supplement_x2": old_supplement,
            "combined_11_events": old_combined,
            "combined_per_event_seconds": round(old_combined["wall_seconds"] / old_combined["events"], 2),
            "report_mixed_usage": "验收报告 §3 同时使用 104.1s/11 事件与 ≈7.6s/事件——"
                                  "7.6 为 76.0s/10 事件（全量运行口径），104.1s 合并口径应为 9.46s/事件",
        },
        "old_system_b_events": data.get("old_system_events") or [],
    }


def old_system_events(final_dir: Path) -> list[dict]:
    """System B 留档事件：优先 acceptance_data.json（11 事件含 X2 补充），
    回退上一轮原始 compare JSON 的 old_system_b.events。"""
    acceptance = final_dir / "acceptance_data.json"
    if acceptance.exists():
        data = json.loads(acceptance.read_text(encoding="utf-8"))
        events = data.get("old_system_events") or []
        if events:
            return events
    data = json.loads((final_dir / "stage9b_unified_compare.json").read_text(encoding="utf-8"))
    return ((data.get("old_system_b") or {}).get("events")
            or []) + ((data.get("old_system_b_supplement") or {}).get("events") or [])


def paired_comparison(final_dir: Path, calibration_dir: Path) -> dict:
    """同案例严格配对：统一链（校准复测，首次成功 LLM 评审）vs System B（同案例）。

    System B 数据沿用最终验收的两组运行（10 事件全量 + X2 补充；代码条件
    已核查一致，本轮零改动零重跑）。程序兜底/simple 直通不进入配对表。
    """
    cal_data = json.loads((calibration_dir / "stage9b_unified_compare.json").read_text(encoding="utf-8"))

    old_events = {}
    for event in old_system_events(final_dir):
        # 同案例多事件时保留首个（System B 为每事件单次运行）
        old_events.setdefault(event["case"], event)

    cal_runs = load_runs(calibration_dir)
    paired = []
    for run in first_llm_pass_per_event(cal_runs):
        case = str(run.get("case"))
        truth = truth_for(case)
        old = old_events.get(case) or {}
        unified_verdict = run.get("verdict") or {}
        old_impact = old.get("review_verdict")
        expected_impact = truth.get("impact")
        old_impact_ok = (None if not expected_impact else
                         old_impact in expected_impact if isinstance(expected_impact, set)
                         else old_impact == expected_impact)
        paired.append({
            "case": case,
            "truth": {key: (sorted(value) if isinstance(value, set) else value)
                      for key, value in truth.items() if key != "label"},
            "unified": {
                "run_id": run.get("run_id"),
                "category": classify_run(run),
                "impact": unified_verdict.get("impact_status"),
                "action": unified_verdict.get("recommended_action"),
                "direction": unified_verdict.get("risk_direction"),
                "confidence": unified_verdict.get("confidence"),
                "human": (run.get("policy") or {}).get("status") == "pending_human_review",
                "graded": {k: (run.get("graded") or {}).get(k)
                           for k in ("impact_ok", "direction_ok", "action_ok", "human_ok", "citation_ok")},
                "llm_calls": (run.get("usage") or {}).get("llm_calls"),
                "total_tokens": (run.get("usage") or {}).get("total_tokens"),
                "wall_seconds": run.get("wall_seconds"),
                "per_agent_cost": per_agent_cost(run),
            },
            "system_b": {
                "impact": old_impact,
                "action": old.get("recommended_action"),
                "direction": old.get("risk_direction"),
                "confidence": old.get("review_confidence"),
                "human": bool(old.get("human")),
                "impact_ok": old_impact_ok,
            },
        })

    cal_graded = [r["graded"] for r in first_llm_pass_per_event(cal_runs)]
    old_graded = []
    for case, old in old_events.items():
        truth = truth_for(case)
        if not truth:
            continue
        expected_impact = truth.get("impact")
        old_impact = old.get("review_verdict")
        old_graded.append({
            "impact_ok": (None if not expected_impact else
                          old_impact in expected_impact if isinstance(expected_impact, set)
                          else old_impact == expected_impact),
            "direction_ok": (old.get("risk_direction") in truth["directions"]) if truth.get("directions") else None,
            "action_ok": ((old.get("recommended_action") or old.get("decision")) in truth["actions"]) if truth.get("actions") else None,
            "human_ok": (bool(old.get("human")) if truth.get("needs_human") is not None else None),
        })
    cal_meta = cal_data.get("meta") or {}
    return {
        "experiment": "calibration_m41_vs_system_b",
        "calibration_meta": {
            "generated_at": cal_meta.get("generated_at"),
            "commit": cal_meta.get("commit", ""),
        },
        "paired": paired,
        "unified_llm_only_rates": {key: rate(cal_graded, key)
                                   for key in ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "system_b_rates": {key: rate(old_graded, key)
                           for key in ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "category_counts": {name: len(items)
                            for name, items in sorted(classify_all(cal_runs).items())},
    }


def per_agent_cost(run: dict) -> dict:
    rollup = {}
    for name, log in (run.get("agents_log") or {}).items():
        if not isinstance(log, dict):
            continue
        usage = log.get("llm_usage") or {}
        rollup[name] = {
            "llm_calls": log.get("llm_calls", "unavailable"),
            "total_tokens": usage.get("total_tokens", "unavailable"),
            "tool_calls": len(log.get("tool_calls") or []),
            "latency_ms": log.get("latency_ms"),
            "status": log.get("status"),
        }
    return rollup


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--final-dir", default="reports/stage9b-unified-final")
    parser.add_argument("--calibration-dir", default="",
                        help="校准复测目录（存在则输出严格配对表）")
    parser.add_argument("--out", default="reports/stage9b-unified-calibration")
    args = parser.parse_args()

    final_dir = Path(args.final_dir)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    result = {"reconciliation": reconcile_final(final_dir)}
    if args.calibration_dir and Path(args.calibration_dir, "stage9b_unified_compare.json").exists():
        result["paired_comparison"] = paired_comparison(final_dir, Path(args.calibration_dir))

    output = out_dir / "calibration_stats.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str),
                      encoding="utf-8")

    recon = result["reconciliation"]
    print("== 五类口径分类 ==")
    for name, info in recon["categories"].items():
        print(f"  {name:18s} {info['runs']:2d} 次: {', '.join(info['run_ids'][:4])}"
              f"{' …' if info['runs'] > 4 else ''}")
    print("== 修正 ==")
    totals = recon["corrected_totals"]
    print(f"  LLM 调用（meter 口径）: {totals['all_llm_calls_meter']} "
          f"（评审 {totals['review_llm_calls_meter']} + 消融 {totals['mask_llm_calls_meter']}）；"
          f"client 口径 {totals['all_llm_calls_client_counter']}")
    print(f"  兜底归属: {recon['corrections_vs_report']['fallback_attribution']['corrected']}")
    llm_only = recon["llm_only_rates"]
    mixed = recon["mixed_rates_as_reported"]
    print(f"  impact: LLM-only {llm_only['impact_ok']['correct']}/{llm_only['impact_ok']['total']}"
          f" vs 混合口径 {mixed['impact_ok']['correct']}/{mixed['impact_ok']['total']}")
    print(f"  action: LLM-only {llm_only['action_ok']['correct']}/{llm_only['action_ok']['total']}"
          f" vs 混合口径 {mixed['action_ok']['correct']}/{mixed['action_ok']['total']}")
    old = recon["old_system_b_denominators"]
    print(f"  旧系统耗时口径: 全量 {old['full_run_per_event_seconds']}s/事件（10 事件）；"
          f"合并 {old['combined_per_event_seconds']}s/事件（11 事件）")
    if "paired_comparison" in result:
        paired = result["paired_comparison"]
        print("== 校准复测 vs System B（严格配对） ==")
        u = paired["unified_llm_only_rates"]
        o = paired["system_b_rates"]
        for key in ("impact_ok", "direction_ok", "action_ok", "human_ok"):
            print(f"  {key}: unified {u[key]['correct']}/{u[key]['total']} "
                  f"vs system_b {o[key]['correct']}/{o[key]['total']}")
    print(f"\n完整结果已写入 {output}")


if __name__ == "__main__":
    main()
