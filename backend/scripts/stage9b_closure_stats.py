"""Stage 9B M4.2 收尾统计：从原始运行产物一键重建收尾报告全部数字。

统计纪律（与主实验一致，全部可离线复现）：
- 分母 = 全部运行文件（主矩阵 25 + 消融 6 + 收尾运行），不挑选、不删除；
- LLM 准确率仅统计 category=llm_full_chain 的运行；程序兜底/simple 单列；
- 同一 run_id 链的重试（*-rN）：每个链取**最后一次**运行参与 LLM 口径，
  被取代的首次外部故障运行保留留档并单列（superseded 口径）；
- 计量口径三分离：run 级 meter（register_call 含零 token 失败调用）/
  client 级 counter（仅成功响应）/ 逐 Agent 表（agents_log 每角色**末次**
  调用——定向复议与补查再执行会覆盖同名条目，故小于 meter 合计）。

用法：python scripts/stage9b_closure_stats.py [--original reports/stage9b-quality]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(BACKEND_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR / "scripts"))

from stage9b_unified_compare import classify_run  # noqa: E402

CASE_LABELS = {"CVE-2026-81001": "E1", "CVE-2026-81002": "E2", "CVE-2026-81003": "E3",
               "CVE-2026-81004": "E4", "CVE-2026-81005": "E5", "CVE-2026-81008": "X2",
               "CVE-2026-81007": "X3", "CVE-2026-81006": "X1",
               "CVE-2026-81010": "Y1", "CVE-2026-81011": "Y2", "CVE-2026-81012": "Y3",
               "CVE-2026-81013": "Y4", "CVE-2026-81014": "Y5", "CVE-2026-81015": "Y6",
               "CVE-2026-81016": "Y7", "CVE-2026-81017": "Y8", "CVE-2026-81018": "Y9",
               "CVE-2026-81019": "Y10", "CVE-2026-81021": "RT"}


def label_of(run_or_case):
    """case 字符串或 run dict → 展示标签（cf2- 前缀的运行标注 CF2 格）。"""
    if isinstance(run_or_case, dict):
        run_id = run_or_case.get("run_id") or ""
        base = label_of(run_or_case.get("case") or "")
        if run_id.startswith("cf2-y6-"):
            cell = run_id.split("-")[2]
            return f"{base}#{cell}"
        if run_id.startswith("rt-"):
            tag = run_id.split("-")[2].upper()
            return f"{base}#{tag}"
        return base
    return CASE_LABELS.get(run_or_case, run_or_case)


def load_runs(runs_dir: Path) -> list[dict]:
    runs = []
    for path in sorted(runs_dir.glob("run-*.json")):
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return runs


def dedup_retry_chains(runs: list[dict]) -> tuple[list[dict], list[dict]]:
    """重试链去重：返回（最终样本, 被取代的首次故障样本）。

    run_id 形如 <base>-rN 的运行取代 <base>；链内取末次。
    """
    by_base: dict[str, list[dict]] = {}
    for run in runs:
        run_id = run.get("run_id") or ""
        base = run_id
        while base.rsplit("-r", 1)[-1].isdigit() and "-r" in base:
            base = base.rsplit("-r", 1)[0]
        by_base.setdefault(base, []).append(run)

    def chain_order(run):
        run_id = run.get("run_id") or ""
        suffix = run_id[len(base_of(run_id)):] if run_id.startswith(base_of(run_id)) else ""
        return int(suffix[2:]) if suffix.startswith("-r") and suffix[2:].isdigit() else 0

    def base_of(run_id: str) -> str:
        base = run_id
        while base.rsplit("-r", 1)[-1].isdigit() and "-r" in base:
            base = base.rsplit("-r", 1)[0]
        return base

    final, superseded = [], []
    for base, chain in by_base.items():
        chain_sorted = sorted(chain, key=lambda r: chain_order(r))
        final.append(chain_sorted[-1])
        superseded.extend(chain_sorted[:-1])
    return final, superseded


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--original", default="reports/stage9b-quality")
    parser.add_argument("--closure", default="reports/stage9b-closure")
    args = parser.parse_args()

    original_dir = Path(args.original)
    closure_dir = Path(args.closure)
    orig_runs = load_runs(original_dir / "runs")
    closure_runs_raw = load_runs(closure_dir / "runs")
    closure_final, closure_superseded = dedup_retry_chains(closure_runs_raw)

    print("=" * 72)
    print("一、主矩阵分母（原始产物，零改动）")
    print("=" * 72)
    main_runs = [run for run in orig_runs
                 if (run.get("run_id") or "").startswith("q-")]
    abl_runs = [run for run in orig_runs if (run.get("run_id") or "").startswith("abl-")]
    cats: dict[str, list[dict]] = {}
    for run in main_runs:
        cats.setdefault(classify_run(run), []).append(run)
    print(f"主矩阵运行总数: {len(main_runs)}（消融 {len(abl_runs)}）")
    for cat, items in sorted(cats.items()):
        ids = ", ".join(sorted(run["run_id"] for run in items))
        print(f"  {cat}: {len(items)} — {ids}")
    llm = cats.get("llm_full_chain", [])
    print("19 次全链 case_id:",
          ", ".join(f"{label_of(run['case'])}({run['run_id'].rsplit('-', 2)[-2]})" for run in llm))
    rates = {key: (sum(1 for run in llm if (run.get("graded") or {}).get(key)), len(llm))
             for key in ("impact_ok", "action_ok", "direction_ok", "citation_ok")}
    human_required = [run for run in llm if (run.get("graded") or {}).get("human_ok") is not None]
    rates["human_ok"] = (sum(1 for run in human_required
                             if (run.get("graded") or {}).get("human_ok")), len(human_required))
    for key, (ok, total) in rates.items():
        print(f"  LLM 口径 {key}: {ok}/{total}")

    print()
    print("=" * 72)
    print("二、计量口径对账（三口径分离）")
    print("=" * 72)
    def meter_sum(runs):
        calls = sum((run.get("usage") or {}).get("llm_calls") or 0 for run in runs)
        tokens = sum((run.get("usage") or {}).get("total_tokens") or 0 for run in runs)
        return calls, tokens

    all_orig = orig_runs
    calls, tokens = meter_sum(all_orig)
    print(f"原始 31 运行 run 级 meter 合计: {calls} 调用 / {tokens:,} tokens")
    mcalls, mtokens = meter_sum(main_runs)
    acalls, atokens = meter_sum(abl_runs)
    print(f"  主矩阵 {mcalls} / {mtokens:,}；消融 {acalls} / {atokens:,}")

    agent_agg: dict[str, dict] = {}
    for run in all_orig:
        for role, entry in (run.get("agents_log") or {}).items():
            entry = entry or {}
            agg = agent_agg.setdefault(role, {"calls": 0, "tokens": 0, "tool": 0, "wall": 0.0})
            agg["calls"] += entry.get("llm_calls") or 0
            agg["tokens"] += (entry.get("llm_usage") or {}).get("total_tokens") or 0
            agg["tool"] += len(entry.get("tool_calls") or [])
            agg["wall"] += (entry.get("latency_ms") or 0) / 1000.0
    a_calls = sum(v["calls"] for v in agent_agg.values())
    a_tokens = sum(v["tokens"] for v in agent_agg.values())
    print("逐 Agent（agents_log=每运行每角色末次调用，复议/补查覆盖同名条目 → 小于 meter）:")
    for role, agg in sorted(agent_agg.items()):
        print(f"  {role:24s} calls={agg['calls']:>3} tokens={agg['tokens']:>9,} "
              f"tools={agg['tool']:>3} wall={agg['wall']:.1f}s")
    print(f"  合计 calls={a_calls} tokens={a_tokens:,}；"
          f"未归属差值 calls={calls - a_calls} tokens={tokens - a_tokens:,}"
          f"（=被覆盖的复议/补查调用 + 零 token 失败调用）")

    print()
    print("=" * 72)
    print("三、收尾运行（新 run_id，原始产物零改动）")
    print("=" * 72)
    ccats: dict[str, list[dict]] = {}
    for run in closure_final:
        ccats.setdefault(classify_run(run), []).append(run)
    print(f"收尾运行文件: {len(closure_runs_raw)}（最终样本 {len(closure_final)}，"
          f"被取代的外部故障首跑 {len(closure_superseded)}）")
    for cat, items in sorted(ccats.items()):
        print(f"  {cat}: {len(items)} — " + ", ".join(sorted(r["run_id"] for r in items)))
    for run in sorted(closure_superseded, key=lambda r: r.get("run_id") or ""):
        print(f"  superseded: {run['run_id']} category={classify_run(run)}")
    llm_closure = ccats.get("llm_full_chain", [])
    print("收尾 LLM 全链逐运行:")
    for run in sorted(llm_closure, key=lambda r: r.get("run_id") or ""):
        g = run.get("graded") or {}
        v = run.get("verdict") or {}
        mask = run.get("ablation_mask") or []
        print(f"  {run['run_id']:34s} case={label_of(run['case']):8s} mask={','.join(mask) or '-':22s} "
              f"impact={str(v.get('impact_status')):22s} action={str(v.get('recommended_action')):22s} "
              f"dir={str(v.get('risk_direction')):16s} I/A/D/H="
              f"{g.get('impact_ok')}/{g.get('action_ok')}/{g.get('direction_ok')}/{g.get('human_ok')}")

    print()
    print("=" * 72)
    print("四、Y6 反事实 2×2（确定性断言 + LLM 处置）")
    print("=" * 72)
    from stage9b_closure_cases import Y6_CF2_TRUTH, Y6_CELL_ORDER
    for cell in Y6_CELL_ORDER:
        runs = [run for run in closure_final
                if (run.get("run_id") or "").startswith(f"cf2-y6-{cell}-")]
        if not runs:
            print(f"  {cell}: 无运行")
            continue
        run = runs[-1]
        actual = ((run.get("evidence_prep") or {}).get("urgency_amplifiers") or {})
        expected = Y6_CF2_TRUTH[cell]["expected_amplifier"]
        match = all(actual.get(k) == v for k, v in expected.items())
        v = run.get("verdict") or {}
        g = run.get("graded") or {}
        print(f"  {cell}: amplifier预期={expected['any_present']} 实际 kev={actual.get('kev')} "
              f"pub={actual.get('critical_public_component')} → 断言{'PASS' if match else 'FAIL'}")
        print(f"      LLM: impact={v.get('impact_status')} action={v.get('recommended_action')} "
              f"dir={v.get('risk_direction')} urgency={v.get('urgency_basis')} "
              f"I/A/D={g.get('impact_ok')}/{g.get('action_ok')}/{g.get('direction_ok')}")

    print()
    print("=" * 72)
    print("五、Runtime Agent 正向贡献（full vs abl 对照；优先 rt2- 干净集，"
          "rt- 首跑集因脚手架缺陷留档）")
    print("=" * 72)
    for condition in ("RT-A", "RT-B", "RT-C", "RT-D"):
        cond_runs = {}
        for tag in ("full", "abl"):
            found = []
            for prefix in ("rt2-", "rt-"):   # rt2 = 修复脚手架后的最终样本
                found = [run for run in closure_final
                         if (run.get("run_id") or "")
                         .startswith(f"{prefix}{condition.lower().replace('-', '')}-{tag}-")]
                if found:
                    break
            cond_runs[tag] = found[-1] if found else None
        line = f"  {condition}: "
        for tag, run in cond_runs.items():
            if run is None:
                line += f"{tag}=无运行; "
                continue
            v = run.get("verdict") or {}
            rd = v.get("runtime_dimension") or {}
            explo = ((run.get("runtime") or {}).get("exploitation_relation") or "")
            g = run.get("graded") or {}
            line += (f"{tag}[{classify_run(run)}] {v.get('impact_status')}/"
                     f"{v.get('recommended_action')}/{v.get('risk_direction')} "
                     f"rt_dim={rd.get('status')} "
                     f"validity={v.get('runtime_evidence_validity')} explo={explo} "
                     f"I/A/D={g.get('impact_ok')}/{g.get('action_ok')}/{g.get('direction_ok')}; ")
        print(line)

    print()
    print("=" * 72)
    print("六、方向维度四层表（规则基线 / 模型方向 / 封顶分数 / 处置紧迫度）")
    print("=" * 72)
    DIRECTION_ADJUSTMENTS = {"maintain": 0, "upgrade_minor": 10, "upgrade_major": 20,
                             "downgrade_minor": -10, "downgrade_major": -20}
    summary_path = original_dir / "stage9b_quality_experiment.json"
    baseline = {}
    if summary_path.exists():
        raw = json.loads(summary_path.read_text(encoding="utf-8"))
        for case, rows in (raw.get("rules_baseline") or {}).items():
            baseline[case] = rows[0] if rows else {}
    focus = ["q-CVE-2026-81001-0-1", "q-CVE-2026-81001-1-1", "q-CVE-2026-81002-1-2",
             "q-CVE-2026-81005-0-7", "q-CVE-2026-81015-0-13", "q-CVE-2026-81015-1-13",
             "q-CVE-2026-81019-0-17"]
    for run_id in focus:
        run = next((r for r in orig_runs if r.get("run_id") == run_id), None)
        if run is None:
            continue
        v = run.get("verdict") or {}
        pol = run.get("policy") or {}
        base = baseline.get(run["case"], {})
        base_score = float(base.get("preliminary_score") or 0)
        direction = v.get("risk_direction") or "maintain"
        adj = DIRECTION_ADJUSTMENTS.get(direction, 0)
        capped = round(max(0.0, min(100.0, base_score + adj)), 2)
        print(f"  {label_of(run['case']):4s} {run_id:28s} 基线={base_score:>6.2f}/{base.get('preliminary_level')} "
              f"规则处置={base.get('preliminary_decision')}")
        print(f"       模型方向={direction}(adj={adj:+d}) → 程序封顶后={capped} "
              f"（封顶语义：分数通道程序独占，模型方向仅选择 adjustment）")
        print(f"       处置={v.get('recommended_action')}/{v.get('recommended_priority')} "
              f"urgency_basis={v.get('urgency_basis')} 门禁={','.join(pol.get('reasons') or [])}")

    print()
    print("=" * 72)
    print("七、收尾轮真实成本")
    print("=" * 72)
    ccalls, ctokens = meter_sum(closure_runs_raw)
    print(f"收尾 {len(closure_runs_raw)} 运行文件 meter 合计: {ccalls} 调用 / {ctokens:,} tokens")
    scalls, stokens = meter_sum(closure_superseded)
    print(f"  其中最终样本 {ccalls - scalls}/{ctokens - stokens:,}；被取代首跑 {scalls}/{stokens:,}")


if __name__ == "__main__":
    main()
