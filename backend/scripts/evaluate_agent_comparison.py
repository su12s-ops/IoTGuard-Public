"""Compare recorded rule/single/four-agent runs on identical, labelled facts.

Offline only: never calls a model, writes a risk, or changes formal routing.
Input JSONL fields are documented in docs/validation/agent-quality-bench.md.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
from pathlib import Path


STRATEGIES = {"rules", "single_agent", "four_agents"}
MIN_LABELLED_CASES = 5
MIN_REPEATS_PER_CASE = 3


def _percentile(values: list[float], q: float) -> float | None:
    """线性插值分位数（不依赖第三方库）。"""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def _observation_metrics(rows: list[dict]) -> dict:
    """按策略统计**全部**观测（含未标注、未成对）：成功率、耗时分布、结论稳定性。

    成对准确率只在三策略齐备的案例上计算（见 `metrics`）；这里回答的是另一个问题：
    「这个策略跑固定案例时，成功率与耗时是多少、结论稳不稳」。
    """
    out = {}
    for strategy in sorted(STRATEGIES):
        selected = [row for row in rows if row["strategy"] == strategy]
        if not selected:
            continue
        latencies = [r["latency_seconds"] for r in selected if r.get("latency_seconds") is not None]
        labelled = [r for r in selected if r.get("expected")]
        correct = sum(r["status"] == "succeeded" and all(
            r.get("actual", {}).get(k) == v for k, v in r["expected"].items()) for r in labelled)
        per_case: dict[tuple, list] = {}
        for item in selected:
            per_case.setdefault((item["case_id"], item["facts_sha256"]), []).append(item)
        repeated = {key: items for key, items in per_case.items() if len(items) > 1}
        stable = sum(
            len({json.dumps(r.get("actual"), sort_keys=True, ensure_ascii=False) for r in items}) == 1
            for items in repeated.values())
        out[strategy] = {
            "runs": len(selected),
            "labelled_runs": len(labelled),
            "success_rate": sum(r["status"] == "succeeded" for r in selected) / len(selected),
            "degraded_or_failed": sum(r["status"] != "succeeded" for r in selected),
            "accuracy_including_failures": (correct / len(labelled)) if labelled else None,
            "latency_seconds_p50": _percentile(latencies, 0.5),
            "latency_seconds_p95": _percentile(latencies, 0.95),
            "latency_seconds_min": min(latencies) if latencies else None,
            "latency_seconds_max": max(latencies) if latencies else None,
            "cases": len(per_case),
            "repeats_per_case_max": max((len(items) for items in repeated.values()), default=1),
            "conclusion_stability": (stable / len(repeated)) if repeated else None,
            "model_modes": sorted({r.get("model_mode", "") for r in selected}),
        }
    return out


def evaluate(rows: list[dict]) -> dict:
    groups = {}
    case_truth = {}
    case_facts = {}
    for row in rows:
        if row["strategy"] not in STRATEGIES:
            raise ValueError("unknown strategy")
        key = (row["case_id"], row["facts_sha256"], row["repeat"])
        group = groups.setdefault(key, {})
        if row["strategy"] in group:
            raise ValueError("duplicate strategy in paired case")
        if not row["facts_sha256"]:
            raise ValueError("facts hash required")
        case_id = row["case_id"]
        if case_id in case_truth and case_truth[case_id] != row.get("expected"):
            raise ValueError("ground truth differs across case repetitions")
        case_truth[case_id] = row.get("expected")
        case_facts.setdefault(case_id, set()).add(row["facts_sha256"])
        if row["strategy"] not in ("rules", "single_agent", "four_agents"):
            raise ValueError("unknown strategy")
        if group and next(iter(group.values())).get("expected") != row.get("expected"):
            raise ValueError("ground truth differs within paired case")
        group[row["strategy"]] = row
    paired = [group for group in groups.values()
              if set(group) == STRATEGIES and all(r.get("expected") for r in group.values())]
    labelled_cases = {row["case_id"] for row in rows if row.get("expected")}
    paired_repeat_counts = {}
    for group in paired:
        item = next(iter(group.values()))
        paired_repeat_counts.setdefault(item["case_id"], set()).add(item["repeat"])
    complete_repeated_cases = sum(
        len(paired_repeat_counts.get(case_id, ())) >= MIN_REPEATS_PER_CASE
        for case_id in labelled_cases)
    metrics = {}
    for strategy in sorted(STRATEGIES):
        selected = [group[strategy] for group in paired]
        correct = sum(r["status"] == "succeeded" and all(
            r.get("actual", {}).get(k) == v for k, v in r["expected"].items()) for r in selected)
        def measured(key):
            values = [r[key] for r in selected if r.get(key) is not None]
            return {"observed": len(values), "mean": statistics.mean(values) if values else None}

        latencies = [r["latency_seconds"] for r in selected if r.get("latency_seconds") is not None]
        # 同一案例多次重复时结论是否稳定：不稳定说明模型方差大，精度提升不可复现
        per_case: dict[tuple, list] = {}
        for item in selected:
            per_case.setdefault((item["case_id"], item["facts_sha256"]), []).append(item)
        repeated = {key: rows for key, rows in per_case.items() if len(rows) > 1}
        stable = sum(
            len({json.dumps(r.get("actual"), sort_keys=True, ensure_ascii=False) for r in rows}) == 1
            for rows in repeated.values())
        metrics[strategy] = {
            "runs": len(selected), "correct": correct,
            "accuracy_including_failures": correct / len(selected) if selected else None,
            "success_rate": (sum(r["status"] == "succeeded" for r in selected) / len(selected)
                             if selected else None),
            "failed_or_degraded": sum(r["status"] != "succeeded" for r in selected),
            "latency_seconds": measured("latency_seconds"),
            "latency_seconds_p50": _percentile(latencies, 0.5),
            "latency_seconds_p95": _percentile(latencies, 0.95),
            "total_tokens": measured("total_tokens"),
            "invalid_evidence_refs": measured("invalid_evidence_refs"),
            "human_review_minutes": measured("human_review_minutes"),
            "repeated_cases": len(repeated),
            "repeats_per_case_max": max((len(rows) for rows in repeated.values()), default=1),
            "conclusion_stability": (stable / len(repeated)) if repeated else None,
        }
    observations = _observation_metrics(rows)
    repeats = {row["repeat"] for row in rows}
    pairwise = {}
    for left in sorted(STRATEGIES):
        for right in sorted(STRATEGIES):
            if left >= right:
                continue
            case_differences: dict[str, list[int]] = {}
            for group in paired:
                expected = group[left]["expected"]
                left_ok = (group[left]["status"] == "succeeded" and all(
                    group[left].get("actual", {}).get(k) == v for k, v in expected.items()))
                right_ok = (group[right]["status"] == "succeeded" and all(
                    group[right].get("actual", {}).get(k) == v for k, v in expected.items()))
                case_differences.setdefault(group[left]["case_id"], []).append(
                    int(left_ok) - int(right_ok))
            clusters = [statistics.mean(values) for values in case_differences.values()]
            pairwise[f"{left}_minus_{right}"] = _bootstrap_mean_ci(clusters)
    fixed_facts = all(len(hashes) == 1 for hashes in case_facts.values())
    gate_ready = (fixed_facts and len(labelled_cases) >= MIN_LABELLED_CASES and
                  complete_repeated_cases >= MIN_LABELLED_CASES and
                  len(paired) >= MIN_LABELLED_CASES * MIN_REPEATS_PER_CASE)
    return {"paired_cases": len(paired), "unpaired_groups": len(groups) - len(paired),
            "observations": observations,
            "repeats_observed": sorted(repeats),
            "metrics": metrics, "pairwise_accuracy_difference": pairwise,
            "quality_gate": {"ready": gate_ready,
                "scope": "sampling_completeness_only",
                "fixed_facts_across_repeats": fixed_facts,
                "labelled_cases": len(labelled_cases),
                "required_labelled_cases": MIN_LABELLED_CASES,
                "cases_with_at_least_three_repeats": complete_repeated_cases,
                "paired_labelled_runs": len(paired),
                "required_paired_labelled_runs": MIN_LABELLED_CASES * MIN_REPEATS_PER_CASE,
                "bootstrap_unit": "independent_case_cluster",
                "statistical_separation_observed": gate_ready and all(
                    item["ci_95"][0] > 0 or item["ci_95"][1] < 0
                    for item in pairwise.values() if item["ci_95"] is not None),
                "claims_allowed": False,
                "claim_blocker": "Independent truth review, frozen replay and model/config provenance require external validation."},
            "formal_routing_changed": False,
            "limitation": "Recorded paired observations only; no automatic approval or production gate.",
            "reading_guide": ("成功率含失败/降级；准确率把失败计入分母；conclusion_stability 只在"
                              "同一案例有多次重复时给出，null 表示尚未重复测量。")}


def _bootstrap_mean_ci(values: list[int], *, samples=10000) -> dict:
    if not values:
        return {"paired_n": 0, "mean_accuracy_difference": None, "ci_95": None}
    rng = random.Random(0)
    draws = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(samples))
    return {"paired_n": len(values), "mean_accuracy_difference": statistics.mean(values),
            "ci_95": [draws[int((samples - 1) * 0.025)], draws[int((samples - 1) * 0.975)]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    result = evaluate(rows)
    # Preserve prior experiments instead of silently replacing their evidence.
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
