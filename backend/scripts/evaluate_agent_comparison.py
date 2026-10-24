"""Compare recorded rule/single/four-agent runs on identical, labelled facts.

Offline only: never calls a model, writes a risk, or changes formal routing.
Input JSONL fields are documented in docs/FOUR_AGENT_IMPROVEMENTS.md.
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


STRATEGIES = {"rules", "single_agent", "four_agents"}


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
    for row in rows:
        if row["strategy"] not in STRATEGIES:
            raise ValueError("unknown strategy")
        key = (row["case_id"], row["facts_sha256"], row["repeat"])
        group = groups.setdefault(key, {})
        if row["strategy"] in group:
            raise ValueError("duplicate strategy in paired case")
        if not row["facts_sha256"]:
            raise ValueError("facts hash required")
        if row["strategy"] not in ("rules", "single_agent", "four_agents"):
            raise ValueError("unknown strategy")
        if group and next(iter(group.values())).get("expected") != row.get("expected"):
            raise ValueError("ground truth differs within paired case")
        group[row["strategy"]] = row
    paired = [group for group in groups.values()
              if set(group) == STRATEGIES and all(r.get("expected") for r in group.values())]
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
    return {"paired_cases": len(paired), "unpaired_groups": len(groups) - len(paired),
            "observations": observations,
            "repeats_observed": sorted(repeats),
            "metrics": metrics, "formal_routing_changed": False,
            "limitation": "Recorded paired observations only; no automatic approval or production gate.",
            "reading_guide": ("成功率含失败/降级；准确率把失败计入分母；conclusion_stability 只在"
                              "同一案例有多次重复时给出，null 表示尚未重复测量。")}


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
