import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("agent_comparison", Path(__file__).parents[1] / "scripts/evaluate_agent_comparison.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def samples():
    return [{"case_id": "case-1", "facts_sha256": "identical-facts", "repeat": 1,
             "strategy": strategy, "expected": {"impact": "fixed"},
             "actual": {"impact": "fixed"}, "status": "succeeded", "latency_seconds": 1}
            for strategy in module.STRATEGIES]


def test_failures_count_and_unpaired_cases_do_not_bias_comparison():
    rows = samples()
    rows[0]["status"] = "timeout"
    rows.append({**rows[1], "case_id": "unpaired"})
    result = module.evaluate(rows)
    assert result["paired_cases"] == 1 and result["unpaired_groups"] == 1
    assert result["metrics"][rows[0]["strategy"]]["accuracy_including_failures"] == 0
    assert result["metrics"][rows[1]["strategy"]]["total_tokens"]["mean"] is None
    assert not result["formal_routing_changed"]


def test_ground_truth_cannot_change_between_strategies():
    rows = samples()
    rows[0]["expected"] = {"impact": "affected"}
    with pytest.raises(ValueError, match="ground truth"):
        module.evaluate(rows)
