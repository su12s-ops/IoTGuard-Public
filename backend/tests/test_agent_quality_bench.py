"""固定案例重复验证：记录器字段契约 + 成功率/耗时/稳定性统计。"""
import importlib.util
import json
import pytest
from types import SimpleNamespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


comparison = _load("agent_comparison2", "scripts/evaluate_agent_comparison.py")
record = _load("agent_quality_record", "scripts/agent_quality_record.py")


def _row(strategy, repeat, actual, status="succeeded", expected=None, case="C-1", facts="f1",
         latency=100.0):
    return {"case_id": case, "facts_sha256": facts, "repeat": repeat, "strategy": strategy,
            "expected": expected if expected is not None else {"impact_status": "confirmed_affected"},
            "actual": actual, "status": status, "latency_seconds": latency,
            "total_tokens": 10, "invalid_evidence_refs": 0, "model_mode": "recorded"}


def test_unlabelled_rows_count_for_success_but_never_for_accuracy():
    rows = [_row(s, 1, {"impact_status": "confirmed_affected"}, expected={"impact_status": "confirmed_affected"})
            for s in ("rules", "single_agent", "four_agents")]
    rows.append(_row("four_agents", 1, {"impact_status": "x"}, case="C-2"))
    rows[-1]["expected"] = None
    result = comparison.evaluate(rows)
    assert result["paired_cases"] == 1
    assert result["observations"]["four_agents"]["runs"] == 2
    assert result["observations"]["four_agents"]["labelled_runs"] == 1
    assert result["observations"]["four_agents"]["success_rate"] == 1.0


def test_repeat_statistics_expose_instability_and_latency_spread():
    rows = [
        _row("four_agents", 1, {"impact_status": "confirmed_affected"}, "succeeded", latency=100),
        _row("four_agents", 2, {"impact_status": "insufficient_evidence"}, "degraded", latency=300),
        _row("four_agents", 3, {"impact_status": "confirmed_affected"}, "succeeded", latency=200),
        _row("four_agents", 4, {"impact_status": "confirmed_affected"}, "succeeded", latency=400),
    ]
    stats = comparison.evaluate(rows)["observations"]["four_agents"]
    assert stats["runs"] == 4
    assert stats["success_rate"] == 0.75
    assert stats["degraded_or_failed"] == 1
    assert stats["repeats_per_case_max"] == 4
    assert stats["conclusion_stability"] == 0.0          # 结论在重复之间发生变化
    assert stats["latency_seconds_p50"] == 250.0
    assert stats["latency_seconds_min"] == 100 and stats["latency_seconds_max"] == 400
    # 准确率把失败计入分母：3/4 命中标注（降级那次不算命中）
    assert stats["accuracy_including_failures"] == 0.75


def test_stable_conclusions_report_full_stability():
    rows = [_row("four_agents", n, {"impact_status": "confirmed_affected"}) for n in (1, 2, 3)]
    stats = comparison.evaluate(rows)["observations"]["four_agents"]
    assert stats["conclusion_stability"] == 1.0
    assert stats["repeats_per_case_max"] == 3


def test_recorder_row_contract_matches_comparison_requirements():
    case = {"case_id": "C-272", "asset_id": 4, "risk_id": 272,
            "target_ref": "OpenWrt-Lab", "expected": {"impact_status": "confirmed_affected"}}
    item = record.row(case, "four_agents", 2, {"impact_status": "confirmed_affected"},
                      "succeeded", "packet-hash", 12.345, 1000, 1, "live", run_id="UA-1")
    assert item["repeat"] == 2 and item["strategy"] == "four_agents"
    assert item["facts_sha256"] and item["facts_sha256"] == record.facts_sha256(case, "packet-hash")
    assert item["latency_seconds"] == 12.35
    assert item["expected"] == case["expected"]
    # 同一案例同一事实 → 不同策略得到同一哈希（成对比较的前提）
    assert item["facts_sha256"] == record.row(case, "rules", 2, {}, "succeeded",
                                              "packet-hash", 1.0, 0, 0, "no_model")["facts_sha256"]


def test_recorder_reports_degraded_and_failed_honestly():
    assert record.status_of({"degraded_roles": ["runtime_analyst"],
                             "decision": {"verdicts": [{"impact_status": "x"}]}}) == "degraded"
    assert record.status_of({"degraded_roles": [], "decision": {}}) == "failed"
    assert record.status_of({"degraded_roles": [],
                             "decision": {"verdicts": [{"impact_status": "x"}]}}) == "succeeded"
    assert record.invalid_evidence_refs(
        {"vulnerability_analyst": {"error": "引用了证据包之外的分析师自造证据 ID"}}) == 1


def test_append_rows_never_overwrites_history(tmp_path):
    path = tmp_path / "obs.jsonl"
    record.append_rows(path, [{"a": 1}])
    record.append_rows(path, [{"a": 2}])
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(line)["a"] for line in lines] == [1, 2]


def test_strategy_mismatch_is_refused_not_recorded():
    # simple 成本分层把 single_agent 短路成 0 次调用：必须拒绝，不能记成单智能体成功
    rules_only = {"routing": {"tier": "simple", "include_asset": False,
                              "include_vulnerability": False, "include_runtime": False,
                              "include_decision": False, "reason": "simple 分层"}}
    try:
        record._assert_strategy_applied("single_agent", rules_only, "UA-x")
    except SystemExit as exc:
        assert "strategy_mismatch" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("策略不一致必须拒绝记录")
    record._assert_strategy_applied("four_agents", {"routing": {
        "include_asset": True, "include_vulnerability": True,
        "include_runtime": True, "include_decision": True}}, "UA-y")
    record._assert_strategy_applied("single_agent", {"routing": {
        "include_asset": False, "include_vulnerability": False,
        "include_runtime": False, "include_decision": True}}, "UA-z")


def test_persisted_facts_hash_is_order_independent_but_tracks_fact_changes():
    state = {"baseline": {"match_status": "fixed"},
             "evidence_prep": {"as_of": "2026-10-21", "candidates": []}}
    same = {"evidence_prep": state["evidence_prep"], "baseline": state["baseline"]}
    assert record._state_facts_sha256(state) == record._state_facts_sha256(same)
    changed = {**state, "evidence_prep": {"as_of": "2026-10-22", "candidates": []}}
    assert record._state_facts_sha256(state) != record._state_facts_sha256(changed)
    with pytest.raises(SystemExit, match="facts_snapshot_missing"):
        record._state_facts_sha256({"baseline": state["baseline"]})


@pytest.mark.parametrize("field,value", [("risk_id", 2), ("target_ref", "other"),
                                          ("target_type", "other"), ("task_type", "other")])
def test_import_rejects_wrong_case_identity(field, value):
    case = {"case_id": "C-1", "risk_id": 1, "target_ref": "x"}
    fields = {"run_id": "UA-1", "risk_id": 1, "target_ref": "x",
              "target_type": "linux_host", "task_type": "risk_review"}
    record._assert_case_matches_run(case, SimpleNamespace(**fields))
    with pytest.raises(SystemExit, match="case_mismatch"):
        record._assert_case_matches_run(case, SimpleNamespace(**{**fields, field: value}))


def test_cli_requires_execution_mode(tmp_path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps({"case_id": "C-1", "risk_id": 1, "target_ref": "x"}) + "\n",
                     encoding="utf-8")
    try:
        record.main(["--cases", str(cases), "--strategy", "rules", "--out", str(tmp_path / "o.jsonl")])
    except SystemExit as exc:
        assert "live" in str(exc) or exc.code not in (None, 0)
    else:  # pragma: no cover
        raise AssertionError("缺少 --live/--from-run 必须拒绝执行")
