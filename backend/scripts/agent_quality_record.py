#!/usr/bin/env python3
"""固定案例记录器：把一次真实/导入的研判写成可比较的观测行。

配套两件事：
- `backend/examples/agent_quality_cases.jsonl`：固定案例集（标注来自已人工复核记录）；
- `backend/scripts/evaluate_agent_comparison.py`：只做统计，不调用模型。

三种策略共用**同一份确定性事实**（同一个案例、同一数据库快照、同一预取节点）：

| 策略 | 是否调用模型 | 说明 |
|---|---|---|
| `rules` | 否 | 规则基线直通（0 次 LLM），映射 match_status → impact_status |
| `single_agent` | 1 个角色 | 只有决策角色，事实仍来自同一确定性预取 |
| `four_agents` | 4 个角色 | 正式链路（与生产同一条图） |

用法（观测按行追加，永不覆盖历史实验）：

    # 导入一次已完成的真实运行
    python backend/scripts/agent_quality_record.py --cases backend/examples/agent_quality_cases.jsonl \
        --case C-272-openwrt-cgi-io --strategy four_agents --from-run UA-20261020232421-f0bbef \
        --repeat 1 --out reports/agent-quality/obs.jsonl

    # 现场执行（会真实调用模型；单次四智能体约 8-30 分钟）
    python backend/scripts/agent_quality_record.py --cases ... --case C-272-openwrt-cgi-io \
        --strategy single_agent --repeat 1 --live --database-url sqlite:///E:/tmp/bench.db \
        --out reports/agent-quality/obs.jsonl

约定：`--live` 写入的运行记录落在 `--database-url` 指定的库（建议用副本），
不触碰正式风险字段；`status` 保留真实的 succeeded/degraded/failed/timeout。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MATCH_TO_IMPACT = {
    "affected": "confirmed_affected",
    "potentially_affected": "potentially_affected",
    "not_affected": "not_affected",
    "fixed": "not_affected",
}


def load_cases(path: Path) -> list[dict]:
    cases = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def facts_sha256(case: dict, packet_sha256: str) -> str:
    """案例事实快照哈希：策略无关（同一案例、同一预取事实 → 同一哈希）。"""
    payload = {
        "case_id": case["case_id"],
        "asset_id": case.get("asset_id"),
        "risk_id": case.get("risk_id"),
        "target_ref": case.get("target_ref"),
        "target_type": case.get("target_type"),
        "packet_sha256": packet_sha256,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _state_facts_sha256(state: dict) -> str:
    """Hash persisted inputs, never substitute today's risk packet for a past run.

    Keep timestamps/freshness in the payload: different time windows are not
    demonstrably identical facts and must not be silently paired.
    """
    if not state.get("evidence_prep"):
        raise SystemExit("facts_snapshot_missing: 运行缺少确定性预取事实，不能进入对照观测")
    payload = {key: state.get(key) for key in
               ("baseline", "candidate_context", "capability_marks", "evidence_prep")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _assert_case_matches_run(case: dict, run) -> None:
    expected = {"risk_id": case.get("risk_id"), "target_ref": case["target_ref"],
                "target_type": case.get("target_type", "linux_host"),
                "task_type": case.get("task_type", "risk_review")}
    if any(getattr(run, key, None) != value for key, value in expected.items()):
        raise SystemExit(f"case_mismatch: 运行 {run.run_id} 不属于案例 {case['case_id']}")


def actual_from_run(state: dict) -> dict:
    verdict = ((state.get("decision") or {}).get("verdicts") or [{}])[0]
    return {
        "impact_status": verdict.get("impact_status"),
        "recommended_action": verdict.get("recommended_action"),
        "recommended_priority": verdict.get("recommended_priority"),
        "risk_direction": verdict.get("risk_direction"),
    }


def actual_from_baseline(baseline: dict, decision: dict) -> dict:
    verdict = (decision.get("verdicts") or [{}])[0]
    return {
        "impact_status": MATCH_TO_IMPACT.get(baseline.get("match_status"), "insufficient_evidence"),
        "recommended_action": verdict.get("recommended_action") or baseline.get("preliminary_decision"),
        "recommended_priority": verdict.get("recommended_priority"),
        "risk_direction": "maintain",
    }


def invalid_evidence_refs(agents: dict) -> int:
    total = 0
    for info in (agents or {}).values():
        if not isinstance(info, dict):
            continue
        error = str(info.get("error") or "")
        if "防幻觉" in error or "自造证据" in error or "不存在的 evidence_id" in error:
            total += 1
    return total


def status_of(state: dict) -> str:
    if state.get("degraded_roles"):
        return "degraded"
    if not ((state.get("decision") or {}).get("verdicts") or []):
        return "failed"
    return "succeeded"


def row(case: dict, strategy: str, repeat: int, actual: dict, status: str,
        packet_sha: str, latency: float, tokens, refs: int, model_mode: str,
        run_id: str = "", error: str = "") -> dict:
    expected = case.get("expected") or None
    return {
        "case_id": case["case_id"],
        "facts_sha256": facts_sha256(case, packet_sha),
        "repeat": repeat,
        "strategy": strategy,
        "expected": expected,
        "actual": actual,
        "status": status,
        "latency_seconds": round(latency, 2),
        "total_tokens": tokens,
        "invalid_evidence_refs": refs,
        "human_review_minutes": None,
        "model_mode": model_mode,
        "run_id": run_id,
        "error": error[:400],
        "label_source": case.get("label_source") or "",
    }


def append_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for item in rows:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")


def import_from_run(case: dict, strategy: str, repeat: int, run_id: str) -> dict:
    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id).one_or_none()
        if run is None:
            raise SystemExit(f"运行不存在：{run_id}")
        if run.status != "completed":
            raise SystemExit(f"运行未完成：{run_id} status={run.status}")
        _assert_case_matches_run(case, run)
        state = json.loads(run.state_json or "{}")
        _assert_strategy_applied(strategy, state, run_id)
        agents = json.loads(run.agents_json or "{}")
        usage = json.loads(run.usage_json or "{}")
        latency = ((run.completed_at - run.created_at).total_seconds()
                   if run.completed_at and run.created_at else 0.0)
        return row(case, strategy, repeat, actual_from_run(state), status_of(state),
                   _state_facts_sha256(state), latency,
                   (usage.get("usage") or {}).get("total_tokens"),
                   invalid_evidence_refs(agents), "recorded", run_id=run_id)
    finally:
        db.close()


EXPECTED_AGENTS = {
    "rules": [],
    "single_agent": ["decision_planner"],
    "four_agents": ["asset_investigator", "vulnerability_analyst",
                    "runtime_analyst", "decision_planner"],
}


def _assert_strategy_applied(strategy: str, state: dict, run_id: str) -> None:
    """实际执行的策略必须与请求一致，否则这次观测不能进对照统计。

    实测教训：simple 成本分层会把 single_agent 短路成 0 次 LLM 调用；
    照记就会产出一条「单智能体成功」的假观测。
    """
    routing = state.get("routing") or {}
    active = sorted(agent for agent, include in (
        ("asset_investigator", routing.get("include_asset")),
        ("vulnerability_analyst", routing.get("include_vulnerability")),
        ("runtime_analyst", routing.get("include_runtime")),
        ("decision_planner", routing.get("include_decision")),
    ) if include)
    expected = EXPECTED_AGENTS[strategy]
    if active != sorted(expected):
        raise SystemExit(
            f"strategy_mismatch: 请求 {strategy}（期望角色 {expected}），实际执行 {active}"
            f"（tier={routing.get('tier')}, 原因={routing.get('reason')}）；"
            f"该运行 {run_id} 不作为对照观测记录")


def execute_case(case: dict, strategy: str, repeat: int) -> dict:
    from app import models
    from app.database import SessionLocal
    from app.services.unified import runner as runner_mod
    from app.services.unified.graph import RunContext, new_run_id, node_prepare, node_prepare_evidence
    from app.services.unified.agent_base import default_client_factory
    from app.services.unified.state import UnifiedAnalysisState, empty_state

    db = SessionLocal()
    try:
        risk = db.get(models.RiskAssessment, case["risk_id"]) if case.get("risk_id") else None
        started = time.monotonic()
        if strategy == "rules":
            state = empty_state(new_run_id(), case.get("task_type", "risk_review"),
                                case["target_ref"], case.get("target_type", "linux_host"), "shadow")
            if risk is not None:
                state.object_id = f"risk-{risk.id}"
            ctx = RunContext(db_factory=SessionLocal, trace_id="", risk=risk)
            update = node_prepare(ctx)(state)
            state = state.model_copy(update=update)
            state = state.model_copy(update=node_prepare_evidence(ctx)(state))
            packet_sha = _state_facts_sha256(state.model_dump())
            state = runner_mod._simple_tier_state(state)
            latency = time.monotonic() - started
            return row(case, strategy, repeat, actual_from_baseline(state.baseline, state.decision),
                       status_of(state.model_dump()), packet_sha, latency, 0, 0, "no_model")
        run_row = models.UnifiedAnalysisRun(
            run_id=new_run_id(), task_type=case.get("task_type", "risk_review"),
            target_type=case.get("target_type", "linux_host"),
            target_ref=case["target_ref"], mode="shadow", status="running",
            risk_id=case.get("risk_id"), trace_id="")
        db.add(run_row)
        db.commit()
        runner_mod.run_unified_sync(db, run_row, client_factory=default_client_factory,
                                   strategy=strategy, force_full_review=True,
                                   budgets={"follow_up_rounds": 0} if strategy == "single_agent" else None)
        db.refresh(run_row)
        latency = ((run_row.completed_at - run_row.created_at).total_seconds()
                   if run_row.completed_at and run_row.created_at else time.monotonic() - started)
        state = json.loads(run_row.state_json or "{}")
        agents = json.loads(run_row.agents_json or "{}")
        usage = json.loads(run_row.usage_json or "{}")
        _assert_strategy_applied(strategy, state, run_row.run_id)
        packet_sha = _state_facts_sha256(state)
        return row(case, strategy, repeat, actual_from_run(state),
                   "failed" if run_row.status == "failed" else status_of(state), packet_sha,
                   latency, (usage.get("usage") or {}).get("total_tokens"),
                   invalid_evidence_refs(agents), "live", run_id=run_row.run_id,
                   error=run_row.error or "")
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--case", default="", help="案例编号；空表示全部案例")
    parser.add_argument("--strategy", required=True,
                        choices=("rules", "single_agent", "four_agents"))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--from-run", default="", help="导入已完成的统一运行（仅 four_agents）")
    parser.add_argument("--live", action="store_true", help="现场执行（会真实调用模型）")
    parser.add_argument("--database-url", default="", help="执行/导入所用数据库（建议副本）")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.database_url:
        os.environ["LINUXGUARD_DATABASE_URL"] = args.database_url
    sys.path.insert(0, str(ROOT))
    cases = load_cases(args.cases)
    selected = [c for c in cases if not args.case or c["case_id"] == args.case]
    if not selected:
        raise SystemExit("未匹配到案例")
    if args.from_run and args.strategy != "four_agents":
        raise SystemExit("导入运行只适用于 four_agents；其他策略必须现场执行")
    rows = []
    for case in selected:
        if args.from_run:
            rows.append(import_from_run(case, args.strategy, args.repeat, args.from_run))
        elif args.live:
            rows.append(execute_case(case, args.strategy, args.repeat))
        else:
            raise SystemExit("必须指定 --live 或 --from-run")
    append_rows(args.out, rows)
    for item in rows:
        print(json.dumps({k: item[k] for k in
                          ("case_id", "strategy", "status", "latency_seconds", "run_id")},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
