"""Stage 9B 最终验收数据汇编：新旧系统对照 + 重复稳定性 + 智能体价值审计。

只做离线汇总（零 LLM 调用）。输入：
- 上一轮实验 JSON（System B 全量对照 + 历史调试运行留档）；
- 本轮最终验收 JSON（统一链全量运行 + System B X2 补充 + 屏蔽消融）。

产物：验收报告所需的全部表格数据（JSON），供 IOT_UNIFIED_FOUR_AGENT_FINAL_ACCEPTANCE.md 引用。

用法：
    python scripts/stage9b_final_acceptance_report.py \
        --previous reports/stage9b-unified/stage9b_unified_compare.json \
        --final reports/stage9b-unified-final/stage9b_unified_compare.json \
        --out reports/stage9b-unified-final/acceptance_data.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from stage9b_unified_compare import TRUTH, UNIFIED_TRUTH, grade_unified  # noqa: E402

CASE_LABELS = {
    "CVE-2026-81001": "E1 公网核心资产·厂商确认·KEV·直接运行时证据",
    "CVE-2026-81002": "E2 客户端包受影响·无运行时证据",
    "CVE-2026-81003": "E3 NVD-only 误匹配候选（3.1.x 受影响/装机 3.0.x）",
    "CVE-2026-81004": "E4 under_investigation vs NVD vs KEV 矛盾情报",
    "CVE-2026-81005": "E5 OpenWrt dropbear·过期采集+丢失未知",
    "CVE-2026-81006": "X1 低复杂度候选（成本分层）",
    "CVE-2026-81008": "X2 KEV+厂商affected但装机已修复",
    "CVE-2026-81007": "X3 仅过期运行时证据+直接命中",
}


def load(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=BACKEND_DIR.parent,
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return "unavailable"


def old_system_events(previous: dict, final: dict) -> list[dict]:
    """合并上一轮 System B 全量事件与本轮 X2 补充事件。"""
    events = list((previous.get("old_system_b") or {}).get("events") or [])
    supplement = final.get("old_system_b_supplement") or {}
    events.extend(supplement.get("events") or [])
    return events


def old_graded(previous: dict, final: dict) -> list[dict]:
    graded = list((previous.get("old_system_b") or {}).get("graded") or [])
    graded.extend((final.get("old_system_b_supplement") or {}).get("graded") or [])
    return graded


def rate(graded: list[dict], key: str) -> dict:
    values = [item.get(key) for item in graded if item.get(key) is not None]
    return {"correct": sum(1 for v in values if v), "total": len(values)}


def agent_value_audit(runs: list[dict]) -> dict:
    """四智能体实际价值审计：真实工具调用 / 补查回灌 / 门禁 / 降级。"""
    audit = {
        "runs_total": len(runs),
        "per_agent_tool_calls": {},
        "agents_succeeded": {},
        "follow_up": {"runs_with_requests": 0, "requests_total": 0,
                      "runs_with_results": 0, "results_total": 0,
                      "runs_reentered_decision": 0},
        "gate": {"auto_confirmed": 0, "pending_human_review": 0,
                 "gate_reason_histogram": {}},
        "degraded_runs": 0,
        "citation_hallucination_runs": 0,
        "consumption_examples": [],
    }
    agent_names = ("asset_investigator", "vulnerability_analyst",
                   "runtime_analyst", "decision_planner")
    for run in runs:
        agents_log = run.get("agents_log") or {}
        for name in agent_names:
            entry = agents_log.get(name) or {}
            if not entry:
                continue
            calls = entry.get("tool_calls") or []
            stats = audit["per_agent_tool_calls"].setdefault(
                name, {"runs": 0, "tool_calls_total": 0, "ok": 0,
                       "tools": {}})
            stats["runs"] += 1
            stats["tool_calls_total"] += len(calls)
            stats["ok"] += sum(1 for c in calls if c.get("ok"))
            for c in calls:
                stats["tools"][c.get("name", "?")] = \
                    stats["tools"].get(c.get("name", "?"), 0) + 1
            if entry.get("status") == "succeeded":
                audit["agents_succeeded"][name] = \
                    audit["agents_succeeded"].get(name, 0) + 1
        follow = run.get("follow_up_audit") or {}
        if follow.get("requested"):
            audit["follow_up"]["runs_with_requests"] += 1
            audit["follow_up"]["requests_total"] += follow.get("requested") or 0
        if follow.get("executed_results"):
            audit["follow_up"]["runs_with_results"] += 1
            audit["follow_up"]["results_total"] += follow.get("executed_results") or 0
        if follow.get("reentered_decision"):
            audit["follow_up"]["runs_reentered_decision"] += 1
        policy = run.get("policy") or {}
        status = policy.get("status")
        if status == "auto_confirmed":
            audit["gate"]["auto_confirmed"] += 1
        elif status == "pending_human_review":
            audit["gate"]["pending_human_review"] += 1
        for reason in policy.get("reasons") or []:
            audit["gate"]["gate_reason_histogram"][reason] = \
                audit["gate"]["gate_reason_histogram"].get(reason, 0) + 1
        if run.get("degraded_roles"):
            audit["degraded_runs"] += 1
        graded = run.get("graded") or {}
        if graded and not graded.get("citation_ok", True):
            audit["citation_hallucination_runs"] += 1
    return audit


def event_brief(run: dict) -> dict:
    verdict = run.get("verdict") or {}
    policy = run.get("policy") or {}
    graded = run.get("graded") or {}
    usage = run.get("usage") or {}
    return {
        "run_id": run.get("run_id"),
        "case": run.get("case"),
        "status": run.get("status"),
        "tier": run.get("tier"),
        "impact": verdict.get("impact_status"),
        "direction": verdict.get("risk_direction"),
        "action": verdict.get("recommended_action"),
        "confidence": verdict.get("confidence"),
        "policy_status": policy.get("status"),
        "gate_reasons": policy.get("reasons"),
        "human": policy.get("status") == "pending_human_review",
        "graded": {k: graded.get(k) for k in
                   ("impact_ok", "direction_ok", "action_ok", "human_ok",
                    "citation_ok", "freshness_ok")},
        "problems": graded.get("problems"),
        "degraded_roles": run.get("degraded_roles"),
        "llm_calls": usage.get("llm_calls"),
        "total_tokens": usage.get("total_tokens"),
        "wall_seconds": run.get("wall_seconds"),
        "error": run.get("error"),
    }


def build(previous_path: str, final_path: str) -> dict:
    previous = load(previous_path)
    final = load(final_path)
    summary = final.get("summary") or {}

    unified_runs = [r for r in (final.get("unified") or {}).get("runs") or []
                    if r.get("graded")]
    # 用修正后的评分器统一重评（引用全集与 runner known_evidence_ids 对齐；
    # 历史存档的 graded 字段保留在原始运行文件中不动）
    for run in unified_runs:
        truth = TRUTH.get(run.get("case")) or UNIFIED_TRUTH.get(run.get("case"))
        if truth:
            run["graded"] = grade_unified(run, truth)
    old_events = old_system_events(previous, final)
    old_graded_rows = old_graded(previous, final)

    first_pass: dict[str, dict] = {}
    for run in unified_runs:
        first_pass.setdefault(run["case"], run)

    per_case = {}
    for case, run in sorted(first_pass.items()):
        repeats = [r for r in unified_runs if r["case"] == case]
        per_case[case] = {
            "label": CASE_LABELS.get(case, case),
            "first_pass": event_brief(run),
            "repeat_stability": {
                "runs": len(repeats),
                "action_ok": [bool(r["graded"]["action_ok"]) if r["graded"]["action_ok"] is not None else None
                              for r in repeats],
                "impact_ok": [bool(r["graded"]["impact_ok"]) if r["graded"]["impact_ok"] is not None else None
                              for r in repeats],
                "human_ok": [bool(r["graded"]["human_ok"]) if r["graded"]["human_ok"] is not None else None
                             for r in repeats],
                "policies": [(r.get("policy") or {}).get("status") for r in repeats],
                "actions": [(r.get("verdict") or {}).get("recommended_action") for r in repeats],
                "impacts": [(r.get("verdict") or {}).get("impact_status") for r in repeats],
            },
            "baseline": _baseline_of(final, case),
        }

    failed_runs = [event_brief(r) for r in (final.get("unified") or {}).get("runs") or []
                   if r.get("status") != "completed"]
    skipped = (final.get("unified") or {}).get("skipped_budget") or []

    mask = final.get("unified_mask_runtime") or {}
    mask_event = mask.get("event") or {}

    unified_usage = (final.get("unified") or {}).get("usage") or {}
    old_usage_total = int(((previous.get("old_system_b") or {}).get("usage") or {}).get("total_tokens") or 0)
    supp_usage = (final.get("old_system_b_supplement") or {}).get("usage") or {}
    mask_usage = mask.get("usage") or {}

    comparison = {
        "impact_ok": {"unified": rate([r["graded"] for r in unified_runs], "impact_ok"),
                      "old": rate(old_graded_rows, "impact_ok")},
        "direction_ok": {"unified": rate([r["graded"] for r in unified_runs], "direction_ok"),
                         "old": rate(old_graded_rows, "direction_ok")},
        "action_ok": {"unified": rate([r["graded"] for r in unified_runs], "action_ok"),
                      "old": rate(old_graded_rows, "action_ok")},
        "human_ok": {"unified": rate([r["graded"] for r in unified_runs], "human_ok"),
                     "old": rate(old_graded_rows, "human_ok")},
        "citation_hallucination": {
            "unified": sum(0 if (r["graded"].get("citation_ok")) else 1 for r in unified_runs),
            "old": "system_b 链路无逐条引用校验器（审计结论：证据包确定性下发，幻觉面更小；不可比项如实标注）"},
        "llm_calls": {"unified": unified_usage.get("llm_calls"),
                      "old": int(((previous.get("old_system_b") or {}).get("usage") or {}).get("llm_calls") or 0)
                      + int(supp_usage.get("llm_calls") or 0)},
        "total_tokens": {"unified": unified_usage.get("total_tokens"),
                         "old": old_usage_total + int(supp_usage.get("total_tokens") or 0)},
        "wall_seconds": {
            "unified": round(sum(r.get("wall_seconds") or 0 for r in unified_runs), 1),
            "old": round(float(((previous.get("old_system_b") or {}).get("wall_seconds")) or 0)
                         + float(supp_usage and (final.get("old_system_b_supplement") or {}).get("wall_seconds") or 0), 1)},
        "failed_runs": {"unified": len(failed_runs) + len(skipped), "old": 0},
        "mask_recovery": mask.get("expectation") or {},
    }

    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "commit": git_commit(),
            "previous_experiment": previous_path,
            "final_experiment": final_path,
            "model": "deepseek-v4-flash（temperature 0.1，与生产/上一轮一致）",
            "repeats": (final.get("meta") or {}).get("repeats"),
        },
        "unified_first_pass_per_case": per_case,
        "unified_failed_runs": failed_runs,
        "unified_skipped_budget": skipped,
        "old_system_events": [
            {k: e.get(k) for k in ("case", "review_status", "human", "decision",
                                   "recommended_action", "risk_direction",
                                   "review_verdict", "review_confidence")}
            for e in old_events],
        "comparison": comparison,
        "agent_value_audit": agent_value_audit(unified_runs),
        "mask_run": {
            "status": mask_event.get("status"),
            "degraded_roles": mask_event.get("degraded_roles"),
            "policy": mask_event.get("policy"),
            "verdict": mask_event.get("verdict"),
            "usage": mask_usage,
        },
        "mask_usage_tokens": mask_usage.get("total_tokens"),
        "summary_snapshot": summary,
    }


def _baseline_of(final: dict, case: str) -> dict | None:
    rows = ((final.get("baseline") or {}).get(case)) or []
    return rows[0] if rows else None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--previous",
                        default="reports/stage9b-unified/stage9b_unified_compare.json")
    parser.add_argument("--final",
                        default="reports/stage9b-unified-final/stage9b_unified_compare.json")
    parser.add_argument("--out", default="reports/stage9b-unified-final/acceptance_data.json")
    args = parser.parse_args()
    data = build(args.previous, args.final)
    out = Path(args.out)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    print(f"验收数据已写入 {out}")
    comparison = data["comparison"]
    print(json.dumps({
        "rates": {k: comparison[k] for k in
                  ("impact_ok", "direction_ok", "action_ok", "human_ok")},
        "tokens": comparison["total_tokens"],
        "llm_calls": comparison["llm_calls"],
        "agent_value_audit": data["agent_value_audit"],
    }, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
