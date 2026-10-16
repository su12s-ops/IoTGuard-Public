"""Stage 9B M4.2 收尾实验（真实 LLM）：补齐遗留项 + 修正版反事实。

三 种模式（全部独立 out 目录，**绝不修改/删除** stage9b-quality 原始产物；
重试一律使用新 run_id 新文件）：

  --mode matrix-retry   补齐主矩阵遗留：E4a/E4b 真实 LLM 复验（新 attempt）、
                        X2/X3 在 M4.2 最终代码状态下的复验、
                        Y4/Y10 的 asset_investigator 语义消融（abl2-*）。
  --mode y6-matrix      Y6 修正版反事实：2×2（KEV 有/无 × 受影响组件公网高危
                        有/无），每格独立库；先断言确定性放大因子预期，再做
                        LLM 运行（先验真值 Y6_CF2_TRUTH）。
  --mode rt             Runtime Agent 正向贡献：RT-A/B/C/D 四条件同构反事实，
                        每条件完整管线 + 隐藏 runtime_analyst 消融对照
                        （先验真值 RT_TRUTH）。

统计纪律（与主实验一致）：程序兜底（classify_run==program_fallback）不计入
LLM 准确率，单独留档；外部 API 故障（APIConnectionError/APIStatusError 等）
自动以新 run_id 重试（--retries，默认 2）；语义 fail-closed（确定性矛盾）
不重试——那是设计行为。真值表先验固定于 stage9b_closure_cases.py。
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
    CountedChatClient,
    UsageCounter,
    build_fixture,
    fresh_session_factory,
)
from stage9b_closure_cases import (  # noqa: E402
    RT_CONDITION_ORDER,
    RT_CVE,
    RT_TRUTH,
    Y6_CELLS,
    Y6_CF2_TRUTH,
    Y6_CELL_ORDER,
    apply_y6_cell,
    build_rt_condition_fixture,
)
from stage9b_quality_cases import extend_fixture_for_y_cases  # noqa: E402
from stage9b_quality_experiment import _make_unified_factory, run_case  # noqa: E402
from stage9b_unified_compare import (  # noqa: E402
    extend_fixture_for_x_cases,
    grade_unified,
    _save_run,
    _sum_run_usage,
)

EXTERNAL_ERROR_MARKERS = ("APIConnectionError", "APITimeoutError", "APIStatusError",
                          "InternalServerError", "RateLimitError", "APIError")


def _is_external_failure(event: dict) -> bool:
    """程序兜底且证据指向外部 API 故障（连接/限流/4xx/5xx），非语义 fail-closed。"""
    if (event.get("graded") or {}).get("category") != "program_fallback":
        return False
    agents = event.get("agents_log") or {}
    for entry in agents.values():
        error = str((entry or {}).get("error") or "")
        if any(marker in error for marker in EXTERNAL_ERROR_MARKERS):
            return True
        if (entry or {}).get("status") == "failed":
            return True
    return False


def _stage_failed_externally(event: dict) -> bool:
    """任一分析/决策阶段因外部错误 failed（stage_status 维度）。"""
    stages = event.get("stage_status") or {}
    return any(status == "failed" for status in stages.values())


def run_with_retry(db, risk, factory, run_id: str, runs_dir: Path, truth: dict,
                   *, ablation_mask=frozenset(), retries: int = 2,
                   usage_so_far: list = None, max_tokens: int = 10**9) -> dict:
    """运行单事件；外部故障兜底时以新 run_id 重试（原始文件永不删除）。"""
    event = run_case(db, risk, factory, run_id, ablation_mask=ablation_mask)
    event["graded"] = grade_unified(event, truth)
    _save_run(runs_dir, event)
    attempt = 1
    while (_is_external_failure(event) or _stage_failed_externally(event)) and attempt <= retries:
        if usage_so_far is not None and _sum_run_usage(usage_so_far)["total_tokens"] >= max_tokens:
            print(f"!! Token 预算触界，停止重试 {run_id}")
            break
        retry_id = f"{run_id}-r{attempt}"
        print(f"   外部故障，重试 → {retry_id}")
        time.sleep(20 * attempt)
        event = run_case(db, risk, factory, retry_id, ablation_mask=ablation_mask)
        event["graded"] = grade_unified(event, truth)
        event["superseded_run_ids"] = [run_id] + list(event.get("superseded_run_ids") or [])
        _save_run(runs_dir, event)
        attempt += 1
    return event


def _fresh_db(tmp_root: Path):
    factory, _engine = fresh_session_factory(tmp_root)
    return factory()


def mode_matrix_retry(args, runs_dir: Path) -> dict:
    """E4a/E4b + X2/X3 + Y4/Y10 asset 消融（主矩阵遗留补齐）。"""
    from app import models

    db = _fresh_db(args.work_root / "matrix")
    build_fixture(db, with_runtime=True)
    extend_fixture_for_x_cases(db)
    extend_fixture_for_y_cases(db)

    risks_by_case: dict[str, list] = {}
    for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
        risks_by_case.setdefault(risk.cve_id.split(":")[0], []).append(risk)

    from stage9b_quality_experiment import ALL_TRUTH, ABLATION_PLAN

    plan: list[tuple[str, object, str, frozenset]] = []
    # E4a/E4b：真实 LLM 复验（新 attempt=1；原始 attempt=0 兜底文件保留在原目录）
    for risk in risks_by_case.get("CVE-2026-81004", []):
        plan.append(("CVE-2026-81004", risk, f"qc-CVE-2026-81004-1-{risk.id}",
                     frozenset()))
    # X2/X3 复验（M4.2 最终代码状态；attempt=0 首跑）
    for case in ("CVE-2026-81008", "CVE-2026-81007"):
        for risk in risks_by_case.get(case, []):
            plan.append((case, risk, f"qc-{case}-0-{risk.id}", frozenset()))
    # Y4/Y10 asset 消融（abl2- 前缀；原 abl-* 文件保留在原目录）
    for role, case in ABLATION_PLAN:
        if role == "asset_investigator":
            risks = risks_by_case.get(case, [])
            if risks:
                plan.append((case, risks[0], f"abl2-asset-{case}",
                             frozenset({"asset_investigator"})))

    counter = UsageCounter()
    factory = _make_unified_factory(counter)
    runs: list[dict] = []
    for index, (case, risk, run_id, mask) in enumerate(plan):
        if _sum_run_usage(runs)["total_tokens"] >= args.max_total_tokens:
            print(f"!! Token 预算触界，停止于 [{index}] {run_id}")
            break
        print(f"== 收尾主矩阵 [{index + 1}/{len(plan)}] {run_id} ==")
        event = run_with_retry(db, risk, factory, run_id, runs_dir,
                               ALL_TRUTH[case], ablation_mask=mask,
                               retries=args.retries, usage_so_far=runs,
                               max_tokens=args.max_total_tokens)
        runs.append(event)
    return {"runs": runs, "usage": counter.as_dict()}


def mode_y6_matrix(args, runs_dir: Path) -> dict:
    """Y6 修正版反事实 2×2：每格独立库，先确定性断言后 LLM 运行。"""
    from app import models

    results: dict[str, dict] = {}
    counter = UsageCounter()
    factory = _make_unified_factory(counter)
    amplifier_assertions: list[dict] = []
    for index, cell in enumerate(Y6_CELL_ORDER):
        if _sum_run_usage([r for item in results.values() for r in item["runs"]])[
                "total_tokens"] >= args.max_total_tokens:
            print(f"!! Token 预算触界，停止于格 {cell}")
            break
        print(f"== Y6 反事实格 [{index + 1}/{len(Y6_CELL_ORDER)}] {cell} "
              f"(kev={Y6_CELLS[cell]['kev']}, public={Y6_CELLS[cell]['public']}) ==")
        db = _fresh_db(args.work_root / f"y6-{cell}")
        build_fixture(db, with_runtime=True)
        extend_fixture_for_y_cases(db, y6_kev=Y6_CELLS[cell]["kev"])
        apply_y6_cell(db, cell)
        risks = [risk for risk in db.query(models.RiskAssessment).filter_by(active=True).all()
                 if risk.cve_id.split(":")[0] == "CVE-2026-81015"]
        cell_runs = []
        run_id = f"cf2-y6-{cell}-{risks[0].id}"
        event = run_with_retry(db, risks[0], factory, run_id, runs_dir,
                               Y6_CF2_TRUTH[cell], retries=args.retries)
        cell_runs.append(event)
        # 确定性断言：放大因子预期（程序事实，非 LLM 判定）
        actual = ((event.get("evidence_prep") or {}).get("urgency_amplifiers") or {})
        expected = Y6_CF2_TRUTH[cell]["expected_amplifier"]
        assertion = {
            "cell": cell, "run_id": event.get("run_id"),
            "expected": expected,
            "actual": {key: actual.get(key) for key in expected},
            "match": all(actual.get(key) == value for key, value in expected.items()),
        }
        amplifier_assertions.append(assertion)
        print(f"   放大因子断言: {'PASS' if assertion['match'] else 'FAIL'} "
              f"actual={assertion['actual']}")
        results[cell] = {"runs": cell_runs, "assertion": assertion}
        db.close()
    return {"cells": results, "amplifier_assertions": amplifier_assertions,
            "usage": counter.as_dict()}


def mode_rt(args, runs_dir: Path) -> dict:
    """Runtime Agent 正向贡献：RT-A/B/C/D ×（完整管线 + 隐藏 runtime_analyst）。"""
    from app import models

    results: dict[str, dict] = {}
    counter = UsageCounter()
    factory = _make_unified_factory(counter)
    for index, condition in enumerate(RT_CONDITION_ORDER):
        print(f"== RT 条件 [{index + 1}/{len(RT_CONDITION_ORDER)}] {condition} ==")
        db = _fresh_db(args.work_root / f"rt-{condition}")
        build_fixture(db, with_runtime=True)
        build_rt_condition_fixture(db, condition)
        risks = [risk for risk in db.query(models.RiskAssessment).filter_by(active=True).all()
                 if risk.cve_id.split(":")[0] == RT_CVE]
        if not risks:
            raise RuntimeError(f"{condition}: {RT_CVE} 未产生风险事件（Fixture 缺陷）")
        risk = risks[0]
        truth = RT_TRUTH[condition]
        condition_runs = {}
        for tag, mask in (("full", frozenset()),
                          ("abl", frozenset({"runtime_analyst"}))):
            if _sum_run_usage([r for item in results.values()
                               for r in item["runs"]])["total_tokens"] >= args.max_total_tokens:
                print(f"!! Token 预算触界，停止于 {condition}/{tag}")
                break
            run_id = f"rt-{condition.lower().replace('-', '')}-{tag}-{risk.id}"
            print(f"   -- {tag}（mask={sorted(mask) or '无'}）→ {run_id}")
            event = run_with_retry(db, risk, factory, run_id, runs_dir, truth,
                                   ablation_mask=mask, retries=args.retries)
            condition_runs[tag] = event
        results[condition] = {"runs": condition_runs, "truth": truth}
        db.close()
    return {"conditions": results, "usage": counter.as_dict()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", required=True,
                        choices=["matrix-retry", "y6-matrix", "rt"])
    parser.add_argument("--out", default="reports/stage9b-closure")
    parser.add_argument("--retries", type=int, default=2,
                        help="外部 API 故障的重试次数（新 run_id，原文件保留）")
    parser.add_argument("--max-total-tokens", type=int, default=6_000_000)
    args = parser.parse_args()

    out_dir = Path(args.out)
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    args.work_root = out_dir / "work"
    args.work_root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("LINUXGUARD_DATA_DIR", str(args.work_root / "data"))
    os.environ["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"

    started = time.monotonic()
    if args.mode == "matrix-retry":
        payload = mode_matrix_retry(args, runs_dir)
    elif args.mode == "y6-matrix":
        payload = mode_y6_matrix(args, runs_dir)
    else:
        payload = mode_rt(args, runs_dir)

    output = out_dir / f"stage9b_closure_{args.mode.replace('-', '_')}.json"
    output.write_text(json.dumps({
        "meta": {"generated_at": datetime.now(timezone.utc).isoformat(),
                 "mode": args.mode,
                 "truth_tables": "stage9b_closure_cases.py（先验固定，先于本实验运行入库）",
                 "originals": "backend/reports/stage9b-quality/ 原始产物零改动"},
        "payload": payload,
        "wall_seconds": round(time.monotonic() - started, 1),
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"== 完成：{output}（wall {round(time.monotonic() - started, 1)}s, "
          f"usage {json.dumps(payload.get('usage', {}))}）")


if __name__ == "__main__":
    main()
