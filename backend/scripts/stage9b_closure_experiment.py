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
    RT_HOSTNAME,
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
    """程序兜底且证据指向外部 API 故障（连接/限流/4xx/5xx），非语义 fail-closed。

    语义 fail-closed（decide 失败但错误为确定性矛盾反馈、无 API 异常标记）
    是设计行为，不重试。decide 单独失败且带 API 异常标记（如 E2 首跑
    APIConnectionError）按外部故障处理。
    """
    if (event.get("graded") or {}).get("category") != "program_fallback":
        return False
    agents = event.get("agents_log") or {}
    for role, entry in agents.items():
        entry = entry or {}
        error = str(entry.get("error") or "")
        has_api_marker = any(marker in error for marker in EXTERNAL_ERROR_MARKERS)
        if entry.get("status") == "failed":
            # 分析师阶段 failed：角色执行层故障（API/工具）；API 标记或非决策角色都重试
            if has_api_marker or role != "decision_planner":
                return True
        elif has_api_marker:
            return True
    return False


def _stage_failed_externally(event: dict) -> bool:
    """分析师阶段因外部错误 failed（decide 语义 fail-closed 不在此列）。"""
    stages = event.get("stage_status") or {}
    analyst_stages = ("investigate_asset", "analyze_runtime", "analyze_vulnerability")
    return any(stages.get(stage) == "failed" for stage in analyst_stages)


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
    """每次调用独立临时 SQLite（重复调用/续跑不与既有库冲突）。"""
    import tempfile

    factory, _engine = fresh_session_factory(Path(tempfile.mkdtemp(prefix="stage9b-closure-")))
    return factory()


def _degenerate_runtime_report(event: dict) -> bool:
    """运行时分析师退化输出检测：预取证据在库（runtime_evidence_ids 非空、
    非 RT-D 设计），但报告 findings/evidence_ids 全空且 exploitation_relation=
    not_observed——模型把 Schema 回显当答案（rt2-RT-A 首跑两次命中的失效
    模式），语义上等价于「没做分析」，须重试；真实无证据的 RT-D 不受影响
    （其 runtime_evidence_ids 为空）。"""
    if (event.get("graded") or {}).get("category") != "llm_full_chain":
        return False
    prep_ids = (event.get("evidence_prep") or {}).get("runtime_evidence_ids") or []
    if not prep_ids:
        return False
    rt = event.get("runtime") or {}
    return (not (rt.get("findings") or []) and not (rt.get("evidence_ids") or [])
            and (rt.get("exploitation_relation") in (None, "", "not_observed")))


def _chain_terminal(runs_dir: Path, base_run_id: str) -> tuple[dict | None, int]:
    """找 base_run_id 链的末端运行与最大 attempt 序号（base=0, base-r1=1…）。"""
    existing: list[tuple[int, dict]] = []
    for path in runs_dir.glob(f"run-{base_run_id}*.json"):
        run_id = path.stem[len("run-"):]
        if run_id == base_run_id:
            existing.append((0, json.loads(path.read_text(encoding="utf-8"))))
        elif run_id.startswith(base_run_id + "-r") and run_id[len(base_run_id) + 2:].isdigit():
            existing.append((int(run_id[len(base_run_id) + 2:]),
                             json.loads(path.read_text(encoding="utf-8"))))
    if not existing:
        return None, 0
    existing.sort(key=lambda item: item[0])
    return existing[-1][1], existing[-1][0]


def run_with_retry(db, risk, factory, run_id: str, runs_dir: Path, truth: dict,
                   *, ablation_mask=frozenset(), retries: int = 2,
                   usage_so_far=None, max_tokens: int = 10**9) -> dict:
    """运行单事件；断点续跑接续既有链末端，外部故障以新 -rN run_id 重试。

    纪律：任何已存在的运行文件永不删除/覆盖——重试一律新 run_id 新文件；
    语义 fail-closed（确定性矛盾反馈）不重试，是设计行为。
    """
    terminal, last_attempt = _chain_terminal(runs_dir, run_id)
    if terminal is not None and not (_is_external_failure(terminal)
                                     or _stage_failed_externally(terminal)
                                     or _degenerate_runtime_report(terminal)):
        print(f"   去重跳过（链末端有效）：{terminal.get('run_id')}")
        return terminal
    attempt = last_attempt + (1 if terminal is not None else 0)
    event = terminal if terminal is not None else None
    while event is None or ((_is_external_failure(event)
                             or _stage_failed_externally(event)
                             or _degenerate_runtime_report(event)) and attempt <= retries):
        target_id = run_id if attempt == 0 else f"{run_id}-r{attempt}"
        if usage_so_far is not None and _sum_run_usage(usage_so_far)["total_tokens"] >= max_tokens:
            print(f"!! Token 预算触界，停止重试 {target_id}")
            break
        if event is not None:
            print(f"   外部故障，重试 → {target_id}")
            time.sleep(20 * attempt)
        event = run_case(db, risk, factory, target_id, ablation_mask=ablation_mask)
        event["graded"] = grade_unified(event, truth)
        if attempt > 0:
            event["superseded_run_ids"] = (
                [run_id] + [f"{run_id}-r{n}" for n in range(1, attempt)]
                + list(event.get("superseded_run_ids") or []))
        _save_run(runs_dir, event)
        attempt += 1
    return event


def _refresh_rt_sensor(db, condition: str) -> None:
    """RT-A/RT-B 运行前刷新传感器心跳（120s stale 阈值的脚手架竞态修复，
    与 E/X/Y 的 _refresh_y_sensor_heartbeats 同语义）；RT-C 的过期心跳是
    设计干预点，绝不刷新；RT-D 无传感器。"""
    if condition not in ("RT-A", "RT-B"):
        return
    from app import models

    (db.query(models.RuntimeSensor)
       .filter(models.RuntimeSensor.sensor_id == f"sensor-{RT_HOSTNAME}")
       .update({models.RuntimeSensor.last_heartbeat_at: datetime.now(timezone.utc)},
               synchronize_session=False))
    db.commit()


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
        prefix = f"cf2-y6-{cell}-"
        prior = [path for path in runs_dir.glob(f"run-{prefix}*.json")]
        if prior:
            print(f"== 去重跳过格 {cell}（已有 {[p.stem for p in prior]}）==")
            continue
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
            prefix = getattr(args, "rt_prefix", "rt")
            run_id = f"{prefix}-{condition.lower().replace('-', '')}-{tag}-{risk.id}"
            prior_usage = [r for item in results.values() for r in item["runs"].values()]
            if _sum_run_usage(prior_usage)["total_tokens"] >= args.max_total_tokens:
                print(f"!! Token 预算触界，停止于 {condition}/{tag}")
                break
            _refresh_rt_sensor(db, condition)
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
    parser.add_argument("--rt-prefix", default="rt",
                        help="RT 运行 ID 前缀（脚手架缺陷修复后的重跑用新前缀，"
                             "旧前缀文件全部保留留档）")
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
