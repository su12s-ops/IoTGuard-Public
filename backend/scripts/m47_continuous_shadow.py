"""Stage 9B M4.7 P1：W47 连续真实 Shadow 窗口（须用户批准后启动）。

仅复用现有 graph/Collector/官方核验/Trace；不构造漏洞、不修改旧风险状态、
不执行设备写操作、不把 shadow 结论写成正式结果。每轮：

  1. 断言 flag=off、双修复写开关=0，保存正式字段快照哈希；
  2. 统一四智能体 shadow：风险126（curl，含调查目标）、风险12（历史
     OpenSSL）、OpenWrt 资产（设备面）——force_full_review 全四角色；
  3. System B 只读对照：风险126/12 各一次（build_evidence_packet +
     _process_event，不落正式库）；
  4. 保存全部原始输出（成功/失败/降级一律保留）、预算、未决调查申请；
  5. 断言正式字段快照不变，记录隔离证据。

轮次节奏默认 T0、T0+30、T0+60 分钟（W47）。产物在 gitignored
reports/m47-work/shadow/。
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import config, models
from app.database import SessionLocal, engine
from app.services import event_review_pipeline as old, trace_service as tracing
from app.services.unified.runner import run_unified_sync

OUT = ROOT / "reports/m47-work/shadow"
OUT.mkdir(parents=True, exist_ok=True)

CURL_GOAL = ("本次调查要求确认调查时点 curl 实际安装版本与发行版身份；如需新清单证据，"
             "请提出明确的 inventory 补采申请（未获操作员持精确申请摘要授权前不会执行，"
             "申请将保留为 pending）。历史清单不能证明当前版本；运行时缺口保持独立。")


def now_local() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def formal_snapshot(db):
    return hashlib.sha256(json.dumps(
        [{c.name: getattr(r, c.name) for c in r.__table__.columns}
         for r in db.query(models.RiskAssessment).order_by(models.RiskAssessment.id)],
        sort_keys=True, default=str).encode()).hexdigest()


def save(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2,
                               default=lambda v: v.model_dump() if hasattr(v, "model_dump") else str(v)),
                    encoding="utf-8")


def shadow(db, asset, risk=None, goal=""):
    run_id = "m47-w47-" + uuid.uuid4().hex[:12]
    trace = tracing.start_trace(
        db, task_type="unified_four_agent", target_type="linux_host", target_ref=asset.hostname,
        run_ref_type="unified_analysis", run_ref_id=run_id,
        metadata={"mode": "shadow", "entry": "m47_w47_continuous", "window": "W47"})
    row = models.UnifiedAnalysisRun(
        run_id=run_id, risk_id=risk.id if risk else None,
        task_type="risk_review" if risk else "device_surface",
        target_type="linux_host", target_ref=asset.hostname,
        mode="shadow", status="running", trace_id=trace.trace_id)
    db.add(row)
    db.commit()
    run_unified_sync(db, row, force_full_review=True, investigation_goal=goal)
    return row


def verdict_digest(row):
    try:
        decision = json.loads(row.decision_json or "{}")
    except Exception:
        decision = {}
    verdicts = decision.get("verdicts") or []
    first = verdicts[0] if verdicts else {}
    return {
        "run_id": row.run_id, "trace_id": row.trace_id, "status": row.status,
        "impact": first.get("impact_status"), "direction": first.get("risk_direction"),
        "action": first.get("recommended_action"), "priority": first.get("recommended_priority"),
        "verdict_confidence": first.get("confidence"), "run_confidence": decision.get("confidence"),
        "degraded_roles": decision.get("degraded_roles") or [],
        "follow_up_requests": decision.get("follow_up_requests") or [],
        "usage": json.loads(row.usage_json or "{}"),
    }


def _plain(value):
    """Pydantic 对象 → dict（M4.6 同款序列化坑：coordinator 是 CoordinatorResult）。"""
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return value


def system_b_readonly(db, risk):
    packet = old.build_evidence_packet(db, risk)
    outcome = asyncio.run(old._process_event(packet, old._create_model_client()))
    outcome = {k: _plain(v) for k, v in (outcome or {}).items()}
    coordinator = outcome.get("coordinator") or {}
    policy = outcome.get("audit_policy") or {}
    return {"risk_id": risk.id, "coordinator": {k: coordinator.get(k) for k in (
                "impact_status", "risk_direction", "recommended_action",
                "recommended_priority", "confidence")},
            "policy": _plain(policy), "full_outcome": outcome}


def one_round(db, index: int) -> dict:
    started = now_local()
    gates = {"flag": config.UNIFIED_PIPELINE_MODE,
             "device_repair": __import__("os").environ.get("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0"),
             "ubuntu_lab_repair": __import__("os").environ.get("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0")}
    assert gates["flag"] == "off" and gates["device_repair"] == "0" and gates["ubuntu_lab_repair"] == "0", gates
    before = formal_snapshot(db)

    risk126 = db.get(models.RiskAssessment, 126)
    risk12 = db.get(models.RiskAssessment, 12)
    asset_ubuntu = db.get(models.LinuxAsset, risk126.asset_id)
    asset_openwrt = db.query(models.LinuxAsset).filter_by(distribution="openwrt").one()

    round_dir = OUT / ("round-%d" % index)
    summary: dict = {"round": index, "started_at": started, "gates": gates,
                     "formal_digest_before": before}

    # 统一链三对象（真实 LLM；成功/失败/降级一律保留）
    for label, risk, asset, goal in (
            ("curl-126", risk126, asset_ubuntu, CURL_GOAL),
            ("openssl-12", risk12, asset_ubuntu, ""),
            ("openwrt", None, asset_openwrt, "")):
        try:
            row = shadow(db, asset, risk, goal)
            digest = verdict_digest(row)
            save(round_dir / (label + ".json"), {
                "run_id": row.run_id, "trace_id": row.trace_id, "status": row.status,
                "error": row.error, "state": json.loads(row.state_json or "{}"),
                "agents": json.loads(row.agents_json or "{}"),
                "decision": json.loads(row.decision_json or "{}"),
                "usage": json.loads(row.usage_json or "{}")})
        except Exception as exc:  # 失败样本保留，不筛选重跑
            digest = {"label": label, "raised": type(exc).__name__, "error": str(exc)[:500]}
        summary[label] = digest
        print("[round %d] %s -> %s" % (index, label, json.dumps(
            {k: digest.get(k) for k in ("run_id", "status", "impact", "direction",
                                        "action", "verdict_confidence", "raised")},
            ensure_ascii=False)), flush=True)

    # System B 只读对照（126/12 各一次）
    for rid in (126, 12):
        try:
            comparison = system_b_readonly(db, db.get(models.RiskAssessment, rid))
            save(round_dir / ("system-b-%d.json" % rid), comparison)
            summary["system_b_%d" % rid] = comparison["coordinator"]
        except Exception as exc:
            summary["system_b_%d" % rid] = {"raised": type(exc).__name__, "error": str(exc)[:400]}
            save(round_dir / ("system-b-%d.json" % rid), summary["system_b_%d" % rid])
        print("[round %d] system_b_%d -> %s" % (index, rid, json.dumps(
            summary["system_b_%d" % rid], ensure_ascii=False)), flush=True)

    db.expire_all()
    after = formal_snapshot(db)
    assert before == after, "formal fields changed during shadow round"
    summary["formal_unchanged"] = True
    summary["formal_digest_after"] = after
    summary["finished_at"] = now_local()
    save(round_dir / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--interval-minutes", type=float, default=30.0)
    parser.add_argument("--label", default="W47")
    args = parser.parse_args()

    models.InvestigationRequest.__table__.create(engine, checkfirst=True)
    window: dict = {"label": args.label, "started_at": now_local(),
                    "rounds": args.rounds, "interval_minutes": args.interval_minutes}
    save(OUT / "window.json", window)
    summaries = []
    with SessionLocal() as db:
        for index in range(1, args.rounds + 1):
            summaries.append(one_round(db, index))
            if index < args.rounds:
                print("[window] sleeping %.1f minutes before round %d" % (
                    args.interval_minutes, index + 1), flush=True)
                time.sleep(args.interval_minutes * 60)

    # 跨轮比较：同事实置信与结论稳定性、System B 分歧、失败/降级保留
    comparison = {"window": args.label, "rounds": [json.loads(json.dumps(
        {k: v for k, v in s.items() if k not in ("formal_digest_before", "formal_digest_after")},
        ensure_ascii=False, default=str)) for s in summaries]}
    for label in ("curl-126", "openssl-12", "openwrt"):
        series = [s.get(label, {}) for s in summaries]
        comparison[label] = {
            "impacts": [x.get("impact") for x in series],
            "directions": [x.get("direction") for x in series],
            "actions": [x.get("action") for x in series],
            "verdict_confidences": [x.get("verdict_confidence") for x in series],
            "statuses": [x.get("status") for x in series],
            "degraded_any": any(x.get("degraded_roles") for x in series),
            "raised": [x.get("raised") for x in series if x.get("raised")],
        }
    for rid in (126, 12):
        key = "system_b_%d" % rid
        comparison[key] = [s.get(key) for s in summaries]
    save(OUT / "cross-round-comparison.json", comparison)
    print("[window] done: %s" % json.dumps(
        {k: comparison[k] for k in ("curl-126", "openssl-12")}, ensure_ascii=False, default=str)[:1200],
        flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
