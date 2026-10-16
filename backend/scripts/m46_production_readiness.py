"""Real business acceptance; shadow only, never approves repairs. Local raw output is ignored."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import config, models
from app.database import SessionLocal, engine
from app.services import event_review_pipeline as old, trace_service as tracing
from app.services.unified.runner import run_unified_sync

OUT = ROOT / "reports/m46-work"
OUT.mkdir(parents=True, exist_ok=True)


def save(name, value):
    (OUT / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False, indent=2,
        default=lambda v: v.model_dump() if hasattr(v, "model_dump") else str(v)), encoding="utf-8")


def formal_snapshot(db):
    return hashlib.sha256(json.dumps([{c.name: getattr(r, c.name) for c in r.__table__.columns}
        for r in db.query(models.RiskAssessment).order_by(models.RiskAssessment.id)], sort_keys=True, default=str).encode()).hexdigest()


def shadow(db, asset, risk=None, goal=""):
    run_id = "m46-real-" + uuid.uuid4().hex[:12]
    trace = tracing.start_trace(db, task_type="unified_four_agent", target_type="linux_host", target_ref=asset.hostname,
        run_ref_type="unified_analysis", run_ref_id=run_id, metadata={"mode": "shadow", "entry": "m46_isolated_real"})
    row = models.UnifiedAnalysisRun(run_id=run_id, risk_id=risk.id if risk else None,
        task_type="risk_review" if risk else "device_surface", target_type="linux_host", target_ref=asset.hostname,
        mode="shadow", status="running", trace_id=trace.trace_id)
    db.add(row)
    db.commit()
    run_unified_sync(db, row, force_full_review=True, investigation_goal=goal)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["curl", "openssl", "openwrt", "old"])
    args = parser.parse_args()
    assert config.UNIFIED_PIPELINE_MODE == "off"
    models.InvestigationRequest.__table__.create(engine, checkfirst=True)
    with SessionLocal() as db:
        before = formal_snapshot(db)
        if args.phase == "old":
            outcomes = {}
            for rid in (126, 12):
                risk = db.get(models.RiskAssessment, rid)
                packet = old.build_evidence_packet(db, risk)
                # Same real objects, original System B inference, no persistence
                # into formal fields and no manual resetting inactive risk 12.
                outcome = asyncio.run(old._process_event(packet, old._create_model_client()))
                outcomes[str(rid)] = {"packet": packet.model_dump(), "outcome": outcome}
                save("system-b", outcomes)
                print("SYSTEM_B", rid, outcome.get("audit_policy"), flush=True)
            outcomes["openwrt"] = {"status": "no_candidates", "reason": "官方零命中，没有风险事件可供旧 System B 事件管线评审"}
            save("system-b", outcomes)
        else:
            rid = {"curl": 126, "openssl": 12}.get(args.phase)
            risk = db.get(models.RiskAssessment, rid) if rid else None
            asset = db.get(models.LinuxAsset, risk.asset_id) if risk else db.query(models.LinuxAsset).filter_by(distribution="openwrt").one()
            goal = "本次调查要求通过新一轮已授权固定清单采集，确认 curl 当前实际安装版本和发行版身份。历史清单不能证明本次调查时点的版本。请提出明确的 inventory 补采申请；运行时缺口保持独立。" if rid == 126 else ""
            row = shadow(db, asset, risk, goal)
            save(args.phase, {"run_id": row.run_id, "trace_id": row.trace_id, "status": row.status,
                "state": json.loads(row.state_json), "agents": json.loads(row.agents_json)})
            print(args.phase, row.run_id, row.status, flush=True)
        db.expire_all()
        assert before == formal_snapshot(db), "formal fields changed"
        save(args.phase + "-isolation", {"formal_unchanged": True, "digest": before, "flag": "off"})


if __name__ == "__main__":
    main()
