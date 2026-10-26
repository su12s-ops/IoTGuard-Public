"""Durable console workflow; HTTP requests never wait on intelligence or models."""
from __future__ import annotations

import json
import hashlib
import threading
import time
import uuid

from fastapi import HTTPException
from app import config, models
from app.database import SessionLocal

lock = threading.RLock()
OWNER = uuid.uuid4().hex
STAGES = (("intelligence", "获取官方情报"), ("matching", "版本匹配"),
          ("risk", "风险计算"), ("agents", "四智能体研判"), ("audit", "审核"))


class ConsoleWindowExpired(RuntimeError):
    pass


def steps():
    return [{"key": key, "label": label, "status": "pending"} for key, label in STAGES]


def advance(db, row, stage, message):
    items = json.loads(row.steps_json)
    index = [key for key, _ in STAGES].index(stage)
    for i, item in enumerate(items):
        item["status"] = "completed" if i < index else "running" if i == index else "pending"
    row.stage, row.message, row.steps_json = stage, message, json.dumps(items, ensure_ascii=False)
    db.commit()


def acquire(db, asset_id=0):
    """Caller holds lock until the background worker has been dispatched."""
    existing = db.query(models.ConsoleWorkflow).filter(
        models.ConsoleWorkflow.status.in_(("running", "awaiting_review"))
    ).order_by(models.ConsoleWorkflow.created_at.desc()).first()
    if existing:
        synchronize(db, existing)
        if existing.status in ("running", "awaiting_review"):
            if existing.asset_id != asset_id:
                raise HTTPException(409, "已有其他设备范围的流程，请先完成当前流程")
            return existing, True
    from app.services.result_archive import active_runs
    if any(active_runs(db).values()) or db.query(models.AnalysisReport).filter_by(status="running").count():
        raise HTTPException(409, "已有分析或设备任务运行，请等待其结束")
    assets = db.query(models.LinuxAsset)
    if asset_id:
        assets = assets.filter_by(id=asset_id)
    if not assets.count():
        raise HTTPException(404, "请先接入需要分析的设备")
    row = models.ConsoleWorkflow(id="FLOW-" + uuid.uuid4().hex[:16], asset_id=asset_id,
                                 owner=OWNER, steps_json=json.dumps(steps(), ensure_ascii=False))
    db.add(row)
    db.commit()
    advance(db, row, "intelligence", "已启动，正在准备官方情报")
    return row, False


def fetch_intelligence(db, asset_id, progress):
    from app.services import openwrt_intel
    from app.services.ubuntu_security_collector import sync_ubuntu_asset_intelligence
    from app.services.kylin_security_collector import sync_kylin_asset_intelligence
    from app.services.real_intel_collector import sync_real_vulnerabilities
    query = db.query(models.LinuxAsset)
    if asset_id:
        query = query.filter_by(id=asset_id)
    distributions = {str(a.distribution or "").lower() for a in query.all()}
    warnings = []
    if "openwrt" in distributions:
        progress("intelligence", "正在获取 OpenWrt 官方安全公告")
        from urllib.error import URLError
        try:
            rows = openwrt_intel.fetch_advisory_rows()
        except (URLError, OSError) as exc:
            # Network outages must not erase or silently refresh a verified
            # official snapshot. Security/validation failures remain fatal.
            snapshots = db.query(models.IotOfficialAdvisory).filter_by(ecosystem="openwrt").all()
            valid = bool(snapshots) and bool(db.query(models.OpenWrtAdvisory).count())
            for snapshot in snapshots:
                try:
                    payload = json.loads(snapshot.payload_json)
                    valid = valid and (
                        hashlib.sha256(snapshot.payload_json.encode()).hexdigest() == snapshot.content_sha256
                        and snapshot.source_url == payload.get("html_url")
                        and snapshot.source_url.startswith("https://github.com/openwrt/openwrt/security/advisories/GHSA-"))
                except (ValueError, TypeError):
                    valid = False
            if not valid:
                raise RuntimeError("OpenWrt 官方情报连接失败，且没有可验证的已有官方快照") from exc
            from datetime import timezone, timedelta
            latest = max(item.updated_at for item in snapshots)
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=timezone.utc)
            stamp = latest.astimezone(timezone(timedelta(hours=8))).isoformat()
            message = f"OpenWrt 本次在线更新失败，使用已有官方快照（保存时间 {stamp}）；不代表最新：{exc}"
            warnings.append(message)
            progress("intelligence", message)
        else:
            openwrt_intel.sync_openwrt_advisories(db, rows)
        db.commit()
    def report(message, *_):
        progress("intelligence", message)
    if "ubuntu" in distributions:
        result = sync_ubuntu_asset_intelligence(db, progress=report)
        warnings.extend(result.warnings)
    if any("kylin" in value for value in distributions):
        result = sync_kylin_asset_intelligence(db, progress=report)
        warnings.extend(result.warnings)
    if any(value not in {"ubuntu", "openwrt"} and "kylin" not in value for value in distributions):
        result = sync_real_vulnerabilities(db, keyword="linux", days=30, limit=100,
                                          replace=False, progress=report)
        warnings.extend(result.warnings)
    db.commit()
    if warnings and not db.query(models.VulnerabilityInfo).count():
        raise RuntimeError("官方情报获取失败：" + "; ".join(warnings)[:1000])
    return warnings


def run(workflow_id, session_factory=SessionLocal):
    db = session_factory()
    try:
        row = db.get(models.ConsoleWorkflow, workflow_id)
        if not row or row.status != "running":
            return
        def progress(stage, message):
            if config.REVIEW_EXECUTION_MODE == "task_graph":
                from datetime import datetime, timezone
                started = row.created_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - started).total_seconds() >= 1800:
                    raise ConsoleWindowExpired("本轮分析窗口已结束，已取得的数据保留，未完成项等待继续")
            # Separate short transaction: never lose the stage while a network
            # call or model is in flight, and do not hold a DB write lock.
            with session_factory() as state_db:
                current = state_db.get(models.ConsoleWorkflow, workflow_id)
                if current:
                    if current.round_id and stage in ("matching", "risk"):
                        stage = "agents"
                    advance(state_db, current, stage, message)
        warnings = fetch_intelligence(db, row.asset_id, progress)
        row.warnings_json = json.dumps(warnings, ensure_ascii=False)
        db.commit()
        from app.routers.rounds import RoundStartInput, execute_round
        seen = set()
        while True:
            result = execute_round(RoundStartInput(asset_id=row.asset_id), db, progress=progress)
            db.refresh(row)
            row.round_id = result["round_id"]
            ids = json.loads(row.round_ids_json)
            if row.round_id not in ids:
                ids.append(row.round_id)
            row.round_ids_json = json.dumps(ids)
            db.commit()
            # Formal analysis already runs in its own worker. Wait for its
            # durable report, with no transaction held between polls.
            from app.routers.rounds import _sync_round_from_report, _selected_ids
            while True:
                db.expire_all()
                linked = db.query(models.AnalysisRound).filter_by(round_id=row.round_id).one()
                _sync_round_from_report(db, linked)
                db.commit()
                if linked.status != "running":
                    break
                time.sleep(3)
            if linked.status in ("failed", "blocked", "partial", "interrupted", "no_candidates"):
                break
            selected = set(_selected_ids(linked))
            if not selected or selected.issubset(seen):
                raise RuntimeError("候选处理未推进，已停止重复研判")
            seen.update(selected)
            from app.services.review_common import select_candidates
            remaining = select_candidates(db, asset_id=row.asset_id or 0)
            if not remaining.get("selected_object_count"):
                break
            if any(risk.id in seen for risk in remaining.get("_selected_risks", [])):
                raise RuntimeError("已处理对象再次进入候选，停止自动重放；请在审核中处理")
            progress("agents", f"已处理 {len(seen)} 项，正在顺序提交下一批候选")
        db.refresh(row)
        row.pipeline_done = True
        db.commit()
        synchronize(db, row)
    except ConsoleWindowExpired as exc:
        db.rollback()
        row = db.get(models.ConsoleWorkflow, workflow_id)
        if row:
            row.status, row.message, row.pipeline_done = "partial", str(exc), True
            db.commit()
    except Exception as exc:
        db.rollback()
        row = db.get(models.ConsoleWorkflow, workflow_id)
        if row:
            row.status = "failed"
            row.error = str(getattr(exc, "detail", exc))[:2000]
            row.message = "流程停止：" + row.error
            items = json.loads(row.steps_json)
            for item in items:
                if item["status"] == "running":
                    item["status"] = "failed"
            row.steps_json = json.dumps(items, ensure_ascii=False)
            db.commit()
    finally:
        db.close()


def launch(workflow_id):
    threading.Thread(target=run, args=(workflow_id,), daemon=True,
                     name="console-" + workflow_id).start()


def synchronize(db, row):
    from app.routers.rounds import _sync_round_from_report, _selected_ids
    if row.status in ("completed", "failed", "interrupted", "partial"):
        return
    if not row.round_id or (row.owner != OWNER and not row.pipeline_done):
        if row.owner != OWNER:
            row.status = "interrupted"
            row.error = "服务重启中断了情报准备，请重新开始；不会自动重放操作"
            row.message = row.error
            db.commit()
        return
    round_row = db.query(models.AnalysisRound).filter_by(round_id=row.round_id).first()
    if not round_row:
        row.status, row.error = "failed", "关联分析轮次不存在"
        db.commit()
        return
    _sync_round_from_report(db, round_row)
    db.commit()
    if round_row.status == "partial":
        row.status = "partial"
        row.message = "本轮仅完成部分研判；已完成结果保留，未完成项等待继续，审核仍需逐项处理"
    elif round_row.status in ("failed", "blocked", "interrupted"):
        row.status = "failed"
        row.error = round_row.error or round_row.blocked_reason or "部分对象未完成，请检查运行详情"
        row.message = row.error
        items = json.loads(row.steps_json)
        for item in items:
            if item["status"] == "running":
                item["status"] = "failed"
        row.steps_json = json.dumps(items, ensure_ascii=False)
    elif round_row.status == "no_candidates" and not audit_ids(db, row):
        row.status, row.message = "completed", "匹配与风险计算完成，无可研判候选；智能体与审核已跳过"
        items = steps()
        for i, item in enumerate(items):
            item["status"] = "completed" if i < 3 else "skipped"
        row.steps_json = json.dumps(items, ensure_ascii=False)
    elif round_row.status != "running":
        if not row.pipeline_done:
            row.message = "本批研判已结束，正在检查剩余候选"
            db.commit()
            return
        advance(db, row, "audit", "研判完成，正在汇总审核对象")
        ids = audit_ids(db, row)
        risks = db.query(models.RiskAssessment).filter(models.RiskAssessment.id.in_(ids)).all() if ids else []
        pending = [risk for risk in risks if risk.human_review_required or
                   risk.review_status in ("pending_human_review", "reanalysis_required", "candidate")]
        row.status = "awaiting_review" if pending else "completed"
        row.message = f"自动流程完成，等待人工审核 {len(pending)} 项" if pending else "本轮流程及审核已完成"
        if not pending:
            items = json.loads(row.steps_json)
            items[-1]["status"] = "completed"
            row.steps_json = json.dumps(items, ensure_ascii=False)
    db.commit()


def audit_ids(db, row):
    from app.routers.rounds import _selected_ids
    round_ids = json.loads(row.round_ids_json) or [row.round_id]
    linked = db.query(models.AnalysisRound).filter(models.AnalysisRound.round_id.in_(round_ids)).all()
    return sorted({risk_id for item in linked for risk_id in _selected_ids(item)})


def payload(db, row):
    synchronize(db, row)
    items = json.loads(row.steps_json)
    # Old terminal workflows can contain the last in-flight stage snapshot.
    # Project it as stopped/partial instead of animating a finished worker.
    if row.status in {"partial", "failed", "interrupted"}:
        items = [{**item, "status": row.status if item["status"] == "running" else item["status"]}
                 for item in items]
    done = sum(item["status"] in ("completed", "skipped") for item in items)
    percent = done * 20
    review = None
    round_payload = None
    if row.round_id:
        from app.routers.rounds import _round_payload
        linked = db.query(models.AnalysisRound).filter_by(round_id=row.round_id).first()
        if linked:
            round_payload = _round_payload(db, linked)
            ids = audit_ids(db, row)
            round_payload["counts"]["selected"] = len(ids)
            round_payload["counts"]["processed"] = db.query(models.RiskAssessment).filter(
                models.RiskAssessment.id.in_(ids),
                models.RiskAssessment.review_status.notin_(("queued", "running", "candidate", "reanalysis_required", "agent_reviewing", "evidence_preparing"))
            ).count() if ids else 0
            review = round_payload.get("review_run")
            if row.status == "running" and row.stage == "agents" and review:
                prior = max(0, len(ids) - int(linked.selected_object_count or 0))
                total = max(1, prior + int(linked.eligible_count or 0))
                actual = prior + int(linked.selected_object_count or 0) * float(review.get("progress_percent") or 0) / 100
                percent = min(79, 60 + int(19 * actual / total))
    execution = live_execution(db, round_payload)
    from app.services.iot_official import snapshot_freshness
    assets = db.query(models.LinuxAsset)
    if row.asset_id:
        assets = assets.filter_by(id=row.asset_id)
    ecosystems = {str(asset.distribution or "").lower() for asset in assets.all()}
    snapshots = {name: snapshot_freshness(db, name)
                 for name in sorted(ecosystems & {"openwrt", "zephyr"})}
    return {"id": row.id, "asset_id": row.asset_id, "status": row.status, "stage": row.stage, "steps": items,
            "progress_percent": percent, "message": row.message, "error": row.error,
            "warnings": json.loads(row.warnings_json), "round": round_payload,
            "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat(),
            "execution": execution, "intelligence_snapshots": snapshots}


def live_execution(db, round_payload):
    """Read observed per-risk/role activity; never infer that queued risks run."""
    from datetime import datetime, timezone
    from app.services.unified.read_model import project_live_roles, project_activity
    review = (round_payload or {}).get("review_run") or {}
    run_id = review.get("run_id")
    if not run_id:
        return None
    rows = db.query(models.UnifiedAnalysisRun).filter(
        models.UnifiedAnalysisRun.run_id.like(f"UA-{run_id}-%")).all()
    active, reused, profile, outcomes = [], 0, "legacy", []
    now = datetime.now(timezone.utc)
    for item in rows:
        state = json.loads(item.state_json or "{}")
        profile = state.get("execution_profile", profile)
        receipts = state.get("task_receipts") or {}
        reused += sum(bool(receipt.get("reused")) for receipt in receipts.values())
        roles = project_live_roles(db, item, {"agents": json.loads(item.agents_json or "{}")})["agents"]
        activity = project_activity(db, item, roles)
        if item.status != "running":
            outcomes.append({"object_id": f"risk-{item.risk_id}", "run_id": item.run_id,
                             "pipeline_version": item.pipeline_version, "created_at": item.created_at.isoformat(),
                             "status": item.status, "roles": activity["roles"], "totals": activity["totals"]})
            continue
        started = item.created_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        active.append({"object_id": f"risk-{item.risk_id}",
            "roles": [role for role, log in roles.items() if log.get("status") == "running"],
            "elapsed_seconds": max(0, int((now - started).total_seconds())),
            "activity": activity,
            "updated_at": item.updated_at.isoformat()})
    pending = max(0, int(review.get("selected_object_count") or 0) - len(rows))
    running = review.get("status") == "running"
    return {"profile": profile, "active": active, "reused_reports": reused,
        "recent_results": outcomes[-6:],
        "queued_objects": pending if running else 0,
        "deferred_objects": 0 if running else pending,
        "processed_objects": sum(item.status != "running" for item in rows),
        "note": "排队、实际运行、复用和待审核分别计数；进度比例不代表剩余时间。"}
