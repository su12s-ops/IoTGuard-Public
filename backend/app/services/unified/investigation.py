"""Deterministic bridge to M4.4 collection_tasks. No agent execution authority."""
from __future__ import annotations

import hashlib
import json
import uuid
from sqlalchemy import update

from app import models
from app.services import collection_tasks, trace_service as tracing
from app.services.unified.schemas import ALL_AGENT_IDS


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def fingerprint(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def substantive_change(before, current):
    # Schema expansion is not new evidence. Older proposals compare only the
    # categories they actually snapshotted, and cannot gain confidence from it.
    return fingerprint(before) != fingerprint({key: current.get(key) for key in before})


def evidence_view(db, asset_id):
    asset = db.get(models.LinuxAsset, asset_id)
    if asset is None:
        raise ValueError("asset_missing")
    # Ignore receipt timestamps and new INV identifiers: identical facts are not
    # substantive updates. Retain complete runtime payloads, not only row IDs.
    runtime = db.query(models.SecurityEvidence).filter_by(asset_id=asset_id).order_by(models.SecurityEvidence.id).all()
    cves = {r.cve_id.split(":")[0] for r in db.query(models.RiskAssessment).filter_by(asset_id=asset_id)}
    official = {}
    for row in db.query(models.OfficialCveRecord).filter(models.OfficialCveRecord.cve_id.in_(cves)).order_by(models.OfficialCveRecord.id):
        if row.evidence_status == "available":
            official[row.cve_id] = row.content_sha256
    metadata = json.loads(asset.inventory_metadata_json or "{}")
    return {"packages": sorted((p.package_name, p.package_version, p.architecture) for p in asset.packages),
            "services": sorted((s.service_name or "", s.port or 0, s.protocol or "", s.listen_address or "",
                s.process_name or "", bool(s.is_public_exposed)) for s in asset.services),
            "package_sources": sorted(metadata.get("package_sources") or []),
            "cached_apt_policy": metadata.get("apt_policy") or {},
            "distribution": asset.distribution, "os_version": asset.os_version,
            "official": official,
            "inventory_complete": asset.inventory_complete,
            "runtime": [{c.name: getattr(r, c.name) for c in r.__table__.columns} for r in runtime]}


def propose(db, run_id, request):
    row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=run_id).one_or_none()
    if row is None or row.mode not in {"shadow", "formal"}:
        raise ValueError("unified_source_required")
    asset = db.query(models.LinuxAsset).filter_by(hostname=row.target_ref).one_or_none()
    risk = db.get(models.RiskAssessment, row.risk_id) if row.risk_id else None
    if row.target_type != "linux_host" or asset is None or (risk and risk.asset_id != asset.id):
        raise ValueError("source_asset_mismatch")
    if request.get("collection_capability") != "inventory" or request.get("target_agent") not in ALL_AGENT_IDS[:3]:
        raise ValueError("unsupported_collection_capability")
    if not request.get("question", "").strip() or not request.get("expected_effect", "").strip():
        raise ValueError("explicit_question_and_effect_required")
    # Collector can resolve package/identity questions only, never runtime gaps.
    if request.get("target_agent") == "runtime_analyst":
        raise ValueError("inventory_cannot_resolve_runtime_gap")
    proposal = {k: request.get(k, "") for k in ("target_agent", "question", "expected_effect", "evidence_hint", "collection_capability")}
    rid = "IR-" + fingerprint([run_id, proposal])[:32]
    existing = db.get(models.InvestigationRequest, rid)
    if existing:
        return existing
    if db.query(models.InvestigationRequest).filter_by(source_run_id=run_id).count() >= 2:
        raise ValueError("investigation_proposal_budget_exhausted")
    proposal.update(asset_id=asset.id, source_run_id=run_id, policy="fixed-inventory-v1")
    proposal["authorized_scope"] = ["installed_package_inventory", "asset_identity", "cached_apt_policy"]
    proposal["unsupported_scope"] = ["package_index_refresh", "runtime_capture", "shell_commands", "repair"]
    item = models.InvestigationRequest(id=rid, source_run_id=run_id, asset_id=asset.id,
        request_json=encode(proposal), request_hash=fingerprint(proposal), before_json=encode(evidence_view(db, asset.id)))
    db.add(item)
    db.commit()
    tracing.emit(db, row.trace_id, "investigation_proposed", actor=request["target_agent"], status="awaiting_authorization",
                 payload={"request_id": rid, **proposal})
    return item


def authorize(db, item, request_hash, connection_id, actor, reason):
    proposal = json.loads(item.request_json)
    if request_hash != item.request_hash or fingerprint(proposal) != item.request_hash:
        raise ValueError("request_changed")
    if not actor.strip() or not reason.strip():
        raise ValueError("operator_and_reason_required")
    connection = db.get(models.DeviceConnection, connection_id)
    if not connection or not connection.enabled or connection.asset_id != item.asset_id:
        raise ValueError("connection_asset_mismatch")
    if item.status != "awaiting_authorization":
        if item.status == "authorized":
            collection_tasks.execute(db, collection_tasks.get_run(db, item.collection_run_id))
        return item
    check = collection_tasks.preflight(db, connection)
    if not check["ready"]:
        raise ValueError("collection_preflight_failed")
    run = collection_tasks.create_run(db, connection_id, request_id=item.id)
    item.collection_run_id = run.id
    item.authorized_by, item.authorization_reason = actor, reason
    item.status = "authorized"
    db.commit()  # Record explicit authorization before dispatch; retry is idempotent.
    tracing.emit(db, run.trace_id, "investigation_authorized", actor=actor, status="authorized",
        payload={"request_id": item.id, "source_run_id": item.source_run_id, "request_hash": request_hash, "reason": reason})
    collection_tasks.execute(db, run)
    return item


def resume(db, item, client_factory=None):
    from app.services.unified.runner import run_unified_sync
    if item.reanalysis_run_id:
        return db.query(models.UnifiedAnalysisRun).filter_by(run_id=item.reanalysis_run_id).one()
    run = collection_tasks.get_run(db, item.collection_run_id) if item.collection_run_id else None
    if item.status != "authorized" or not item.authorized_by or not run or run.status != "completed" or run.asset_id != item.asset_id:
        raise ValueError("authorized_completed_collection_required")
    result = json.loads(run.result_json)
    evidence_id = result.get("inventory_evidence_id")
    raw = db.query(models.CollectionEvidence).filter_by(evidence_id=evidence_id, run_id=run.id, asset_id=item.asset_id).one_or_none()
    if not raw or hashlib.sha256(raw.raw_text.encode()).hexdigest() != raw.content_sha256:
        raise ValueError("raw_evidence_missing_or_corrupt")
    asset = db.get(models.LinuxAsset, item.asset_id)
    if json.loads(asset.inventory_metadata_json or "{}").get("collection_run_id") != run.id:
        raise ValueError("collection_superseded")
    parent = db.query(models.UnifiedAnalysisRun).filter_by(run_id=item.source_run_id).one()
    if parent.mode == "formal":
        from app import config
        risk = db.get(models.RiskAssessment, parent.risk_id)
        if config.UNIFIED_PIPELINE_MODE != "on" or not risk or not risk.active:
            raise ValueError("active_formal_source_required")
        current_run = json.loads(risk.device_context_json or "{}").get("unified_run_id")
        if current_run != parent.run_id or risk.review_status not in {"pending_human_review", "reanalysis_required"}:
            raise ValueError("formal_source_superseded_or_under_review")
    claimed = db.execute(update(models.InvestigationRequest).where(
        models.InvestigationRequest.id == item.id, models.InvestigationRequest.status == "authorized",
        models.InvestigationRequest.reanalysis_run_id == "").values(status="reanalysis_running"))
    if claimed.rowcount != 1:
        db.rollback()
        raise ValueError("reanalysis_already_claimed")
    if parent.mode == "formal":
        changed_risk = db.execute(update(models.RiskAssessment).where(
            models.RiskAssessment.id == risk.id,
            models.RiskAssessment.review_status.in_({"pending_human_review", "reanalysis_required"})).values(review_status="agent_reviewing"))
        if changed_risk.rowcount != 1:
            db.rollback()
            raise ValueError("formal_review_state_changed")
    child = models.UnifiedAnalysisRun(run_id="UA-" + uuid.uuid4().hex[:24], risk_id=parent.risk_id,
        task_type=parent.task_type, target_type=parent.target_type, target_ref=parent.target_ref, mode=parent.mode, status="running")
    trace = tracing.start_trace(db, task_type="unified_four_agent", target_type=child.target_type, target_ref=child.target_ref,
        run_ref_type="unified_analysis", run_ref_id=child.run_id, metadata={"mode": parent.mode, "parent": parent.run_id, "request_id": item.id})
    child.trace_id = trace.trace_id
    db.add(child)
    item.reanalysis_run_id, item.status = child.run_id, "reanalysis_running"
    db.commit()  # An interrupted reanalysis is inspectable, never silently replayed.
    tracing.emit(db, child.trace_id, "investigation_evidence", actor="collection_policy", status="succeeded",
        payload={"request_id": item.id, "collection_run_id": run.id, "collection_trace_id": run.trace_id}, evidence_refs=[evidence_id])
    kwargs = {"client_factory": client_factory} if client_factory else {}
    previous_state = json.loads(parent.state_json)
    goal = encode({"question": json.loads(item.request_json)["question"],
        "expected_effect": json.loads(item.request_json)["expected_effect"],
        "new_inventory_evidence_id": evidence_id, "collection_run_id": run.id,
        "previous_verdicts": (previous_state.get("decision") or {}).get("verdicts"),
        "instruction": "本次已完成授权固定清单采集。逐项说明新证据解决了什么、未解决什么，为什么改变或保持判断；未刷新 apt 索引、未采集新运行时。不得因重跑提高置信度。"})
    if parent.mode == "formal":
        from app import config
        from app.services.unified.adapter import formal_sink
        risk = db.get(models.RiskAssessment, parent.risk_id)
        if config.UNIFIED_PIPELINE_MODE != "on" or not risk or not risk.active:
            raise ValueError("active_formal_source_required")
        kwargs["sink"] = formal_sink
    run_unified_sync(db, child, force_full_review=True, investigation_goal=goal, **kwargs)
    if parent.mode == "formal" and child.status != "completed":
        risk.review_status, risk.human_review_required = "pending_human_review", True
        risk.final_score = risk.risk_level = risk.decision = None
        risk.review_reason = "unified_investigation_reanalysis_failed:" + (child.error or "unknown")
        db.commit()
    old, new = json.loads(parent.state_json), json.loads(child.state_json)
    if parent.mode == "formal":
        from app.services.unified.adapter import persist_investigation_report
        from app.services.unified.state import UnifiedAnalysisState
        persist_investigation_report(db, child, UnifiedAnalysisState.model_validate(new))
    changed = substantive_change(json.loads(item.before_json), evidence_view(db, item.asset_id))
    # A new receipt alone cannot justify increased confidence in any role.
    # Preserve every raw model confidence. Repeated reasoning is variance,
    # never evidence that independently justifies a risk change.
    contributions = {role: {"judgment_changed": judgment(old.get(key)) != judgment(new.get(key)),
        "output_changed": old.get(key) != new.get(key), "before": old.get(key), "after": new.get(key)}
        for role, key in zip(ALL_AGENT_IDS, ("investigation", "vulnerability", "runtime", "decision"))}
    item.result_json = encode({"evidence_id": evidence_id, "substantive_update": changed,
        "gap_resolution": "current_inventory_verified_partial_question",
        "model_variance_only": not changed,
        "raw_model_confidence_preserved": True,
        "resolved_facts": {"distribution": asset.distribution, "os_version": asset.os_version,
            "package_count": len(asset.packages), "inventory_sha256": raw.content_sha256,
            "candidate_packages": [{"name": p.package_name, "version": p.package_version} for p in asset.packages
                if parent.risk_id and p.package_name == db.get(models.RiskAssessment, parent.risk_id).package_name]},
        "remaining_gaps": ["运行时覆盖与心跳不由清单采集解决", "只读取本地 apt 索引，未刷新，不能证明官方仓库最新可用性"],
        "reason": "新原文确认本次采集时点的清单事实；相同事实不提高置信度。申请中的运行时、刷新索引等问题不在授权能力范围。",
        "agents": contributions, "decision_changed": old.get("decision") != new.get("decision"),
        "collection_trace_id": run.trace_id, "reanalysis_trace_id": child.trace_id})
    item.status = "completed" if child.status == "completed" else "reanalysis_failed"
    db.commit()
    tracing.emit(db, child.trace_id, "investigation_reassessed", actor="collection_policy", status=item.status,
        payload={"request_id": item.id, "substantive_update": changed, "model_variance_only": not changed}, evidence_refs=[evidence_id])
    return child



def judgment(report):
    report = report or {}
    keys = ("evidence_quality", "behavior_level", "runtime_status", "exploitation_relation", "impact_status",
            "risk_direction", "recommended_action", "recommended_priority", "applicability", "version_impact", "installed_version")
    return {**{k: report[k] for k in keys if k in report},
        **{k: [judgment(v) for v in report[k]] for k in ("findings", "verdicts") if k in report}}


def serialize(item):
    return {c.name: (json.loads(getattr(item, c.name)) if c.name.endswith("_json") else getattr(item, c.name))
            for c in item.__table__.columns}
