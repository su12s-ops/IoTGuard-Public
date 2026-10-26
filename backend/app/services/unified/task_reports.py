"""Report reuse with exact scope and current-snapshot validation."""
from copy import deepcopy
from dataclasses import replace
import json
import time
import uuid
from typing import Literal

from pydantic import Field, ValidationError, create_model

from app.services.unified import collaboration as protocol
from app.services.unified.schemas import AGENT_ASSET, AGENT_DECISION, AGENT_VULNERABILITY
from app.services.unified.task_runtime import digest, semantic, VERSION
from app.services.unified.prompt_views import asset_quality_dependencies


def scoped_spec(spec, state):
    """Put the decision handoff's exact object contract in the model schema."""
    report = spec.output_model
    if "messages" in report.model_fields:
        report = create_model("Bounded" + report.__name__, __base__=report,
            messages=(report.model_fields["messages"].annotation,
                      Field(default_factory=list, max_length=0)))
    if spec.name != AGENT_DECISION or not state.object_id:
        return replace(spec, output_model=report)
    from app.services.unified.schemas import VerdictItem
    verdict = create_model("ScopedVerdict", __base__=VerdictItem,
        object_id=(Literal[state.object_id], ...))
    report = create_model("ScopedDecisionReport", __base__=report,
        verdicts=(list[verdict], Field(min_length=1, max_length=1)))
    return replace(spec, output_model=report)


def scoped_input(ctx, state, role, context):
    snapshot = state.evidence_snapshot
    if role != AGENT_ASSET:
        return state, context, semantic({
            "snapshot": {k: snapshot.get(k) for k in
                         ("asset_id", "target_type", "categories", "evidence_registry", "integrity_errors")},
            "packet": state.evidence_prep, "goal": state.investigation_goal,
            "asset_report": state.investigation,
            "risk": ctx.risk.id if role == AGENT_DECISION and ctx.risk else None,
            "run": state.run_id if role == AGENT_DECISION else None})
    # The asset report answers device questions, independent of an individual
    # CVE. Keep the full inventory dependency, even if its prompt view is bounded.
    categories = deepcopy(snapshot.get("categories") or {})
    inventory = categories.get("inventory") or {}
    inventory.pop("candidate_versions", None)
    (categories.get("identity") or {}).pop("risk_id", None)
    subset = {k: categories.get(k) for k in ("identity", "inventory")}
    packet = deepcopy(state.evidence_prep or {})
    runtime = packet.get("runtime_facts") or {}
    quality = asset_quality_dependencies(runtime)
    registry = {k: v for k, v in (snapshot.get("evidence_registry") or {}).items()
                if v.get("kind") == "inventory"}
    dependencies = semantic({"categories": subset, "registry": registry,
        "quality": quality, "asset_facts": packet.get("asset_facts"),
        "integrity_errors": [e for e in snapshot.get("integrity_errors", []) if e.startswith("inventory")],
        "goal": state.investigation_goal})
    scoped = state.model_copy(deep=True)
    scoped.shared_findings, scoped.collaboration_messages = [], []
    scoped.candidate_context = []
    scoped.evidence_snapshot = {**snapshot, "risk_id": None,
        "categories": subset, "categories_hashes": {k: digest(v) for k, v in subset.items()},
        "evidence_registry": registry, "integrity_errors": dependencies["integrity_errors"]}
    # The compact collaboration view must not include the per-risk snapshot ID
    # as a dependency or leak a previous CVE's messages into a shared report.
    scoped.evidence_snapshot["snapshot_id"] = "AS-" + digest(dependencies)[:32]
    from app.services.unified.graph import _asset_prep_context
    context = (f"调查设备 {state.target_ref} 的身份、软件清单、服务暴露和证据覆盖。\n"
        "本任务供同一设备多个风险共用，不裁定任何 CVE，不讨论具体漏洞。"
        "仅回答输入中设备范围的问题；清单展示截断不表示原始清单不完整。"
        "已有事实直接引用；缺口列入 missing_evidence，不重复查询同一事实。"
        "messages 留空，后续由具体风险任务提出问题。\n"
        + _asset_prep_context(scoped))
    return scoped, context, dependencies


def validate_scope(role, state, report):
    errors = []
    if role == AGENT_VULNERABILITY:
        candidates = [(str(c.get("cve_id") or ""), str(c.get("package_name") or ""))
                      for c in state.candidate_context]
        for finding in report.get("findings") or []:
            cve, package = str(finding.get("cve_id") or ""), str(finding.get("package_name") or "")
            if not any((cve == expected or (":" not in cve and cve == expected.split(":")[0]))
                       and (not package or package == name) for expected, name in candidates):
                errors.append("finding_outside_task_scope:" + cve + ":" + package)
        if not report.get("findings") and not report.get("data_gaps"):
            errors.append("empty_vulnerability_report")
    if role == AGENT_DECISION and state.object_id:
        if not report.get("verdicts"):
            errors.append("missing_object_verdict")
        if any(v.get("object_id") != state.object_id for v in report.get("verdicts") or []):
            errors.append("verdict_outside_task_scope")
    return errors


def execute(ctx, state, spec, context, validator, run, *, deadline=None):
    runtime = ctx.batch_runtime
    scoped, context, dependencies = scoped_input(ctx, state, spec.name, context)
    previous_validator = validator
    def validator(report):
        return (list(previous_validator(report)) if previous_validator else []) + validate_scope(spec.name, scoped, report)
    dependencies["schema"] = digest(spec.output_model.model_json_schema())
    dependencies["contract"] = VERSION
    # Store hashes, not full inventory/official payloads, in the task receipt.
    dependencies = {"facts_sha256": digest(dependencies), "contract": VERSION}
    asset_id = state.evidence_snapshot.get("asset_id")
    if not asset_id:
        return run(context, state, validator, state.run_id + ":" + spec.name)
    limit = time.monotonic() + min(240, ctx.remaining_s(), runtime.remaining())
    if deadline is not None:
        limit = min(limit, deadline)
    waiting_observed = False
    wait_started = time.monotonic()
    # Each execution owns its lease, rather than sharing the whole batch owner.
    # An expired execution may return after another risk reclaimed the task.
    lease_owner = uuid.uuid4().hex
    while True:
        if time.monotonic() >= limit:
            return None, "shared_task_wait_deadline"
        task_id, cached, origin, origin_snapshot = runtime.claim(
            spec.name, asset_id, dependencies, state.run_id, scoped.evidence_snapshot.get("snapshot_id", ""),
            lease_owner=lease_owner)
        if task_id:
            break
        if not waiting_observed:
            with ctx.session() as observation_db:
                ctx.emit(observation_db, "task_waiting", actor=spec.name, status="waiting",
                         payload={"phase": "shared_report"})
            waiting_observed = True
        if time.monotonic() >= limit:
            return None, "shared_task_wait_deadline"
        runtime.wait_for_report(limit - time.monotonic())
    shared_wait_ms = int((time.monotonic() - wait_started) * 1000) if waiting_observed else 0
    # Validate every reuse against today's registry and role-specific checks.
    # Old messages cannot be replayed into a new risk or snapshot.
    if cached is not None:
        if isinstance(cached, dict) and "_task_error" in cached:
            error = "shared_task_failed_no_new_evidence: " + cached["_task_error"]
            ctx.log_agent(spec.name, {"status": "degraded", "llm_calls": 0,
                "latency_ms": shared_wait_ms, "shared_wait_ms": shared_wait_ms, "origin_run_id": origin, "task_id": task_id,
                "requests": [], "error": error, "stop_reason": "same_facts_after_failure"})
            ctx.task_receipts[spec.name] = {"task_id": task_id, "origin_run_id": origin,
                "origin_snapshot_id": origin_snapshot, "reused": False, "status": "blocked_same_facts"}
            return None, error
        try:
            spec.output_model.model_validate(cached)
        except ValidationError:
            # A stale or damaged cached payload is not an orchestrator failure.
            # Keep the immutable receipt and run the normal bounded validator.
            return run(context, scoped, validator, state.run_id + ":" + spec.name)
        cached["messages"] = []
        errors = protocol.validate_evidence_ids(protocol.collect_evidence_ids(cached), scoped.evidence_snapshot)
        if validator:
            errors.extend(validator(cached))
        if not errors:
            cached = spec.output_model.model_validate(cached).model_dump()
            ctx.log_agent(spec.name, {"status": "reused", "output": cached,
                "llm_calls": 0, "latency_ms": shared_wait_ms, "shared_wait_ms": shared_wait_ms, "origin_run_id": origin,
                "task_id": task_id, "requests": [], "error": ""})
            ctx.task_receipts[spec.name] = {"task_id": task_id, "origin_run_id": origin,
                "origin_snapshot_id": origin_snapshot, "reused": True}
            return cached, ""
        # Do not overwrite an immutable report or use an invalid one. A fresh
        # scoped run may obtain a valid report, still subject to the batch limits.
        return run(context, scoped, validator, state.run_id + ":" + spec.name)
    try:
        output, error = run(context, scoped, validator, task_id)
        if output is not None:
            output = deepcopy(output)
            # Retain questions in the originating graph. Persist shared reports
            # without snapshot-bound collaboration messages.
            saved = {**output, "messages": []}
            persisted = runtime.finish(task_id, saved, lease_owner=lease_owner)
        else:
            persisted = runtime.finish(task_id, error=error, lease_owner=lease_owner)
        ctx.task_receipts[spec.name] = {"task_id": task_id, "origin_run_id": state.run_id,
            "origin_snapshot_id": scoped.evidence_snapshot.get("snapshot_id", ""), "reused": False}
        if not persisted:
            ctx.task_receipts[spec.name]["status"] = "lease_lost"
            # The model call remains in execution history and usage, but its
            # result is not the current authoritative role report.
            with ctx._lock:
                log = ctx.agent_logs.setdefault(spec.name, {
                    "llm_calls": 0, "latency_ms": 0, "requests": [],
                    "total_llm_calls": 0, "total_latency_ms": 0, "executions": []})
                correction = {"status": "degraded", "output": None, "task_id": task_id,
                    "error": "shared_task_lease_lost", "stop_reason": "shared_task_lease_lost"}
                log.update(correction)
                if log.get("executions"):
                    log["executions"][-1].update(correction)
            return None, "shared_task_lease_lost"
        return output, error
    except Exception as exc:
        runtime.finish(task_id, error=str(exc), lease_owner=lease_owner)
        raise
