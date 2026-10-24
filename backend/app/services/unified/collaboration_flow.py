"""Deterministic collaboration nodes for the existing four-role graph."""
from datetime import datetime, timedelta, timezone
import json

from app.services.unified import collaboration as protocol, harness_bridge
from app.services.unified.schemas import ALL_AGENT_IDS, AGENT_DECISION
from app.services.unified.selective_replay import ROLE_KEYS, select_roles


def emit_messages(ctx, messages):
    if not messages or not ctx.trace_id:
        return
    with ctx.session() as db:
        for message in messages:
            ctx.emit(db, "collaboration_message", actor=message["sender"],
                     status=message["status"], payload=message, evidence_refs=message["evidence_ids"])


def system_message(ctx, state, kind, claim, receiver=AGENT_DECISION, refs=(), action="", reply_to=""):
    messages, _ = protocol.validate_messages([{"receiver": receiver, "message_type": kind,
        "claim": claim[:1900], "evidence_ids": list(refs), "requested_action": action,
        "reply_to": reply_to, "status": "informational"}], "orchestrator", state.evidence_snapshot)
    emit_messages(ctx, messages)
    return messages


def prepare(ctx, state, db, packet):
    caps = harness_bridge.query_capabilities(db, state)
    parent = ctx.replay_parent or {}
    previous = parent.get("evidence_snapshot") or state.evidence_snapshot or None
    snapshot = protocol.build_snapshot(db, packet, state.run_id,
        risk_id=ctx.risk.id if ctx.risk else None, previous=previous, harness=caps,
        asset_ref=state.target_ref, target_type=state.target_type)
    ctx.snapshot_id = snapshot["snapshot_id"]
    ctx.packet_evidence_ids = protocol.evidence_registry_ids(snapshot)
    active, reuse, reason = select_roles(parent, snapshot, force_full=ctx.force_full_review,
                                        ttl_seconds=state.budgets.reuse_ttl_seconds)
    update = {"evidence_snapshot": snapshot, "evidence_snapshot_id": snapshot["snapshot_id"],
        "evidence_versions": list(parent.get("evidence_versions") or []) + [snapshot],
        "replay_roles": active, "reuse_roles": reuse, "harness_capabilities": caps,
        "collaboration_stop_reason": reason if reason == "no_new_evidence" else ""}
    if parent:
        update["replay_from_run_id"] = parent.get("run_id", "")
        for role in reuse:
            update[ROLE_KEYS[role]] = parent.get(ROLE_KEYS[role])
        ctx.emit(db, "selective_replay", actor="orchestrator", status="succeeded", payload={
            "parent_run_id": parent.get("run_id"), "snapshot_id": snapshot["snapshot_id"],
            "changed_fields": snapshot.get("changed_fields"), "active_roles": active,
            "reused_roles": reuse, "reason": reason})
    return update


def publish(ctx, state, role, output, *, reused=False):
    if not state.evidence_snapshot:
        return {}
    findings = protocol.build_findings(role, output, state.evidence_snapshot, state.shared_findings)
    now = datetime.now(timezone.utc)
    previous = (ctx.replay_parent or {}).get("role_provenance", {}).get(role, {})
    provenance = {"status": "reused" if reused else "executed", "run_id": state.run_id,
        "snapshot_id": state.evidence_snapshot_id,
        "origin_run_id": previous.get("origin_run_id", previous.get("run_id")) if reused else state.run_id,
        "origin_snapshot_id": previous.get("origin_snapshot_id", previous.get("snapshot_id")) if reused else state.evidence_snapshot_id,
        "valid_until": previous.get("valid_until") if reused else (now + timedelta(seconds=state.budgets.reuse_ttl_seconds)).isoformat(),
        "llm_called_this_execution": not reused}
    messages, errors = protocol.validate_messages([] if reused else output.get("messages", []),
        role, state.evidence_snapshot, state.shared_findings + findings)
    for finding in findings:
        finding["provenance"] = provenance
        finding["finding_id"] = "SF-" + protocol.fingerprint(finding)[:32]
    # FINDING is a projection of the actual validated report, not fabricated dialogue.
    for finding in findings:
        if finding["claim"] and role != AGENT_DECISION:
            generated, _ = protocol.validate_messages([{"receiver": AGENT_DECISION, "message_type": "FINDING",
                "claim": finding["claim"], "evidence_ids": finding["evidence_ids"],
                "status": "informational"}], role, state.evidence_snapshot)
            messages = protocol.merge_immutable(messages, generated)
    receipts = {}
    inbox = {m["message_id"]: m for m in state.collaboration_messages}
    for message in messages:
        original = inbox.get(message.get("reply_to"))
        if original and original["receiver"] in {role, "all"}:
            receipts[original["message_id"]] = {"status": "resolved" if message["message_type"] == "RESOLUTION" else "answered",
                "reply_message_id": message["message_id"], "role": role, "snapshot_id": state.evidence_snapshot_id}
    emit_messages(ctx, messages)
    return {"shared_findings": findings, "collaboration_messages": messages,
        "message_receipts": receipts, "role_provenance": {role: provenance},
        **({"error": ";".join(errors)} if errors else {})}


def reused(ctx, state, role, stage):
    if role not in state.reuse_roles:
        return None
    output = getattr(state, ROLE_KEYS[role])
    if not output:
        return None
    result = publish(ctx, state, role, output, reused=True)
    ctx.log_agent(role, {"status": "reused", "llm_calls": 0, "latency_ms": 0,
        "provenance": result["role_provenance"][role], "output": output})
    return {**result, "stage_status": {stage: "reused"}}


def compact_report(report):
    if not report:
        return report
    keep = {"device_id", "evidence_quality", "missing_evidence", "data_gaps", "findings",
        "confidence", "behavior_level", "runtime_status", "exploitation_relation", "evidence_freshness",
        "evidence_ids", "intelligence_conflicts", "contradictions", "verified_facts", "conflicting_facts"}
    return {key: value for key, value in report.items() if key in keep}


def inbox(state):
    return [m for m in state.collaboration_messages if m["snapshot_id"] == state.evidence_snapshot_id
        and m["message_type"] in {"QUESTION", "CHALLENGE", "EVIDENCE_REQUEST"}
        and m["message_id"] not in state.message_receipts and m["receiver"] != AGENT_DECISION]


def node_exchange(ctx):
    def exchange(state):
        from app.services.unified import graph as graph_mod
        from app.services.unified.agents_def import SPEC_BY_NAME
        update = {"collaboration_rounds": state.collaboration_rounds + 1, "message_receipts": {}}
        pending = inbox(state)
        if state.collaboration_rounds >= state.budgets.message_rounds:
            return {"collaboration_stop_reason": "message_budget_exhausted"}
        current = state.model_copy(deep=True)
        for role in ALL_AGENT_IDS[:3]:
            requests = [m for m in pending if m["receiver"] == role]
            if not requests:
                continue
            # Message text never becomes a tool name, shell, authorization or collection request.
            if ctx.remaining_s() <= min(300, ctx.run_deadline_s * .25):
                update["collaboration_stop_reason"] = "budget_reserved_for_decision"
                break
            context = ctx.first_contexts.get(role, "") + "\n定向协作调查，只处理以下问题；工具不能提供的证据必须保留缺口：\n" + json.dumps(requests, ensure_ascii=False)
            output, error = graph_mod._run_specialist(ctx, SPEC_BY_NAME[role], context, state=current,
                validate_fn=graph_mod._role_validator(ctx, current, role))
            for message in requests:
                update["message_receipts"][message["message_id"]] = {"status": "answered" if output else "unresolved",
                    "role": role, "snapshot_id": state.evidence_snapshot_id,
                    "evidence_changed": False, "note": "Same snapshot analysis; not new collection or confidence evidence."}
            if output:
                key = ROLE_KEYS[role]
                update[key] = output
                setattr(current, key, output)
                published = publish(ctx, current, role, output)
                for key in ("shared_findings", "collaboration_messages"):
                    update[key] = protocol.merge_immutable(update.get(key, []), published[key])
                    setattr(current, key, protocol.merge_immutable(getattr(current, key), published[key]))
                update.setdefault("role_provenance", {}).update(published["role_provenance"])
                update["message_receipts"].update(published["message_receipts"])
            else:
                update.setdefault("degraded_roles", []).append(role)
                update["collaboration_stop_reason"] = "evidence_partial"
        from app.services.unified.conflicts import detect_conflicts
        update["conflict_result"] = detect_conflicts({**state.model_dump(), **update})
        return update
    return exchange
