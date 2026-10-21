"""Compiled four-role graph safety regressions, using scripted model responses.

These isolated tests validate orchestration, never live model/device acceptance.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import threading

import pytest

from app import models
from app.services.unified.agent_base import UsageMeter
from app.services.unified.graph import RunContext, build_graph
from app.services.unified.schemas import (
    AGENT_ASSET, AGENT_DECISION, AGENT_RUNTIME, AGENT_VULNERABILITY, ALL_AGENT_IDS,
)
from app.services.unified.state import TASK_RISK_REVIEW, UnifiedAnalysisState, empty_state


ROLE_TITLES = {AGENT_ASSET: "资产与证据调查员", AGENT_VULNERABILITY: "漏洞分析师",
               AGENT_RUNTIME: "运行时分析师", AGENT_DECISION: "研判与处置规划师"}
CVE = "CVE-2026-81001"


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def payloads():
    return {
        AGENT_ASSET: {"device_id": "flow-router", "device_type": "gateway",
            "evidence_quality": "partial", "confidence": 0.6,
            "missing_evidence": ["Exact vendor applicability remains unconfirmed."]},
        AGENT_VULNERABILITY: {"findings": [{"cve_id": CVE, "package_name": "daemon",
            "applicability": "insufficient_evidence", "version_impact": "unknown",
            "confidence": 0.6, "supporting_evidence_ids": ["ADV-flow"],
            "rationale": "The recorded advisory requires branch review."}], "confidence": 0.6},
        AGENT_RUNTIME: {"behavior_level": "NORMAL", "runtime_status": "contextual",
            "exploitation_relation": "service_active_only", "evidence_freshness": "fresh",
            "evidence_ids": ["SE-flow"], "findings": [{"aspect": "process",
                "evidence_id": "SE-flow", "relation": "service_active",
                "description": "The daemon started; this does not establish exploitation."}],
            "confidence": 0.6},
        AGENT_DECISION: {"verdicts": [{"object_id": "risk-1", "impact_status": "insufficient_evidence",
            "risk_direction": "maintain", "recommended_action": "collect_more_evidence",
            "recommended_priority": "medium", "confidence": 0.6,
            "supporting_evidence_ids": ["ADV-flow"], "reason": "Vendor branch and collection coverage need review."}],
            "confidence": 0.6},
    }


class Recorder:
    def __init__(self, overrides=None):
        self.defaults = payloads()
        self.overrides = {key: list(value) for key, value in (overrides or {}).items()}
        self.calls = []
        self.lock = threading.Lock()
        self.ctx = None

    def complete(self, messages, tools=None):
        first_line = messages[0]["content"].splitlines()[0]
        role = next(role for role, title in ROLE_TITLES.items() if title in first_line)
        with self.lock:
            self.calls.append({"role": role, "messages": deepcopy(messages), "tools": deepcopy(tools)})
            script = self.overrides.get(role, [])
            response = script.pop(0) if script else deepcopy(self.defaults[role])
        if callable(response):
            response = response(messages, self)
        if isinstance(response, dict) and "tool_calls" in response:
            return response
        return {"content": json.dumps(response, ensure_ascii=False), "tool_calls": []}

    def count(self, role):
        return sum(call["role"] == role for call in self.calls)


def add_runtime(db, asset_id, evidence_id="SE-flow", *, device_id="flow-router"):
    row = models.SecurityEvidence(evidence_id=evidence_id, evidence_hash=digest(evidence_id),
        asset_id=asset_id, device_id=device_id, source="logread", evidence_type="process",
        process="daemon", timestamp=datetime.now(timezone.utc).isoformat())
    db.add(row)


@pytest.fixture
def graph_rig(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="flow-router", ip_address="192.0.2.20",
            distribution="openwrt", os_version="24.10.2", architecture="x86_64",
            inventory_complete=True)
        db.add(asset)
        db.flush()
        db.add(models.AssetPackage(asset_id=asset.id, package_name="daemon", package_version="1.0"))
        raw = '{"packages":{"daemon":"1.0"}}'
        db.add(models.CollectionEvidence(evidence_id="INV-flow", run_id="collect-flow", asset_id=asset.id,
            raw_text=raw, content_sha256=digest(raw)))
        asset.inventory_metadata_json = json.dumps({"inventory_evidence_id": "INV-flow"})
        official = '{"cve_id":"CVE-2026-81001","affected":"unknown branch"}'
        db.add(models.OfficialCveRecord(evidence_id="ADV-flow", cve_id=CVE,
            source_url="https://vendor.invalid/advisory", raw_json=official,
            content_sha256=digest(official), evidence_status="available"))
        risk = models.RiskAssessment(asset_id=asset.id, cve_id=CVE, package_name="daemon",
            preliminary_level="High", preliminary_score=70, affected_status="unknown")
        db.add(risk)
        add_runtime(db, asset.id)
        db.commit()
        yield {"factory": session_factory, "asset_id": asset.id, "risk_id": risk.id}


def invoke(rig, client=None, *, parent=None, force=False, run_id="flow-root", budgets=None,
           meter=None, tool_cache=None):
    client = client or Recorder()
    state = empty_state(run_id, TASK_RISK_REVIEW, "flow-router", "linux_host", "shadow")
    for key, value in (budgets or {}).items():
        setattr(state.budgets, key, value)
    with rig["factory"]() as db:
        risk = db.get(models.RiskAssessment, rig["risk_id"])
        db.expunge(risk)
    ctx = RunContext(db_factory=rig["factory"], trace_id="", risk=risk,
        client_factory=lambda: client, meter=meter or UsageMeter(), force_full_review=force,
        replay_parent=deepcopy(parent or {}), tool_cache=tool_cache if tool_cache is not None else {})
    client.ctx = ctx
    result = UnifiedAnalysisState.model_validate(build_graph(ctx).invoke(state))
    return result, ctx, client


def question(receiver=AGENT_RUNTIME, claim="Which process does the existing event identify?"):
    return {"receiver": receiver, "message_type": "QUESTION", "claim": claim,
        "evidence_ids": ["SE-flow"], "requested_action": "Inspect the existing event and retain unknown facts."}


def test_compiled_graph_routes_question_to_named_role_and_records_actual_reply(graph_rig):
    asset = payloads()[AGENT_ASSET]
    asset["messages"] = [question()]

    def answer(messages, client):
        prompt = "\n".join(message.get("content") or "" for message in messages[1:])
        ids = re.findall(r'"message_id"\s*:\s*"(CM-[a-f0-9]+)"', prompt)
        assert ids, "Directed request must carry the immutable real message id."
        report = payloads()[AGENT_RUNTIME]
        report["messages"] = [{"receiver": AGENT_ASSET, "message_type": "FINDING",
            "claim": "The stored process is daemon; a parent identity is unavailable.",
            "evidence_ids": ["SE-flow"], "reply_to": ids[-1]}]
        return report

    client = Recorder({AGENT_ASSET: [asset], AGENT_RUNTIME: [payloads()[AGENT_RUNTIME], answer]})
    result, ctx, client = invoke(graph_rig, client)
    requests = [item for item in result.collaboration_messages if item["message_type"] == "QUESTION"]
    assert len(requests) == 1
    request = requests[0]
    replies = [item for item in result.collaboration_messages if item["reply_to"] == request["message_id"]]
    assert len(replies) == 1 and replies[0]["sender"] == AGENT_RUNTIME
    assert result.message_receipts[request["message_id"]]["reply_message_id"] == replies[0]["message_id"]
    assert result.collaboration_rounds == 1
    assert client.count(AGENT_RUNTIME) == 2
    assert client.count(AGENT_ASSET) == client.count(AGENT_VULNERABILITY) == client.count(AGENT_DECISION) == 1
    assert result.evidence_snapshot_id
    assert all(item["snapshot_id"] == result.evidence_snapshot_id for item in result.collaboration_messages)
    assert ctx.agent_logs[AGENT_RUNTIME]["total_llm_calls"] == 2


def test_same_snapshot_message_cannot_inflate_confidence_from_prose(graph_rig):
    asset = payloads()[AGENT_ASSET]
    asset["messages"] = [question()]
    revised = payloads()[AGENT_RUNTIME]
    revised["confidence"] = 0.99
    revised["findings"][0]["description"] = "The same daemon startup, restated more confidently."
    result, _, _ = invoke(graph_rig, Recorder({AGENT_ASSET: [asset],
        AGENT_RUNTIME: [payloads()[AGENT_RUNTIME], revised]}))
    assert result.runtime["confidence"] <= 0.6
    assert result.collaboration_rounds == 1
    latest = [item for item in result.shared_findings if item["publisher"] == AGENT_RUNTIME][-1]
    assert latest["material_change"] is False


def test_same_snapshot_followup_preserves_confidence_without_repeating_decision(graph_rig):
    decision = payloads()[AGENT_DECISION]
    decision["follow_up_requests"] = [{"target_agent": AGENT_RUNTIME,
        "question": "Can the existing event supply a parent execution identity?",
        "expected_effect": "Clarify whether a causal parent can be established.", "collection_capability": "database"}]
    revised = payloads()[AGENT_RUNTIME]
    revised["confidence"] = 0.99
    revised["findings"][0]["description"] = "The same event in different words."
    result, _, client = invoke(graph_rig, Recorder({AGENT_DECISION: [decision],
        AGENT_RUNTIME: [payloads()[AGENT_RUNTIME], revised]}))
    assert result.follow_ups_used == 1
    assert result.follow_up_results[0]["new_evidence"] is False
    assert result.follow_up_results[0]["changed"] is False
    assert client.count(AGENT_DECISION) == 1
    assert result.runtime["confidence"] <= 0.6


@pytest.mark.parametrize("change,active,reused", [
    ("runtime", [AGENT_RUNTIME, AGENT_DECISION], [AGENT_ASSET, AGENT_VULNERABILITY]),
    ("official", [AGENT_VULNERABILITY, AGENT_DECISION], [AGENT_ASSET, AGENT_RUNTIME]),
])
def test_compiled_selective_replay_executes_only_invalidated_roles(graph_rig, change, active, reused):
    parent, _, _ = invoke(graph_rig, force=True)
    assert not parent.degraded_roles
    frozen = parent.model_dump()
    with graph_rig["factory"]() as db:
        if change == "runtime":
            add_runtime(db, graph_rig["asset_id"], "SE-flow-new")
        else:
            raw = '{"cve_id":"CVE-2026-81001","affected":"revised vendor branch"}'
            db.add(models.OfficialCveRecord(evidence_id="ADV-flow-new", cve_id=CVE,
                source_url="https://vendor.invalid/advisory", raw_json=raw,
                content_sha256=digest(raw), evidence_status="available"))
        db.commit()
    result, ctx, client = invoke(graph_rig, parent=frozen, run_id="flow-child")
    assert result.replay_roles == active
    assert result.reuse_roles == reused
    assert parent.model_dump() == frozen
    assert len(result.evidence_versions) == 2
    assert result.evidence_versions[0] == frozen["evidence_versions"][0]
    for role in ALL_AGENT_IDS:
        assert client.count(role) == (1 if role in active else 0)
        assert ctx.agent_logs[role]["status"] == ("succeeded" if role in active else "reused")
    for role in reused:
        provenance = result.role_provenance[role]
        assert provenance["origin_run_id"] == parent.run_id
        assert provenance["origin_snapshot_id"] == parent.evidence_snapshot_id
        assert provenance["snapshot_id"] == result.evidence_snapshot_id
        assert provenance["valid_until"] == parent.role_provenance[role]["valid_until"]
        assert provenance["llm_called_this_execution"] is False
    assert not result.final["collaboration"]["full_four_role_execution"]


def test_force_full_review_reexecutes_four_roles_even_with_unchanged_parent(graph_rig):
    parent, _, _ = invoke(graph_rig, force=True)
    result, _, client = invoke(graph_rig, parent=parent.model_dump(), force=True, run_id="flow-forced")
    assert result.replay_roles == ALL_AGENT_IDS and result.reuse_roles == []
    assert all(client.count(role) == 1 for role in ALL_AGENT_IDS)
    assert result.final["collaboration"]["full_four_role_execution"] is True


def test_unchanged_replay_reuses_without_extending_original_validity(graph_rig):
    parent, _, _ = invoke(graph_rig, force=True)
    result, _, client = invoke(graph_rig, parent=parent.model_dump(), run_id="flow-reused")
    assert result.replay_roles == []
    assert result.reuse_roles == ALL_AGENT_IDS
    assert client.calls == []
    assert result.collaboration_stop_reason == "no_new_evidence"
    for role in ALL_AGENT_IDS:
        assert result.role_provenance[role]["valid_until"] == parent.role_provenance[role]["valid_until"]


@pytest.mark.parametrize("bad_provenance", ["expired", "wrong_snapshot", "missing_origin"])
def test_reuse_rejects_expired_or_unbound_provenance(graph_rig, bad_provenance):
    parent, _, _ = invoke(graph_rig, force=True)
    saved = parent.model_dump()
    provenance = saved["role_provenance"][AGENT_RUNTIME]
    if bad_provenance == "expired":
        provenance["valid_until"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    elif bad_provenance == "wrong_snapshot":
        provenance["snapshot_id"] = "ES-other-event"
    else:
        provenance.pop("origin_run_id")
        provenance.pop("origin_snapshot_id")
        provenance.pop("run_id")
    result, _, client = invoke(graph_rig, parent=saved, run_id="flow-invalid-origin")
    assert result.replay_roles == [AGENT_RUNTIME, AGENT_DECISION]
    assert client.count(AGENT_RUNTIME) == client.count(AGENT_DECISION) == 1
    assert result.role_provenance[AGENT_RUNTIME]["status"] == "executed"


def test_runtime_cross_asset_reference_is_rejected_even_when_id_exists(graph_rig):
    with graph_rig["factory"]() as db:
        other = models.LinuxAsset(hostname="unrelated-router", ip_address="192.0.2.21")
        db.add(other)
        db.flush()
        add_runtime(db, other.id, "SE-cross-asset", device_id="flow-router")
        db.commit()
    report = payloads()[AGENT_RUNTIME]
    report["evidence_ids"] = ["SE-cross-asset"]
    report["findings"][0]["evidence_id"] = "SE-cross-asset"
    result, ctx, _ = invoke(graph_rig, Recorder({AGENT_RUNTIME: [report, report]}))
    assert AGENT_RUNTIME in result.degraded_roles
    assert result.runtime is None
    assert "SE-cross-asset" not in result.evidence_snapshot["evidence_registry"]
    assert "evidence_not_in_snapshot:SE-cross-asset" in ctx.agent_logs[AGENT_RUNTIME]["error"]
    assert result.final["policy"]["status"] == "pending_human_review"


def test_cached_foreign_tool_cannot_bypass_role_allowlist_in_compiled_graph(graph_rig):
    secret = "FORBIDDEN_CACHE_SENTINEL"

    def foreign_tool(messages, client):
        args = {"cve_id": CVE}
        key = client.ctx.snapshot_id + "|query_cve_intelligence|" + json.dumps(args, sort_keys=True, ensure_ascii=False)
        client.ctx.tool_cache[key] = {"secret": secret}
        return {"content": "", "tool_calls": [{"id": "foreign-tool", "name": "query_cve_intelligence", "arguments": args}]}

    result, ctx, client = invoke(graph_rig, Recorder({AGENT_ASSET: [foreign_tool, payloads()[AGENT_ASSET]]}))
    call = ctx.agent_logs[AGENT_ASSET]["tool_calls"][0]
    assert call["ok"] is False and call["cached"] is False
    assert secret not in json.dumps(client.calls)
    assert any("未注册到当前智能体" in json.dumps(call["messages"], ensure_ascii=False)
               for call in client.calls if call["role"] == AGENT_ASSET)
    assert result.stage_status["investigate_asset"] == "succeeded"


def test_cache_reuses_only_allowed_tool_within_current_snapshot(graph_rig):
    parent, _, _ = invoke(graph_rig, force=True)
    args = {"host": "flow-router"}
    old_key = parent.evidence_snapshot_id + "|query_device_profile|" + json.dumps(args, sort_keys=True, ensure_ascii=False)
    cache = {old_key: {"secret": "STALE_CACHE_SENTINEL"}}

    def request_profile(messages, client):
        return {"content": "", "tool_calls": [{"id": "profile-read", "name": "query_device_profile", "arguments": args}]}

    client = Recorder({AGENT_ASSET: [request_profile, request_profile, payloads()[AGENT_ASSET]]})
    result, ctx, client = invoke(graph_rig, client, parent=parent.model_dump(), force=True,
        run_id="flow-new-cache-snapshot", tool_cache=cache)
    calls = ctx.agent_logs[AGENT_ASSET]["tool_calls"]
    assert len(calls) == 2 and all(call["ok"] for call in calls)
    assert calls[0]["cached"] is False and calls[1]["cached"] is True
    assert "STALE_CACHE_SENTINEL" not in json.dumps(client.calls)
    assert result.evidence_snapshot_id != parent.evidence_snapshot_id


def test_official_evidence_arriving_mid_run_requires_new_snapshot(graph_rig):
    report = payloads()[AGENT_VULNERABILITY]
    report["findings"][0]["supporting_evidence_ids"] = ["ADV-mid-run"]

    def new_evidence_then_report(messages, client):
        with graph_rig["factory"]() as db:
            raw = '{"cve_id":"CVE-2026-81001","affected":"new evidence after snapshot"}'
            db.add(models.OfficialCveRecord(evidence_id="ADV-mid-run", cve_id=CVE,
                source_url="https://vendor.invalid/new-advisory", raw_json=raw,
                content_sha256=digest(raw), evidence_status="available"))
            db.commit()
        return report

    result, ctx, _ = invoke(graph_rig, Recorder({AGENT_VULNERABILITY: [new_evidence_then_report, report]}))
    assert "ADV-mid-run" not in result.evidence_snapshot["evidence_registry"]
    assert AGENT_VULNERABILITY in result.degraded_roles
    assert result.vulnerability is None
    assert "ADV-mid-run" in ctx.agent_logs[AGENT_VULNERABILITY]["error"]
    assert result.final["policy"]["status"] == "pending_human_review"


def test_message_budget_exhaustion_is_bounded_and_keeps_human_gate(graph_rig):
    asset = payloads()[AGENT_ASSET]
    asset["messages"] = [question()]
    result, _, client = invoke(graph_rig, Recorder({AGENT_ASSET: [asset]}), budgets={"message_rounds": 0})
    request = next(item for item in result.collaboration_messages if item["message_type"] == "QUESTION")
    assert result.collaboration_rounds == 0
    assert request["message_id"] not in result.message_receipts
    assert client.count(AGENT_RUNTIME) == 1
    assert result.final["policy"]["status"] == "pending_human_review"
    assert "collaboration_requires_human_review" in result.final["policy"]["reasons"]


def test_llm_budget_exhaustion_finishes_with_degradation_and_human_review(graph_rig):
    result, ctx, client = invoke(graph_rig, meter=UsageMeter(max_llm_calls=1))
    assert len(client.calls) == 1
    assert ctx.meter.requests == 1 and ctx.meter.exceeded
    assert result.stage_status["finalize"] == "succeeded"
    assert AGENT_DECISION in result.degraded_roles
    assert result.final["policy"]["status"] == "pending_human_review"
    assert result.final["policy"]["final_score"] is None


def test_candidate_write_plan_remains_blocked_and_never_executes(graph_rig, monkeypatch):
    from app.services import agent_harness

    def forbidden(*args, **kwargs):
        raise AssertionError("Graph planning must never execute or authorize device writes")

    for name in ("create_run", "approve", "execute", "install_registered_package"):
        monkeypatch.setattr(agent_harness, name, forbidden)
    decision = payloads()[AGENT_DECISION]
    decision["response_plan"] = {"risk_ref": CVE, "requires_approval": False,
        "actions": [{"action": "update_package", "target": "daemon", "rationale": "Candidate only"}],
        "rollback_plan": ["A registered recovery artifact is required before approval."]}
    result, _, client = invoke(graph_rig, Recorder({AGENT_DECISION: [decision]}))
    assert result.final["policy"]["status"] == "pending_human_review"
    assert result.harness_feedback["execution_authorized"] is False
    assert result.harness_feedback["device_writes"] is False
    assert result.harness_feedback["terminal"] is True
    assert result.final["plan_execution_mode"] == "blocked"
    assert result.final["plan"]["requires_approval"] is True
    assert client.count(AGENT_DECISION) == 1
    with graph_rig["factory"]() as db:
        assert db.query(models.HarnessRun).count() == 0
