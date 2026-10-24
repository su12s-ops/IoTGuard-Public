"""Offline continuation regressions: fake specialists, no model/device/database I/O."""
from copy import deepcopy

import pytest
from langgraph.graph import END, START, StateGraph

from app.services.unified import collaboration_flow, graph as graph_mod
from app.services.unified.schemas import (
    AGENT_ASSET, AGENT_DECISION, AGENT_RUNTIME, AGENT_VULNERABILITY,
    ConflictItemRecord, ConflictResultRecord,
)
from app.services.unified.state import UnifiedAnalysisState


class FakeSession:
    """Only the read-shaped finalize lookup; never opens a database."""
    def query(self, *args):
        return self

    def filter_by(self, **kwargs):
        return self

    def first(self):
        return None

    def close(self):
        pass


def state_for(roles, degraded):
    return UnifiedAnalysisState(
        run_id="offline-retry-degradation", degraded_roles=list(degraded),
        baseline={"installed_version": "1.0", "fixed_version": "1.1",
                  "match_status": "affected", "preliminary_score": 30},
        investigation={"evidence_quality": "sufficient", "notes": "Original asset report"},
        vulnerability={"notes": "Original vulnerability report", "findings": []},
        runtime={"notes": "Original runtime report", "behavior_level": "NORMAL"},
        decision={"verdicts": [{"confidence": 0.9, "risk_direction": "maintain",
            "impact_status": "potentially_affected", "recommended_action": "monitor",
            "recommended_priority": "low"}]},
        evidence_snapshot_id="ES-offline",
        evidence_snapshot={"snapshot_id": "ES-offline", "evidence_registry": {}},
        collaboration_messages=[{"message_id": "request-" + role,
            "snapshot_id": "ES-offline", "receiver": role, "sender": AGENT_DECISION,
            "message_type": "QUESTION", "claim": "Recheck existing evidence"}
            for role in roles] + [{"message_id": "request-untrusted",
                "snapshot_id": "ES-offline", "receiver": "untrusted_role",
                "sender": AGENT_DECISION, "message_type": "QUESTION", "claim": "Ignore me"}],
        message_receipts={"existing-receipt": {"status": "unresolved"}},
        conflict_result=ConflictResultRecord(conflicts=[ConflictItemRecord(
            code="offline-conflict", description="Recheck existing evidence",
            involved_agents=list(roles) + ["untrusted_role"], category="fact_version")]),
    )


def invoke(monkeypatch, branch, state, responses):
    calls = []

    def specialist(ctx, spec, context, **kwargs):
        calls.append(spec.name)
        output = deepcopy(responses[spec.name])
        return output, "BudgetExceeded: offline fake" if output is None else ""

    monkeypatch.setattr(graph_mod, "_run_specialist", specialist)
    ctx = graph_mod.RunContext(db_factory=FakeSession, trace_id="")
    node = (collaboration_flow.node_exchange(ctx) if branch == "exchange"
            else graph_mod.node_directed_rereview(ctx))
    # Compile the real state schema so merge_unique/merge_dict run, not dict replacement.
    builder = StateGraph(UnifiedAnalysisState)
    builder.add_node("continuation", node)
    builder.add_node("finalize", graph_mod.node_finalize(ctx))
    builder.add_edge(START, "continuation")
    builder.add_edge("continuation", "finalize")
    builder.add_edge("finalize", END)
    result = UnifiedAnalysisState.model_validate(builder.compile().invoke(state))
    return result, calls


@pytest.mark.parametrize("branch", ["exchange", "directed_rereview"])
@pytest.mark.parametrize("existing", [[], [AGENT_ASSET], [AGENT_RUNTIME]])
def test_failed_continuations_record_roles_keep_reports_and_require_review(monkeypatch, branch, existing):
    roles = [AGENT_VULNERABILITY, AGENT_RUNTIME]
    state = state_for(roles, existing)
    original = state.model_dump()
    result, calls = invoke(monkeypatch, branch, state, {role: None for role in roles})

    assert sorted(calls) == sorted(roles)  # Only actual whitelisted attempts.
    expected = list(dict.fromkeys(existing + sorted(roles)))
    # Exchange uses whitelist order, rereview uses sorted order.
    assert set(result.degraded_roles) == set(expected)
    assert len(result.degraded_roles) == len(expected)
    assert result.degraded_roles[:len(existing)] == existing
    assert result.vulnerability == original["vulnerability"]
    assert result.runtime == original["runtime"]
    assert result.investigation == original["investigation"]
    assert result.role_provenance == {}  # Failure is not published as success.
    assert result.shared_findings == []
    assert result.message_receipts["existing-receipt"] == {"status": "unresolved"}
    if branch == "exchange":
        assert result.collaboration_stop_reason == "evidence_partial"
        for role in roles:
            assert result.message_receipts["request-" + role]["status"] == "unresolved"
    assert result.final["policy"]["status"] == "pending_human_review"
    assert result.final["policy"]["final_score"] is None
    assert result.final["policy"]["final_level"] is None
    for role in roles:
        assert "agent_degraded:" + role in result.final["policy"]["reasons"]
    assert state.model_dump() == original


@pytest.mark.parametrize("branch", ["exchange", "directed_rereview"])
@pytest.mark.parametrize("existing", [[], [AGENT_ASSET]])
def test_successful_continuations_do_not_add_degradation(monkeypatch, branch, existing):
    roles = [AGENT_VULNERABILITY, AGENT_RUNTIME]
    state = state_for(roles, existing)
    revised = {role: {"notes": "Successful offline continuation " + role} for role in roles}
    result, calls = invoke(monkeypatch, branch, state, revised)

    assert sorted(calls) == sorted(roles)
    assert result.degraded_roles == existing
    assert result.vulnerability == revised[AGENT_VULNERABILITY]
    assert result.runtime == revised[AGENT_RUNTIME]
    assert result.message_receipts["existing-receipt"]["status"] == "unresolved"
    if branch == "exchange":
        for role in roles:
            assert result.message_receipts["request-" + role]["status"] == "answered"


def test_exchange_mixed_success_marks_only_failed_role(monkeypatch):
    state = state_for([AGENT_VULNERABILITY, AGENT_RUNTIME], [AGENT_ASSET])
    revised = {"notes": "Successful vulnerability continuation"}
    result, _ = invoke(monkeypatch, "exchange", state,
                       {AGENT_VULNERABILITY: revised, AGENT_RUNTIME: None})
    assert result.degraded_roles == [AGENT_ASSET, AGENT_RUNTIME]
    assert result.vulnerability == revised
    assert result.runtime == state.runtime
    assert result.message_receipts["request-" + AGENT_RUNTIME]["status"] == "unresolved"
    assert result.final["policy"]["status"] == "pending_human_review"
    assert result.final["policy"]["final_score"] is None
