"""Isolated GET lifecycle projection: no model, device, production DB or writes."""
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import event as sql_event

from app import models
from app.routers.unified import get_run

T0 = datetime(2026, 10, 23, 1, 55)
ASSET = "asset_investigator"
RUNTIME = "runtime_analyst"
VULN = "vulnerability_analyst"


def seed(db, **kwargs):
    values = dict(run_id="UA-isolated", trace_id="trace-own", status="running",
                  updated_at=T0, agents_json=json.dumps({ASSET: {"status": "succeeded", "output": {"ok": True}}}),
                  usage_json=json.dumps({"llm_calls": 4, "total_tokens": 120}),
                  state_json=json.dumps({"stage_status": {"investigate_asset": "succeeded"},
                                         "runtime": None, "final": {}}))
    values.update(kwargs)
    row = models.UnifiedAnalysisRun(**values)
    db.add(row)
    db.commit()
    return row


def trace(db, kind, role, seq, seconds, trace_id="trace-own", **detail):
    db.add(models.TraceEvent(trace_id=trace_id, event_type=kind, actor=role,
                            seq=seq, created_at=T0 + timedelta(seconds=seconds),
                            payload_json=json.dumps(detail), status={
                                "agent_started": "running", "agent_finished": "succeeded",
                                "agent_failed": "failed"}.get(kind, "failed")))
    db.commit()


def test_get_shows_real_parallel_failure_and_running_without_state_or_usage_write(session_factory):
    with session_factory() as db:
        row = seed(db)
        trace(db, "agent_started", VULN, 1, 1)
        trace(db, "agent_started", RUNTIME, 2, 2)
        trace(db, "agent_failed", RUNTIME, 3, 3, error="token budget exceeded", total_tokens=999999)
        trace(db, "agent_finished", VULN, 4, 4, trace_id="trace-other")
        trace(db, "agent_failed", "unknown_role", 5, 5)
        trace(db, "tool_failed", ASSET, 6, 6)
        before = (row.agents_json, row.state_json, row.usage_json, row.updated_at)
        writes = []

        def inspect(conn, cursor, statement, parameters, context, executemany):
            if not statement.lstrip().upper().startswith("SELECT"):
                writes.append(statement)

        sql_event.listen(db.bind, "before_cursor_execute", inspect)
        try:
            result = get_run(row.run_id, db)
        finally:
            sql_event.remove(db.bind, "before_cursor_execute", inspect)
        assert not writes
        assert result["agents"][RUNTIME]["status"] == "failed"
        assert result["agents"][RUNTIME]["error"] == "token budget exceeded"
        assert result["agents"][VULN]["status"] == "running"
        assert result["agents"][ASSET]["status"] == "succeeded"
        assert set(result["agents"]) == {ASSET, VULN, RUNTIME}
        assert result["runtime"] is None and result["final"] == {}
        assert result["stage_status"] == {"investigate_asset": "succeeded"}
        assert result["degraded_roles"] == []
        assert result["usage"] == {"llm_calls": 4, "total_tokens": 120}
        assert result["snapshot"]["lagging"] is True
        assert result["snapshot"]["usage_may_lag"] is True
        assert not db.dirty
        db.expire(row)
        assert before == (row.agents_json, row.state_json, row.usage_json, row.updated_at)


def test_http_detail_serializes_live_observations(client, session_factory):
    with session_factory() as db:
        seed(db)
        trace(db, "agent_failed", RUNTIME, 1, 1, error="token budget")
    response = client.get("/api/unified/runs/UA-isolated")
    assert response.status_code == 200
    result = response.json()
    assert result["agents"][RUNTIME]["status"] == "failed"
    assert result["agents"][RUNTIME]["observed_at"].startswith("2026-10-23")
    assert result["snapshot"]["usage_source"] == "persisted_usage_meter"


def test_finished_trace_is_observation_not_succeeded_output(session_factory):
    with session_factory() as db:
        row = seed(db)
        trace(db, "agent_finished", RUNTIME, 1, 1, output_summary={"approved": True})
        result = get_run(row.run_id, db)
        observed = result["agents"][RUNTIME]
        assert observed["status"] == "finished"
        assert observed["trace_status"] == "succeeded"
        assert observed["snapshot_pending"] is True
        assert "output" not in observed
        assert result["runtime"] is None and result["decision"] == {} and result["plan"] == {}


@pytest.mark.parametrize("status", ["succeeded", "degraded"])
def test_newer_or_equal_real_snapshot_wins_over_old_trace(session_factory, status):
    with session_factory() as db:
        real = {"status": status, "output": {"real": True}, "llm_calls": 7}
        row = seed(db, updated_at=T0 + timedelta(seconds=3), agents_json=json.dumps({RUNTIME: real}))
        trace(db, "agent_failed", RUNTIME, 1, 1)
        trace(db, "agent_started", RUNTIME, 2, 3)
        result = get_run(row.run_id, db)
        assert result["agents"][RUNTIME] == real
        assert result["snapshot"]["lagging"] is False


def test_latest_reexecution_replaces_old_role_summary_without_reusing_output(session_factory):
    with session_factory() as db:
        row = seed(db, agents_json=json.dumps({RUNTIME: {"status": "succeeded", "output": {"old": True}}}))
        trace(db, "agent_failed", RUNTIME, 1, 1)
        trace(db, "agent_started", RUNTIME, 2, 2)
        result = get_run(row.run_id, db)
        assert result["agents"][RUNTIME]["status"] == "running"
        assert "output" not in result["agents"][RUNTIME]


def test_running_role_start_before_other_boundary_is_not_hidden(session_factory):
    with session_factory() as db:
        row = seed(db, updated_at=T0 + timedelta(seconds=3))
        trace(db, "agent_started", VULN, 1, 1)
        assert get_run(row.run_id, db)["agents"][VULN]["status"] == "running"


@pytest.mark.parametrize("status", ["completed", "failed"])
def test_terminal_run_keeps_authoritative_snapshot(session_factory, status):
    with session_factory() as db:
        row = seed(db, status=status)
        trace(db, "agent_started", RUNTIME, 1, 1)
        result = get_run(row.run_id, db)
        assert RUNTIME not in result["agents"]
        assert result["snapshot"]["usage_may_lag"] is False


def test_no_trace_does_not_borrow_unrelated_events(session_factory):
    with session_factory() as db:
        row = seed(db, trace_id="")
        trace(db, "agent_failed", RUNTIME, 1, 1)
        result = get_run(row.run_id, db)
        assert RUNTIME not in result["agents"]
        assert result["snapshot"]["live_roles"] == []
