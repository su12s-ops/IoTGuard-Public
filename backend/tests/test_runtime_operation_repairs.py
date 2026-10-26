import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app import models
from app.services import ebpf_event_collector as events
from app.services.runtime_telemetry import coverage, reliability_snapshot, sensor_summary


def test_log_tail_reads_only_bounded_bytes_and_keeps_utf8_order(monkeypatch):
    body = b"x" * (6 * 1024 * 1024) + b"\n" + '\n'.join(
        json.dumps({"number": i, "message": "真实事件"}, ensure_ascii=False) for i in range(4)
    ).encode("utf-8") + b"\n"
    class File:
        def open(self, mode):
            assert mode == "rb"
            return io.BytesIO(body)
    monkeypatch.setattr(events, "EVENT_FILE", File())
    rows, meta = events._event_file_tail(2)
    assert [row["number"] for row in rows] == [2, 3]
    assert rows[0]["message"] == "真实事件"
    assert meta["truncated"] and meta["bytes_read"] <= 65536
    assert meta["file_size_bytes"] == len(body)
    rows, meta = events._event_file_tail(500, max_bytes=128)
    assert meta["truncated"] and meta["bytes_read"] <= 128
    assert all(isinstance(row, dict) for row in rows)


def test_sensor_health_is_consistent_for_stale_and_pull_sensors(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="health-device")
        db.add(asset)
        db.flush()
        db.add_all([
            models.RuntimeSensor(sensor_id="old", asset_id=asset.id, source="falco", status="running",
                                 last_heartbeat_at=datetime.now(timezone.utc) - timedelta(hours=1)),
            models.RuntimeSensor(sensor_id="pull", asset_id=asset.id, source="logread", status="stopped",
                                 capabilities_json='{"mode":"pull"}', last_heartbeat_at=datetime.now(timezone.utc)),
        ])
        db.commit()
        expected = {"old": "stale", "pull": "reporting"}
        assert {x["sensor_id"]: x["status"] for x in sensor_summary(db)["sensors"]} == expected
        assert {x["sensor_id"]: x["status"] for x in coverage(db, asset.id)["sensors"]} == expected
        reliable = reliability_snapshot(db)["sensors"]
        assert {x["sensor_id"]: x["status"] for x in reliable} == expected
        assert reliable[0]["reported_status"] == "running"


def test_historical_events_never_advertise_current_health(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        db.add(models.LinuxAsset(hostname="old-device"))
        db.commit()
        events.append_events([{"hostname": "old-device", "source": "falco", "timestamp": "2020-01-01T00:00:00Z",
                               "event_type": "execve", "process_name": "daemon"}], db=db)
        status = events.runtime_status(db, "http://localhost/api")
        assert not status["runtime_evidence"]["fresh"]
        assert not any("is healthy" in recommendation for recommendation in status["recommendations"])
        assert status["file_event_count_exact"] and status["file_event_count"] == 1


def test_existing_database_gets_idempotent_covering_time_indexes(session_factory, monkeypatch):
    from app import database
    with session_factory() as db:
        engine = db.get_bind()
    monkeypatch.setattr(database, "engine", engine)
    with engine.begin() as conn:
        for name in ("ix_runtime_event_occurred_at", "ix_runtime_event_asset_time", "ix_runtime_event_sensor_time"):
            conn.execute(text(f"DROP INDEX {name}"))
    assert len(database._ensure_runtime_time_indexes()) == 3
    assert database._ensure_runtime_time_indexes() == []
    with engine.connect() as conn:
        plan = conn.execute(text("EXPLAIN QUERY PLAN SELECT max(occurred_at) FROM runtime_event")).all()
        assert "ix_runtime_event_occurred_at" in str(plan)


def test_model_queue_does_not_consume_http_allowance_but_keeps_role_deadline(session_factory, monkeypatch):
    from app.services.unified import task_runtime
    clock = [task_runtime.time.monotonic()]
    received = []
    class Slot:
        def acquire(self, timeout):
            assert timeout == pytest.approx(10)
            clock[0] += 5
            return True
        def release(self):
            pass
    class Client:
        def complete_with_timeout(self, messages, tools=None, *, timeout_s):
            received.append(timeout_s)
            return {"content": "{}", "usage": {"total_tokens": 3}}
    batch = task_runtime.BatchRuntime("queue-test", session_factory, Client, request_seconds=2)
    monkeypatch.setattr(task_runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(task_runtime, "_slots", Slot())
    batch.client("one").complete_with_timeout([], timeout_s=10)
    assert received == [2]
    assert batch.requests == 1 and batch.consumed == 3 and batch.reserved == 0


@pytest.mark.parametrize("status", ["partial", "interrupted", "failed"])
def test_terminal_workflow_does_not_show_running_stage(session_factory, status):
    from app.services import console_workflow
    steps = console_workflow.steps()
    steps[0]["status"] = "running"
    with session_factory() as db:
        row = models.ConsoleWorkflow(id="terminal", status=status, owner=console_workflow.OWNER,
                                     steps_json=json.dumps(steps))
        db.add(row)
        db.commit()
        result = console_workflow.payload(db, row)
        assert result["steps"][0]["status"] == status
        assert not any(step["status"] == "running" for step in result["steps"])


def test_terminal_timing_separates_wall_queue_model_and_tools(session_factory):
    from types import SimpleNamespace
    from app.services.unified.read_model import project_activity
    start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with session_factory() as db:
        for i, (kind, seconds, detail) in enumerate([
            ("model_waiting", 0, {"request_id": "one"}),
            ("model_started", 5, {"request_id": "one"}),
            ("model_finished", 15, {"request_id": "one"}),
            ("tool_started", 16, {"tool": "query"}),
            ("tool_finished", 18, {"tool": "query"}),
        ]):
            db.add(models.TraceEvent(trace_id="timing", seq=i, actor="asset_investigator", event_type=kind,
                                     payload_json=json.dumps(detail), created_at=start + timedelta(seconds=seconds)))
        db.commit()
        row = SimpleNamespace(trace_id="timing", status="completed", created_at=start,
                              completed_at=start + timedelta(seconds=30))
        result = project_activity(db, row, {"asset_investigator": {"status": "succeeded", "latency_ms": 30000}})
        assert result["totals"]["wall_seconds"] == 30
        assert result["totals"]["queue_seconds"] == 5
        assert result["totals"]["model_seconds"] == 10
        assert result["totals"]["tool_seconds"] == 2
