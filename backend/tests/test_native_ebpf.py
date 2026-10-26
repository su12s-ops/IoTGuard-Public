import json
from datetime import datetime, timedelta, timezone
import pytest
from app import models
from app.services import ebpf_event_collector as events
from app.services import runtime_outbox as outbox
from app.services.security_evidence import serialize_evidence, event_to_evidence


def payload(**changes):
    return {"source": "c_ebpf", "schema_version": 1, "timestamp": "2026-10-20T00:00:00Z",
            "hostname": "native-test", "boot_id": "boot", "process_id": 12, "process_name": "cat",
            "event_type": "openat", "file_path": "/etc/shadow", "operation": "open", "result": "failure",
            "retval": -13, "errno": 13, "raw": {"flags": 2}, **changes}


def test_live_ingestion_and_analysis_ledger_can_write_concurrently(session_factory, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import text
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        db.execute(text("PRAGMA journal_mode=WAL"))
        db.add(models.AnalysisBudget(batch_id="concurrent-review"))
        db.commit()

    def ingest():
        for index in range(12):
            with session_factory() as db:
                events.append_events([payload(process_id=100 + index)], db=db)

    def account():
        for index in range(40):
            with session_factory() as db:
                row = db.get(models.AnalysisBudget, "concurrent-review")
                row.requests = index + 1
                db.commit()

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(ingest), workers.submit(account)]
        for future in futures:
            future.result(timeout=15)
    with session_factory() as db:
        assert db.query(models.RuntimeEvent).count() == 12
        assert db.query(models.RuntimeEvidenceJob).count() == 12
        assert db.get(models.AnalysisBudget, "concurrent-review").requests == 40


def test_native_ack_is_durable_and_evidence_recovers_after_restart(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        records = events.append_events([payload()], db=db)
        assert records[0]["evidence_state"] == "pending"
        assert db.query(models.RuntimeEvent).count() == db.query(models.RuntimeEvidenceJob).count() == 1
        assert db.query(models.SecurityEvidence).count() == 0
    assert outbox.drain(session_factory) == 1
    with session_factory() as db:
        row = db.query(models.SecurityEvidence).one()
        exposed = serialize_evidence(row)
        assert exposed["operation"] == "open"
        assert exposed["result"] == "failure" and exposed["errno"] == 13
        assert "failure" in exposed["description"]
        assert outbox.snapshot(db)["pending"] == 0
        assert events.append_events([payload()], db=db)[0]["duplicate"]
    outbox.drain(session_factory)
    with session_factory() as db:
        assert db.query(models.SecurityEvidence).count() == 1


def test_worker_failure_keeps_durable_job_then_retries(session_factory, tmp_path, monkeypatch):
    from app.services import security_evidence
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        events.append_events([payload()], db=db)
    original = security_evidence.persist_evidence
    def fail(*args, **kwargs):
        raise RuntimeError("injected worker outage")
    monkeypatch.setattr(security_evidence, "persist_evidence", fail)
    assert outbox.drain(session_factory) == 0
    with session_factory() as db:
        job = db.query(models.RuntimeEvidenceJob).one()
        assert job.attempts == 1
        job.next_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(security_evidence, "persist_evidence", original)
    assert outbox.drain(session_factory) == 1


def test_event_and_job_transaction_roll_back_together(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    def fail(*args):
        raise RuntimeError("outbox storage unavailable")
    monkeypatch.setattr(outbox, "enqueue", fail)
    with session_factory() as db:
        with pytest.raises(RuntimeError):
            events.append_events([payload()], db=db)
        db.rollback()
        assert db.query(models.RuntimeEvent).count() == 0


def test_legacy_open_not_inferred_as_write():
    event = events.normalize_event({"event_type": "openat", "file_path": "/etc/shadow", "rule": "open_write"})
    assert event_to_evidence(event)["operation"] == "open"


def test_native_source_and_batch_duplicates(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    assert events._observation_mode("c_ebpf") == "ebpf"
    with session_factory() as db:
        events.append_events([payload(), payload()], db=db)
        assert db.query(models.RuntimeEvidenceJob).count() == 1
    assert outbox.drain(session_factory) == 1


def test_fastapi_native_ack_outcomes_and_backlog(client, session_factory, control_headers):
    reply = client.post("/api/runtime/ebpf/events/batch", headers=control_headers, json={"events": [payload()]})
    assert reply.status_code == 200
    assert reply.json()["ack"] is True and reply.json()["evidence_pending"] == 1
    assert client.get("/api/runtime/ebpf/reliability").json()["evidence_processing"]["pending"] == 1
    assert outbox.drain(session_factory) == 1
    record = client.get("/api/runtime/evidence/file").json()["events"][0]
    assert record["result"] == "failure" and record["errno"] == 13
    replay = client.post("/api/runtime/ebpf/events/batch", headers=control_headers, json={"events": [payload()]}).json()
    assert replay["duplicates"] == 1
    outbox.drain(session_factory)
    assert len(client.get("/api/runtime/evidence/file").json()["events"]) == 1


def test_backlog_limit_rejects_without_partial_commit(client, session_factory, control_headers, monkeypatch):
    monkeypatch.setenv("IOTGUARD_EVIDENCE_MAX_PENDING", "1")
    response = client.post("/api/runtime/ebpf/events/batch", headers=control_headers,
                           json={"events": [payload(), payload(timestamp="2026-10-20T00:00:01Z")]})
    assert response.status_code == 503
    with session_factory() as db:
        assert db.query(models.RuntimeEvent).count() == 0


def test_native_tree_keeps_exec_generations_and_excludes_failed_exec(session_factory, tmp_path, monkeypatch):
    from app.services.security_evidence import build_process_tree
    monkeypatch.setattr(events, "EVENT_FILE", tmp_path / "events.jsonl")
    with session_factory() as db:
        for n, result in enumerate(["success", "success", "failure"]):
            events.append_events([payload(event_type="execve", file_path="", operation="exec", result=result,
                process_exec_id=f"generation-{n}", timestamp=f"2026-10-20T00:00:0{n}Z")], db=db)
    outbox.drain(session_factory)
    with session_factory() as db:
        tree = build_process_tree(db)["devices"]["native-test"]
        assert tree["process_count"] == 2
        assert {n["process_exec_id"] for n in tree["roots"]} == {"generation-0", "generation-1"}


@pytest.mark.parametrize("reply", [
    {"ack": True, "accepted": 0, "duplicates": 0, "rejected": []},
    {"ack": True, "accepted": 0, "duplicates": 0, "rejected": [{"index": 0}]},
    {"ack": True, "accepted": True, "duplicates": 0, "rejected": []},
])
def test_forwarder_requires_complete_ack(monkeypatch, reply):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("native_ack_forwarder", Path(__file__).resolve().parents[2] / "collector/ebpf_event_collector.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "post_json", lambda *args: reply)
    with pytest.raises(ValueError):
        module.post_batch("http://127.0.0.1", [payload()], "")
