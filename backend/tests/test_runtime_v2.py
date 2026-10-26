import json
import ssl
from copy import deepcopy

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec, AgentTool
from app.services.unified.agent_base import UnifiedToolLoopAgent
from app.services.unified.prompt_views import inventory_provenance, asset_quality_dependencies
from app.services.intel_transport import verified_https_handler


def test_known_mixed_evidence_gets_conservative_status_without_model_retry():
    from app.services.unified.prompt_views import conservative_runtime_status
    from app.services.unified.schemas import RuntimeAnalysisReport, AGENT_RUNTIME
    raw = {"behavior_level": "NORMAL", "runtime_status": "verified", "evidence_freshness": "mixed",
           "evidence_ids": ["SE-fresh", "SE-old"], "findings": [
               {"evidence_id": "SE-fresh", "aspect": "process", "description": "observed process", "relation": "unrelated"}]}
    snapshot = {"evidence_registry": {"SE-fresh": {"kind": "runtime", "fresh": True}, "SE-old": {"kind": "runtime", "fresh": False}}}
    calls = []
    class Client:
        def complete(self, messages, tools=None):
            calls.append(1)
            return {"content": json.dumps(raw)}
    agent = UnifiedToolLoopAgent(AgentSpec(AGENT_RUNTIME, "runtime", RuntimeAnalysisReport, llm_retries=0), Client(),
        output_normalizer=lambda report: conservative_runtime_status(report, snapshot))
    result = agent.run(None, "registered evidence", deadline_s=3)
    assert result.status == "succeeded" and result.output["runtime_status"] == "stale_verified"
    assert len(calls) == 1 and agent.normalized_reports[0]["original"] == raw
    assert raw["runtime_status"] == "verified"
    assert conservative_runtime_status({**raw, "behavior_level": "ACTIVE"}, snapshot)["runtime_status"] == "verified"
    assert conservative_runtime_status({**raw, "evidence_ids": ["invented"]}, snapshot)["runtime_status"] == "verified"


def test_prefetched_runtime_contains_only_unchanged_registered_rows(session_factory):
    from app import models
    from app.services.unified.collaboration import fingerprint
    from app.services.unified.prompt_views import runtime_observations
    with session_factory() as db:
        rows = [models.SecurityEvidence(evidence_id="SE-" + str(i), evidence_hash="hash-" + str(i), process="daemon", timestamp="2026-10-25T00:00:00Z") for i in range(3)]
        db.add_all(rows)
        db.commit()
        registry = {}
        for row in rows[:2]:
            raw = {c.name: getattr(row, c.name) for c in row.__table__.columns
                   if c.name not in {"id", "created_at", "evidence_id", "evidence_hash"}}
            registry[row.evidence_id] = {"kind": "runtime", "fresh": True,
                "observation_sha256": fingerprint(raw), "observed_at": row.timestamp}
        rows[1].process = "changed-after-snapshot"
        db.commit()
        result = runtime_observations(db, {"evidence_registry": registry})
        assert [event["evidence_id"] for event in result["events"]] == ["SE-0"]
        assert result["sampled"] and result["invalid_or_missing"] == 1
        assert result["registered_total"] == 2


def test_runtime_tools_do_not_return_new_arrivals_or_other_assets(session_factory):
    from app import models
    from app.services.unified.prompt_views import bind_runtime_snapshot
    from app.services.agent_tools import tool_query_process_evidence
    with session_factory() as db:
        db.add(models.LinuxAsset(hostname="snapshot-device"))
        db.add_all([models.SecurityEvidence(evidence_id=key, evidence_hash=key,
                   device_id="snapshot-device", evidence_type="process", process="daemon")
                   for key in ("SE-original", "SE-new-arrival", "SE-other")])
        db.commit()
    with session_factory() as db:
        bind_runtime_snapshot(db, {"evidence_registry": {"SE-original": {"kind": "runtime"}}})
        result = tool_query_process_evidence(db, "snapshot-device")
        assert [event["evidence_id"] for event in result["events"]] == ["SE-original"]
    with session_factory() as db:
        assert db.query(models.SecurityEvidence).count() == 3


def test_tool_limit_still_produces_final_report_and_never_runs_tools_after_limit():
    class Report(BaseModel):
        answer: int
    calls = []
    class Client:
        def complete(self, messages, tools=None):
            calls.append((deepcopy(messages), tools))
            if tools:
                return {"tool_calls": [{"id": str(len(calls)), "name": "query", "arguments": {}}]}
            assert sum(message.get("role") == "tool" for message in messages) == 2
            return {"content": '{"answer":42}'}
    count = []
    tool = AgentTool("query", "read", {}, lambda db: count.append(1) or {"fact": 42})
    spec = AgentSpec("role", "role", Report, tools=[tool], max_tool_rounds=2,
                     llm_retries=0, finalize_on_tool_limit=True)
    result = UnifiedToolLoopAgent(spec, Client()).run(None, "facts", deadline_s=3)
    assert result.status == "succeeded" and result.output == {"answer": 42}
    assert len(calls) == 3 and calls[-1][1] is None and len(count) == 2


def test_large_provenance_is_bounded_but_original_and_hash_are_preserved():
    raw = {"inventory_evidence_id": "INV-real", "sha256": "original-receipt-hash",
           "package_sources": ["source " + str(i) + "=" + "x" * 100 for i in range(1800)]}
    saved = deepcopy(raw)
    view = inventory_provenance(raw)
    assert len(json.dumps(view)) < 4000
    assert view["inventory_evidence_id"] == "INV-real" and view["sha256"] == raw["sha256"]
    assert view["package_sources"]["total_items"] == 1800 and view["package_sources"]["truncated"]
    assert raw == saved


def test_traffic_receipts_do_not_invalidate_asset_but_freshness_and_loss_do():
    old = {"coverage": {"status": "running", "sensors": [{"sensor_id": "s", "status": "running",
        "source": "falco", "dropped_events": None, "self_reported_metrics": {"received": 100}}]},
        "freshness": {"process": {"freshness": "fresh", "latest_timestamp": "one", "count_recent": 100}}}
    new = deepcopy(old)
    new["coverage"]["sensors"][0]["self_reported_metrics"]["received"] = 1000
    new["freshness"]["process"]["latest_timestamp"] = "two"
    assert asset_quality_dependencies(old) == asset_quality_dependencies(new)
    new["freshness"]["process"]["freshness"] = "stale"
    assert asset_quality_dependencies(old) != asset_quality_dependencies(new)
    new = deepcopy(old)
    new["coverage"]["sensors"][0]["dropped_events"] = 2
    assert asset_quality_dependencies(old) != asset_quality_dependencies(new)


def test_reliability_snapshot_exposes_logread_window_limits_and_unknown_ring_loss(session_factory):
    from app import models
    from app.services.runtime_telemetry import reliability_snapshot
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="log-window-host", distribution="openwrt")
        db.add(asset)
        db.flush()
        sensor = models.RuntimeSensor(asset_id=asset.id, sensor_id="logread-window",
            source="logread", status="stopped", dropped_events=None,
            capabilities_json=json.dumps({"mode": "pull", "last_window": {
                "lines_total": 100, "events_built": 92, "year_missing_lines": 3,
                "unparseable_lines": 5, "stored_new": 80, "duplicates": 12,
                "truncated": False, "window_first": "a", "window_last": "b",
                "boot_id": "boot-1"}}))
        db.add(sensor)
        db.commit()
        row = reliability_snapshot(db)["sensors"][0]
        assert row["dropped_events"] == "unavailable"
        assert row["collection_window"] == {
            "status": "bounded_window", "lines_total": 100, "events_built": 92,
            "skipped_lines": 8, "stored_new": 80, "duplicates": 12,
            "ring_loss": "unavailable", "window_first": "a", "window_last": "b",
            "boot_id": "boot-1"}


def test_reliability_snapshot_marks_capped_logread_window(session_factory):
    from app import models
    from app.services.runtime_telemetry import reliability_snapshot
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="log-window-capped", distribution="openwrt")
        db.add(asset)
        db.flush()
        db.add(models.RuntimeSensor(asset_id=asset.id, sensor_id="logread-capped",
            source="logread", status="stopped", capabilities_json=json.dumps({
                "last_window": {"lines_total": 20000, "events_built": 19999,
                                "year_missing_lines": 0, "unparseable_lines": 0,
                                "truncated": True}})))
        db.commit()
        row = reliability_snapshot(db)["sensors"][0]
        assert row["collection_window"]["status"] == "truncated"
        assert row["collection_window"]["ring_loss"] == "unavailable"


def test_tls_compatibility_keeps_certificate_and_hostname_verification(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_INTEL_TLS_MAX_VERSION", "1.2")
    handler = verified_https_handler()
    assert handler._context.maximum_version == ssl.TLSVersion.TLSv1_2
    assert handler._context.verify_mode == ssl.CERT_REQUIRED and handler._context.check_hostname


def test_reliability_counts_same_sensor_name_separately_per_asset(session_factory):
    from app import models
    from app.services.runtime_telemetry import reliability_snapshot
    with session_factory() as db:
        assets = [models.LinuxAsset(hostname=name) for name in ("one", "two")]
        db.add_all(assets)
        db.flush()
        for index, asset in enumerate(assets):
            db.add(models.RuntimeSensor(asset_id=asset.id, sensor_id="falco", source="falco"))
            for event in range(index + 1):
                db.add(models.RuntimeEvent(asset_id=asset.id, sensor_id="falco",
                    event_fingerprint=f"same-sensor-{index}-{event}", occurred_at=f"2026-10-2{index}T12:00:00Z"))
        db.commit()
        rows = reliability_snapshot(db)["sensors"]
        assert [row["server_observed"]["stored_events"] for row in rows] == [1, 2]
        assert rows[0]["server_observed"]["last_event_at"] != rows[1]["server_observed"]["last_event_at"]
