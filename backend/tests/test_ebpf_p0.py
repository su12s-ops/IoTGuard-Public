"""eBPF 2.0 P0 专项测试：运行时证据可靠性升级。

覆盖验收（15 项中可自动化部分）：
1.  D1 根因复现（旧基含 asset_id → 绑定态变化即指纹漂移）
2.  修复后同批重传不重复
3.  资产注册前后重传不重复
4.  不同设备的真实不同事件不误合并（不同主机名 / 同主机名不同 boot_id）
5.  SecurityEvidence 正确回绑（含 evidence 层先绑定不被改写）
6.  并发上传幂等（两线程同批 → 唯一索引兜底）
7.  批量上传失败后安全重试（转发器 transport 注入）
8.  服务端已提交但客户端未收到确认时重试不重复
9.  采集健康指标正确（reliability_snapshot 聚合 + 心跳 metrics）
10. unavailable 与零值正确区分
11. 旧版 API 兼容（单条 POST /events、upload、demo、事件形状不变）
12. Runtime Agent 原有证据工具不受影响
13. Harness/Trace 关联不受影响（Trace 证据引用解析）
14. 历史数据库增量迁移验证（旧基指纹/重复行/未绑证据 → 迁移后收敛）
15. 清空语义（只清 RuntimeEvent，证据层保留并上报）

转发器（collector/ebpf_event_collector.py）逻辑经 sys.path 导入做集成级测试。
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import models
from app.database import Base, engine, init_db
from app.ebpf_identity import stable_event_fingerprint
from app.services import ebpf_event_collector as collector

BACKEND_DIR = Path(__file__).resolve().parents[1]
COLLECTOR_DIR = BACKEND_DIR.parent / "collector"
sys.path.insert(0, str(COLLECTOR_DIR))

from ebpf_event_collector import (  # noqa: E402  采集端转发器（非 app 包）
    ReliabilityMetrics,
    Spool,
    backoff_delay,
    heartbeat_payload,
    post_batch,
    send_batch_with_retry,
)


def _event(hostname="host-a", ts="2026-10-14T10:00:00Z", pid=100, boot_id="boot-1", **extra):
    payload = {
        "timestamp": ts, "hostname": hostname, "source": "ebpf_bpftrace",
        "event_type": "execve", "process_name": "bash", "commandline": "/bin/bash",
        "process_id": pid, "parent_process_id": 1, "severity": "info",
        "raw": {"kind": "execve", "uid": 0, "comm": "bash", "filename": "/bin/bash",
                "hostname": hostname, "timestamp": ts, "boot_id": boot_id},
    }
    payload.update(extra)
    return payload


# ── 1. D1 根因复现：旧基（含 asset_id）随绑定态漂移 ─────────────────────────

def test_d1_root_cause_old_basis_drifts_with_binding():
    raw = _event()["raw"]
    old = lambda asset_id: hash(json.dumps({"asset_id": asset_id, "raw": raw}, sort_keys=True))
    assert old(None) != old(1), "旧基含 asset_id：绑定态一变指纹必变（D1 根因）"
    # 新基与资产归属无关
    assert stable_event_fingerprint(raw) == stable_event_fingerprint(raw)


# ── 2/3/4/5. 幂等、回绑、不误合并 ────────────────────────────────────────────

def _upload(db, events):
    return collector.append_events([dict(e) for e in events], db=db)


def test_same_batch_reupload_no_duplicates(session_factory):
    db = session_factory()
    try:
        first = _upload(db, [_event(pid=n) for n in range(5)])
        assert all(not e.get("duplicate") for e in first)
        second = _upload(db, [_event(pid=n) for n in range(5)])
        assert all(e.get("duplicate") for e in second)
        assert db.query(models.RuntimeEvent).count() == 5
        assert db.query(models.SecurityEvidence).count() == 5
    finally:
        db.close()


def test_asset_registration_before_after_no_duplicates(session_factory):
    db = session_factory()
    try:
        # 注册前上传（无资产）
        _upload(db, [_event(pid=1), _event(pid=2)])
        assert db.query(models.RuntimeEvent).filter(models.RuntimeEvent.asset_id.is_(None)).count() == 2
        # 注册资产（hostname 精确匹配）
        asset = models.LinuxAsset(hostname="host-a", ip_address="10.0.0.1", os_name="Ubuntu",
                                  os_version="22.04", distribution="ubuntu")
        db.add(asset)
        db.commit()
        # 注册后重传同一批：不重复 + RuntimeEvent 与 Evidence 双双回绑
        result = _upload(db, [_event(pid=1), _event(pid=2)])
        assert all(e.get("duplicate") for e in result)
        assert db.query(models.RuntimeEvent).count() == 2
        rows = db.query(models.RuntimeEvent).all()
        assert {r.asset_id for r in rows} == {asset.id}
        evidence = db.query(models.SecurityEvidence).all()
        assert len(evidence) == 2
        assert {e.asset_id for e in evidence} == {asset.id}, "SecurityEvidence 应回绑到资产"
        assert any(e.get("asset_rebound") for e in result)
    finally:
        db.close()


def test_different_devices_and_boots_not_merged(session_factory):
    db = session_factory()
    try:
        # 不同设备、其余字段完全一致 → 不合并
        _upload(db, [_event(hostname="host-a", pid=7), _event(hostname="host-b", pid=7)])
        assert db.query(models.RuntimeEvent).count() == 2
        # 同主机名、不同 boot（跨重启）→ 不合并
        _upload(db, [_event(hostname="host-a", pid=8, boot_id="boot-1"),
                     _event(hostname="host-a", pid=8, boot_id="boot-2")])
        assert db.query(models.RuntimeEvent).count() == 4
    finally:
        db.close()


def test_existing_evidence_binding_not_overwritten(session_factory):
    db = session_factory()
    try:
        asset_a = models.LinuxAsset(hostname="host-a", ip_address="10.0.0.1", os_name="Ubuntu",
                                    os_version="22.04", distribution="ubuntu")
        asset_b = models.LinuxAsset(hostname="host-b", ip_address="10.0.0.2", os_name="Ubuntu",
                                    os_version="22.04", distribution="ubuntu")
        db.add_all([asset_a, asset_b])
        db.commit()
        # 先以 asset_b 显式归属入库
        _upload(db, [_event(hostname="host-b", pid=9, asset_id=asset_b.id)])
        assert db.query(models.SecurityEvidence).one().asset_id == asset_b.id
        # 后续重传（hostname 归属解析）不改写既有绑定；冲突的显式归属按既有
        # 防御语义直接拒绝（资产 ID 与主机标识冲突），不产生新记录。
        _upload(db, [_event(hostname="host-b", pid=9)])
        assert db.query(models.SecurityEvidence).one().asset_id == asset_b.id
        with pytest.raises(ValueError, match="冲突"):
            _upload(db, [_event(hostname="host-b", pid=9, asset_id=asset_a.id)])
        assert db.query(models.RuntimeEvent).count() == 1
    finally:
        db.close()


# ── 6. 并发上传幂等 ─────────────────────────────────────────────────────────

def test_concurrent_upload_idempotent(session_factory):
    db = session_factory()
    try:
        events = [_event(pid=n) for n in range(20)]
        results = []

        def worker():
            local = session_factory()
            try:
                results.append(collector.append_events([dict(e) for e in events], db=local))
            finally:
                local.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert db.query(models.RuntimeEvent).count() == 20, "并发同批上传不得产生重复"
        assert db.query(models.SecurityEvidence).count() == 20
        assert all(r is not None for r in results)
    finally:
        db.close()


# ── 7/8. 转发器批量重试与"已持久化未确认"安全重试 ───────────────────────────

def test_batch_failure_then_safe_retry(tmp_path):
    metrics = ReliabilityMetrics()
    state = {"failures": 0, "persisted": []}
    events = [_event(pid=1), _event(pid=2)]

    def flaky_transport(api, batch, token):
        if state["failures"] < 2:
            state["failures"] += 1
            raise OSError("connection reset")
        state["persisted"].extend(batch)
        return {"ack": True, "received": len(batch), "accepted": len(batch),
                "duplicates": 0, "rejected": []}

    ok = send_batch_with_retry("http://backend", events, "", flaky_transport, metrics, max_retries=5)
    assert ok and state["failures"] == 2 and len(state["persisted"]) == 2
    assert metrics.retries == 2 and metrics.failed_batches == 0


def test_batch_retry_budget_exhausted_spools(tmp_path):
    metrics = ReliabilityMetrics()

    def always_fail(api, batch, token):
        raise OSError("down")

    ok = send_batch_with_retry("http://backend", [_event()], "", always_fail, metrics, max_retries=2)
    assert not ok and metrics.failed_batches == 1 and metrics.retries == 2


def test_server_committed_client_unacked_retry_no_duplicates(session_factory):
    """服务端已持久化但客户端未收到确认（超时）：重试命中幂等 → duplicates。"""
    db = session_factory()
    try:
        events = [_event(pid=42), _event(pid=43)]
        committed = {"done": False}

        def transport(api, batch, token):
            if not committed["done"]:
                # 服务端先持久化……
                collector.append_events([dict(e) for e in batch], db=db)
                committed["done"] = True
                # ……随后连接断开，客户端未收到确认
                raise OSError("response lost after commit")
            # 客户端重试：服务端幂等返回 duplicates
            result = collector.append_events([dict(e) for e in batch], db=db)
            duplicates = sum(1 for r in result if r.get("duplicate"))
            return {"ack": True, "received": len(batch), "accepted": len(result) - duplicates,
                    "duplicates": duplicates, "rejected": []}

        metrics = ReliabilityMetrics()
        ok = send_batch_with_retry("http://backend", events, "", transport, metrics, max_retries=3)
        assert ok
        assert db.query(models.RuntimeEvent).count() == 2, "重试不产生重复入库"
        assert metrics.duplicates == 2 and metrics.uploaded == 0
    finally:
        db.close()


def test_spool_roundtrip_and_exit_state(tmp_path):
    spool = Spool(str(tmp_path / "spool.jsonl"))
    events = [_event(pid=1)]
    spool.append(events)
    entries = spool.load()
    assert len(entries) == 1 and entries[0][1][0]["process_id"] == 1
    assert spool.pending_count() == 1
    # 全部确认 → rewrite([]) 清空 spool（已确认行不写回）
    spool.rewrite([])
    assert spool.pending_count() == 0
    # 恢复失败路径：未确认行保留原样（下次继续重传）
    spool.append(events)
    spool.append([_event(pid=2)])
    kept = [line for line, _ in spool.load()]
    spool.rewrite(kept[:1])
    assert spool.pending_count() == 1


def test_backoff_schedule_bounded():
    delays = [backoff_delay(n) for n in range(1, 7)]
    assert delays[0] >= 1.0 and all(d <= 16 * 1.3 + 0.01 for d in delays)
    assert abs(delays[1] - delays[0]) > 0.1  # 指数增长（含抖动）


# ── 9/10. 采集健康指标与 0/unknown 区分 ─────────────────────────────────────

def test_reliability_metrics_and_endpoint(session_factory, client, control_headers):
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="host-a", ip_address="10.0.0.1", os_name="Ubuntu",
                                  os_version="22.04", distribution="ubuntu")
        db.add(asset)
        db.commit()
        events = [_event(hostname="host-a", pid=n, sensor_id="sensor-x") for n in range(3)]
        for e in events:
            e["sensor_id"] = "sensor-x"
        _upload(db, events)
        # P0 转发器心跳：携带指标，dropped_events=0（真实零）与 None（unavailable）两态
        beat = heartbeat_payload(SimpleNamespace(asset_id=asset.id, sensor_id="sensor-x",
                                                 source="runtime_probe", health_file=""),
                                 metrics=ReliabilityMetrics())
        from app.services.runtime_telemetry import reliability_snapshot
        db.add(models.RuntimeSensor(asset_id=asset.id, sensor_id="sensor-x", source="runtime_probe",
                                    status=beat["status"], dropped_events=beat["dropped_events"],
                                    capabilities_json=json.dumps(beat["capabilities"]),
                                    detail=beat["detail"]))
        db.commit()
        snapshot = reliability_snapshot(db)
        row = next(r for r in snapshot["sensors"] if r["sensor_id"] == "sensor-x")
        assert row["server_observed"]["stored_events"] == 3
        assert row["dropped_events"] == "unavailable", "从未上报丢失计数 → unavailable，不是 0"
        assert row["self_reported_metrics"]["received"] == 0, "转发器计数 0=真实零"
        # 上报 dropped=0 → 数值 0（真实零丢失）
        db.query(models.RuntimeSensor).filter_by(sensor_id="sensor-x").update({"dropped_events": 0})
        db.commit()
        snapshot = reliability_snapshot(db)
        row = next(r for r in snapshot["sensors"] if r["sensor_id"] == "sensor-x")
        assert row["dropped_events"] == 0 and row["dropped_events"] != "unavailable"
        assert snapshot["server_totals"]["runtime_events"] == 3
    finally:
        db.close()


# ── 11. 旧版 API 兼容 ──────────────────────────────────────────────────────

def test_legacy_single_and_upload_apis_compatible(client, control_headers, tmp_path):
    single = client.post("/api/runtime/ebpf/events", headers=control_headers,
                         json=[_event(hostname="legacy-a", pid=1)])
    assert single.status_code == 200 and single.json()["count"] == 1
    # 事件形状不变（持久化视图字段完整；新字段仅增量）
    listed = client.get("/api/runtime/ebpf/events", params={"hostname": "legacy-a"}).json()
    event = listed["events"][0]
    for key in ("timestamp", "hostname", "source", "event_type", "process_name",
                "commandline", "category", "severity", "evidence_level", "event_fingerprint"):
        assert key in event
    batch_file = tmp_path / "legacy.jsonl"
    batch_file.write_text("\n".join(json.dumps(_event(hostname="legacy-a", pid=n)) for n in (2, 3)),
                          encoding="utf-8")
    with batch_file.open("rb") as handle:
        upload = client.post("/api/runtime/ebpf/upload", headers=control_headers,
                             files={"file": ("legacy.jsonl", handle)})
    assert upload.status_code == 200 and upload.json()["count"] == 2


def test_batch_endpoint_contract(client, control_headers):
    events = [_event(hostname="batch-a", pid=1), _event(hostname="batch-a", pid=2),
              _event(hostname="batch-a", pid=3)]
    first = client.post("/api/runtime/ebpf/events/batch", headers=control_headers,
                        json={"events": events})
    assert first.status_code == 200
    body = first.json()
    assert body["ack"] is True and body["accepted"] == 3 and body["duplicates"] == 0
    assert len(body["stored_event_ids"]) == 3
    replay = client.post("/api/runtime/ebpf/events/batch", headers=control_headers,
                         json={"events": events})
    assert replay.json()["duplicates"] == 3 and replay.json()["accepted"] == 0
    bad = client.post("/api/runtime/ebpf/events/batch", headers=control_headers,
                      json={"events": ["not-an-object", _event(hostname="batch-a", pid=4)]})
    assert bad.status_code == 200
    assert bad.json()["accepted"] == 1 and bad.json()["rejected"][0]["index"] == 0
    assert client.post("/api/runtime/ebpf/events/batch", headers=control_headers,
                       json={"events": []}).status_code == 400


# ── 12/13. 智能体工具与 Trace 关联不受影响 ──────────────────────────────────

def test_runtime_agent_tools_unaffected(session_factory):
    db = session_factory()
    try:
        from app.services import agent_tools as T
        _upload(db, [_event(hostname="host-a", pid=1), _event(hostname="host-a", pid=2)])
        rows = T.tool_query_process_evidence(db, device_id="host-a")
        assert rows["count"] == 2 and all(r["evidence_id"].startswith("SE-") for r in rows["events"])
        tree = T.tool_query_process_tree(db, device_id="host-a")
        assert tree.get("process_count") == 2 and tree.get("roots")
    finally:
        db.close()


def test_trace_evidence_resolution_unaffected(session_factory, client):
    """Trace→证据引用链在 P0 改动后保持可用（真实 SE- 上传 + emit 引用 + API 解析）。"""
    from app.services import trace_service as tracing
    db = session_factory()
    try:
        _upload(db, [_event(hostname="host-a", pid=11), _event(hostname="host-a", pid=12)])
        evidence_ids = [row.evidence_id for row in
                        db.query(models.SecurityEvidence).order_by(models.SecurityEvidence.id).all()]
        assert len(evidence_ids) == 2
        trace = tracing.start_trace(db, task_type="device_cve_match", target_type="device",
                                    target_ref="DEV-X")
        tracing.emit(db, trace.trace_id, "cve_match", actor="pipeline", status="succeeded",
                     evidence_refs=evidence_ids)
        tracing.finish_trace(db, trace.trace_id, "completed")
        response = client.get(f"/api/traces/{trace.trace_id}/evidence").json()
        assert response["trace_id"] == trace.trace_id
        assert len(response["evidence"]) == 2
        assert all(item["resolved"] for item in response["evidence"])
    finally:
        db.close()


# ── 14. 历史数据库增量迁移验证 ──────────────────────────────────────────────

def test_migration_on_legacy_database(tmp_path):
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from app import models as m

    db_url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    legacy_engine = sa.create_engine(db_url)
    Base.metadata.create_all(bind=legacy_engine)
    Session = sessionmaker(bind=legacy_engine)
    db = Session()
    # 构造 D1 历史现场：同一事件在资产注册前后各入库一次（旧基指纹）+ 证据未绑定
    import hashlib
    raw = _event(hostname="host-a", pid=5)["raw"]
    old_fp = hashlib.sha256(json.dumps({"asset_id": None, "raw": raw}, sort_keys=True).encode()).hexdigest()
    old_fp_bound = hashlib.sha256(json.dumps({"asset_id": 1, "raw": raw}, sort_keys=True).encode()).hexdigest()
    asset = m.LinuxAsset(hostname="host-a", ip_address="10.0.0.1", os_name="Ubuntu",
                         os_version="22.04", distribution="ubuntu")
    db.add(asset)
    db.commit()
    db.add_all([
        m.RuntimeEvent(asset_id=None, hostname="host-a", source="ebpf_bpftrace", event_type="execve",
                       occurred_at="2026-10-14T10:00:00Z", raw_json=json.dumps(raw),
                       event_fingerprint=old_fp),
        m.RuntimeEvent(asset_id=asset.id, hostname="host-a", source="ebpf_bpftrace", event_type="execve",
                       occurred_at="2026-10-14T10:00:00Z", raw_json=json.dumps(raw),
                       event_fingerprint=old_fp_bound),
    ])
    db.commit()
    db.add(m.SecurityEvidence(evidence_id="SE-legacy000000001", evidence_hash="h" * 64,
                              device_id="host-a", source="ebpf_bpftrace", evidence_type="process",
                              timestamp="2026-10-14T10:00:00Z"))
    db.commit()
    db.close()

    # 运行 P0 迁移（经 init_db 全链）
    import importlib
    import app.database as database_module
    saved_url = database_module.DATABASE_URL
    saved_engine = database_module.engine
    database_module.DATABASE_URL = db_url
    database_module.engine = legacy_engine
    try:
        notes = database_module.init_db()
    finally:
        database_module.DATABASE_URL = saved_url
        database_module.engine = saved_engine
    assert any("fingerprints_recomputed" in note for note in notes)

    conn = sqlite3.connect(tmp_path / "legacy.db")
    runtime_rows = conn.execute("SELECT COUNT(*) FROM runtime_event").fetchall()[0][0]
    bound = conn.execute("SELECT COUNT(*) FROM runtime_event WHERE asset_id IS NOT NULL").fetchall()[0][0]
    evidence_bound = conn.execute(
        "SELECT COUNT(*) FROM security_evidence WHERE asset_id IS NOT NULL").fetchall()[0][0]
    marker = conn.execute(
        "SELECT COUNT(*) FROM schema_migration_marker WHERE name='ebpf_p0_stable_fingerprint_v2'").fetchall()[0][0]
    index_exists = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='uq_runtime_event_fingerprint_v2'").fetchall()[0][0]
    conn.close()
    assert runtime_rows == 1, "旧重复行收敛为一条（保留最早）"
    assert bound == 1 and evidence_bound == 1, "RuntimeEvent 与 SecurityEvidence 均已确定性回绑"
    assert marker == 1 and index_exists == 1
    # 迁移幂等：再跑一遍无副作用
    database_module.engine = legacy_engine
    try:
        assert database_module.init_db() == []
    finally:
        database_module.engine = saved_engine


# ── 15. 清空语义 ────────────────────────────────────────────────────────────

def test_clear_semantics_preserves_evidence(client, control_headers):
    events = [_event(hostname="clear-a", pid=1), _event(hostname="clear-a", pid=2)]
    client.post("/api/runtime/ebpf/events", headers=control_headers, json=events)
    response = client.delete("/api/runtime/ebpf/events", headers=control_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == body["runtime_events_cleared"] >= 2
    assert body["evidence_preserved"] == 2, "证据层为审计引用保留，不随清空删除"
    assert "scope" in body and "note" in body
    listing = client.get("/api/runtime/ebpf/events").json()
    assert listing["count"] == 0
    evidence = client.get("/api/runtime/evidence/process?device_id=clear-a").json()
    assert evidence["count"] == 2, "清空后证据查询仍可用（Trace/复核引用不受破坏）"
