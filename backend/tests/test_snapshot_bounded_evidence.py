"""A1：证据快照只逐条纳入新鲜/相关运行时证据。

回归对象（2026-10 真实运行 risk158）：state.evidence_snapshot 13.9MB，
其中 22,559 条历史 runtime 证据（observed_at 多为 2026-10-14）逐条进入
registry/categories；每个超步都持久化，拖慢节点与后续提示词。

这里使用隔离的临时 SQLite + 假 packet，不调用真实模型/设备，不触碰生产库。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from app import models
from app.services.unified import collaboration as protocol

OLD = "2026-10-14T03:04:05+00:00"


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_runtime(db, evidence_id, asset_id, *, process="nginx", commandline="/usr/sbin/nginx",
                timestamp=OLD, raw_data='{"message":"observed"}', device_id="ubuntu-host"):
    row = models.SecurityEvidence(
        evidence_id=evidence_id, asset_id=asset_id, device_id=device_id,
        source="logread", evidence_type="process", timestamp=timestamp,
        process=process, commandline=commandline, evidence_hash=text_hash(evidence_id),
        raw_data=raw_data)
    db.add(row)
    return row


@pytest.fixture
def rig(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="ubuntu-host", ip_address="192.0.2.50",
                                  distribution="ubuntu", os_version="24.04",
                                  architecture="x86_64", inventory_complete=True,
                                  identity_source="ssh_inventory")
        db.add(asset)
        db.flush()
        raw = '{"packages":[["openssl","3.0.2"]]}'
        inventory = models.CollectionEvidence(
            evidence_id="INV-ubuntu", run_id="collection-ubuntu", asset_id=asset.id,
            raw_text=raw, content_sha256=text_hash(raw))
        asset.inventory_metadata_json = json.dumps({
            "inventory_evidence_id": inventory.evidence_id,
            "collection_run_id": inventory.run_id, "package_sources": ["dpkg"]})
        db.add(inventory)
        db.commit()
        packet = {
            "target_ref": asset.hostname, "target_type": "linux_host",
            "as_of": "fixture", "asset_facts": {"profile": {"device_id": asset.hostname}},
            "runtime_facts": {"freshness": {"process": {"freshness": "stale"}},
                              "coverage": {"status": "observed", "sensors": []}},
            "candidates": [{"cve_id": "CVE-2026-1000", "package_name": "openssl",
                            "installed_version": "3.0.2", "fixed_version": "3.0.3"}],
        }
        yield type("Rig", (), {"db": db, "asset": asset, "inventory": inventory,
                               "packet": packet})()


def build(rig):
    return protocol.build_snapshot(rig.db, rig.packet, "run-bounded")


def test_historical_unrelated_runtime_events_are_summarized(rig):
    ids = [f"SE-old-{number:03}" for number in range(40)]
    for evidence_id in ids:
        add_runtime(rig.db, evidence_id, rig.asset.id,
                    commandline=f"/usr/sbin/nginx worker {evidence_id}")
    rig.db.commit()

    snapshot = build(rig)
    assert rig.db.query(models.SecurityEvidence).count() == len(ids)   # 只读，不删除证据行
    registry = snapshot["evidence_registry"]
    summary = registry[protocol.RUNTIME_SUMMARY_KEY]
    assert summary["kind"] == protocol.RUNTIME_SUMMARY_KIND
    assert summary["summarized"] is True
    assert summary["count"] == len(ids)
    assert summary["oldest"] == summary["newest"] == OLD
    assert not [evidence_id for evidence_id in ids if evidence_id in registry]
    # 摘要身份是 ID 集合的 sha256，可复核；成员哈希用于服务端判定历史引用。
    assert summary["sha256_of_ids"] == hashlib.sha256(json.dumps(
        sorted(ids), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert len(summary["id_sha256"]) == len(ids)
    # categories 只保留有界摘要视图，不再逐条复制 22k 事件。
    runtime_category = snapshot["categories"]["runtime"]
    assert runtime_category["events"] == []
    assert runtime_category["summarized"]["count"] == len(ids)
    # 非 runtime 证据（inventory）保持原样逐条登记。
    assert registry["INV-ubuntu"]["kind"] == "inventory"


def test_fresh_and_candidate_related_runtime_events_stay_individual(rig):
    seen_at = datetime.now(timezone.utc) - timedelta(seconds=30)
    add_runtime(rig.db, "SE-fresh", rig.asset.id, process="nginx",
                commandline="/usr/sbin/nginx -g daemon off;",
                timestamp=seen_at.isoformat())
    add_runtime(rig.db, "SE-related-package", rig.asset.id, process="openssl",
                commandline="/usr/bin/openssl s_client -connect 192.0.2.9:443",
                timestamp="2026-10-14T03:04:05+00:00")
    add_runtime(rig.db, "SE-related-cve", rig.asset.id, process="helper",
                commandline="/usr/bin/helper", timestamp="2026-10-14T04:04:05+00:00",
                raw_data='{"alert":"CVE-2026-1000 exploit attempt observed"}')
    add_runtime(rig.db, "SE-stale-unrelated", rig.asset.id, process="cron",
                commandline="/usr/sbin/cron -f", timestamp="2026-10-14T05:04:05+00:00")
    rig.db.commit()

    snapshot = build(rig)
    registry = snapshot["evidence_registry"]
    assert {"SE-fresh", "SE-related-package", "SE-related-cve"} <= set(registry)
    assert "SE-stale-unrelated" not in registry
    assert registry["SE-fresh"]["fresh"] is True
    # 相关但历史：仍逐条保留，但绝不冒充新鲜证据。
    assert registry["SE-related-package"]["fresh"] is False
    assert registry["SE-related-package"]["included_reason"] == "candidate_related"
    assert registry["SE-related-cve"]["fresh"] is False
    # 新鲜的、与候选无关的事件也逐条保留（fresh 独立于 relevance）。
    assert registry["SE-fresh"]["included_reason"] == "fresh"
    summary = registry[protocol.RUNTIME_SUMMARY_KEY]
    assert summary["count"] == 1
    assert summary["newest"] == "2026-10-14T05:04:05+00:00"


def test_validation_does_not_treat_summarized_history_as_fabricated(rig):
    add_runtime(rig.db, "SE-history", rig.asset.id, process="cron",
                commandline="/usr/sbin/cron -f")
    rig.db.commit()
    snapshot = build(rig)

    assert protocol.classify_evidence_id("SE-history", snapshot) == "known_but_summarized"
    # 历史证据存在，只是被摘要：不能判成捏造。
    assert protocol.validate_evidence_ids(["SE-history"], snapshot) == []
    # 也不能把摘要键当成证据 ID 引用。
    assert protocol.validate_evidence_ids([protocol.RUNTIME_SUMMARY_KEY], snapshot)
    # 真正不存在的 ID 仍要被拒（防幻觉语义不降低）。
    assert protocol.validate_evidence_ids(["SE-fabricated"], snapshot)
    # kind 约束仍然生效：runtime 历史证据不能冒充 inventory。
    assert protocol.validate_evidence_ids(["SE-history"], snapshot, kinds={"inventory"})
    assert protocol.validate_evidence_ids(["INV-ubuntu"], snapshot, kinds={"runtime"})
    # 摘要成员不是逐条条目，不能出现在可引用 ID 枚举里。
    assert "SE-history" not in protocol.evidence_registry_ids(snapshot)
    assert protocol.RUNTIME_SUMMARY_KEY not in protocol.evidence_registry_ids(snapshot)


def test_legacy_summary_without_member_hashes_uses_conservative_fallback():
    """只有 {count, sha256_of_ids, oldest, newest} 的摘要也不能判成捏造。"""
    snapshot = {"evidence_registry": {protocol.RUNTIME_SUMMARY_KEY: {
        "kind": protocol.RUNTIME_SUMMARY_KIND, "count": 12,
        "sha256_of_ids": "a" * 64, "oldest": OLD, "newest": OLD, "summarized": True}}}
    assert protocol.classify_evidence_id("SE-history", snapshot) == "known_but_summarized"
    assert protocol.validate_evidence_ids(["SE-history"], snapshot) == []


def test_snapshot_size_stays_under_one_megabyte_for_risk158_scale(rig):
    """22,560 条历史 runtime 证据的等价数据：有界快照 < 1MB。"""
    total = 22_560
    rows = []
    for number in range(total):
        evidence_id = f"SE-risk158-{number:05}"
        rows.append({
            "evidence_id": evidence_id,
            "asset_id": rig.asset.id,
            "device_id": rig.asset.hostname,
            "source": "logread",
            "evidence_type": "process",
            "timestamp": OLD,
            "severity": "info",
            "severity_score": 0,
            "process": "nginx",
            "pid": 1000 + number % 500,
            "ppid": 1,
            "user": "www-data",
            "commandline": "/usr/sbin/nginx -g 'daemon off;' worker process",
            "parent_process": "nginx",
            "process_exec_id": f"exec-{number:05}",
            "parent_exec_id": "exec-parent",
            "operation": "exec",
            "destination_ip": "",
            "destination_port": 0,
            "file_path": "/var/log/nginx/access.log",
            "description": "observed process execution event from runtime sensor",
            "raw_data": json.dumps({"message": "runtime observation " + "x" * 80}),
            "evidence_hash": hashlib.sha256(evidence_id.encode()).hexdigest(),
        })
    rig.db.bulk_insert_mappings(models.SecurityEvidence, rows)
    rig.db.commit()

    snapshot = build(rig)
    bounded_bytes = len(json.dumps(snapshot, ensure_ascii=False, default=str))

    # 原实现会逐条写入 registry + categories.events；用同样的行估算其体积。
    legacy_entry = {
        "kind": "runtime", "source": "logread",
        "collected_at": "2026-10-14T03:04:05+00:00", "observed_at": OLD,
        "content_sha256": "a" * 64, "observation_sha256": "b" * 64,
        "asset_id": rig.asset.id, "source_run_id": "",
        "integrity": "snapshot_observation_hash",
        **{key: rows[0][key] for key in (
            "device_id", "evidence_type", "timestamp", "severity", "severity_score",
            "process", "pid", "ppid", "user", "commandline", "parent_process",
            "process_exec_id", "parent_exec_id", "operation", "destination_ip",
            "destination_port", "file_path", "description", "raw_data")},
    }
    legacy_event = {"observed_at": OLD, "source": "logread",
                    "observation_sha256": "b" * 64}
    legacy_bytes = len(json.dumps(
        {"evidence_registry": {row["evidence_id"]: legacy_entry for row in rows},
         "runtime_events": [legacy_event for _ in rows]},
        ensure_ascii=False, default=str))

    assert bounded_bytes < 1_000_000, bounded_bytes
    assert legacy_bytes > 10_000_000, legacy_bytes
    assert bounded_bytes < legacy_bytes * 0.1, (bounded_bytes, legacy_bytes)
