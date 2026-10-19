"""通用 OpenWrt 情报接入与匹配的回归测试。

夹具 ``fixtures/openwrt_ghsa_snapshot.json`` 是 2026-10-19 从
api.github.com openwrt/openwrt security-advisories 抓取的真实官方快照
（仅裁剪与规范化无关的字段）。断言只针对确定性的规范化/判定规则，
不针对任何单一 CVE 的特殊逻辑。
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import models
from app.services import openwrt_intel
from app.services.iot_official import assess_snapshot
from app.services.iot_devices import match_openwrt

FIXTURE = Path(__file__).parent / "fixtures" / "openwrt_ghsa_snapshot.json"


@pytest.fixture()
def ghsa_rows() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture()
def synced(session_factory, ghsa_rows):
    with session_factory() as db:
        summary = openwrt_intel.sync_openwrt_advisories(db, ghsa_rows)
        db.commit()
        yield db, summary


# ── 官方范围表达式解析 ───────────────────────────────────────────────────────


@pytest.mark.parametrize("expression,scope,extra", [
    ("< 24.10.6", "release", {"op": "<", "version": "24.10.6"}),
    ("<= 25.12.4 (cgi-io HEAD 658b14b)", "release",
     {"op": "<=", "version": "25.12.4", "annotation": "cgi-io HEAD 658b14b"}),
    ("≤ 24.10.4", "release", {"op": "<=", "version": "24.10.4"}),
    ("main", "branch", {"branch": "main"}),
    ("≤ commit 8e724fc", "commit", {"commit": "8e724fc"}),
    ("dc803ab", "unknown", {}),
    ("all versions", "unknown", {}),
    ("", "unknown", {}),
])
def test_parse_range_domains(expression, scope, extra):
    parsed = openwrt_intel.parse_range(expression)
    assert parsed["scope"] == scope
    for key, value in extra.items():
        assert parsed.get(key) == value


def test_series_of():
    assert openwrt_intel.series_of("25.12.6") == "25.12"
    assert openwrt_intel.series_of("24.10") == "24.10"
    assert openwrt_intel.series_of("snapshot") == ""


# ── 组件名规范化（官方载荷 → 组件） ─────────────────────────────────────────


def test_component_normalization_from_real_payloads(ghsa_rows):
    by_cve = {row["cve_id"]: row for row in ghsa_rows}
    # 仓库级占位 + summary 前缀 → procd
    assert ("procd", ) == tuple(c for c, _ in openwrt_intel.normalize_components(by_cve["CVE-2026-30874"]))
    # 仓库级占位 + summary 首词（无冒号前缀）→ ead
    assert ["ead"] == [c for c, _ in openwrt_intel.normalize_components(by_cve["CVE-2026-55490"])]
    # 斜杠拆分 → odhcpd + luci
    assert ["odhcpd", "luci"] == [c for c, _ in openwrt_intel.normalize_components(by_cve["CVE-2026-62948"])]
    # 去掉 ` (OpenWrt)` 装饰 → cgi-io
    assert ["cgi-io"] == [c for c, _ in openwrt_intel.normalize_components(by_cve["CVE-2026-62947"])]


# ── 同步落库 ─────────────────────────────────────────────────────────────────


def test_sync_writes_normalized_rows_and_evidence(synced, ghsa_rows):
    db, summary = synced
    rows = db.query(models.OpenWrtAdvisory).all()
    assert rows, "normalized advisory rows must be written"
    assert summary["ingested_snapshots"] == len(ghsa_rows)
    scopes = {json.loads(row.notes)["scope"] for row in rows}
    assert {"release", "branch", "commit"} <= scopes
    # 每条记录都携带官方溯源：ghsa、内容哈希、官方原文范围
    for row in rows:
        note = json.loads(row.notes)
        assert note["provenance"] == "openwrt_ghsa_normalized"
        assert note["ghsa_id"].startswith("GHSA-")
        assert len(note["content_sha256"]) == 64
        assert note["official_range"]
    # commit 域（ead）被显式标记为未确定，而不是被猜测成 release 事实
    assert any(item["scope"] == "commit" for item in summary["undetermined"])
    # 通用情报行建立（风险引擎按 cve_id 查询依赖它）
    intel = db.query(models.VulnerabilityInfo).filter_by(source="openwrt_official_ghsa").all()
    assert {row.cve_id for row in intel} == {row["cve_id"] for row in ghsa_rows}


def test_sync_is_idempotent_and_keeps_operator_records(session_factory, ghsa_rows):
    with session_factory() as db:
        db.add(models.OpenWrtAdvisory(
            cve_id="CVE-2026-62947", package_name="cgi-io", release="25.12.6",
            affected_versions_json='["2025.12.11~658b14b-r1"]',
            fixed_versions_json='["2026.07.21~31cb3c89-r1"]',
            source_url="https://operator.example/advisory", notes="人工登记"))
        db.commit()
        first = openwrt_intel.sync_openwrt_advisories(db, ghsa_rows)
        db.commit()
        second = openwrt_intel.sync_openwrt_advisories(db, ghsa_rows)
        db.commit()
        assert first["normalized_records"] == second["normalized_records"]
        operator = db.query(models.OpenWrtAdvisory).filter_by(
            cve_id="CVE-2026-62947", package_name="cgi-io", release="25.12.6").one()
        assert operator.notes == "人工登记"  # 操作员精确记录不被自动覆盖


# ── 四态判定 ─────────────────────────────────────────────────────────────────


def _find_rows(db, cve_id, package):
    return db.query(models.OpenWrtAdvisory).filter_by(
        cve_id=cve_id, package_name=package).all()


def test_evaluate_four_states_on_real_records(synced):
    db, _ = synced

    def evaluate(cve, package, installed):
        return openwrt_intel.evaluate_candidate(
            "25.12.6", installed, _find_rows(db, cve, package))

    # affected：分支范围无修复版本，设备包为主干快照（~commit 锚点）
    outcome = evaluate("CVE-2026-62948", "odhcpd", "2026.06.29~5d7be43f-r1")
    assert outcome["status"] == "affected" and outcome["code"] == "openwrt_branch_range_no_fix"
    assert "main" in outcome["reason"] and "5d7be43f" in outcome["reason"]

    # not_affected：procd 公告仅声明 < 24.10.6，25.12.6 全局不在范围内且无修复声明
    outcome = evaluate("CVE-2026-30874", "procd", "2026.03.13~58eb263d-r1")
    assert outcome["status"] == "not_affected" and outcome["code"] == "openwrt_release_out_of_range"

    # fixed：设备系列 25.12 的官方边界 25.12.1（jsonpath/mdnsd 公告双系列条目）
    outcome = evaluate("CVE-2026-30873", "jsonpath", "2026.03.16~b9034210-r1")
    assert outcome["status"] == "fixed" and outcome["fixed_version"] == "25.12.1"

    # fixed：官方 “fixed in OpenWrt 24.10.4 and later” 声明覆盖后续 release（ubusd）
    outcome = evaluate("CVE-2025-62526", "ubusd", "2026.06.28~24864e78-r2")
    assert outcome["status"] == "fixed" and outcome["code"] == "openwrt_fix_statement_covers_later"

    # not_affected：官方范围 <= 25.12.4 不含 25.12.6（cgi-io），且不作修复断言
    outcome = evaluate("CVE-2026-62947", "cgi-io", "2026.07.21~31cb3c89-r1")
    assert outcome["status"] == "not_affected" and outcome["code"] == "openwrt_release_out_of_range"
    assert outcome["fixed_version"] == ""

    # insufficient_data：commit 域范围无法映射到 release 设备（ead）
    outcome = evaluate("CVE-2026-55490", "ead", "any-version")
    assert outcome["status"] == "insufficient_data" and outcome["code"] == "openwrt_scope_not_stated"

    # insufficient_data：分支范围但安装串无源码锚点
    outcome = evaluate("CVE-2026-62948", "luci", "26.288.56989")
    assert outcome["status"] == "insufficient_data" and outcome["code"] == "openwrt_branch_version_unverifiable"


def test_evaluate_affected_release_range():
    row = SimpleNamespace(
        cve_id="CVE-X", package_name="x", release="25.12",
        affected_versions_json='["< 25.12.1"]', fixed_versions_json='["25.12.1"]',
        source_url="https://github.com/openwrt/openwrt/security/advisories/GHSA-xxxx-xxxx-xxxx",
        notes=json.dumps({"ghsa_id": "GHSA-xxxx-xxxx-xxxx", "scope": "release",
                          "official_range": "< 25.12.1", "provenance": "openwrt_ghsa_normalized"}))
    hit = openwrt_intel.evaluate_candidate("25.12.0", "25.12.0~abc1234-r1", [row])
    assert hit["status"] == "affected" and hit["code"] == "openwrt_release_range_affected"


# ── match_openwrt 端到端（模拟 25.12.6 设备） ────────────────────────────────


DEVICE_PACKAGES = {
    "cgi-io": "2026.07.21~31cb3c89-r1",
    "odhcpd-ipv6only": "2026.06.29~5d7be43f-r1",
    "luci-base": "26.288.56989~75a306d",
    "ubusd": "2026.06.28~24864e78-r2",
    "procd": "2026.03.13~58eb263d-r1",
    "busybox": "1.37.0-r6",
}


def _device_asset(db):
    asset = models.LinuxAsset(hostname="openwrt-test", distribution="openwrt",
                              os_version="25.12.6", inventory_complete=True)
    db.add(asset)
    db.flush()
    for name, version in DEVICE_PACKAGES.items():
        db.add(models.AssetPackage(asset_id=asset.id, package_name=name,
                                   package_version=version, package_manager="apk"))
    db.flush()
    return asset


def test_match_openwrt_end_to_end(synced):
    db, _ = synced
    asset = _device_asset(db)
    stats: dict = {}
    keys = match_openwrt(db, asset, None, stats=stats)
    db.commit()

    rows = {(row.cve_id, row.package_name): row
            for row in db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id)}
    assert ("CVE-2026-62948", "odhcpd-ipv6only") in rows  # 别名 odhcpd → odhcpd-ipv6only
    assert rows[("CVE-2026-62948", "odhcpd-ipv6only")].match_status == "affected"
    assert rows[("CVE-2026-62948", "odhcpd-ipv6only")].affected is True
    assert rows[("CVE-2026-62947", "cgi-io")].match_status == "not_affected"
    assert rows[("CVE-2026-30874", "procd")].match_status == "not_affected"
    assert rows[("CVE-2025-62526", "ubusd")].match_status == "fixed"
    # 未安装组件不产生匹配行，也不被解读为安全，仅进入 absent 统计
    absent = stats["absent_components"]
    assert set(absent) >= {"mdnsd", "jsonpath", "ead", "ltq-ptm"}
    assert not any(row.package_name in {"mdnsd", "jsonpath", "ead", "ltq-ptm"}
                   for row in rows.values())
    assert stats["evaluated"].get("affected") == 2  # odhcpd-ipv6only + luci-base
    assert stats["evaluated"].get("fixed") == 1     # ubusd（fix-later 官方声明）
    assert stats["evaluated"].get("not_affected") == 2  # cgi-io + procd
    assert len(keys) == len(rows)

    # 幂等重跑不产生重复行
    match_openwrt(db, asset, None)
    db.commit()
    assert db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).count() == len(rows)


def test_match_openwrt_operator_exact_record_still_wins(session_factory, ghsa_rows):
    with session_factory() as db:
        openwrt_intel.sync_openwrt_advisories(db, ghsa_rows)
        db.add(models.OpenWrtAdvisory(
            cve_id="CVE-2026-62947", package_name="cgi-io", release="25.12.6",
            affected_versions_json='["2025.12.11~658b14b-r1"]',
            fixed_versions_json='["2026.07.21~31cb3c89-r1"]',
            source_url="https://operator.example/x", notes="人工登记"))
        db.commit()
        asset = _device_asset(db)
        match_openwrt(db, asset, None)
        db.commit()
        row = db.query(models.VulnerabilityMatch).filter_by(
            asset_id=asset.id, cve_id="CVE-2026-62947", package_name="cgi-io").one()
        assert row.match_status == "fixed" and row.reason_code == "openwrt_exact_fixed_version"


# ── 覆盖评估 API（原 9 条全 insufficient_data 的根因修复） ───────────────────


def test_assess_snapshot_openwrt_now_differentiates(ghsa_rows, session_factory):
    with session_factory() as db:
        openwrt_intel.sync_openwrt_advisories(db, ghsa_rows)
        db.commit()
        result = assess_snapshot(db, "openwrt", "25.12.6")
    statuses = {item["cve_id"]: item["status"] for item in result["results"]}
    assert result["count"] == 9
    assert statuses["CVE-2026-30873"] == "not_in_reported_range"   # 设备系列边界 25.12.1 已达
    assert statuses["CVE-2026-30874"] == "not_in_reported_range"   # 全局范围外（仅声明 < 24.10.6）
    assert statuses["CVE-2025-62526"] == "not_in_reported_range"   # 官方 fix-later 声明覆盖
    assert statuses["CVE-2026-55490"] == "insufficient_data"       # commit 域
    assert statuses["CVE-2026-62948"] == "insufficient_data"       # 分支域：仅凭版本不可判
    # 至少一条 release 域命中受影响范围的版本评估
    vulnerable = assess_snapshot(db, "openwrt", "25.12.0")
    by_cve = {item["cve_id"]: item["status"] for item in vulnerable["results"]}
    assert by_cve["CVE-2026-30873"] == "potentially_affected"


def test_sync_endpoint_and_run_with_stats(client, control_headers, ghsa_rows):
    response = client.post("/api/matching/openwrt-intel/sync", json={"rows": ghsa_rows},
                           headers=control_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["ingested_snapshots"] == len(ghsa_rows)
    assert body["advisory_rows_written"] > 0
    assert any(item["scope"] == "commit" for item in body["undetermined"])

    response = client.post("/api/matching/run", headers=control_headers)
    assert response.status_code == 200
    assert "count" in response.json()
