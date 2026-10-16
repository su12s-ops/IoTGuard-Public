"""Stage 9B M4.2 收尾专项回归：修正版反事实（Y6 2×2）与 RT 正向贡献设计。

全部离线（假客户端不触网）：锁定收尾实验的**先验设计**——
- Y6 2×2 每格的确定性放大因子预期（程序事实，非 LLM 判定）；
- Y6_CF2_TRUTH / RT_TRUTH 不变量（无放大因子格 immediate 禁止等）；
- RT 四条件同构性（设备身份/CVE/静态事实逐字段一致，仅运行时层不同）
  与干预点正确性（新鲜/过期/无关/缺失）；
- 旧 Y6 单因素反事实设计保留且标注 superseded（历史不静默覆盖）。

真值表先验：stage9b_closure_cases.py 于本轮实现提交入库，
先于任何真实 LLM 收尾运行（git 时序可核验）。
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from app.services.unified.evidence_prep import build_evidence_prep_packet  # noqa: E402

from stage9_agent_effectiveness_audit import (  # noqa: E402
    build_fixture,
    fresh_session_factory,
)
from stage9b_closure_cases import (  # noqa: E402
    RT_CONDITION_ORDER,
    RT_CVE,
    RT_FRESH_OFFSET,
    RT_STALE_OFFSET,
    RT_TRUTH,
    Y6_CELLS,
    Y6_CF2_TRUTH,
    Y6_CELL_ORDER,
    Y6_EXPECTED_AMPLIFIER,
    apply_y6_cell,
    build_rt_condition_fixture,
)
from stage9b_quality_cases import (  # noqa: E402
    Y6_COUNTERFACTUAL_CVE,
    Y6_COUNTERFACTUAL_TRUTH,
    extend_fixture_for_y_cases,
)


@pytest.fixture(scope="module")
def y6_cells(tmp_path_factory):
    """四格 Y6 2×2 独立库（模块级一次构建，供放大因子断言）。"""
    dbs = {}
    engines = []
    for cell in Y6_CELL_ORDER:
        root = tmp_path_factory.mktemp(f"y6-{cell}")
        factory, engine = fresh_session_factory(root / "db")
        db = factory()
        build_fixture(db, with_runtime=True)
        extend_fixture_for_y_cases(db, y6_kev=Y6_CELLS[cell]["kev"])
        apply_y6_cell(db, cell)
        dbs[cell] = db
        engines.append(engine)
    yield dbs
    for db in dbs.values():
        db.close()
    for engine in engines:
        engine.dispose()


@pytest.mark.parametrize("cell", Y6_CELL_ORDER)
def test_y6_cell_amplifier_matches_prior(y6_cells, cell):
    """每格确定性放大因子与先验预期一致（evidence_prep 真实计算路径）。"""
    db = y6_cells[cell]
    packet = build_evidence_prep_packet(db, "edge-15", "linux_host", [{
        "cve_id": "CVE-2026-81015:jammy", "package_name": "caddy",
        "installed_version": "2.6.4-1", "fixed_version": "2.6.4-2",
        "match_status": "affected"}])
    amplifiers = packet.candidates[0].urgency_amplifiers
    expected = Y6_EXPECTED_AMPLIFIER[cell]
    assert amplifiers["kev"] is expected["kev"]
    assert amplifiers["critical_public_component"] is expected["critical_public_component"]
    assert amplifiers["any_present"] is expected["any_present"]


def test_y6_cf2_truth_invariants():
    """真值不变量：无放大因子格 immediate 禁止；在场格 immediate 合法非必然。"""
    for cell in Y6_CELL_ORDER:
        truth = Y6_CF2_TRUTH[cell]
        expected = Y6_EXPECTED_AMPLIFIER[cell]
        assert truth["expected_amplifier"] == expected
        if expected["any_present"]:
            assert "immediate_fix" in truth["actions"]
            assert "scheduled_fix" in truth["actions"]   # 非必然：scheduled 亦可
        else:
            assert "immediate_fix" not in truth["actions"]
            assert "scheduled_fix" in truth["actions"]
        # 静态适用性事实四格一致：impact 允许集相同
        assert truth["impact"] == {"confirmed_affected", "potentially_affected"}
        assert truth["needs_human"] is True   # Critical 核心资产审计门禁


def test_y6_cell_static_facts_identical(y6_cells):
    """四格静态适用性事实逐字段一致（唯一干预点 = KEV×公网暴露）。"""
    from app import models

    snapshots = []
    for cell in Y6_CELL_ORDER:
        db = y6_cells[cell]
        asset = db.query(models.LinuxAsset).filter_by(hostname="edge-15").one()
        package = db.query(models.AssetPackage).filter_by(asset_id=asset.id).one()
        vuln = db.query(models.VulnerabilityInfo).filter_by(
            cve_id="CVE-2026-81015:jammy").one()
        caddy = (db.query(models.AssetService)
                 .filter_by(asset_id=asset.id, service_name="caddy").one())
        snapshots.append({
            "package": (package.package_name, package.package_version),
            "vuln": (vuln.cvss_score, vuln.fixed_version),
            "caddy_port": caddy.port,
        })
    assert all(s == snapshots[0] for s in snapshots)
    assert snapshots[0]["vuln"] == (9.8, "2.6.4-2")


def test_old_y6_counterfactual_retained_and_superseded():
    """旧单因素反事实设计保留（历史不覆盖）且文档标注 superseded。"""
    import stage9b_quality_cases as quality_cases

    assert Y6_COUNTERFACTUAL_CVE == "CVE-2026-81015"
    # 原预期仍保留原样（immediate 禁止）——其缺陷由收尾轮 kev0_pub1 格证伪
    assert "immediate_fix" not in Y6_COUNTERFACTUAL_TRUTH["actions"]
    source = Path(quality_cases.__file__).read_text(encoding="utf-8")
    assert "SUPERSEDED" in source
    assert "stage9b_closure_cases" in source


# ── RT 条件库 ────────────────────────────────────────────────────────────────

def _rt_db(tmp_path_factory, condition):
    root = tmp_path_factory.mktemp(f"rt-{condition}")
    factory, engine = fresh_session_factory(root / "db")
    db = factory()
    build_fixture(db, with_runtime=True)
    build_rt_condition_fixture(db, condition)
    return db, engine


@pytest.fixture(scope="module")
def rt_dbs(tmp_path_factory):
    dbs, engines = {}, []
    for condition in RT_CONDITION_ORDER:
        db, engine = _rt_db(tmp_path_factory, condition)
        dbs[condition] = db
        engines.append(engine)
    yield dbs
    for db in dbs.values():
        db.close()
    for engine in engines:
        engine.dispose()


def test_rt_risk_exists_single_per_condition(rt_dbs):
    """每条件恰好产生一条 CVE-2026-81021 活跃风险（同构反事实可运行）。"""
    from app import models

    for condition in RT_CONDITION_ORDER:
        db = rt_dbs[condition]
        risks = [risk for risk in db.query(models.RiskAssessment).filter_by(active=True).all()
                 if risk.cve_id.split(":")[0] == RT_CVE]
        assert len(risks) == 1, f"{condition}: 期望 1 条风险，实得 {len(risks)}"


def test_rt_static_facts_identical_across_conditions(rt_dbs):
    """四条件设备身份/CVE/静态版本与厂商事实逐字段一致。"""
    from app import models

    snapshots = []
    for condition in RT_CONDITION_ORDER:
        db = rt_dbs[condition]
        asset = db.query(models.LinuxAsset).filter_by(hostname="edge-rt").one()
        package = db.query(models.AssetPackage).filter_by(asset_id=asset.id).one()
        vuln = db.query(models.VulnerabilityInfo).filter_by(
            cve_id=f"{RT_CVE}:jammy").one()
        intel = db.query(models.ThreatIntelSource).filter_by(
            cve_id=f"{RT_CVE}:jammy").one()
        services = [(s.service_name, s.is_public_exposed) for s in
                    db.query(models.AssetService).filter_by(asset_id=asset.id).all()]
        snapshots.append({
            "identity": (asset.hostname, asset.ip_address, asset.distribution,
                         asset.os_version, asset.exposure_level),
            "package": (package.package_name, package.package_version),
            "vuln": (vuln.cvss_score, vuln.cvss_severity, vuln.fixed_version),
            "kev": intel.is_kev,
            "services": sorted(services),
        })
    assert all(s == snapshots[0] for s in snapshots)
    assert snapshots[0]["kev"] is False          # 无静态放大因子（RT 证据是唯一变量）
    assert snapshots[0]["vuln"][0] < 9.0


def test_rt_condition_interventions(rt_dbs):
    """干预点正确：A 新鲜相关 / B 新鲜无关 / C 过期相关 / D 无监控。"""
    from app import models
    from app.services.runtime_evidence import _freshness

    now = datetime.now(timezone.utc)
    for condition in RT_CONDITION_ORDER:
        db = rt_dbs[condition]
        asset = db.query(models.LinuxAsset).filter_by(hostname="edge-rt").one()
        sensor = db.query(models.RuntimeSensor).filter_by(asset_id=asset.id).first()
        events = (db.query(models.RuntimeEvent)
                  .filter_by(asset_id=asset.id).order_by(models.RuntimeEvent.process_id).all())
        if condition == "RT-D":
            assert sensor is None and not events
            continue
        assert sensor is not None, condition
        if condition == "RT-C":
            heartbeat_age = (now - sensor.last_heartbeat_at.replace(
                tzinfo=sensor.last_heartbeat_at.tzinfo or timezone.utc)).total_seconds()
            assert heartbeat_age >= RT_STALE_OFFSET.total_seconds() * 0.99
        else:
            assert sensor.last_heartbeat_at is not None
        assert events, condition
        vsftpd_children = [event for event in events
                           if event.parent_process == "vsftpd"]
        if condition in ("RT-A", "RT-C"):
            # 相关证据：vsftpd 拉起 shell 的利用模式链在场
            assert vsftpd_children, f"{condition}: 缺少 vsftpd→shell 利用模式链"
            for event in events:
                age_hours = (now - datetime.fromisoformat(event.occurred_at)
                             ).total_seconds() / 3600
                bucket = _freshness(str(event.occurred_at))[1]
                if condition == "RT-A":
                    assert bucket == "last_hour", f"{condition}: 事件应新鲜，实得 {bucket}"
                else:
                    assert bucket == "stale", f"{condition}: 事件应过期，实得 {bucket}"
        elif condition == "RT-B":
            # 无关可疑链父进程为 sshd 会话（非 vsftpd 利用模式）+ vsftpd 常规活动
            assert not vsftpd_children, "RT-B: 不应出现 vsftpd→shell 利用模式链"
            suspicious = [event for event in events if event.severity == "warning"]
            assert suspicious and all(event.parent_process != "vsftpd"
                                      for event in suspicious)
            active = [event for event in events if event.process_name == "vsftpd"]
            assert active, "RT-B: 应有 vsftpd 常规服务活动事件"


def test_rt_truth_invariants():
    """RT 真值不变量：仅 RT-A 允许 immediate；B/D 不得升级方向。"""
    assert set(RT_CONDITION_ORDER) == set(RT_TRUTH)
    for condition, truth in RT_TRUTH.items():
        if condition == "RT-A":
            assert "immediate_fix" in truth["actions"]
            assert "upgrade_major" in truth["directions"]
        else:
            assert "immediate_fix" not in truth["actions"], condition
        if condition in ("RT-B", "RT-D"):
            assert truth["directions"] <= {"maintain", "downgrade_minor"}
        assert truth["impact"] == {"confirmed_affected", "potentially_affected"}
    # 时间偏移设计先验固定
    assert RT_FRESH_OFFSET.total_seconds() == 300
    assert RT_STALE_OFFSET.days == 45
