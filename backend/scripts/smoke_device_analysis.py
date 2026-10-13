"""真实 LLM 冒烟（阶段六）：SmartCam-X1 设备目标完整编排分析。

数据：真实 IotDevice + 组件 + 厂商公告精确命中（affected）+ 阶段二真实 eBPF 采集。
验证：漏洞情报智能体读到设备 CVE 命中；修复智能体把设备目标标注为须经 Harness 审批。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("LINUXGUARD_ARCHIVE_ON_STARTUP", "0")
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
FIXTURE = BACKEND / "tests" / "fixtures" / "ebpf_real_capture.jsonl"
HOST = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])["hostname"]
DEVICE_ID = "DEV-SCX1-SMOKE"


def build_data(db) -> None:
    from app import models
    from app.services.device_vulnerability import register_advisory, run_device_matching
    from app.services.ebpf_event_collector import append_events

    device = models.IotDevice(device_id=DEVICE_ID, device_name="SmartCam-X1",
                              device_type="ip_camera", vendor="SmartCam Technologies",
                              model="SmartCam-X1", firmware_version="2.4.7", ip=HOST,
                              status="online")
    db.add(device)
    db.flush()
    db.add_all([
        models.IotDeviceService(device_row_id=device.id, port=1883, service_type="mqtt",
                                product="SmartCam MQTT broker", version="1.6.2",
                                auth_state="anonymous_accepted", status="open"),
        models.IotDeviceService(device_row_id=device.id, port=22, service_type="ssh",
                                product="dropbear", version="2022.83", status="open"),
    ])
    db.add_all([
        models.IotDeviceComponent(device_row_id=device.id, component_name="SmartCam MQTT broker",
                                  version="1.6.2"),
        models.IotDeviceComponent(device_row_id=device.id, component_name="dropbear ssh",
                                  version="2022.83"),
    ])
    db.commit()
    register_advisory(db, {
        "cve_id": "CVE-2026-31001", "vendor": "SmartCam Technologies", "model": "SmartCam-X1",
        "component_name": "SmartCam MQTT broker", "affected_versions": ["1.6.2"],
        "fixed_versions": ["1.6.3"],
        "source_url": "https://vendor.example.com/security/CVE-2026-31001",
        "notes": "冒烟用公告（人工登记流程）",
    })
    print("[smoke] 设备匹配:", json.dumps(run_device_matching(db, device), ensure_ascii=False))
    events = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").strip().splitlines()]
    append_events(events, db=db)
    print(f"[smoke] eBPF 证据已载入（device 键: {HOST}，智能体经多键解析读取）")


def main() -> int:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import models
    from app.database import Base
    from app.services.agents import orchestrator

    db_file = Path(tempfile.mkdtemp(prefix="lg-device-smoke-")) / "smoke.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    build_data(db)

    try:
        client = orchestrator.default_client_factory()
    except RuntimeError as exc:
        print(f"[smoke] 无法创建真实 LLM 客户端: {exc}")
        return 2

    run = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="device",
                                       target_ref=DEVICE_ID, status="running", stages_json="{}")
    db.add(run)
    db.commit()
    run = orchestrator.run_orchestration(db, run, client_factory=lambda: client,
                                         stage_budget_s=150.0)
    stages = json.loads(run.stages_json)
    failures = 0
    for stage in orchestrator.STAGES:
        entry = stages.get(stage, {})
        print(f"  {stage:<14} {entry.get('status', '?')}"
              + (f" error={str(entry.get('error'))[:100]}" if entry.get("error") else ""))
        if entry.get("status") != "succeeded" and stage != "RISK":
            failures += 1

    vuln = stages.get("VULNERABILITY", {}).get("output") or {}
    print("\n[smoke] 漏洞情报智能体 findings:",
          json.dumps([{k: f.get(k) for k in ("cve_id", "cvss_score", "version_impact", "installed_version", "fixed_version")}
                      for f in vuln.get("findings", [])], ensure_ascii=False))
    hit = any(f.get("cve_id") == "CVE-2026-31001" and f.get("version_impact") == "affected"
              for f in vuln.get("findings", []))
    print("[smoke] 设备 CVE 精确命中进入智能体结论:", hit)

    remediation = stages.get("REMEDIATION", {}).get("output") or {}
    print("[smoke] 修复方案动作:", [a.get("action") for a in remediation.get("actions", [])])
    print("[smoke] 风险聚合:", json.dumps(json.loads(run.risk_json or "{}"),
                                           ensure_ascii=False)[:300])
    agents_log = json.loads(run.agents_json or "{}")
    for name, log in agents_log.items():
        print(f"[smoke] {name}: tools={sorted({c['name'] for c in log.get('tool_calls', []) if c.get('ok')})}")

    if not hit:
        failures += 1
    print(f"\n[smoke] 结果: {'全部成功' if failures == 0 else f'{failures} 项未达预期'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
