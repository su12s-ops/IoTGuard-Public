"""真实 LLM 冒烟测试：用 DeepSeek 真实调用重构后的四智能体与编排器。

数据全部来自真实项目模型 + 阶段二真实 eBPF 采集 fixture；
不注入任何假 LLM。运行：python scripts/smoke_real_agents.py
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
CVE = "CVE-2026-49975"


def build_data(db) -> None:
    from app import models
    from app.services.ebpf_event_collector import append_events

    asset = models.LinuxAsset(hostname=HOST, ip_address="127.0.0.1", os_name="Ubuntu",
                              os_version="22.04", distribution="ubuntu")
    db.add(asset)
    db.flush()
    db.add_all([
        models.AssetService(asset_id=asset.id, service_name="sshd", port=22, process_name="sshd"),
        models.AssetService(asset_id=asset.id, service_name="mosquitto", port=1883, process_name="mosquitto"),
        models.AssetPackage(asset_id=asset.id, package_name="openssl", package_version="1.1.1-1ubuntu0.1"),
    ])
    db.add(models.VulnerabilityInfo(cve_id=CVE, title="OpenSSL 缓冲区溢出", cvss_score=9.8,
                                    cvss_severity="Critical", affected_package="openssl",
                                    fixed_version="1.1.1-1ubuntu0.2", source="nvd"))
    db.add(models.ThreatIntelSource(cve_id=CVE, is_kev=True, epss_score=0.94, epss_percentile=0.99))
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id=CVE, package_name="openssl",
                                      installed_version="1.1.1-1ubuntu0.1",
                                      fixed_version="1.1.1-1ubuntu0.2", affected=True,
                                      match_status="potentially_affected", confidence=0.92, active=True)
    db.add(match)
    db.flush()
    db.add(models.RiskAssessment(match_id=match.id, asset_id=asset.id, cve_id=CVE,
                                 package_name="openssl", review_status="auto_confirmed",
                                 human_review_required=False, risk_level="Medium",
                                 active=True, final_score=55))
    db.commit()
    events = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").strip().splitlines()]
    append_events(events, db=db)


def main() -> int:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import models
    from app.database import Base
    from app.services.agents import agents as A
    from app.services.agents.base import ToolLoopAgent
    from app.services.agents import orchestrator

    db_file = Path(tempfile.mkdtemp(prefix="lg-agent-smoke-")) / "smoke.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    build_data(db)

    try:
        shared_client = orchestrator.default_client_factory()
    except RuntimeError as exc:
        print(f"[smoke] 无法创建真实 LLM 客户端: {exc}")
        return 2

    failures = 0
    print(f"[smoke] 目标主机: {HOST}（真实数据 + 真实 eBPF 采集）")
    for spec in A.ALL_SPECS:
        agent = ToolLoopAgent(spec, shared_client)
        result = agent.run(db, context=f"分析目标设备: {HOST}。请先调用你的工具获取真实数据再下结论。",
                           deadline_s=120.0)
        tools_used = sorted({call["name"] for call in result.tool_calls if call.get("ok")})
        print(f"\n=== {spec.name} ===")
        print(f"  status={result.status} attempts={result.attempts} latency={result.latency_ms}ms")
        print(f"  tools_used={tools_used or '无'}")
        if result.error:
            print(f"  error={result.error[:200]}")
            failures += 1
        if result.output:
            text = json.dumps(result.output, ensure_ascii=False)
            print(f"  output={text[:400]}")

    # 完整编排（真实 LLM）
    print("\n=== 完整编排 DEVICE→VULNERABILITY→RUNTIME→RISK→REMEDIATION→VERIFY ===")
    run = models.AgentOrchestrationRun(run_id=orchestrator.new_run_id(), target_type="linux_host",
                                       target_ref=HOST, status="running", stages_json="{}")
    db.add(run)
    db.commit()
    run = orchestrator.run_orchestration(db, run, client_factory=lambda: shared_client,
                                         stage_budget_s=150.0)
    stages = json.loads(run.stages_json)
    for stage in orchestrator.STAGES:
        entry = stages.get(stage, {})
        print(f"  {stage:<14} {entry.get('status', '?')}" +
              (f" error={str(entry.get('error'))[:120]}" if entry.get("error") else ""))
        if entry.get("status") != "succeeded" and stage in {"DEVICE", "VULNERABILITY", "RUNTIME", "REMEDIATION"}:
            failures += 1
    risk = json.loads(run.risk_json or "{}")
    print(f"  risk={risk.get('priority')} score={risk.get('risk_score')} runtime={risk.get('runtime_level')}")
    plan = json.loads(run.remediation_json or "{}")
    print(f"  remediation actions={[a.get('action') for a in plan.get('actions', [])]}")
    print(f"  execution={json.dumps(plan.get('execution', {}), ensure_ascii=False)[:300]}")
    task_count = db.query(models.RemediationTask).count()
    print(f"  真实修复任务数: {task_count}")
    agents_log = json.loads(run.agents_json or "{}")
    for name, log in agents_log.items():
        print(f"  agent {name}: tools={sorted({c['name'] for c in log.get('tool_calls', []) if c.get('ok')})}")

    print(f"\n[smoke] 结果: {'全部成功' if failures == 0 else f'{failures} 项失败'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
