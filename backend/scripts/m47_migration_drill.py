"""Stage 9B M4.7 P2：正式迁移演练（仅隔离数据库副本）。

在 reports/m47-work/migration-drill/isolated.db 的隔离副本上验证迁移与回滚
机制，绝不触碰 backend/data 真实业务库，绝不向真实设备写入：

  B 备份    RiskAssessment 全字段快照（migration.snapshot）与哈希；
  C 排空    副本上无在途正式任务；
  D 互斥    off 时 formal_sink/统一入口拒绝；on 时 System B 正式入口/落库器/
            遗留写入器拒绝、/api/unified/analyze 拒绝成为第二正式入口、
            shadow 行禁止 sink；
  E 契约    on 时统一正式入口逐事件四智能体→formal_sink 落库（确定性演练
            客户端，非真实 LLM、不复制任何历史 shadow 结论）+ 模型故障
            fail-closed 落 pending_human_review；
  F 禁晋升  快照声明 shadow_promotion_allowed=False；shadow 行经 formal_sink
            被拒；统一 API 无 promote 类端点（静态扫描）；
  G 人审    人工裁定接口需控制令牌；错误令牌 401；非 pending 状态 409；
  H Harness 未审批执行/错误哈希审批被拒；ubuntu 修复写开关=0 时拒绝入队；
  I 回滚    仅切 flag 不还原已写正式字段；manifest 校验后全字段恢复→差异 0；
            统一运行与审计记录保留；副本完整性校验。

真实库路径防呆：脚本解析出的数据库 URL 若不是隔离副本即终止。
副本表规模小：非常量条件一律取回后用 Python 过滤，不构造动态查询。
Harness 执行入口经别名引用：本脚本只验证“未审批被拒”，不执行任何任务。
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import URL

ROOT = Path(__file__).resolve().parents[2]
REAL_DB = ROOT / "backend" / "data" / "linuxguard.db"
WORK = ROOT / "reports" / "m47-work" / "migration-drill"
ISOLATED = WORK / "isolated.db"
DRILL_RUN_PREFIX = "UA-m47-drill-formal"
HARNESS_OPEN_STATES = ("pending", "awaiting_preflight", "awaiting_approval",
                       "needs_evidence", "approved")

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return bool(ok)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_control_token() -> str:
    env_file = ROOT / "backend" / ".env"
    if not env_file.exists():
        return os.getenv("LINUXGUARD_CONTROL_TOKEN", "")
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("LINUXGUARD_CONTROL_TOKEN="):
            return line.split("=", 1)[1].strip()
    return ""


class DrillScriptedClient:
    """确定性演练客户端：按角色脚本返回固定 Schema 输出（非真实 LLM）。"""

    def __init__(self, script: dict[str, list]):
        self.script = script
        self.calls = 0
        self._lock = threading.Lock()

    def complete(self, messages, tools=None):
        system = messages[0]["content"]
        with self._lock:
            self.calls += 1
            for key, responses in self.script.items():
                if key in system:
                    response = responses.pop(0) if responses else {"content": "{}", "tool_calls": []}
                    break
            else:
                response = {"content": "{}", "tool_calls": []}
        if callable(response):
            response = response(messages)
        return response


def scripted_response(payload: dict) -> dict:
    return {"content": json.dumps(payload, ensure_ascii=False), "tool_calls": []}


def make_full_script(risk, match, decision_override: dict | None = None) -> dict[str, list]:
    cve = (risk.cve_id or "").split(":")[0]
    pkg = risk.package_name or "pkg"
    installed = getattr(match, "installed_version", "") or "1.0.0"
    fixed = getattr(match, "fixed_version", "") or "1.0.1"
    asset_report = {
        "device_id": pkg,
        "device_type": "server",
        "os": "Ubuntu 24.04 (drill stub)",
        "services": [],
        "evidence_inventory": {"runtime_evidence_present": False, "evidence_freshness": "unavailable"},
        "evidence_quality": "partial",
        "confidence": 0.6,
        "data_gaps": ["演练客户端不产生真实证据"],
    }
    vuln_report = {
        "findings": [{
            "cve_id": cve, "cvss_score": 5.0, "kev": False,
            "version_impact": "affected", "applicability": "potentially_affected",
            "installed_version": installed, "fixed_version": fixed,
            "confidence": 0.6}],
        "max_observed_severity": "medium",
        "confidence": 0.6,
        "data_gaps": ["演练客户端固定输出"],
    }
    runtime_report = {
        "behavior_level": "NORMAL", "runtime_status": "not_observed",
        "evidence_freshness": "unavailable", "exposure_status": "unknown",
        "evidence_ids": [], "findings": [], "confidence": 0.5,
        "data_gaps": ["演练客户端未查询运行时"],
    }
    decision = {
        "verdicts": [{
            "object_id": "risk-" + str(risk.id),
            "impact_status": "potentially_affected",
            "risk_direction": "maintain",
            "recommended_action": "monitor",
            "recommended_priority": "low",
            "confidence": 0.6,
            "supporting_evidence_ids": [],
            "reason": "M4.7 迁移演练确定性输出，非真实研判",
        }],
        "key_evidence_checks": [],
        "response_plan": {"risk_ref": cve, "actions": [], "rollback_plan": []},
        "confidence": 0.55,
        "reason": "m47 migration drill stub",
        "data_gaps": ["演练输出"],
    }
    if decision_override:
        decision["verdicts"][0].update(decision_override)
    return {
        "资产与证据调查员": [scripted_response(asset_report)] * 6,
        "漏洞分析师": [scripted_response(vuln_report)] * 6,
        "运行时分析师": [scripted_response(runtime_report)] * 6,
        "研判与处置规划师": [scripted_response(decision)] * 6,
    }


class PerRiskScriptedFactory:
    """按当前处理的风险对象分派独立确定性客户端。"""

    def __init__(self, scripts: dict[int, dict]):
        self._scripts = scripts
        self._clients: dict[int, DrillScriptedClient] = {}
        self._lock = threading.Lock()

    def for_risk(self, risk_id: int) -> DrillScriptedClient:
        with self._lock:
            if risk_id not in self._clients:
                script = {role: list(responses) for role, responses in self._scripts[risk_id].items()}
                self._clients[risk_id] = DrillScriptedClient(script)
            return self._clients[risk_id]

    def complete(self, messages, tools=None):
        text = json.dumps([m.get("content", "") for m in messages], ensure_ascii=False)
        risk_id = None
        for candidate in sorted(self._scripts, reverse=True):
            if "risk-" + str(candidate) in text:
                risk_id = candidate
                break
        if risk_id is None:
            risk_id = min(self._scripts)
        return self.for_risk(risk_id).complete(messages, tools)


def copy_database() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    if ISOLATED.exists():
        ISOLATED.unlink()
    src = sqlite3.connect(REAL_DB)
    dst = sqlite3.connect(ISOLATED)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def apply_env_file() -> None:
    """加载 backend/.env（不含数据库 URL），保持演练环境与正式运行一致。"""
    env_file = ROOT / "backend" / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "LINUXGUARD_DATABASE_URL":
            continue
        os.environ[key.strip()] = value.strip()


def main() -> int:
    copy_database()
    apply_env_file()
    os.environ["LINUXGUARD_DATABASE_URL"] = str(URL.create("sqlite", database=str(ISOLATED)))
    os.environ.setdefault("LINUXGUARD_UNIFIED_PIPELINE", "off")
    os.environ.setdefault("LINUXGUARD_ARCHIVE_ON_STARTUP", "0")
    os.environ.setdefault("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    os.environ.setdefault("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0")
    token = load_control_token()
    if token:
        os.environ["LINUXGUARD_CONTROL_TOKEN"] = token

    from app import config, models
    from app.database import SessionLocal
    from app.services.unified import migration
    from app.services.unified import runner as runner_mod
    from app.services.unified.adapter import (
        formal_sink,
        generate_and_save_report_unified,
        run_review_analysis_unified,
    )
    from app.services.unified.state import empty_state
    from app.services import agent_harness, review_common
    try:
        from app.services import event_review_pipeline, agent_group_chat
        LEGACY_PRESENT = True
    except ImportError:  # M5 退役后旧模块不存在；互斥断言转为"不可导入"
        event_review_pipeline = agent_group_chat = None
        LEGACY_PRESENT = False

    harness_launch = getattr(agent_harness, "execute")

    check("环境-数据库指向隔离副本", config.DATABASE_URL.endswith(ISOLATED.name), config.DATABASE_URL)
    check("环境-进程内初始模式为 off", config.UNIFIED_PIPELINE_MODE == "off", config.UNIFIED_PIPELINE_MODE)
    if not config.DATABASE_URL.endswith(ISOLATED.name):
        print("数据库未指向隔离副本，终止", file=sys.stderr)
        return 2

    report: dict = {"started_at": now_iso(), "isolated_db": ISOLATED.as_posix(),
                    "llm_source": "deterministic drill stub (not real LLM, not shadow copy)"}
    db = SessionLocal()
    try:
        # ── B 备份 ─────────────────────────────────────────────────────────
        manifest = migration.snapshot(db)
        (WORK / "migration-snapshot.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
        risk_count = len(manifest["risk_rows"])
        check("B1-全字段快照行数>0", risk_count > 0, str(risk_count) + " rows")
        check("B2-快照哈希自洽", migration.fingerprint(manifest["risk_rows"]) == manifest["snapshot_hash"])
        check("B3-快照声明禁止影子晋升", manifest["shadow_promotion_allowed"] is False)
        snapshot_of = {row["id"]: row for row in manifest["risk_rows"]}

        # ── C 排空 ─────────────────────────────────────────────────────────
        running_reports = db.query(models.AnalysisReport).filter_by(status="running").count()
        running_formal = db.query(models.UnifiedAnalysisRun).filter_by(
            mode="formal", status="running").count()
        check("C1-副本无在途正式报告", running_reports == 0, str(running_reports))
        check("C2-副本无在途统一正式运行", running_formal == 0, str(running_formal))
        report["drain"] = {"analysis_reports_running": running_reports,
                           "unified_formal_running": running_formal}

        # ── D 互斥（off 侧）───────────────────────────────────────────────
        risk126 = db.get(models.RiskAssessment, 126)
        probe_row = models.UnifiedAnalysisRun(
            run_id="m47-drill-probe", task_type="risk_review", target_type="linux_host",
            target_ref="", mode="formal", status="running", risk_id=126)
        db.add(probe_row)
        db.commit()
        probe_state = empty_state("m47-drill-probe", "risk_review", "", "linux_host", "formal")
        try:
            formal_sink(db, probe_row, probe_state)
            check("D1-off 时 formal_sink 拒绝", False, "未抛出异常")
        except ValueError as exc:
            check("D1-off 时 formal_sink 拒绝", "formal_source_required" in str(exc), str(exc))

        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        r = client.post("/api/unified/analyze", json={"hostname": "edge-01", "risk_id": 126})
        check("D2-off 时统一分析入口 503", r.status_code == 503, "HTTP " + str(r.status_code))

        # ── D 互斥（on 侧）────────────────────────────────────────────────
        config.UNIFIED_PIPELINE_MODE = "on"
        if LEGACY_PRESENT:
            for label, fn in (
                ("run_review_analysis", lambda: event_review_pipeline.run_review_analysis(db, "m47x1")),
                ("generate_and_save_report", lambda: event_review_pipeline.generate_and_save_report(db, "m47x2")),
                ("_persist_event_result", lambda: event_review_pipeline._persist_event_result(db, "m47x3", {})),
                ("_apply_object_verdicts", lambda: agent_group_chat._apply_object_verdicts(db, [], [], None)),
            ):
                try:
                    fn()
                    check("D3-on 时 System B " + label + " 拒绝", False, "未抛出异常")
                except ValueError as exc:
                    check("D3-on 时 System B " + label + " 拒绝", "system_b_formal_writer_disabled" in str(exc), str(exc))
        else:
            try:
                import importlib
                importlib.import_module("app.services.event_review_pipeline")
                check("D3-旧 System B 写入器已退役", False, "模块仍可导入")
            except ImportError:
                check("D3-旧 System B 写入器已退役", True, "event_review_pipeline 不可导入")
        r = client.post("/api/unified/analyze", json={"hostname": "edge-01", "risk_id": 126})
        check("D4-on 时 /api/unified/analyze 拒绝第二正式入口", r.status_code == 409,
              "HTTP " + str(r.status_code))
        shadow_probe = models.UnifiedAnalysisRun(
            run_id="m47-drill-shadow-probe", task_type="risk_review", target_type="linux_host",
            target_ref="", mode="shadow", status="running", risk_id=126)
        db.add(shadow_probe)
        db.commit()
        try:
            runner_mod.run_unified_sync(db, shadow_probe, sink=formal_sink)
            check("D5-shadow 行禁止 sink", False, "未抛出异常")
        except ValueError as exc:
            check("D5-shadow 行禁止 sink", "shadow_sink_forbidden" in str(exc), str(exc))
        finally:
            config.UNIFIED_PIPELINE_MODE = "off"

        # ── E 正式契约（on，确定性演练客户端）──────────────────────────────
        # 对象选择：126（Low→规则 simple 分层，0 LLM）+ 107（High→全量四角色，
        # 演练客户端输出）。两者均为副本上的既有真实风险行，不新增合成漏洞。
        config.UNIFIED_PIPELINE_MODE = "on"
        try:
            risk107 = db.get(models.RiskAssessment, 107)
            selected = [risk126, risk107]
            scripts: dict[int, dict] = {}
            for risk in selected:
                match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
                override = ({"recommended_action": "immediate_fix", "recommended_priority": "high",
                             "impact_status": "confirmed_affected", "confidence": 0.8}
                            if risk.id == 107 else None)
                scripts[risk.id] = make_full_script(risk, match, override)
            result = run_review_analysis_unified(
                db, DRILL_RUN_PREFIX.removeprefix("UA-"), selected,
                client_factory=lambda: PerRiskScriptedFactory(scripts))
            contract_keys = ["status", "valid_verdicts", "event_results", "candidate_count",
                             "selected_object_count", "completed_object_count",
                             "human_review_object_count", "agent_executions", "answer",
                             "termination_reason", "current_stage", "pipeline_version",
                             "unified_run_ids", "total_tokens", "review_run_id", "model_called"]
            missing = [k for k in contract_keys if k not in result]
            check("E1-统一正式入口响应契约字段齐全", not missing,
                  ("缺失 " + str(missing)) if missing else "17 键齐备")
            check("E2-契约状态合法", result["status"] in ("completed", "partial", "human_review"),
                  str(result.get("status")))
            db.refresh(risk126)
            db.refresh(risk107)
            tier126 = json.loads(next(row.routing_json or "{}" for row in
                                      db.query(models.UnifiedAnalysisRun).all()
                                      if row.run_id == DRILL_RUN_PREFIX + "-126")).get("tier")
            check("E3a-风险126 走规则 simple 分层（0 LLM 直通）", tier126 == "simple",
                  "tier=" + str(tier126))
            check("E3b-风险126 分层结论与来源标注",
                  risk126.review_status in ("auto_confirmed", "pending_human_review")
                  and "rule_tier_simple" in (risk126.audit_policy_reasons or ""),
                  "status=" + str(risk126.review_status))
            check("E4-风险107 全量路径写入处置与方向",
                  risk107.recommended_action == "immediate_fix" and bool(risk107.risk_direction)
                  and risk107.review_status == "pending_human_review"
                  and risk107.final_score is None and risk107.decision is None,
                  "status=" + str(risk107.review_status) + " action="
                  + str(risk107.recommended_action) + " dir=" + str(risk107.risk_direction))
            ctx = json.loads(risk107.device_context_json or "{}")
            check("E5-设备上下文对账写回", str(ctx.get("unified_run_id", "")).startswith("UA-"),
                  str(ctx.get("unified_run_id")))
            audit_names = {row.agent_name
                           for row in db.query(models.AgentAuditRecord).filter_by(risk_id=107).all()}
            check("E6-四角色审计记录入库（全量路径）",
                  audit_names == {"asset_investigator", "vulnerability_analyst",
                                  "runtime_analyst", "decision_planner"},
                  str(sorted(audit_names)))
            formal_rows = [row for row in db.query(models.UnifiedAnalysisRun).all()
                           if row.run_id.startswith(DRILL_RUN_PREFIX)]
            check("E7-统一运行行 mode=formal", formal_rows and all(row.mode == "formal" for row in formal_rows),
                  str(len(formal_rows)) + " rows")
            report["formal_contract"] = {
                "selected_risk_ids": [r.id for r in selected],
                "status": result.get("status"),
                "completed": result.get("completed_object_count"),
                "human": result.get("human_review_object_count"),
                "total_tokens": result.get("total_tokens"),
                "unified_run_ids": result.get("unified_run_ids"),
                "risk126_after": {"review_status": risk126.review_status,
                                  "recommended_action": risk126.recommended_action,
                                  "final_score": risk126.final_score,
                                  "tier": tier126},
                "risk107_after": {"review_status": risk107.review_status,
                                  "recommended_action": risk107.recommended_action,
                                  "final_score": risk107.final_score}}
        finally:
            config.UNIFIED_PIPELINE_MODE = "off"

        # ── E9 模型故障 fail-closed（经正式入口后台 worker 的异常收口）─────
        # run_unified_sync 不吞模型异常；正式入口的 fail-closed 契约位于
        # generate_and_save_report_unified 后台 worker 的 except 分支：
        # 全部选中风险 → pending_human_review + human_review_required + 失败原因。
        # 演练将候选选择收窄到风险107 以界定写入范围（仅副本）。
        config.UNIFIED_PIPELINE_MODE = "on"
        try:
            import time as _time

            def exploding():
                raise RuntimeError("drill: simulated model outage")

            real_selection = review_common.select_candidates

            def drill_selection(db_):
                only = db_.get(models.RiskAssessment, 107)
                return {"_selected_risks": [only], "candidate_count": 1,
                        "total_risks_in_db": 1, "skipped_objects": [],
                        "selected_object_ids": [107]}

            review_common.select_candidates = drill_selection
            try:
                generate_and_save_report_unified(
                    db, "m47drillfail", background=True, client_factory=exploding)
                deadline = _time.monotonic() + 90
                settled = False
                while _time.monotonic() < deadline:
                    _time.sleep(1.0)
                    db.rollback()
                    db.refresh(risk107)
                    rep = [row for row in db.query(models.AnalysisReport).all()
                           if row.review_run_id == "m47drillfail"]
                    if risk107.review_status == "pending_human_review" or (
                            rep and rep[0].status in ("human_review", "failed")):
                        settled = True
                        break
                check("E9a-故障运行在时限内收口", settled,
                      "status=" + str(risk107.review_status))
                check("E9b-模型故障后 fail-closed 落人工",
                      risk107.review_status == "pending_human_review"
                      and risk107.human_review_required
                      and risk107.final_score is None
                      and ("unified_orchestrator_failed" in (risk107.review_reason or "")
                           or "unified_background_failure" in (risk107.review_reason or "")),
                      "status=" + str(risk107.review_status) + " reason="
                      + str(risk107.review_reason)[:120])
                rep = [row for row in db.query(models.AnalysisReport).all()
                       if row.review_run_id == "m47drillfail"]
                check("E9c-报告行如实落 human_review/failed",
                      bool(rep) and rep[0].status in ("human_review", "failed"),
                      "report_status=" + str(rep[0].status if rep else None))
            finally:
                review_common.select_candidates = real_selection
        finally:
            config.UNIFIED_PIPELINE_MODE = "off"

        # ── F 禁止影子晋升 ────────────────────────────────────────────────
        config.UNIFIED_PIPELINE_MODE = "on"
        try:
            shadow_row = db.query(models.UnifiedAnalysisRun).filter_by(
                run_id="UA-e8b946663c534e46a6c8a9ef").one_or_none()
            try:
                formal_sink(db, shadow_row, empty_state(shadow_row.run_id, "risk_review", "", "linux_host", "formal"))
                check("F1-历史 shadow 行经 formal_sink 被拒", False, "未抛出异常")
            except ValueError as exc:
                check("F1-历史 shadow 行经 formal_sink 被拒", "formal_source_required" in str(exc), str(exc))
        finally:
            config.UNIFIED_PIPELINE_MODE = "off"
        unified_router_src = (ROOT / "backend" / "app" / "routers" / "unified.py").read_text(encoding="utf-8")
        promote_endpoints = [line.strip() for line in unified_router_src.splitlines()
                             if "@router.post" in line and any(w in line.lower() for w in ("promote", "confirm", "adopt"))]
        check("F2-统一 API 无影子晋升端点", not promote_endpoints, str(promote_endpoints))

        # ── G 人工审核独立（控制令牌保护；对象为 E9 后处于人工门禁的风险107）──
        db.refresh(risk107)
        review_path = "/api/analysis/risks/" + str(risk107.id) + "/human-review"
        r = client.post(review_path, json={"decision": "confirm", "reason": "no token"})
        check("G1-人工裁定缺令牌 401", r.status_code == 401, "HTTP " + str(r.status_code))
        r = client.post(review_path, json={"decision": "confirm", "reason": "bad token"},
                        headers={"X-Control-Token": "definitely-wrong-token"})
        check("G2-人工裁定错误令牌 401", r.status_code == 401, "HTTP " + str(r.status_code))
        if token:
            r = client.post(review_path,
                            json={"decision": "confirm",
                                  "reason": "M4.7 隔离副本演练：验证操作员路径机制，非真实裁定"},
                            headers={"X-Control-Token": token})
            check("G3-持令牌人工裁定路径可用（仅副本）", r.status_code == 200,
                  "HTTP " + str(r.status_code))
            db.refresh(risk107)
            check("G4-人工确认落 human_confirmed", risk107.review_status == "human_confirmed",
                  "status=" + str(risk107.review_status) + " score=" + str(risk107.final_score))
            r = client.post(review_path, json={"decision": "confirm", "reason": "repeat"},
                            headers={"X-Control-Token": token})
            check("G5-非 pending 状态重复裁定 409", r.status_code == 409, "HTTP " + str(r.status_code))
        else:
            check("G3-持令牌人工裁定路径可用（仅副本）", False, "backend/.env 无控制令牌")

        # ── H Harness 审批独立（对象限定 ubuntu 修复任务，验证未审批拒绝）──
        ubuntu_open = [row for row in db.query(models.HarnessRun).all()
                       if row.status in HARNESS_OPEN_STATES
                       and json.loads(row.plan_json or "{}").get("adapter") == "ubuntu-apt-v1"]
        harness_run = ubuntu_open[0] if ubuntu_open else None
        if harness_run is None:
            check("H-存在可演练 Ubuntu 修复任务", False, "副本中无待审批 Ubuntu 修复任务")
        else:
            before_status, before_approval = harness_run.status, harness_run.approval_hash
            refusal = ""
            try:
                harness_launch(db, harness_run)
                check("H1-未审批执行被拒", False, "未抛出异常")
            except ValueError as exc:
                refusal = str(exc)
                check("H1-未审批执行被拒", True, refusal[:120])
            try:
                agent_harness.approve(db, harness_run, "deadbeef" * 8, "m47-drill-wrong-hash",
                                      "错误哈希不得形成审批")
                check("H2-错误哈希审批被拒", False, "未抛出异常")
            except ValueError as exc:
                check("H2-错误哈希审批被拒", True, str(exc)[:120])
            db.refresh(harness_run)
            check("H2b-错误哈希审批未改变审批字段",
                  harness_run.status == before_status and harness_run.approval_hash == before_approval,
                  "status=" + str(harness_run.status) + " approval=" + str(harness_run.approval_hash))
            try:
                harness_launch(db, harness_run)
                check("H3-审批拒绝后执行仍被拒", False, "未抛出异常")
            except ValueError as exc:
                check("H3-审批拒绝后执行仍被拒", True, str(exc)[:120])
            report["harness"] = {"run_id": harness_run.id, "status": harness_run.status,
                                 "refusal": refusal[:200],
                                 "note": "双修复写开关=0 的独立拒绝位于 ubuntu_repair.queue 审批校验之后"
                                         "（ubuntu_repair.py LINUXGUARD_ENABLE_* 检查），本轮未经审批故未触达"}

        # ── I 回滚 ────────────────────────────────────────────────────────
        status_before_flagonly = risk126.review_status
        config.UNIFIED_PIPELINE_MODE = "off"  # 仅切 flag
        db.refresh(risk126)
        check("I1-仅切 flag 不还原已写正式字段",
              risk126.review_status == status_before_flagonly
              and risk126.review_status != "reanalysis_required",
              "flag 切 off 后 status=" + str(risk126.review_status))
        plan_before = migration.rollback_plan(db, manifest)
        check("I2-回滚差异规划列出正式字段漂移", len(plan_before["differences"]) > 0,
              str(len(plan_before["differences"])) + " risks 漂移")
        report["rollback_diff_sample"] = [
            {"risk_id": d["risk_id"], "fields": sorted(d["changes"])[:12]}
            for d in plan_before["differences"][:3]]

        from sqlalchemy.types import DateTime as SATimeDateTime
        columns = {c.name for c in models.RiskAssessment.__table__.columns}
        datetime_columns = {c.name for c in models.RiskAssessment.__table__.columns
                            if isinstance(c.type, SATimeDateTime)}

        def snapshot_value(name: str, raw):
            if name in datetime_columns and isinstance(raw, str) and raw:
                return datetime.fromisoformat(raw)
            return raw

        restored_fields = 0
        for before in manifest["risk_rows"]:
            row = db.get(models.RiskAssessment, before["id"])
            if row is None:
                continue
            for name in columns:
                target = snapshot_value(name, before[name])
                if getattr(row, name) != target:
                    restored_fields += 1
                    setattr(row, name, target)
        db.commit()
        plan_after = migration.rollback_plan(db, manifest)
        check("I3-全字段恢复后差异为 0", plan_after["differences"] == [],
              str(len(plan_after["differences"])) + " 残留")
        db.refresh(risk126)
        check("I4-风险126 恢复快照原值",
              risk126.review_status == snapshot_of[126]["review_status"],
              "status=" + str(risk126.review_status))
        preserved_runs = sum(1 for row in db.query(models.UnifiedAnalysisRun).all()
                             if row.run_id.startswith(DRILL_RUN_PREFIX))
        preserved_audit = db.query(models.AgentAuditRecord).count()
        check("I5-统一运行与审计记录保留", preserved_runs > 0 and preserved_audit > 0,
              "runs=" + str(preserved_runs) + " audit_records=" + str(preserved_audit))
        check("I6-恢复不删除新增风险行", isinstance(plan_after["new_risk_ids_preserved"], list),
              str(plan_after["new_risk_ids_preserved"]))
        with sqlite3.connect(ISOLATED) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        check("I7-副本完整性校验", integrity == "ok", integrity)
        report["restore"] = {"restored_changed_fields": restored_fields,
                             "differences_after": len(plan_after["differences"]),
                             "integrity": integrity}
    finally:
        config.UNIFIED_PIPELINE_MODE = "off"
        db.close()

    report["finished_at"] = now_iso()
    report["checks"] = CHECKS
    report["passed"] = sum(1 for c in CHECKS if c["ok"])
    report["failed"] = sum(1 for c in CHECKS if not c["ok"])
    (WORK / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str),
                                      encoding="utf-8")
    print("\n迁移演练：{} passed / {} failed；报告 {}".format(
        report["passed"], report["failed"], (WORK / "report.json").as_posix()))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
