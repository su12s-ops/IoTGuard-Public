#!/usr/bin/env python3
"""智能体 + Harness 黑盒闭环检测器（纯 HTTP，不导入后端任何代码）。

设计目标（黑盒 = 只经公开 HTTP 契约观察，不读源码内部状态、不直连数据库）：

1. 契约面：服务存活、四智能体规格、流水线模式、写开关、修复产物登记表；
2. 内嵌证据：Harness 能力查询、候选意图、预检反馈、计划审批闸门确实发生在
   四智能体链路内部（体现在 run 的 final.harness_feedback /
   candidate_intents / plan_execution_mode / plan.requires_approval）；
3. 闭环：影子研判 → Harness 计划（绑定影子候选）→ 审批边界 → 执行 →
   结果落库 → Trace 收尾 → 重复执行被状态机阻断；
4. 失败面：写开关关闭时修复计划 fail-closed；未授权请求 401；计划哈希不匹配 409；
   资产锁、预算、尝试次数边界不越权。

安全边界：本检测器不执行任何设备写操作。修复类任务最多推进到"待审批"边界，
执行阶段只允许只读调查任务（goal=investigate）。任何 side_effect 工具调用一旦
出现即判为失败。

用法：
    python scripts/agent_blackbox.py --base-url http://127.0.0.1:8000 --risk-id 28
    python scripts/agent_blackbox.py --scope contract,harness        # 不调用模型
    python scripts/agent_blackbox.py --run-id UA-...                 # 复用已完成的影子运行

令牌解析顺序：--token > --token-env 指定的环境变量 > LINUXGUARD_CONTROL_TOKEN
> backend/.env(.local) 中的 LINUXGUARD_CONTROL_TOKEN。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "agent-blackbox-v2"
ROOT = Path(__file__).resolve().parents[1]
HARNESS_CONTRACT = "unified-harness-readonly-v1"
WRITE_TOOLS = {"install_registered_package", "install_rollback_package"}


# ── HTTP 传输层（唯一与系统交互的边界） ─────────────────────────────────────


class Response:
    def __init__(self, status: int, body, text: str = "", headers=None):
        self.status = status
        self.body = body
        self.text = text
        self.headers = headers or {}

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Response {self.status}>"


class Transport:
    """最小 HTTP 客户端；可被替换为 ASGI/内存传输以便在进程内复用同一套检查。"""

    def __init__(self, base_url: str, token: str = "", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # 子类/测试可覆盖该钩子注入自定义传输
    def _send(self, method: str, url: str, data: bytes | None, headers: dict):
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as raw:
                text = raw.read().decode("utf-8", "replace")
                return Response(raw.status, _json_or_text(text), text, dict(raw.headers))
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            return Response(exc.code, _json_or_text(text), text, dict(exc.headers or {}))
        except urllib.error.URLError as exc:
            raise ConnectionError(f"{method} {url} 不可达: {exc.reason}") from exc

    def request(self, method: str, path: str, payload=None, token=None,
                headers: dict | None = None) -> Response:
        url = self.base_url + path if path.startswith("/") else path
        body = None
        final = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode()
            final["Content-Type"] = "application/json"
        use = self.token if token is None else token
        if use:
            final["X-Control-Token"] = use
        final.update(headers or {})
        return self._send(method, url, body, final)

    def get(self, path: str, **kwargs) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, payload=None, **kwargs) -> Response:
        return self.request("POST", path, payload, **kwargs)


def _json_or_text(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


# ── 记录器 ──────────────────────────────────────────────────────────────────


class Recorder:
    """检查项记录：pass / fail / skip / info。fail 决定退出码。"""

    def __init__(self, fail_fast: bool = False):
        self.rows: list[dict] = []
        self.fail_fast = fail_fast
        self.data: dict = {}

    def add(self, phase: str, name: str, status: str, detail: str = "", **data) -> dict:
        row = {"phase": phase, "name": name, "status": status,
               "detail": str(detail)[:1500]}
        if data:
            row["data"] = data
        self.rows.append(row)
        if status == "fail" and self.fail_fast:
            raise SystemExit(1)
        return row

    def check(self, phase: str, name: str, ok: bool, detail: str = "", **data) -> bool:
        self.add(phase, name, "pass" if ok else "fail", detail, **data)
        return bool(ok)

    def equal(self, phase: str, name: str, actual, expected, **data) -> bool:
        ok = actual == expected
        return self.check(phase, name, ok,
                          f"期望={expected!r} 实际={actual!r}" if not ok else f"{actual!r}", **data)

    def info(self, phase: str, name: str, detail: str = "", **data) -> None:
        self.add(phase, name, "info", detail, **data)

    def skip(self, phase: str, name: str, reason: str) -> None:
        self.add(phase, name, "skip", reason)

    def counts(self) -> dict:
        out = {"pass": 0, "fail": 0, "skip": 0, "info": 0}
        for row in self.rows:
            out[row["status"]] = out.get(row["status"], 0) + 1
        return out

    @property
    def failed(self) -> bool:
        return any(row["status"] == "fail" for row in self.rows)


# ── 分层判定：「契约通过」不等于「研判成功」 ────────────────────────────────
#
# 2026-10-20 实测的两个运行都是「运行 completed、契约全部通过」，但
# runtime/vulnerability/decision 三角色降级、candidate_intents 为空。原报告只有一个
# 全局 PASS/FAIL，把这种状态记成「通过」，与「研判成功」混为一谈。这里把结论拆成三层：
#   contract：服务/规格/授权边界/目标解析（不调用模型即可判定）
#   closure ：Harness 闭环、修复面 fail-closed、Trace 链
#   analysis：四智能体真实研判产出（角色无降级 + 有可用结论）

PHASE_LAYER = {
    "contract": "contract", "authz": "contract", "target": "contract",
    "harness": "closure", "repair": "closure", "trace": "closure",
    "agent": "analysis", "embedding": "analysis",
}
LAYER_ORDER = ("contract", "closure", "analysis")
LAYER_LABEL = {"contract": "契约面", "closure": "闭环面", "analysis": "研判面"}


def analysis_outcome(detail: dict) -> dict:
    """研判面结论：completed 不等于研判成功。

    succeeded 需要同时满足：运行 completed、无降级角色、至少产出可用结论
    （决策 verdicts 或候选意图）。needs_evidence 这类「如实收口但无计划」记为
    degraded（带原因），不再冒充成功。
    """
    if not detail:
        return {"status": "not_run", "reasons": ["未执行研判（scope 未包含 agent，或未提供 run-id）"]}
    reasons: list[str] = []
    degraded = list(detail.get("degraded_roles") or [])
    if detail.get("status") != "completed":
        reasons.append(f"run_status={detail.get('status')}")
    if degraded:
        reasons.append("degraded_roles=" + ",".join(degraded))
    final = detail.get("final") or {}
    intents = final.get("candidate_intents") or []
    verdicts = (detail.get("decision") or {}).get("verdicts") or []
    mode = final.get("plan_execution_mode")
    if not intents and not verdicts:
        reasons.append(f"no_usable_output(plan_execution_mode={mode})")
    stages = detail.get("stage_status") or {}
    failed_stages = sorted(k for k, v in stages.items() if v == "failed")
    if failed_stages:
        reasons.append("failed_stages=" + ",".join(failed_stages))
    status = "succeeded" if not reasons else ("failed" if detail.get("status") == "failed" else "degraded")
    return {"status": status, "reasons": reasons, "degraded_roles": degraded,
            "candidate_intents": len(intents), "verdicts": len(verdicts),
            "plan_execution_mode": mode, "failed_stages": failed_stages}


def classify_verdicts(rec: "Recorder", scopes: set[str], detail: dict) -> dict:
    """把检查项按层归一：not_run / pass / degraded / fail，并给出总判定。

    - not_run：该层本次没有执行（例如只跑 contract 不调模型）；
    - degraded：契约与闭环都通过，但研判没有产出可用结论——必须与「通过」区分；
    - fail：该层有失败检查项。
    """
    by_layer: dict[str, dict] = {layer: {"status": "not_run", "checks": 0, "failed": []}
                                 for layer in LAYER_ORDER}
    for row in rec.rows:
        layer = PHASE_LAYER.get(row["phase"])
        if not layer:
            continue
        by_layer[layer]["checks"] += 1
        if row["status"] == "fail":
            by_layer[layer]["failed"].append(f"{row['phase']}/{row['name']}")
    for layer in LAYER_ORDER:
        if by_layer[layer]["checks"] == 0:
            continue
        by_layer[layer]["status"] = "fail" if by_layer[layer]["failed"] else "pass"
    analysis = analysis_outcome(detail)
    if by_layer["analysis"]["checks"]:
        if by_layer["analysis"]["status"] == "pass" and analysis["status"] != "succeeded":
            by_layer["analysis"]["status"] = ("degraded" if analysis["status"] == "degraded"
                                              else analysis["status"])
        by_layer["analysis"]["reasons"] = analysis["reasons"]
        by_layer["analysis"]["degraded_roles"] = analysis["degraded_roles"]
        by_layer["analysis"]["candidate_intents"] = analysis["candidate_intents"]
        by_layer["analysis"]["plan_execution_mode"] = analysis["plan_execution_mode"]
    executed = [layer for layer in LAYER_ORDER if by_layer[layer]["status"] != "not_run"]
    if any(by_layer[layer]["status"] == "fail" for layer in executed):
        overall = "fail"
    elif any(by_layer[layer]["status"] == "degraded" for layer in executed):
        overall = "degraded"
    else:
        overall = "pass"
    return {"overall": overall, "layers": by_layer,
            "analysis": analysis, "executed": executed,
            "note": ("契约面通过只表示服务契约与授权边界符合声明，不代表研判产出可用结论。"
                     if "analysis" not in executed else
                     "研判面结论独立判定；契约面通过不能替代它。")}


EXIT_CODES = {"pass": 0, "degraded": 3, "fail": 1}


# ── 阶段 1：契约与边界 ──────────────────────────────────────────────────────


def phase_contract(t: Transport, rec: Recorder) -> dict:
    phase = "contract"
    health = t.get("/api/health")
    rec.equal(phase, "健康检查 HTTP 200", health.status, 200)
    body = health.body or {}
    rec.equal(phase, "健康检查状态", body.get("status"), "ok")
    rec.equal(phase, "数据库可用", body.get("database"), "ok")
    rec.check(phase, "分层状态可核验", isinstance(body.get("layers"), dict) and "backend_online" in (body.get("layers") or {}),
              "health.layers 缺失" if not isinstance(body.get("layers"), dict) else "backend_online 存在")

    specs = t.get("/api/unified/specs")
    rec.equal(phase, "统一规格 HTTP 200", specs.status, 200)
    spec = specs.body or {}
    agents = spec.get("agents") or []
    rec.equal(phase, "四智能体数量", len(agents), 4)
    names = {item.get("name") for item in agents}
    rec.check(phase, "智能体角色集合",
              names == {"asset_investigator", "vulnerability_analyst", "runtime_analyst", "decision_planner"},
              sorted(names))
    rec.check(phase, "图拓扑含 harness 预检节点",
              "harness_precheck" in json.dumps(spec.get("topology") or {}, ensure_ascii=False)
              or "decide" in (spec.get("topology") or {}),
              "topology.decide 存在" if (spec.get("topology") or {}).get("decide") else "topology 缺失")
    rec.equal(phase, "正式入口声明", spec.get("formal_entry"), "/api/analysis")
    rec.check(phase, "流水线模式可核验", spec.get("mode") in {"off", "shadow", "on"}, f"mode={spec.get('mode')}")
    rec.info(phase, "写开关状态",
             f"device_repair={spec.get('device_repair_enabled')} "
             f"ubuntu_lab={spec.get('ubuntu_lab_repair_enabled')} "
             f"openwrt_lab_scope={spec.get('ubuntu_lab_asset_scope_declared')}")
    rec.data["specs"] = spec

    status = t.get("/api/analysis/status")
    rec.equal(phase, "研判状态 HTTP 200", status.status, 200)
    rec.check(phase, "模型已配置", bool((status.body or {}).get("configured")),
              f"model={(status.body or {}).get('model')}")

    preflight = t.get("/api/analysis/preflight")
    rec.equal(phase, "候选预检 HTTP 200", preflight.status, 200)
    pre = preflight.body or {}
    rec.check(phase, "候选统计可核验",
              isinstance(pre.get("selected_object_count"), int) and "candidate_count" in pre,
              f"candidates={pre.get('candidate_count')} selected={pre.get('selected_object_count')}")
    rec.data["preflight"] = {k: pre.get(k) for k in ("candidate_count", "selected_object_count",
                                                     "total_risks_in_db", "status", "pipeline_version")}

    artifacts = t.get("/api/harness/artifacts")
    if artifacts.status == 200:
        rows = artifacts.body or []
        rec.check(phase, "修复产物登记表可读", isinstance(rows, list), f"{len(rows)} 条登记产物")
        rec.data["artifacts"] = rows
    else:
        rec.info(phase, "修复产物登记表不可用", f"status={artifacts.status}（未配置清单属预期）")
        rec.data["artifacts"] = []
    return spec


def phase_authorization(t: Transport, rec: Recorder) -> None:
    phase = "authz"
    rec.equal(phase, "无令牌创建 Harness 任务被拒",
              t.post("/api/harness/runs", {"asset_id": 1, "goal": "investigate"}, token="").status, 401)
    rec.equal(phase, "无令牌发起研判被拒",
              t.post("/api/analysis/runs", token="").status, 401)
    rec.equal(phase, "无令牌发起影子研判被拒",
              t.post("/api/unified/shadow", {"asset_id": 1}, token="").status, 401)
    rec.equal(phase, "错误令牌被拒",
              t.post("/api/harness/runs", {"asset_id": 1, "goal": "investigate"},
                     token="blackbox-wrong-token").status, 401)
    # 只读端点：设计上允许未授权读取，如实记录，不计失败。
    for path in ("/api/harness/runs", "/api/unified/runs", "/api/traces"):
        rec.info(phase, f"只读端点未要求令牌 {path}", f"status={t.get(path, token='').status}")


# ── 阶段 2：目标解析 ────────────────────────────────────────────────────────


def resolve_target(t: Transport, rec: Recorder, asset_id: int, risk_id: int) -> tuple[int, int, str]:
    """确定被测对象：显式参数优先；否则取该资产上排名最高的 active 风险。"""
    phase = "target"
    assets = t.get("/api/assets")
    if assets.status != 200 or not isinstance(assets.body, list):
        rec.add(phase, "资产列表可读", "fail", f"status={assets.status}")
        return asset_id, risk_id, ""
    known = {row.get("id"): row for row in assets.body}
    if asset_id not in known:
        rec.add(phase, "资产存在", "fail", f"asset_id={asset_id} 不在 {sorted(known)}")
        return asset_id, risk_id, ""
    asset = known[asset_id]
    rec.info(phase, "被测资产", f"#{asset_id} {asset.get('hostname')} {asset.get('distribution')} "
                              f"repair_domain={asset.get('repair_domain')}")
    rec.check(phase, "资产清单完整", bool(asset.get("inventory_complete")),
              f"inventory_complete={asset.get('inventory_complete')}")

    if risk_id:
        ranking = t.get("/api/risk/ranking")
        rows = ranking.body if isinstance(ranking.body, list) else []
        hit = next((row for row in rows if row.get("risk_id") == risk_id), None)
        if not hit:
            rec.add(phase, "风险存在", "fail", f"risk_id={risk_id} 未在风险排行中")
            return asset_id, risk_id, ""
        rec.equal(phase, "风险属于被测资产", hit.get("asset_id"), asset_id)
        rec.check(phase, "风险处于可执行状态", bool(hit.get("active")),
                  f"active={hit.get('active')} review_status={hit.get('review_status')}")
        rec.data["risk"] = {k: hit.get(k) for k in ("risk_id", "cve_id", "package_name", "review_status", "rank")}
        return asset_id, risk_id, asset.get("hostname", "")

    ranking = t.get("/api/risk/ranking")
    rows = [row for row in (ranking.body if isinstance(ranking.body, list) else [])
            if row.get("asset_id") == asset_id and row.get("active")]
    if not rows:
        rec.add(phase, "资产存在可执行风险", "fail", f"asset_id={asset_id} 无 active 风险")
        return asset_id, risk_id, asset.get("hostname", "")
    best = sorted(rows, key=lambda row: (row.get("rank") or 10 ** 6))[0]
    rec.info(phase, "自动选择风险", f"risk={best.get('risk_id')} {best.get('cve_id')} {best.get('package_name')}")
    rec.data["risk"] = {k: best.get(k) for k in ("risk_id", "cve_id", "package_name", "review_status", "rank")}
    return asset_id, int(best["risk_id"]), asset.get("hostname", "")


# ── 阶段 3：四智能体研判（可选调用模型） ────────────────────────────────────


def phase_agent(t: Transport, rec: Recorder, asset_id: int, risk_id: int,
                run_id: str, timeout_s: float, interval_s: float) -> dict:
    phase = "agent"
    if not run_id:
        created = t.post("/api/unified/shadow", {
            "asset_id": asset_id, "risk_id": risk_id,
            "investigation_goal": "黑盒闭环检测：只做只读研判，输出处置计划与证据引用，不执行设备写。"})
        rec.equal(phase, "影子研判受理 HTTP 202", created.status, 202)
        if created.status != 202:
            return {}
        run_id = (created.body or {}).get("run_id", "")
        rec.check(phase, "影子运行号返回", bool(run_id), f"run_id={run_id}")
        rec.equal(phase, "影子运行不具正式权限", (created.body or {}).get("formal_authority"), False)
    else:
        rec.info(phase, "复用既有运行", f"run_id={run_id}")

    started = time.time()
    detail, last = {}, ""
    while True:
        response = t.get(f"/api/unified/runs/{run_id}")
        if response.status != 200:
            rec.add(phase, "轮询运行详情", "fail", f"status={response.status} {response.text[:300]}")
            return {}
        detail = response.body or {}
        state = detail.get("status")
        if state != last:
            last = state
            rec.info(phase, f"运行状态 {state}", f"elapsed={time.time() - started:.0f}s")
        if state in {"completed", "failed"}:
            break
        if time.time() - started > timeout_s:
            rec.add(phase, "运行在超时内结束", "fail",
                    f"status={state} elapsed={time.time() - started:.0f}s timeout={timeout_s:.0f}s")
            rec.data["run"] = detail
            return detail
        time.sleep(interval_s)

    rec.equal(phase, "运行最终状态", detail.get("status"), "completed")
    rec.check(phase, "运行错误为空", not detail.get("error"), detail.get("error") or "")
    rec.equal(phase, "运行模式", detail.get("mode"), "shadow")
    rec.equal(phase, "运行绑定被测目标", detail.get("risk_id"), risk_id)
    stages = detail.get("stage_status") or {}
    for stage in ("prepare", "prepare_evidence", "investigate_asset", "analyze_vulnerability",
                  "analyze_runtime", "detect_conflicts", "decide", "harness_precheck", "finalize"):
        rec.check(phase, f"阶段执行 {stage}", stages.get(stage) in {"succeeded", "failed"},
                  f"status={stages.get(stage)}")
    rec.info(phase, "阶段结果", json.dumps(stages, ensure_ascii=False))
    degraded = detail.get("degraded_roles") or []
    rec.info(phase, "降级角色", json.dumps(degraded, ensure_ascii=False))
    collaboration = (detail.get("final") or {}).get("collaboration") or {}
    if collaboration:
        rec.info(phase, "四角色全量执行",
                 f"full_four_role_execution={collaboration.get('full_four_role_execution')} "
                 f"stop_reason={collaboration.get('stop_reason') or '无'}")
    usage = detail.get("usage") or {}
    rec.info(phase, "模型开销", json.dumps({k: usage.get(k) for k in ("llm_calls", "total_tokens", "budget_exceeded")},
                                        ensure_ascii=False))
    rec.data["run"] = {k: detail.get(k) for k in ("run_id", "status", "trace_id", "mode", "risk_id",
                                                  "target_ref", "degraded_roles")}
    rec.data["run"]["full_four_role_execution"] = collaboration.get("full_four_role_execution")
    rec.data["run_stages"] = stages
    return detail


def phase_embedding(t: Transport, rec: Recorder, detail: dict) -> None:
    """核验 Harness 确实嵌在四智能体链路内部，而不是旁路。"""
    phase = "embedding"
    if not detail:
        rec.skip(phase, "内嵌核验", "无已完成运行可核验")
        return
    final = detail.get("final") or {}
    feedback = final.get("harness_feedback") or {}
    rec.equal(phase, "预检契约", feedback.get("contract"), HARNESS_CONTRACT)
    rec.check(phase, "预检为只读", feedback.get("read_only") is True, f"read_only={feedback.get('read_only')}")
    rec.check(phase, "预检不授予执行权", feedback.get("execution_authorized") is False,
              f"execution_authorized={feedback.get('execution_authorized')}")
    rec.check(phase, "预检不写设备", feedback.get("device_writes") is False,
              f"device_writes={feedback.get('device_writes')}")
    rec.check(phase, "预检状态可核验", feedback.get("status") in
              {"executable", "authorization_required", "policy_denied", "no_action"} or bool(feedback),
              f"status={feedback.get('status')} terminal={feedback.get('terminal')}")

    intents = final.get("candidate_intents") or []
    rec.check(phase, "候选意图进入运行结论", isinstance(intents, list), f"{len(intents)} 条意图")
    rec.check(phase, "候选意图永不持执行权",
              all(item.get("execution_authorized") is False for item in intents),
              f"unsatisfied={[i.get('unsatisfied_conditions') for i in intents][:3]}")
    for item in intents:
        rec.check(phase, f"意图绑定确定性身份 {item.get('intent_id')}",
                  bool(item.get("asset_id")) and bool(item.get("risk_id")),
                  f"asset={item.get('asset_id')} risk={item.get('risk_id')} action={item.get('action_type')}")
        rec.check(phase, f"意图要求审批 {item.get('intent_id')}",
                  item.get("requires_approval") is True, f"requires_approval={item.get('requires_approval')}")

    plan = detail.get("plan") or {}
    mode = final.get("plan_execution_mode")
    rec.check(phase, "计划为待审批执行模式", mode in {"pending_approval", "blocked"},
              f"plan_execution_mode={mode}")
    if plan:
        rec.check(phase, "程序强制计划需审批", plan.get("requires_approval") is True,
                  f"requires_approval={plan.get('requires_approval')}")
        rec.check(phase, "计划执行方式非自动", plan.get("execution_authorized") in {None, False},
                  f"execution_authorized={plan.get('execution_authorized')}")
    rec.check(phase, "harness 检查链接可查询", isinstance(detail.get("harness_checks"), list),
              f"{len(detail.get('harness_checks') or [])} 条关联")
    rec.data["embedding"] = {
        "feedback_status": feedback.get("status"), "terminal": feedback.get("terminal"),
        "reasons": feedback.get("reasons", [])[:10], "plan_execution_mode": mode,
        "intent_count": len(intents), "reasons_from_harness": (feedback.get("reasons") or [])[:10],
    }


# ── 阶段 4：Harness 闭环 ────────────────────────────────────────────────────


def poll_run(t: Transport, run_id: str, timeout_s: float = 120.0,
             interval_s: float = 2.0) -> dict:
    started = time.time()
    while True:
        response = t.get(f"/api/harness/runs/{run_id}")
        if response.status != 200:
            raise RuntimeError(f"查询 Harness 任务失败 status={response.status}")
        detail = response.body or {}
        if detail.get("status") not in {"running", "pending_execute"}:
            return detail
        if time.time() - started > timeout_s:
            return detail
        time.sleep(interval_s)


def phase_harness(t: Transport, rec: Recorder, asset_id: int, risk_id: int,
                  shadow_run_id: str, allow_link: bool) -> dict:
    phase = "harness"
    payload = {"asset_id": asset_id, "risk_id": risk_id, "goal": "investigate"}
    if allow_link and shadow_run_id:
        payload["shadow_run_id"] = shadow_run_id
    created = t.post("/api/harness/runs", payload)
    rec.equal(phase, "创建只读调查任务 HTTP 200", created.status, 200)
    if created.status != 200:
        rec.data["harness_create"] = {"status": created.status, "body": created.text[:600]}
        return {}
    run = created.body or {}
    run_id = run.get("id", "")
    rec.check(phase, "任务号返回", bool(run_id), f"id={run_id}")
    plan = run.get("plan") or {}
    rec.equal(phase, "计划目标", plan.get("goal"), "investigate")
    rec.check(phase, "计划哈希生成", bool(run.get("plan_hash")) and len(run.get("plan_hash") or "") == 64,
              f"plan_hash={run.get('plan_hash')}")
    rec.check(phase, "计划含策略版本与预算", bool(plan.get("policy_version")) and bool(plan.get("limits")),
              f"policy={plan.get('policy_version')} limits={plan.get('limits')}")
    if allow_link and shadow_run_id:
        candidate = plan.get("shadow_candidate") or {}
        rec.equal(phase, "计划绑定影子候选", candidate.get("run_id"), shadow_run_id)
        rec.check(phase, "影子候选不构成授权", candidate.get("authorization"), "none" if candidate else None)
    rec.equal(phase, "只读任务初始状态", run.get("status"), "pending")

    # 只读任务没有审批前置：审批入口必须拒绝，避免出现"假审批"路径
    rejected = t.post(f"/api/harness/runs/{run_id}/approve",
                      {"plan_hash": run.get("plan_hash"), "actor": "blackbox-detector",
                       "reason": "只读调查任务不应存在审批环节"})
    rec.equal(phase, "只读任务拒绝审批入口", rejected.status, 409)

    exec_response = t.post(f"/api/harness/runs/{run_id}/execute")
    rec.equal(phase, "执行受理 HTTP 200", exec_response.status, 200)
    detail = poll_run(t, run_id)
    status = detail.get("status")
    rec.check(phase, "执行进入终态", status in {"completed", "needs_evidence"},
              f"status={status} error={detail.get('error')}")
    calls = detail.get("tool_calls") or []
    rec.check(phase, "产生工具调用记录", len(calls) >= 2, f"{len(calls)} 次调用")
    rec.check(phase, "无任何写副作用", not any(call.get("side_effect") for call in calls),
              f"side_effect={[c.get('tool') for c in calls if c.get('side_effect')]}")
    tools = [call.get("tool") for call in calls]
    rec.check(phase, "只读工具集合", set(tools) <= {"collect_inventory", "inspect_inventory",
                                                 "inspect_runtime", "inspect_evidence"},
              f"tools={tools}")
    result = detail.get("result") or {}
    rec.check(phase, "结果含缺失证据清单", "missing_evidence" in result,
              f"missing={result.get('missing_evidence')}")
    rec.check(phase, "结果含运行时覆盖", "runtime_coverage" in result,
              f"coverage_status={(result.get('runtime_coverage') or {}).get('status')}")
    rec.equal(phase, "尝试次数为 1", detail.get("attempts"), 1)

    # 状态机：已成功的任务不得重复执行；证据不足是"有界可续跑"，不是成功。
    repeated = t.post(f"/api/harness/runs/{run_id}/execute")
    final_status, attempts = status, detail.get("attempts")
    if status == "completed":
        rec.equal(phase, "终态任务拒绝重复执行", repeated.status, 409)
        rec.equal(phase, "终态任务不能取消", t.post(f"/api/harness/runs/{run_id}/cancel").status, 409)
    else:
        rec.equal(phase, "证据不足允许有界续跑", repeated.status, 200)
        if repeated.status == 200:
            again = poll_run(t, run_id)
            attempts = again.get("attempts")
            rec.equal(phase, "续跑计入尝试次数", attempts, 2)
            rec.check(phase, "续跑仍无写副作用",
                      not any(call.get("side_effect") for call in (again.get("tool_calls") or [])),
                      f"{len(again.get('tool_calls') or [])} 次调用")
            cancelled = t.post(f"/api/harness/runs/{run_id}/cancel")
            rec.equal(phase, "可取消任务被收口", cancelled.status, 200)
            final_status = (cancelled.body or {}).get("status") or final_status
            rec.equal(phase, "取消后进入终态", final_status, "cancelled")
    rec.check(phase, "Trace 已关联", bool(detail.get("trace_id")), f"trace_id={detail.get('trace_id')}")
    rec.data["harness"] = {"run_id": run_id, "status": status, "final_status": final_status,
                           "plan_hash": detail.get("plan_hash"),
                           "trace_id": detail.get("trace_id"), "tools": tools,
                           "attempts": attempts,
                           "missing_evidence": result.get("missing_evidence")}
    return detail


def phase_repair_failclosed(t: Transport, rec: Recorder, asset_id: int, risk_id: int) -> None:
    """修复面：在写开关关闭时应 fail-closed，且绝不产生写调用。"""
    phase = "repair"
    created = t.post("/api/harness/runs", {
        "asset_id": asset_id, "risk_id": risk_id, "goal": "repair", "artifact_id": ""})
    if created.status not in {200, 400}:
        rec.add(phase, "修复计划创建返回契约内状态", "fail", f"status={created.status} {created.text[:300]}")
        return
    if created.status == 400:
        rec.info(phase, "修复计划被创建期拒绝", f"{created.text[:200]}")
        return
    run = created.body or {}
    status = run.get("status")
    plan = run.get("plan") or {}
    rec.check(phase, "缺产物修复计划被阻断或待审批", status in {"blocked", "awaiting_approval"},
              f"status={status} blocked_reasons={(plan.get('blocked_reasons') or [])[:4]}")
    rec.check(phase, "阻断原因可核验", bool(plan.get("blocked_reasons")) or status == "awaiting_approval",
              json.dumps((plan.get("blocked_reasons") or [])[:4], ensure_ascii=False))
    rec.check(phase, "计划未产生工具调用", (run.get("tool_calls") or []) == [], f"{len(run.get('tool_calls') or [])} 条")
    run_id = run.get("id", "")
    if status == "blocked":
        rec.equal(phase, "阻断任务不可审批", t.post(
            f"/api/harness/runs/{run_id}/approve",
            {"plan_hash": run.get("plan_hash"), "actor": "blackbox-detector",
             "reason": "黑盒检测：阻断任务不应可审批"}).status, 409)
        rec.equal(phase, "阻断任务不可执行", t.post(f"/api/harness/runs/{run_id}/execute").status, 409)
    elif status == "awaiting_approval":
        rec.equal(phase, "错误计划哈希被拒", t.post(
            f"/api/harness/runs/{run_id}/approve",
            {"plan_hash": "0" * 64, "actor": "blackbox-detector",
             "reason": "黑盒检测：故意提交错误计划哈希"}).status, 409)
        rec.equal(phase, "撤销待审批任务", t.post(f"/api/harness/runs/{run_id}/cancel").status, 200)
    rec.data["repair"] = {"run_id": run_id, "status": status,
                          "blocked_reasons": (plan.get("blocked_reasons") or [])[:6]}


# ── 阶段 5：Trace 与证据链 ──────────────────────────────────────────────────


def phase_trace(t: Transport, rec: Recorder, trace_id: str, expect_agent: bool,
                expect_harness: bool = True) -> None:
    phase = "trace"
    if not trace_id:
        rec.skip(phase, "Trace 链核验", "无 trace_id")
        return
    detail = t.get(f"/api/traces/{trace_id}")
    rec.equal(phase, "Trace 详情 HTTP 200", detail.status, 200)
    if detail.status != 200:
        return
    body = detail.body or {}
    events = body.get("events") or []
    types = [event.get("event_type", "") for event in events]
    rec.check(phase, "事件流非空", len(events) > 0, f"{len(events)} 条事件")
    rec.check(phase, "Trace 已收口", body.get("status") in {"completed", "failed", "blocked"},
              f"status={body.get('status')}")
    if expect_agent:
        rec.check(phase, "含智能体事件", any(t.startswith("agent_") for t in types),
                  f"{[t for t in types if t.startswith('agent_')][:6]}")
        rec.check(phase, "含阶段事件", "stage_finished" in types, "stage_finished 存在" if "stage_finished" in types else "缺失")
    harness_events = t.get(f"/api/traces/{trace_id}/harness")
    rec.equal(phase, "Harness 事件端点 HTTP 200", harness_events.status, 200)
    harness_types = [event.get("event_type", "") for event in (harness_events.body or {}).get("events", [])]
    if expect_harness:
        rec.check(phase, "Harness 事件入库", any(t.startswith("harness_") for t in harness_types),
                  f"{harness_types[:6]}")
        rec.check(phase, "Harness 事件含计划与收尾",
                  {"harness_plan", "harness_finished"} & set(harness_types) != set(),
                  f"{sorted(set(harness_types))[:8]}")
    else:
        # 纯研判 Trace 不派发 Harness 任务：关联状态必须是 not_requested/not_applicable。
        rec.check(phase, "研判 Trace 不伪造 Harness 关联",
                  (harness_events.body or {}).get("association") in
                  {"not_requested", "not_applicable", "linked"},
                  f"association={(harness_events.body or {}).get('association')}")
    rec.data["trace"] = {"trace_id": trace_id, "status": body.get("status"),
                         "event_count": len(events),
                         "harness_event_types": sorted(set(harness_types))[:10],
                         "agent_event_types": sorted({t for t in types if t.startswith("agent_")})[:10]}


# ── 报告 ────────────────────────────────────────────────────────────────────


def _layer_line(name: str, info: dict) -> str:
    text = f"{LAYER_LABEL[name]}=**{info['status']}**"
    details = []
    if info.get("reasons"):
        details.append("；".join(info["reasons"][:3]))
    if info.get("failed"):
        details.append("失败项=" + ", ".join(info["failed"][:3]))
    if details:
        text += "（" + "；".join(details) + "）"
    return text


def render_markdown(meta: dict, rec: Recorder, verdicts: dict | None = None) -> str:
    counts = rec.counts()
    verdicts = verdicts or {}
    overall = (verdicts.get("overall") or ("fail" if rec.failed else "pass")).upper()
    layers = verdicts.get("layers") or {}
    lines = [
        "# 智能体 + Harness 黑盒闭环检测报告",
        "",
        f"- 总判定：**{overall}**（pass={counts['pass']} fail={counts['fail']} "
        f"skip={counts['skip']} info={counts['info']}）",
    ]
    if layers:
        lines.append("- 分层判定：" + "　".join(_layer_line(name, layers[name])
                                            for name in LAYER_ORDER if name in layers))
        lines.append(f"- 口径：{verdicts.get('note', '')}")
    lines += [
        f"- 检测器：{meta.get('version')}　目标：{meta.get('base_url')}",
        f"- 开始：{meta.get('started_at')}　耗时：{meta.get('duration_s'):.1f}s",
        f"- 被测资产：#{meta.get('asset_id')}　风险：#{meta.get('risk_id')}",
        f"- 影子运行：`{meta.get('agent_run_id') or '未执行'}`　"
        f"Harness 任务：`{meta.get('harness_run_id') or '未执行'}`",
        "",
        "> 边界：本次检测不执行任何设备写操作；修复面只验证到审批/阻断边界。"
        "通过不代表设备已修复、业务已签收或安全验收完成。",
        "> 口径：契约面通过只说明服务契约与授权边界符合声明；研判产出是否可用见「分层判定」的研判面。",
        "",
        "## 检查明细",
        "",
        "| 阶段 | 检查项 | 结果 | 细节 |",
        "|---|---|---|---|",
    ]
    icons = {"pass": "✅", "fail": "❌", "skip": "➖", "info": "ℹ️"}
    for row in rec.rows:
        detail = row["detail"].replace("|", "\\|")
        if len(detail) > 220:
            detail = detail[:220] + "…"
        lines.append(f"| {row['phase']} | {row['name']} | {icons.get(row['status'], row['status'])} "
                     f"{row['status']} | {detail} |")
    if rec.failed:
        lines += ["", "## 失败项", ""]
        for row in rec.rows:
            if row["status"] == "fail":
                lines.append(f"- **{row['phase']} / {row['name']}**：{row['detail']}")
    analysis = verdicts.get("analysis") or {}
    if analysis.get("status") == "degraded":
        lines += ["", "## 研判面降级（契约通过 ≠ 研判成功）", ""]
        for reason in analysis.get("reasons") or []:
            lines.append(f"- {reason}")
        if analysis.get("degraded_roles"):
            lines.append(f"- 降级角色：{', '.join(analysis['degraded_roles'])}")
        lines.append(f"- 可用结论：candidate_intents={analysis.get('candidate_intents')} "
                     f"verdicts={analysis.get('verdicts')} "
                     f"plan_execution_mode={analysis.get('plan_execution_mode')}")
    lines.append("")
    return "\n".join(lines)


def write_reports(meta: dict, rec: Recorder, out_dir: Path, stamp: str,
                  verdicts: dict | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    verdicts = verdicts or {}
    overall = verdicts.get("overall") or ("fail" if rec.failed else "pass")
    payload = {"meta": meta, "summary": rec.counts(),
               "verdict": overall,                      # pass | degraded | fail
               "verdicts": verdicts,                    # 分层判定（contract/closure/analysis）
               "checks": rec.rows, "observations": rec.data}
    json_path = out_dir / f"agent-blackbox-{stamp}.json"
    md_path = out_dir / f"agent-blackbox-{stamp}.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(meta, rec, verdicts), encoding="utf-8")
    return json_path, md_path


# ── 令牌与入口 ──────────────────────────────────────────────────────────────


def load_token(explicit: str, env_name: str) -> str:
    if explicit:
        return explicit.strip()
    value = os.getenv(env_name or "LINUXGUARD_CONTROL_TOKEN", "").strip()
    if value:
        return value
    for candidate in (ROOT / "backend" / ".env.local", ROOT / "backend" / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^\s*LINUXGUARD_CONTROL_TOKEN\s*=\s*(.+?)\s*$", line)
            if match:
                return match.group(1).strip().strip("'\"")
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="智能体 + Harness 黑盒闭环检测器")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default="", help="控制令牌；默认读环境变量或 backend/.env")
    parser.add_argument("--token-env", default="LINUXGUARD_CONTROL_TOKEN")
    parser.add_argument("--asset-id", type=int, default=0, help="被测资产；0 表示按风险自动推断")
    parser.add_argument("--risk-id", type=int, default=0, help="被测风险；0 表示自动选取")
    parser.add_argument("--run-id", default="", help="复用已完成的统一研判运行")
    parser.add_argument("--scope", default="all",
                        help="逗号分隔：contract,authz,agent,embedding,harness,repair,trace,all")
    parser.add_argument("--no-link", action="store_true", help="Harness 计划不绑定影子候选")
    parser.add_argument("--timeout", type=float, default=3600.0, help="智能体运行等待上限（秒）")
    parser.add_argument("--poll", type=float, default=15.0, help="智能体轮询间隔（秒）")
    parser.add_argument("--out-dir", default=str(ROOT / "reports" / "agent-blackbox"))
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args(argv)

    scopes = {item.strip() for item in args.scope.split(",") if item.strip()}
    if "all" in scopes:
        scopes = {"contract", "authz", "target", "agent", "embedding", "harness", "repair", "trace"}

    token = load_token(args.token, args.token_env)
    if not token:
        print("错误：未找到控制令牌（--token / 环境变量 / backend/.env）", file=sys.stderr)
        return 2

    rec = Recorder(fail_fast=args.fail_fast)
    transport = Transport(args.base_url, token, timeout=60.0)
    started = time.time()
    started_at = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    meta = {"version": VERSION, "base_url": args.base_url, "started_at": started_at,
            "scope": sorted(scopes), "asset_id": args.asset_id, "risk_id": args.risk_id}

    try:
        spec = {}
        if "contract" in scopes:
            spec = phase_contract(transport, rec)
        if "authz" in scopes:
            phase_authorization(transport, rec)

        asset_id, risk_id = args.asset_id, args.risk_id
        target_ready = False
        if scopes & {"target", "agent", "harness", "repair"}:
            asset_id, risk_id, hostname = resolve_target(transport, rec, args.asset_id, args.risk_id)
            meta.update({"asset_id": asset_id, "risk_id": risk_id, "hostname": hostname})
            target_ready = bool(asset_id and risk_id)

        detail: dict = {}
        if "agent" in scopes:
            if not target_ready:
                rec.skip("agent", "四智能体研判", "未解析到可用资产/风险")
            else:
                detail = phase_agent(transport, rec, asset_id, risk_id,
                                     args.run_id, args.timeout, args.poll)
                meta["agent_run_id"] = (detail or {}).get("run_id", args.run_id)
                meta["agent_trace_id"] = (detail or {}).get("trace_id", "")
        elif args.run_id:
            response = transport.get(f"/api/unified/runs/{args.run_id}")
            detail = response.body or {} if response.status == 200 else {}
            meta["agent_run_id"] = args.run_id
            meta["agent_trace_id"] = detail.get("trace_id", "")

        if "embedding" in scopes:
            phase_embedding(transport, rec, detail)

        harness_detail: dict = {}
        if "harness" in scopes:
            if not target_ready:
                rec.skip("harness", "Harness 闭环", "未解析到可用资产/风险")
            else:
                harness_detail = phase_harness(transport, rec, asset_id, risk_id,
                                               meta.get("agent_run_id", ""), not args.no_link)
                meta["harness_run_id"] = harness_detail.get("id", "")
                meta["harness_trace_id"] = harness_detail.get("trace_id", "")

        if "repair" in scopes:
            if not target_ready:
                rec.skip("repair", "修复面 fail-closed", "未解析到可用资产/风险")
            else:
                phase_repair_failclosed(transport, rec, asset_id, risk_id)

        if "trace" in scopes:
            if meta.get("harness_trace_id"):
                phase_trace(transport, rec, meta["harness_trace_id"], expect_agent=False)
            elif meta.get("agent_trace_id"):
                phase_trace(transport, rec, meta["agent_trace_id"], expect_agent=True,
                            expect_harness=False)
            else:
                rec.skip("trace", "Trace 链核验", "本次未产生 trace_id")

    except ConnectionError as exc:
        rec.add("transport", "服务可达", "fail", str(exc))
    except KeyboardInterrupt:  # pragma: no cover
        rec.add("runtime", "人工中断", "skip", "检测被中断，已保留已完成检查")
    finally:
        meta["duration_s"] = time.time() - started
        counts = rec.counts()
        verdicts = classify_verdicts(rec, scopes, detail)
        overall = verdicts["overall"]
        meta["verdicts"] = {layer: verdicts["layers"][layer]["status"] for layer in LAYER_ORDER}
        meta["overall"] = overall
        if not args.no_report:
            stamp = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
            json_path, md_path = write_reports(meta, rec, Path(args.out_dir), stamp, verdicts)
            print(f"报告：{md_path}")
            print(f"数据：{json_path}")
        print(f"结果：{overall.upper()} "
              f"(pass={counts['pass']} fail={counts['fail']} skip={counts['skip']} info={counts['info']}) "
              f"耗时={meta['duration_s']:.1f}s")
        for layer in LAYER_ORDER:
            info = verdicts["layers"][layer]
            if info["status"] != "not_run":
                print(f"  {LAYER_LABEL[layer]}: {info['status']}"
                      + (f"（{'；'.join(info.get('reasons') or [])}）" if info.get("reasons") else ""))
        for row in rec.rows:
            if row["status"] == "fail":
                print(f"  ❌ {row['phase']}/{row['name']}: {row['detail']}")
    return EXIT_CODES.get(overall, 1)


if __name__ == "__main__":
    raise SystemExit(main())
