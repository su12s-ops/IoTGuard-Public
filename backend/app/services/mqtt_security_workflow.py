"""MQTT 匿名接入修复工作流（阶段四 Demo）。

流程与真实动作一一对应，禁止只改数据库状态：

    DETECTED（真实 MQTT CONNECT 探测：匿名 rc=0 → allow_anonymous=true）
    → Agent 分析生成白名单修复方案（backup_file / change_config / restart_service）
    → REMEDIATING（设备侧真实备份、修改配置、重启服务）
    → VERIFYING（重新真实探测：匿名连接必须失败；认证用户连接必须成功）
    → RESOLVED 或 ROLLBACK（验证失败自动恢复原配置并复核）

探测函数构造真实 MQTT 3.1.1 CONNECT 报文（支持 username/password），
适配真 mosquitto 与模拟器两种 broker。
"""
from __future__ import annotations

import hashlib
import json
import socket
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app import models

SCENARIO = "mqtt_anonymous"
STATUS_ORDER = ["DETECTED", "REMEDIATING", "VERIFYING", "RESOLVED", "ROLLBACK", "FAILED"]


def _mqtt_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def _build_connect_packet(client_id: str, username: str | None = None,
                          password: str | None = None) -> bytes:
    flags = 0x02  # clean session
    payload = _mqtt_string(client_id)
    if username is not None:
        flags |= 0x80
        payload += _mqtt_string(username)
    if password is not None:
        flags |= 0x40
        payload += _mqtt_string(password)
    variable = _mqtt_string("MQTT") + bytes([0x04, flags, 0x00, 0x3C])
    body = variable + payload
    return bytes([0x10, len(body)]) + body


def mqtt_connect_probe(host: str, port: int, username: str | None = None,
                       password: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
    """真实发起一次 MQTT CONNECT，返回 CONNACK 结果。

    返回 {"connected": bool, "return_code": int, "detail": str}
    rc=0 接受；rc=5 Not authorized；无法建立 TCP 连接返回 connected=False, error。
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_build_connect_packet("linuxguard-workflow", username, password))
            header = b""
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    break
                header += chunk
    except OSError as exc:
        return {"connected": False, "return_code": None, "error": f"{type(exc).__name__}: {exc}"}
    if len(header) < 4 or header[0] != 0x20:
        return {"connected": False, "return_code": None, "error": f"非 CONNACK 响应: {header!r}"}
    rc = header[3]
    reason = {0: "接受连接", 2: "客户端标识被拒", 4: "用户名/密码格式错误", 5: "未授权"}[rc] if rc in (0, 2, 4, 5) else "其他"
    return {"connected": rc == 0, "return_code": rc, "detail": f"CONNACK rc={rc} {reason}"}


def detect_mqtt_security(host: str, port: int, username: str = "iotadmin",
                         password: str = "demo-password") -> dict[str, Any]:
    """修复前/后共用的真实检测：匿名与认证两条 CONNECT。"""
    anonymous = mqtt_connect_probe(host, port)
    authenticated = mqtt_connect_probe(host, port, username=username, password=password)
    return {
        "host": host, "port": port,
        "anonymous": anonymous,
        "authenticated": authenticated,
        "anonymous_allowed": anonymous.get("connected") is True,
        "auth_works": authenticated.get("connected") is True,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


def create_configuration_evidence(db: Session, detection: dict[str, Any]) -> str:
    """把「allow_anonymous=true」写成 configuration 类 SecurityEvidence。"""
    digest = hashlib.sha256(json.dumps(
        {"type": "configuration", "scenario": SCENARIO, "host": detection["host"],
         "port": detection["port"], "at": detection["detected_at"]},
        sort_keys=True).encode()).hexdigest()
    evidence_id = "SE-" + digest[:16]
    if db.query(models.SecurityEvidence).filter_by(evidence_hash=digest).first():
        return evidence_id
    row = models.SecurityEvidence(
        evidence_id=evidence_id,
        evidence_hash=digest,
        device_id=str(detection["host"]),
        source="mqtt_config_probe",
        evidence_type="configuration",
        timestamp=detection["detected_at"],
        severity="error", severity_score=72,
        process="mosquitto", pid=0, user="",
        commandline=f"MQTT CONNECT {detection['host']}:{detection['port']}",
        destination_ip=str(detection["host"]), destination_port=int(detection["port"]),
        operation="anonymous_connect_accepted",
        description=(f"MQTT broker {detection['host']}:{detection['port']} 允许匿名连接"
                     f"（推断 allow_anonymous=true，CONNACK rc=0）；任意客户端可发布/订阅。"),
        raw_data=json.dumps({"detection": detection, "inference": "allow_anonymous=true"},
                            ensure_ascii=False),
    )
    db.add(row)
    db.commit()
    return evidence_id


def fallback_plan(host: str, port: int) -> dict[str, Any]:
    """确定性兜底修复方案（与 Agent 产出同属白名单动作）。"""
    return {
        "risk_ref": f"mqtt-anonymous:{host}:{port}",
        "actions": [
            {"action": "backup_file", "target": "/etc/mosquitto/mosquitto.conf",
             "params": {}, "rationale": "修改配置前先备份，供回滚使用",
             "expected_verification": "备份文件存在", "requires_approval": True},
            {"action": "change_config", "target": "mosquitto:allow_anonymous=false",
             "params": {"key": "allow_anonymous", "value": "false"},
             "rationale": "禁止匿名连接，启用密码文件认证",
             "expected_verification": "匿名 CONNECT 被拒（rc=5），认证用户 CONNECT 成功",
             "requires_approval": True},
            {"action": "restart_service", "target": "mosquitto",
             "params": {}, "rationale": "重载配置使修复生效",
             "expected_verification": "端口重新监听且行为符合新配置", "requires_approval": True},
        ],
        "verification_plan": [
            {"check": "匿名连接必须失败", "evidence_source": "MQTT CONNECT rc=5"},
            {"check": "认证用户连接必须成功", "evidence_source": "MQTT CONNECT rc=0"},
        ],
        "rollback_plan": ["restore_file /etc/mosquitto/mosquitto.conf（恢复备份）并重启服务"],
        "confidence": 0.95, "data_gaps": [], "source": "deterministic_fallback",
    }


def agent_plan(db: Session, host: str, port: int, detection: dict[str, Any],
               client_factory=None) -> dict[str, Any]:
    """用阶段三的修复智能体（真实 LLM）分析并生成白名单方案；失败用兜底方案。"""
    from app.services.agents import agents as A
    from app.services.agents.base import ToolLoopAgent
    try:
        if client_factory is None:
            from app.services.agents.orchestrator import default_client_factory
            client_factory = default_client_factory
        context = (
            f"分析目标: MQTT broker {host}:{port}。真实检测结果：匿名 CONNECT rc=0"
            f"（allow_anonymous=true，任意客户端可连接），设备 SmartCam-X1 智能摄像头。"
            "请基于此生成白名单修复方案（备份→修改配置→重启→验证），并给出回滚计划。"
        )
        result = ToolLoopAgent(A.REMEDIATION_VERIFICATION_SPEC, client_factory()).run(
            db, context=context, deadline_s=90.0)
        if result.status == "succeeded" and result.output.get("actions"):
            plan = dict(result.output)
            plan["risk_ref"] = plan.get("risk_ref") or f"mqtt-anonymous:{host}:{port}"
            plan["source"] = "agent_llm"
            return plan
        reason = result.error or "方案缺少动作"
    except Exception as exc:  # LLM 不可用等情况：记录原因并使用兜底方案
        reason = f"{type(exc).__name__}: {exc}"
    plan = fallback_plan(host, port)
    plan["data_gaps"] = [f"Agent 方案不可用，使用确定性兜底方案（{reason}）"]
    return plan


def create_workflow_run(db: Session, host: str, port: int, plan: dict[str, Any],
                        detection: dict[str, Any], evidence_id: str) -> models.RemediationWorkflowRun:
    run = models.RemediationWorkflowRun(
        run_id="RW-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid4().hex[:6],
        scenario=SCENARIO, target_host=host, target_port=port,
        status="DETECTED", evidence_id=evidence_id,
        agent_plan_json=json.dumps(plan, ensure_ascii=False),
        before_json=json.dumps(detection, ensure_ascii=False),
    )
    db.add(run)
    db.commit()
    return run


def apply_report(db: Session, run: models.RemediationWorkflowRun, phase: str,
                 payload: dict[str, Any], commands: list[str] | None = None) -> models.RemediationWorkflowRun:
    """设备侧执行器上报真实动作结果，驱动状态机。"""
    if phase == "action":
        run.status = "REMEDIATING"
        run.actions_json = json.dumps(payload.get("actions", []), ensure_ascii=False)
    elif phase == "after":
        run.status = "VERIFYING"
        run.after_json = json.dumps(payload.get("after", payload), ensure_ascii=False)
    elif phase == "verify":
        verified = bool(payload.get("verified"))
        run.verification_json = json.dumps(payload, ensure_ascii=False)
        run.status = "RESOLVED" if verified else "FAILED"
        if verified:
            run.completed_at = models.utcnow()
    elif phase == "rollback":
        run.rollback_json = json.dumps(payload, ensure_ascii=False)
        run.status = "ROLLBACK"
        run.completed_at = models.utcnow()
    else:
        raise ValueError(f"未知阶段: {phase}")
    if commands:
        run.commands_json = json.dumps(commands, ensure_ascii=False)
    if run.error is None:
        run.error = ""
    run.updated_at = models.utcnow()
    db.commit()
    return run


def backend_verify(host: str, port: int, expect: dict[str, bool]) -> dict[str, Any]:
    """平台侧复核（不信任设备侧单方面上报）：重新真实探测并比对预期。

    expect 语义：修复后期望 anonymous_allowed=False（匿名被拒）、auth_works=True（认证可用）。
    """
    detection = detect_mqtt_security(host, port)
    expect_anonymous = bool(expect.get("anonymous_allowed", False))
    expect_auth = bool(expect.get("auth_works", True))
    checks = {
        "anonymous_blocked": (detection["anonymous_allowed"] is False) and (expect_anonymous is False),
        "authenticated_ok": (detection["auth_works"] is True) and (expect_auth is True),
    }
    verified = all(checks.values())
    return {"recheck": detection, "checks": checks, "verified": verified,
            "expectation": expect}


def serialize_run(row: models.RemediationWorkflowRun) -> dict[str, Any]:
    return {
        "run_id": row.run_id, "scenario": row.scenario,
        "target": f"{row.target_host}:{row.target_port}",
        "status": row.status, "evidence_id": row.evidence_id,
        "agent_plan": json.loads(row.agent_plan_json or "{}"),
        "before": json.loads(row.before_json or "{}"),
        "actions": json.loads(row.actions_json or "[]"),
        "after": json.loads(row.after_json or "{}"),
        "verification": json.loads(row.verification_json or "{}"),
        "rollback": json.loads(row.rollback_json or "{}"),
        "commands": json.loads(row.commands_json or "[]"),
        "error": row.error,
        "created_at": row.created_at, "completed_at": row.completed_at,
    }
