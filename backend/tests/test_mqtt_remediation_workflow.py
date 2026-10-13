"""阶段四：MQTT 匿名接入修复工作流（模拟器真实闭环）。

不用 mock 探测：所有检测都是真实 MQTT CONNECT；
所有修复动作都真实修改配置文件并重启 broker 线程。
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

SIMULATOR_DIR = Path(__file__).resolve().parents[2] / "simulator"
if str(SIMULATOR_DIR) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_DIR))

import smartcam_x1  # noqa: E402

from app import models  # noqa: E402
from app.services import mqtt_security_workflow as W  # noqa: E402


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class MqttDevice:
    """本地 SmartCam 模拟 MQTT broker：真实配置文件 + 真实重启。"""

    def __init__(self, tmp: Path):
        self.port = _free_port()
        self.config = tmp / "mosquitto.conf"
        self.password_file = tmp / "pwfile"
        self.config.write_text("allow_anonymous true\n", encoding="utf-8")
        self.password_file.write_text("iotadmin:demo-password\n", encoding="utf-8")
        self.listener = self._start()
        self.commands: list[str] = []

    def _start(self):
        listener = smartcam_x1._MqttListener(("127.0.0.1", self.port), config_path=str(self.config))
        listener.start()
        time.sleep(0.3)
        return listener

    def restart(self):
        self.listener.stop()
        self.listener = self._start()

    def stop(self):
        self.listener.stop()

    # ── 白名单动作（真实文件操作 + 真实重启） ──
    def backup_config(self):
        backup = self.config.with_suffix(".conf.bak")
        backup.write_text(self.config.read_text(encoding="utf-8"), encoding="utf-8")
        self.commands.append(f"cp {self.config} {backup}")
        return str(backup)

    def harden_config(self):
        self.config.write_text(
            f"allow_anonymous false\npassword_file {self.password_file}\n", encoding="utf-8")
        self.commands.append(f"rewrite {self.config}: allow_anonymous false + password_file")
        self.restart()
        self.commands.append("restart mosquitto (simulated broker)")

    def corrupt_config(self):
        """模拟修改失败：password_file 指向不存在文件 → 认证必败。"""
        self.config.write_text("allow_anonymous false\npassword_file /nonexistent/pw\n", encoding="utf-8")
        self.commands.append("rewrite (bad) password_file /nonexistent/pw")
        self.restart()

    def restore_config(self, backup_path: str):
        Path(backup_path).replace(self.config)
        self.commands.append(f"restore_file {backup_path} -> {self.config}")
        self.restart()


@pytest.fixture()
def mqtt_device(tmp_path):
    device = MqttDevice(tmp_path)
    yield device
    device.stop()


@pytest.fixture()
def iot_env(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "stage4-test-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "127.0.0.0/8")


def _auth():
    return {"X-Control-Token": "stage4-test-token"}


# ── 探测原语 ─────────────────────────────────────────────────────────────────

def test_probe_detects_anonymous_before_fix(mqtt_device):
    detection = W.detect_mqtt_security("127.0.0.1", mqtt_device.port)
    assert detection["anonymous_allowed"] is True          # 修复前：匿名连接成功
    assert detection["anonymous"]["return_code"] == 0
    assert detection["authenticated"]["connected"] is True  # 认证用户同样能连


def test_probe_after_hardening(mqtt_device):
    mqtt_device.harden_config()
    detection = W.detect_mqtt_security("127.0.0.1", mqtt_device.port)
    assert detection["anonymous_allowed"] is False         # 修复后：匿名连接失败
    assert detection["anonymous"]["return_code"] == 5      # CONNACK Not authorized
    assert detection["auth_works"] is True                 # 认证用户连接正常


# ── 完整闭环（服务层直调，禁 mock 探测） ────────────────────────────────────

def test_full_workflow_resolved(session_factory, mqtt_device):
    db = session_factory()
    host, port = "127.0.0.1", mqtt_device.port
    try:
        # DETECTED：真实检测 + 证据 + 方案（LLM 用兜底，动作仍为白名单）
        detection = W.detect_mqtt_security(host, port)
        assert detection["anonymous_allowed"] is True
        evidence_id = W.create_configuration_evidence(db, detection)
        assert db.query(models.SecurityEvidence).filter_by(evidence_id=evidence_id).one().evidence_type == "configuration"

        plan = W.fallback_plan(host, port)
        run = W.create_workflow_run(db, host, port, plan, detection, evidence_id)
        assert run.status == "DETECTED"

        # REMEDIATING：真实备份 → 修改配置 → 重启
        backup = mqtt_device.backup_config()
        mqtt_device.harden_config()
        run = W.apply_report(db, run, "action", {"actions": [
            {"action": "backup_file", "target": backup, "result": "done"},
            {"action": "change_config", "target": "allow_anonymous=false", "result": "done"},
            {"action": "restart_service", "target": "mosquitto", "result": "done"},
        ]}, commands=mqtt_device.commands)
        assert run.status == "REMEDIATING"

        # VERIFYING：重新真实检测（After）
        after = W.detect_mqtt_security(host, port)
        assert after["anonymous_allowed"] is False and after["auth_works"] is True
        run = W.apply_report(db, run, "after", {"after": after})
        assert run.status == "VERIFYING"

        # RESOLVED：平台侧复核（再次真实探测）
        verification = W.backend_verify(host, port, {"anonymous_allowed": False, "auth_works": True})
        assert verification["verified"] is True
        run = W.apply_report(db, run, "verify",
                             {"verified": True, "checks": verification["checks"]})
        assert run.status == "RESOLVED"
        assert run.completed_at is not None
    finally:
        db.close()


def test_rollback_restores_original_config(session_factory, mqtt_device):
    """修改失败自动恢复：写坏配置 → 验证失败 → restore → 回到 Before 状态。"""
    db = session_factory()
    host, port = "127.0.0.1", mqtt_device.port
    try:
        detection = W.detect_mqtt_security(host, port)
        evidence_id = W.create_configuration_evidence(db, detection)
        run = W.create_workflow_run(db, host, port, W.fallback_plan(host, port),
                                    detection, evidence_id)
        backup = mqtt_device.backup_config()
        mqtt_device.corrupt_config()  # 故意写坏（修改失败场景）

        # After：认证与匿名均不可用 → 验证失败
        after = W.detect_mqtt_security(host, port)
        assert after["auth_works"] is False and after["anonymous_allowed"] is False
        verification = W.backend_verify(host, port, {"anonymous_allowed": False, "auth_works": True})
        assert verification["verified"] is False

        # 自动回滚：恢复备份并重启，复核回到 Before（匿名重新可用）
        mqtt_device.restore_config(backup)
        recheck = W.detect_mqtt_security(host, port)
        assert recheck["anonymous_allowed"] is True  # 原配置已恢复

        run = W.apply_report(db, run, "action", {"actions": [{"action": "change_config", "result": "failed_bad_password_file"}]})
        run = W.apply_report(db, run, "rollback",
                             {"reason": "配置修改后验证失败（认证不可用）",
                              "restored_from": backup,
                              "recheck_after_restore": recheck,
                              "restored_ok": recheck["anonymous_allowed"]})
        assert run.status == "ROLLBACK"
        assert json.loads(run.rollback_json)["restored_ok"] is True
    finally:
        db.close()


# ── API ──────────────────────────────────────────────────────────────────────

def test_workflow_api_end_to_end(client, session_factory, mqtt_device, iot_env):
    # 用兜底方案替代 LLM（单元测试不依赖网络）
    import app.services.mqtt_security_workflow as workflow_module
    original_agent_plan = workflow_module.agent_plan
    workflow_module.agent_plan = lambda db, host, port, detection: W.fallback_plan(host, port)
    import app.routers.remediation_workflow as router_module
    router_module.W.agent_plan = lambda db, host, port, detection: W.fallback_plan(host, port)
    try:
        response = client.post("/api/remediation/workflow/mqtt-anonymous",
                               json={"host": "127.0.0.1", "port": mqtt_device.port},
                               headers=_auth())
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["status"] == "DETECTED"
        assert data["detection"]["anonymous_allowed"] is True
        run_id = data["run_id"]

        # 不需要修复的场景：修复后再发起 → not_vulnerable
        backup = mqtt_device.backup_config()
        mqtt_device.harden_config()
        again = client.post("/api/remediation/workflow/mqtt-anonymous",
                            json={"host": "127.0.0.1", "port": mqtt_device.port},
                            headers=_auth()).json()
        assert again["status"] == "not_vulnerable"

        # 上报 action → after → verify（平台复核真实探测）
        report = client.post(f"/api/remediation/workflow/{run_id}/report",
                             json={"phase": "action", "payload": {"actions": [
                                 {"action": "backup_file", "result": "done"},
                                 {"action": "change_config", "result": "done"},
                                 {"action": "restart_service", "result": "done"}]},
                                 "commands": mqtt_device.commands},
                             headers=_auth()).json()
        assert report["status"] == "REMEDIATING"

        report = client.post(f"/api/remediation/workflow/{run_id}/report",
                             json={"phase": "verify",
                                   "payload": {"verified": True,
                                               "expectation": {"anonymous_allowed": False, "auth_works": True}}},
                             headers=_auth()).json()
        assert report["status"] == "RESOLVED"
        assert report["verification"]["platform_recheck"]["verified"] is True
        assert report["verification"]["platform_recheck"]["recheck"]["anonymous"]["return_code"] == 5

        detail = client.get(f"/api/remediation/workflow/runs/{run_id}").json()
        assert detail["status"] == "RESOLVED"
        assert detail["before"]["anonymous_allowed"] is True
        assert detail["verification"]["platform_recheck"]["recheck"]["anonymous_allowed"] is False
        assert detail["commands"], "实际执行命令清单不应为空"
        assert any("allow_anonymous false" in c for c in detail["commands"])
        assert any("restart" in c for c in detail["commands"])
    finally:
        workflow_module.agent_plan = original_agent_plan


def test_workflow_api_requires_control_token(client, mqtt_device, iot_env):
    response = client.post("/api/remediation/workflow/mqtt-anonymous",
                           json={"host": "127.0.0.1", "port": mqtt_device.port})
    assert response.status_code == 401
