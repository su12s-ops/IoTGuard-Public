"""Configurable orchestration for asset collection and runtime verification."""

from __future__ import annotations

import os
import re
import shlex
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import paramiko
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import SessionLocal, get_db
from app.services.asset_parser import parse_asset_text, save_parsed_asset
from app.services.device_access import HostKeyMismatch, PinnedHostKey, require_control
from app.services.ebpf_event_collector import append_events, clear_events, parse_event_lines, summarize_runtime_events
from app.services.kylin_security_collector import sync_kylin_asset_intelligence
from app.services.matching_engine import run_matching
from app.services.remediation_engine import generate_remediation_tasks
from app.services.risk_engine import calculate_risk
from app.services.ubuntu_security_collector import sync_ubuntu_asset_intelligence
from app.services.unified.adapter import generate_and_save_report_unified as generate_and_save_report

router = APIRouter(prefix="/demo", tags=["Demo"])

STEP_SYNC_INTEL = "同步漏洞情报（Ubuntu/麒麟）"

REPO_ROOT = Path(__file__).resolve().parents[3]
COLLECT_SCRIPT_LOCAL = REPO_ROOT / "collector" / "collect_linux_asset.sh"
CAPTURE_SCRIPT_LOCAL = REPO_ROOT / "collector" / "capture_ebpf.sh"
DEMO_EBPF_SECONDS = int(os.getenv("DEMO_EBPF_SECONDS", "30"))
DEMO_SYNC_MAX_PACKAGES = int(os.getenv("DEMO_SYNC_MAX_PACKAGES", "8"))
DEMO_SYNC_LIMIT_PER_PACKAGE = int(os.getenv("DEMO_SYNC_LIMIT_PER_PACKAGE", "10"))

_progress = {
    "running": False,
    "current_step": "",
    "current_agent": "",
    "steps_done": [],
    "total_steps": 0,
    "planned_steps": [],
    "error": "",
}


def _split_env_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_env_ports() -> list[int]:
    raw_ports = _split_env_csv(os.getenv("VM_PORTS", ""))
    if not raw_ports:
        fallback_port = os.getenv("VM_PORT", "").strip()
        raw_ports = [fallback_port] if fallback_port else []
    if not raw_ports:
        return []
    try:
        return [int(port) for port in raw_ports]
    except ValueError as exc:
        raise RuntimeError("VM_PORTS must contain only integer port values") from exc


def _expand_ssh_bootstrap_targets(
    hosts: list[str],
    ports: list[int],
) -> list[tuple[str, int]]:
    if not hosts:
        return []
    if not ports:
        ports = [22]
    if len(hosts) == 1 and len(ports) >= 1:
        return [(hosts[0], port) for port in ports]
    if len(ports) == 1:
        return [(host, ports[0]) for host in hosts]
    if len(hosts) == len(ports):
        return list(zip(hosts, ports, strict=True))
    raise RuntimeError("VM_HOSTS and VM_PORTS must have equal lengths, or define a single host with multiple ports")


def _env_ssh_targets() -> list[models.DemoTarget]:
    hosts = _split_env_csv(os.getenv("VM_HOSTS", ""))
    if not hosts:
        fallback_host = os.getenv("VM_HOST", "").strip()
        hosts = [fallback_host] if fallback_host else []
    ports = _parse_env_ports()
    labels = _split_env_csv(os.getenv("VM_LABELS", ""))
    asset_hostnames = _split_env_csv(os.getenv("VM_ASSET_HOSTNAMES", ""))
    username = os.getenv("VM_USER", "")
    targets = []
    for index, (host, port) in enumerate(_expand_ssh_bootstrap_targets(hosts, ports), 1):
        default_label = f"SSH Target {index} ({host}:{port})"
        targets.append(
            models.DemoTarget(
                label=labels[index - 1] if index <= len(labels) else default_label,
                target_type="ssh",
                enabled=True,
                host=host,
                ssh_port=port,
                username=username,
                password="",
                credential_env="VM_PASS",
                asset_hostname=asset_hostnames[index - 1] if index <= len(asset_hostnames) else "",
                collect_asset=True,
                collect_runtime=True,
            )
        )
    return targets


def _env_container_target() -> models.DemoTarget | None:
    container_name = os.getenv("BIONIC_CONTAINER", "").strip()
    if not container_name:
        return None
    return models.DemoTarget(
        label="本地容器",
        target_type="container",
        enabled=True,
        container_name=container_name,
        collect_asset=True,
        collect_runtime=True,
    )


def _bootstrap_targets(db: Session) -> None:
    if db.query(models.DemoTarget).count() > 0:
        return
    for target in _env_ssh_targets():
        db.add(target)
    container_target = _env_container_target()
    if container_target:
        db.add(container_target)
    if db.new:
        db.commit()


def _serialize_target(target: models.DemoTarget) -> dict[str, Any]:
    return {
        "id": target.id,
        "label": target.label,
        "target_type": target.target_type,
        "enabled": target.enabled,
        "host": target.host,
        "ssh_port": target.ssh_port,
        "username": target.username,
        "password_configured": bool(os.getenv(target.credential_env or "", "")),
        "credential_env": target.credential_env or "",
        "credential_migration_required": bool(target.password),
        "asset_hostname": target.asset_hostname,
        "container_name": target.container_name,
        "install_falco_if_missing": target.install_falco_if_missing,
        "collect_asset": target.collect_asset,
        "collect_runtime": target.collect_runtime,
        "notes": target.notes,
    }


def _planned_steps(targets: list[SimpleNamespace]) -> list[dict[str, str]]:
    steps = []
    for target in targets:
        if target.collect_asset:
            steps.append({"step": f"采集资产：{target.label}", "agent": "collector"})
    for target in targets:
        if target.collect_runtime:
            steps.append({"step": f"采集运行时证据：{target.label}", "agent": "collector"})
    steps.extend(
        [
            {"step": STEP_SYNC_INTEL, "agent": "collector"},
            {"step": "执行软件包命中分析", "agent": "analysis"},
            {"step": "建立候选风险与基线", "agent": "orchestrator"},
            {"step": "四智能体联合研判", "agent": "analysis"},
            {"step": "生成最终结论与整改建议", "agent": "orchestrator"},
        ]
    )
    return steps


def _reset_progress(planned_steps: list[dict[str, str]]) -> None:
    _progress["running"] = True
    _progress["current_step"] = "Initializing"
    _progress["current_agent"] = ""
    _progress["steps_done"] = []
    _progress["planned_steps"] = planned_steps
    _progress["total_steps"] = len(planned_steps)
    _progress["error"] = ""


def _mark_done(step: str, agent: str, detail: str = "", status: str = "ok") -> None:
    _progress["steps_done"].append({"step": step, "agent": agent, "detail": detail, "status": status})
    _progress["current_step"] = step
    _progress["current_agent"] = agent


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sudo_refresh(target: SimpleNamespace) -> None:
    """sudo 时间戳刷新：口令只经 SSH stdin 通道送达（sudo -S）。

    口令绝不进入远端命令行（`ps`/shell 历史不可见）；后续命令一律
    `sudo -n`（非交互，使用刚刷新的凭据缓存）。
    """
    if not target.password:
        return
    client = _ssh_connect(target)
    try:
        stdin, stdout, _stderr = client.exec_command("sudo -S -p '' -v", timeout=20)
        stdin.write(target.password + "\n")
        stdin.flush()
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    if code != 0:
        raise RuntimeError(f"{target.label} sudo 认证失败（exit={code}）")


def _sudo_prefix(target: SimpleNamespace) -> str:
    # 调用前必须先 _sudo_refresh(target)；-n 保证口令缺失时失败而非挂起
    return "sudo -n"


def _require_pinned_host_key() -> str:
    fingerprint = os.getenv("VM_HOSTKEY_SHA256", "").strip()
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise RuntimeError(
            "演示 SSH 需要预先配置可信主机指纹 VM_HOSTKEY_SHA256"
            "（格式 SHA256:Base64，可通过 ssh-keyscan 获取后经可信渠道核对）；"
            "拒绝在未校验主机身份时建立 SSH 连接")
    return fingerprint


def _ssh_connect(target: SimpleNamespace) -> paramiko.SSHClient:
    if not target.host or not target.username:
        raise RuntimeError(f"SSH target {target.label} is missing host or username")
    client = paramiko.SSHClient()
    # 与 device_access 同一主机身份策略：指纹钉扎，不匹配即拒绝（防 MITM）
    client.set_missing_host_key_policy(PinnedHostKey(_require_pinned_host_key()))
    try:
        client.connect(
            target.host,
            port=int(target.ssh_port or 22),
            username=target.username,
            password=target.password or None,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
    except HostKeyMismatch as exc:
        client.close()
        raise RuntimeError(f"{target.label} SSH 主机指纹不匹配，连接已阻止") from exc
    return client


def _ssh_put(local: Path, remote: str, target: SimpleNamespace) -> None:
    client = _ssh_connect(target)
    sftp = client.open_sftp()
    try:
        sftp.put(str(local), remote)
        # 0700：脚本由属主（上传用户或 root）执行；组/其余用户不可读改
        sftp.chmod(remote, 0o700)
    finally:
        sftp.close()
        client.close()


def _ssh_exec(cmd: str, target: SimpleNamespace, timeout: int = 200, check: bool = True) -> tuple[str, str, int]:
    client = _ssh_connect(target)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    code = stdout.channel.recv_exit_status()
    client.close()
    if check and code != 0:
        snippet = (err or out).strip().replace("\n", " ")
        raise RuntimeError(f"{target.label} ({target.host}) exit={code}: {snippet[:240]}")
    return out, err, code


def _ssh_get_bytes(remote: str, target: SimpleNamespace) -> bytes:
    client = _ssh_connect(target)
    sftp = client.open_sftp()
    try:
        with sftp.open(remote, "rb") as handle:
            return handle.read()
    finally:
        sftp.close()
        client.close()


def _asset_by_identity(db: Session, identity: str) -> models.LinuxAsset | None:
    if not identity:
        return None
    asset = db.query(models.LinuxAsset).filter_by(hostname=identity).first()
    if asset:
        return asset
    return db.query(models.LinuxAsset).filter_by(ip_address=identity).first()


def _probe_specs(packages: set[str], ports: set[int]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    package_set = {package.lower() for package in packages}

    def add(
        process_name: str,
        shell_command: str,
        *,
        event_type: str = "execve",
        category: str = "process_execution",
        severity: str = "Informational",
        rule: str = "Runtime package probe",
        destination: str = "",
        port: int = 0,
    ) -> None:
        specs.append(
            {
                "process_name": process_name,
                "commandline": shell_command,
                "shell_command": shell_command,
                "event_type": event_type,
                "category": category,
                "severity": severity,
                "rule": rule,
                "destination": destination,
                "port": port,
            }
        )

    if "bash" in package_set:
        add("bash", "bash -lc 'echo linuxguard_runtime_probe_bash'", rule="Bash runtime probe")
    if "curl" in package_set:
        add("curl", "curl --version", rule="Curl version probe")
    if "nginx" in package_set:
        add("nginx", "nginx -v", rule="Nginx version probe")
    if "openssl" in package_set:
        add("openssl", "openssl version", rule="OpenSSL version probe")
    if "openssh-server" in package_set:
        add("sshd", "sshd -T", rule="OpenSSH server probe")
    if "apache2" in package_set:
        add("apache2ctl", "apache2ctl -v", rule="Apache version probe")
    if "redis-server" in package_set:
        add("redis-server", "redis-server --version", rule="Redis version probe")
    if ("nginx" in package_set or "apache2" in package_set or 80 in ports) and "curl" in package_set:
        add(
            "curl",
            "curl -I --max-time 3 http://127.0.0.1 || true",
            event_type="connect",
            category="network_activity",
            severity="Notice",
            rule="Loopback HTTP probe",
            destination="127.0.0.1",
            port=80,
        )
    if (443 in ports or "openssl" in package_set) and "openssl" in package_set:
        add("openssl", "openssl version -a", rule="OpenSSL detail probe")
    return specs


def _build_probe_event(
    hostname: str,
    source: str,
    probe: dict[str, Any],
    stdout_text: str,
    stderr_text: str,
    exit_code: int,
) -> dict[str, Any]:
    return {
        "timestamp": _utc_now(),
        "hostname": hostname,
        "source": source,
        "event_type": probe["event_type"],
        "process_name": probe["process_name"],
        "commandline": probe["commandline"],
        "parent_process": "linuxguard-runtime-probe",
        "destination": probe["destination"],
        "port": probe["port"],
        "severity": probe["severity"],
        "rule": probe["rule"],
        "category": probe["category"],
        "raw": {
            "stdout": stdout_text.strip(),
            "stderr": stderr_text.strip(),
            "exit_code": exit_code,
            "probe": probe["shell_command"],
        },
    }


def _collect_ssh_asset(target: SimpleNamespace, db: Session) -> str:
    directory, _, _ = _ssh_exec("umask 077; mktemp -d /tmp/iotguard-XXXXXXXXXX", target)
    directory = directory.strip()
    if not re.fullmatch(r"/tmp/iotguard-[A-Za-z0-9]{10}", directory):
        raise RuntimeError("Remote private collection directory was not created")
    try:
        _ssh_put(COLLECT_SCRIPT_LOCAL, directory + "/collect.sh", target)
        _ssh_exec("BUSINESS_LEVEL=core bash " + shlex.quote(directory + "/collect.sh") + " " +
                  shlex.quote(directory + "/asset.txt"), target, timeout=180)
        asset_text = _ssh_get_bytes(directory + "/asset.txt", target).decode("utf-8", "ignore")
    finally:
        _ssh_exec("rm -rf -- " + shlex.quote(directory), target, check=False)
    parsed = parse_asset_text(asset_text)
    if target.asset_hostname:
        parsed.hostname = target.asset_hostname
    if not parsed.hostname:
        raise RuntimeError(f"Collected asset from {target.label} but hostname is empty")
    asset = save_parsed_asset(db, parsed)
    return asset.hostname


def _resolve_asset_hostname(db: Session, target: SimpleNamespace, discovered_hostname: str = "") -> str:
    for identity in [discovered_hostname, target.asset_hostname, target.host]:
        asset = _asset_by_identity(db, identity)
        if asset:
            return asset.hostname
    raise RuntimeError(f"Unable to map target {target.label} to an imported asset")


def _collect_ssh_runtime_probe(target: SimpleNamespace, asset_hostname: str, db: Session) -> int:
    asset = _asset_by_identity(db, asset_hostname)
    if not asset:
        raise RuntimeError(f"Asset not found for target {target.label}")
    packages = {package.package_name for package in asset.packages if package.package_name}
    ports = {service.port for service in asset.services if service.port}
    payloads: list[dict[str, Any]] = []
    for probe in _probe_specs(packages, ports):
        out, err, code = _ssh_exec(probe["shell_command"], target, timeout=60, check=False)
        if code == 127:
            continue
        payloads.append(_build_probe_event(asset.hostname, "runtime_probe_ssh", probe, out, err, code))
    if not payloads:
        return 0
    append_events(payloads, db=db)
    return len(payloads)


def _ensure_falco_installed(target: SimpleNamespace) -> str:
    out, _, _ = _ssh_exec("command -v falco >/dev/null 2>&1 && echo FALCO_OK || echo FALCO_MISSING", target, check=False)
    if "FALCO_OK" in out:
        return "already-present"
    sudo = _sudo_prefix(target)
    repo_line = "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main"
    _ssh_exec("command -v apt-get >/dev/null 2>&1", target, timeout=20)
    _ssh_exec("command -v curl >/dev/null 2>&1", target, timeout=20)
    _ssh_exec(
        f"curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | {sudo} gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg",
        target,
        timeout=120,
    )
    _ssh_exec(
        f"printf '%s\\n' {shlex.quote(repo_line)} | {sudo} tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null",
        target,
        timeout=30,
    )
    _ssh_exec(f"{sudo} apt-get update", target, timeout=900)
    _ssh_exec(f"{sudo} DEBIAN_FRONTEND=noninteractive apt-get install -y falco", target, timeout=1800)
    _ssh_exec(f"{sudo} systemctl enable --now falco-modern-bpf", target, timeout=180, check=False)
    _ssh_exec("falco --version", target, timeout=30)
    return "installed"


def _capture_falco_via_ssh(target: SimpleNamespace, asset_hostname: str, db: Session) -> tuple[int, str]:
    out, _, _ = _ssh_exec("command -v falco >/dev/null 2>&1 && echo FALCO_OK || echo FALCO_MISSING", target, check=False)
    install_detail = ""
    if "FALCO_OK" not in out and target.install_falco_if_missing:
        install_detail = _ensure_falco_installed(target)
        out, _, _ = _ssh_exec("command -v falco >/dev/null 2>&1 && echo FALCO_OK || echo FALCO_MISSING", target, check=False)
    if "FALCO_OK" not in out:
        return 0, "falco missing"

    # Read the existing sensor's window. Never stop it or inject synthetic
    # secret-file reads/processes just to manufacture positive evidence.
    seconds = max(1, min(DEMO_EBPF_SECONDS, 3600))
    content, _, _ = _ssh_exec(
        f"{_sudo_prefix(target)} journalctl -u falco-modern-bpf --since '-{seconds} seconds' --no-pager -o cat",
        target, timeout=45)
    payloads = parse_event_lines(content)
    if target.asset_hostname:
        for payload in payloads:
            payload["hostname"] = target.asset_hostname
    elif asset_hostname:
        for payload in payloads:
            if not payload.get("hostname"):
                payload["hostname"] = asset_hostname
    events = append_events(payloads, db=db)
    detail = f"{install_detail or 'present'}, events={len(events)}"
    return len(events), detail


def _collect_container_asset(target: SimpleNamespace, db: Session) -> str:
    import docker

    client = docker.from_env()
    container = client.containers.get(target.container_name)
    exit_code, output = container.exec_run(
        "bash -c 'BUSINESS_LEVEL=core bash /collect.sh /tmp/asset.txt 2>/dev/null && cat /tmp/asset.txt'"
    )
    if exit_code != 0:
        raise RuntimeError(f"{target.label} asset collection failed: {output.decode()[:200]}")
    asset_text = output.decode("utf-8", "ignore")
    parsed = parse_asset_text(asset_text)
    if target.asset_hostname:
        parsed.hostname = target.asset_hostname
    if not parsed.hostname:
        raise RuntimeError(f"Collected asset from {target.label} but hostname is empty")
    asset = save_parsed_asset(db, parsed)
    return asset.hostname


def _collect_container_runtime_probe(target: SimpleNamespace, asset_hostname: str, db: Session) -> int:
    import docker

    asset = _asset_by_identity(db, asset_hostname)
    if not asset:
        raise RuntimeError(f"Asset not found for target {target.label}")
    packages = {package.package_name for package in asset.packages if package.package_name}
    ports = {service.port for service in asset.services if service.port}
    payloads: list[dict[str, Any]] = []
    client = docker.from_env()
    container = client.containers.get(target.container_name)
    for probe in _probe_specs(packages, ports):
        exec_result = container.exec_run(["bash", "-lc", probe["shell_command"]], demux=True)
        stdout_bytes, stderr_bytes = exec_result.output if exec_result.output else (b"", b"")
        stdout_text = (stdout_bytes or b"").decode("utf-8", "ignore")
        stderr_text = (stderr_bytes or b"").decode("utf-8", "ignore")
        if exec_result.exit_code == 127:
            continue
        payloads.append(
            _build_probe_event(asset.hostname, "runtime_probe_container", probe, stdout_text, stderr_text, exec_result.exit_code)
        )
    if not payloads:
        return 0
    append_events(payloads, db=db)
    return len(payloads)


def _describe_container_ebpf_support(target: SimpleNamespace) -> str:
    import docker

    client = docker.from_env()
    container = client.containers.get(target.container_name)
    host_config = container.attrs.get("HostConfig") or {}
    if host_config.get("Privileged"):
        return "requires host-side falco sidecar"
    reasons = ["unprivileged"]
    exit_code, _ = container.exec_run(["bash", "-lc", "test -d /lib/modules"])
    if exit_code != 0:
        reasons.append("no-/lib/modules")
    exit_code, _ = container.exec_run(["bash", "-lc", "test -w /sys/fs/bpf"])
    if exit_code != 0:
        reasons.append("bpf-fs-readonly")
    return "unsupported(" + ",".join(reasons) + ")"


def _target_payloads(db: Session) -> list[dict[str, Any]]:
    _bootstrap_targets(db)
    rows = db.query(models.DemoTarget).order_by(models.DemoTarget.id.asc()).all()
    return [_serialize_target(row) for row in rows]


@router.get("/targets", dependencies=[Depends(require_control)])
def demo_targets(db: Session = Depends(get_db)):
    payloads = _target_payloads(db)
    return {
        "targets": payloads,
        "defaults": {
            "runtime_seconds": DEMO_EBPF_SECONDS,
            "sync_max_packages": DEMO_SYNC_MAX_PACKAGES,
            "sync_limit_per_package": DEMO_SYNC_LIMIT_PER_PACKAGE,
        },
    }


@router.put("/targets", dependencies=[Depends(require_control)])
def update_demo_targets(payload: schemas.DemoTargetConfigUpdate, db: Session = Depends(get_db)):
    # Only dedicated environment references are persisted. Never accept secrets.
    previous = {row.id: row for row in db.query(models.DemoTarget).all()}
    values = []
    seen_ids = set()
    for item in payload.targets:
        value = item.model_dump()
        if item.password:
            raise HTTPException(400, "不再接收或保存明文密码；请配置后端专用凭据变量并填写 credential_env")
        if value.get("id") is not None:
            if value["id"] not in previous or value["id"] in seen_ids:
                raise HTTPException(400, "历史目标 ID 不存在或重复")
            seen_ids.add(value["id"])
        if item.target_type == "ssh" and item.enabled and not item.host:
            raise HTTPException(400, "启用的 SSH 目标须提供地址")
        if item.target_type == "container" and item.enabled and not item.container_name:
            raise HTTPException(400, "启用的容器目标须提供名称")
        values.append(value)
    db.query(models.DemoTarget).delete()
    db.flush()
    for item, value in zip(payload.targets, values):
        if item.target_type == "ssh" and item.enabled and not item.host:
            raise HTTPException(status_code=400, detail=f"Enabled SSH target '{item.label}' requires a host")
        if item.target_type == "container" and item.enabled and not item.container_name:
            raise HTTPException(status_code=400, detail=f"Enabled container target '{item.label}' requires a container name")
        db.add(models.DemoTarget(**value))
    db.commit()
    return {"message": "Demo targets updated", "targets": _target_payloads(db)}


@router.get("/progress")
def demo_progress():
    return _progress


@router.post("/start", dependencies=[Depends(require_control)])
def demo_start(db: Session = Depends(get_db)):
    if _progress["running"]:
        raise HTTPException(status_code=409, detail="Demo workflow is already running")
    _bootstrap_targets(db)
    payloads = []
    for row in db.query(models.DemoTarget).filter_by(enabled=True).all():
        if row.password:
            raise HTTPException(409, "历史明文凭据须迁移到专用环境变量并重新保存目标后才能运行")
        name = row.credential_env or ""
        if name and not re.fullmatch(r"VM_PASS|LINUXGUARD_DEMO_[A-Z0-9_]{1,80}", name):
            raise HTTPException(409, "演示凭据引用无效")
        secret = os.getenv(name, "") if name else ""
        if row.target_type == "ssh" and not secret:
            raise HTTPException(409, "后端未配置演示目标专用凭据")
        payloads.append({**_serialize_target(row), "password": secret})
    if not payloads:
        raise HTTPException(status_code=400, detail="No enabled demo targets configured")
    targets = [SimpleNamespace(**item) for item in payloads]
    planned = _planned_steps(targets)

    def _run() -> None:
        session = SessionLocal()
        critical_errors: list[str] = []
        try:
            _reset_progress(planned)
            asset_hostnames: dict[int, str] = {}

            for target in targets:
                if not target.collect_asset:
                    continue
                step_name = f"采集资产：{target.label}"
                _progress["current_step"] = step_name
                _progress["current_agent"] = "collector"
                try:
                    if target.target_type == "ssh":
                        hostname = _collect_ssh_asset(target, session)
                    else:
                        hostname = _collect_container_asset(target, session)
                    asset_hostnames[target.id] = hostname
                    _mark_done(step_name, "collector", f"完成，资产={hostname}", status="ok")
                except Exception as exc:
                    _mark_done(step_name, "collector", f"失败: {exc}", status="error")
                    critical_errors.append(f"资产采集失败({target.label}): {exc}")
                    _progress["error"] = "; ".join(critical_errors)

            runtime_targets = [target for target in targets if target.collect_runtime]
            if runtime_targets:
                clear_events(session)

            for target in runtime_targets:
                step_name = f"采集运行时证据：{target.label}"
                _progress["current_step"] = step_name
                _progress["current_agent"] = "collector"
                try:
                    asset_hostname = _resolve_asset_hostname(session, target, asset_hostnames.get(target.id, ""))
                    details = []
                    if target.target_type == "ssh":
                        falco_count, falco_detail = _capture_falco_via_ssh(target, asset_hostname, session)
                        probe_count = _collect_ssh_runtime_probe(target, asset_hostname, session)
                        details.append(f"eBPF={falco_detail}")
                        details.append(f"probe={probe_count}")
                        if falco_count:
                            details.append(f"stored={falco_count}")
                    else:
                        details.append(f"eBPF={_describe_container_ebpf_support(target)}")
                        probe_count = _collect_container_runtime_probe(target, asset_hostname, session)
                        details.append(f"probe={probe_count}")
                    _mark_done(step_name, "collector", "完成，" + "; ".join(details), status="ok")
                except Exception as exc:
                    _mark_done(step_name, "collector", f"失败: {exc}", status="error")
                    critical_errors.append(f"运行时采集失败({target.label}): {exc}")
                    _progress["error"] = "; ".join(critical_errors)

            if runtime_targets:
                verify_db = SessionLocal()
                try:
                    summary = summarize_runtime_events(verify_db)
                finally:
                    verify_db.close()
                if summary["total"] <= 0:
                    notice = "未采集到运行时事件，将继续使用资产和漏洞情报进行静态分析"
                    for item in reversed(_progress["steps_done"]):
                        if item["agent"] == "collector":
                            item["detail"] = f"{item['detail']}；{notice}".strip("；")
                            break

            _progress["current_step"] = STEP_SYNC_INTEL
            _progress["current_agent"] = "collector"
            intel_saved = 0

            def sync_progress(message: str, current: int | None = None, total: int | None = None) -> None:
                if current is not None and total:
                    _progress["current_step"] = f"{message} ({current}/{total})"
                else:
                    _progress["current_step"] = message
                _progress["current_agent"] = "collector"

            detail_parts: list[str] = []
            intel_warnings: list[str] = []
            intel_failed = False
            for collector_sync, collector_label in (
                (sync_ubuntu_asset_intelligence, "Ubuntu"),
                (sync_kylin_asset_intelligence, "麒麟"),
            ):
                try:
                    result = collector_sync(
                        session,
                        max_packages_per_asset=DEMO_SYNC_MAX_PACKAGES,
                        limit_per_package=DEMO_SYNC_LIMIT_PER_PACKAGE,
                        replace=True,
                        progress=sync_progress,
                    )
                    intel_saved += result.saved
                    detail_parts.append(f"{collector_label}入库={result.saved}")
                    if result.warnings:
                        intel_warnings.extend(result.warnings)
                    if result.notices:
                        detail_parts.append(f"{collector_label}skipped={len(result.notices)}")
                except Exception as exc:
                    intel_failed = True
                    critical_errors.append(f"{collector_label}情报同步失败: {exc}")
                    detail_parts.append(f"{collector_label}失败")
            if intel_warnings:
                detail_parts.append(f"warnings={len(intel_warnings)}")
                for warning in intel_warnings:
                    critical_errors.append(f"情报同步警告: {warning}")
            intel_status = "error" if intel_failed else ("warning" if intel_warnings else "ok")
            _mark_done(STEP_SYNC_INTEL, "collector", ", ".join(detail_parts), status=intel_status)
            if critical_errors:
                _progress["error"] = "; ".join(critical_errors)

            _progress["current_step"] = "执行软件包命中分析"
            _progress["current_agent"] = "analysis"
            try:
                matches = run_matching(session)
                analysis_status = "warning" if matches == 0 else "ok"
                detail = f"{matches} 条"
                if matches == 0 and intel_saved == 0:
                    detail += "（情报同步失败或入库为 0，无可匹配的漏洞数据）"
                _mark_done("执行软件包命中分析", "analysis", detail, status=analysis_status)
            except Exception as exc:
                _mark_done("执行软件包命中分析", "analysis", f"失败: {exc}", status="error")
                critical_errors.append(f"命中分析失败: {exc}")
                _progress["error"] = "; ".join(critical_errors)

            _progress["current_step"] = "建立候选风险与基线"
            _progress["current_agent"] = "orchestrator"
            try:
                risks = calculate_risk(session)
                risk_status = "warning" if (risks == 0 and matches == 0) else "ok"
                _mark_done("建立候选风险与基线", "orchestrator", f"{risks} 条候选（基线分数，非最终结论）", status=risk_status)
            except Exception as exc:
                _mark_done("建立候选风险与基线", "orchestrator", f"失败: {exc}", status="error")
                critical_errors.append(f"建立候选风险失败: {exc}")
                _progress["error"] = "; ".join(critical_errors)

            # ── 四智能体联合研判（候选/基线之后、最终结论之前） ──
            _progress["current_step"] = "四智能体联合研判（核验证据并形成裁定…）"
            _progress["current_agent"] = "analysis"
            try:
                from app.services.unified.adapter import generate_and_save_report_unified as _ai_report

                ai_result = _ai_report(session)
                ai_status = ai_result.get("status", "failed")
                verdict = ai_result.get("verdict") or {}
                if ai_status == "running":
                    _mark_done(
                        "四智能体联合研判", "analysis",
                        f"已有研判任务进行中：{ai_result.get('error', '')}",
                        status="warning",
                    )
                elif ai_status == "skipped":
                    _mark_done(
                        "四智能体联合研判", "analysis",
                        f"跳过：{ai_result.get('error', '未配置API Key')}",
                        status="warning",
                    )
                elif ai_status == "human_review":
                    _mark_done(
                        "四智能体联合研判", "analysis",
                        f"需人工复核：{ai_result.get('error', '模型不可用或裁定未通过校验')}",
                        status="warning",
                    )
                    critical_errors.append(f"智能研判未完成，需人工复核: {ai_result.get('error', '')}")
                    _progress["error"] = "; ".join(critical_errors)
                elif ai_status == "failed":
                    _mark_done(
                        "四智能体联合研判", "analysis",
                        f"失败：{ai_result.get('error', '未知错误')}",
                        status="error",
                    )
                    critical_errors.append(f"智能研判失败: {ai_result.get('error', '')}")
                    _progress["error"] = "; ".join(critical_errors)
                else:
                    answer_len = len(ai_result.get("answer", ""))
                    agent_count = len(ai_result.get("transcript", []))
                    verdict_name = verdict.get("verdict", "")
                    confidence = verdict.get("confidence", 0)
                    adjustment = verdict.get("risk_adjustment", 0)
                    _mark_done(
                        "四智能体联合研判", "analysis",
                        f"完成，{agent_count} 轮发言，裁定={verdict_name}，置信度={confidence}，调整={adjustment}",
                        status="ok",
                    )
            except Exception as exc:
                _mark_done(
                    "四智能体联合研判", "analysis",
                    f"跳过: {exc}",
                    status="warning",
                )

            _progress["current_step"] = "生成最终结论与整改建议"
            _progress["current_agent"] = "orchestrator"
            try:
                # 仅对研判完成且无需人工复核的候选生成整改建议；
                # 研判未完成（skipped/human_review）时生成 0 条，等待人工审批。
                tasks = generate_remediation_tasks(session)
                _mark_done("生成最终结论与整改建议", "orchestrator", f"{tasks} 条", status="ok")
            except Exception as exc:
                _mark_done("生成最终结论与整改建议", "orchestrator", f"失败: {exc}", status="error")

            if critical_errors:
                _progress["error"] = "; ".join(critical_errors)

        except Exception as exc:
            _progress["error"] = str(exc)
        finally:
            _progress["running"] = False
            _progress["current_step"] = "Completed"
            session.close()

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Demo started", "progress_url": "/api/demo/progress", "targets": payloads}
