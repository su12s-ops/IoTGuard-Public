"""Formal remediation task generation with deterministic authorization."""

from sqlalchemy.orm import Session

from app import models


VERIFY_COMMANDS = {
    "curl": "curl --version",
    "nginx": "nginx -v",
    "openssl": "openssl version",
    "sudo": "sudo -V",
    "systemd": "systemd --version",
}

AUTHORIZED_STATES = {
    "completed",  # migrated legacy confirmation
    "auto_confirmed",
    "human_confirmed",
    "remediation_ready",
    "remediation_in_progress",
    "verification",
}


def _package_command(distribution: str, package_name: str) -> str:
    distro = (distribution or "").lower()
    if distro == "openwrt":
        return "在设备任务中选择适配当前固件与型号的已登记应用软件包；禁止批量 opkg/apk 升级。"
    if distro in {"ubuntu", "debian"}:
        return f"sudo apt update && sudo apt install --only-upgrade {package_name}"
    if distro in {"centos", "rhel", "redhat", "openeuler"}:
        return f"sudo dnf update {package_name} || sudo yum update {package_name}"
    return f"使用发行版包管理器升级 {package_name}"


def _requires_ubuntu_esm(asset: models.LinuxAsset, target_version: str) -> bool:
    return (
        (asset.distribution or "").lower() == "ubuntu"
        and (asset.os_version or "").startswith("18.04")
        and "+esm" in (target_version or "").lower()
    )


def _esm_remediation_command(package_name: str) -> str:
    return (
        "sudo pro status  # attach Ubuntu Pro and enable esm-infra first; "
        f"then run: sudo apt update && sudo apt install --only-upgrade {package_name}"
    )


def _authorized(risk: models.RiskAssessment) -> bool:
    if risk.review_status not in AUTHORIZED_STATES or risk.human_review_required:
        return False
    # High/Critical and core assets never receive formal repair authorization
    # from an automatic LLM-backed decision.
    if risk.risk_level in {"High", "Critical"} and risk.review_status == "auto_confirmed":
        return False
    return True


def generate_remediation_tasks(db: Session, allow_human_override: bool = False) -> int:
    """Incrementally create/update tasks for explicitly authorized risk events.

    ``allow_human_override`` is kept for API compatibility only. It no longer
    bypasses authorization; callers must use the human-review endpoint first.
    """
    del allow_human_override
    count = 0
    assessments = (
        db.query(models.RiskAssessment)
        .filter(models.RiskAssessment.active.is_(True))
        .order_by(models.RiskAssessment.priority_rank)
        .all()
    )
    for risk in assessments:
        if not _authorized(risk):
            continue
        asset = db.get(models.LinuxAsset, risk.asset_id)
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        if match is None:
            matches = db.query(models.VulnerabilityMatch).filter_by(
                asset_id=risk.asset_id, cve_id=risk.cve_id, active=True, affected=True
            ).all()
            if len(matches) == 1:
                match = matches[0]
                risk.match_id = match.id
                risk.package_name = match.package_name
        if not asset or not match or not match.active or not match.affected:
            continue

        requires_esm = _requires_ubuntu_esm(asset, match.fixed_version)
        command = _esm_remediation_command(match.package_name) if requires_esm else _package_command(
            asset.distribution, match.package_name
        )
        mitigation = f"优先升级 {match.package_name}；升级前确认业务窗口并准备回滚方案。"
        task_status = "pending"
        if requires_esm:
            mitigation = (
                f"目标补丁 {match.fixed_version} 仅由 Ubuntu Pro/ESM 提供。"
                "请先绑定 Ubuntu Pro 并启用 esm-infra，或升级到受支持版本。"
            )
            task_status = "blocked"
        if asset.distribution == "openwrt":
            mitigation = "需核对官方公告、固件与型号，登记修复及回退产物、漏洞回归和业务检查，审批计划后执行。整机固件升级另行实施。"
            if match.reason_code != "openwrt_exact_affected_version" or not match.fixed_version or not asset.inventory_complete:
                task_status = "blocked"
                mitigation = "缺少完整清单或当前 OpenWrt 版本的适用性证据，先补证，不能直接升级。"

        task = db.query(models.RemediationTask).filter_by(risk_id=risk.id).one_or_none()
        values = {
            "asset_id": asset.id,
            "cve_id": risk.cve_id,
            "package_name": match.package_name,
            "current_version": match.installed_version,
            "target_version": match.fixed_version,
            "remediation_command": command,
            "mitigation": mitigation,
            "verification_command": VERIFY_COMMANDS.get(
                match.package_name, f"dpkg -l | grep {match.package_name}"
            ),
        }
        if asset.distribution == "openwrt":
            values["verification_command"] = "重新采集 OpenWrt 软件清单，并执行已登记的漏洞回归和业务检查。"
        if task is None:
            task = models.RemediationTask(risk_id=risk.id, status=task_status, **values)
            db.add(task)
        else:
            for name, value in values.items():
                setattr(task, name, value)
            if task.status not in {"in_progress", "verified", "resolved"}:
                task.status = task_status
        if risk.review_status in {"auto_confirmed", "human_confirmed"}:
            risk.review_status = "remediation_ready"
        count += 1

    db.commit()
    return count
