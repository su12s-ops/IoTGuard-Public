from app import models
from app.services.remediation_engine import generate_remediation_tasks


def test_bionic_esm_target_creates_blocked_task(session_factory):
    db = session_factory()
    try:
        asset = models.LinuxAsset(
            hostname="legacy-bionic-web",
            distribution="ubuntu",
            os_version="18.04",
        )
        db.add(asset)
        db.flush()
        db.add(
            models.RiskAssessment(
                asset_id=asset.id,
                cve_id="CVE-2099-0001:bionic",
                priority_rank=1,
                review_status="completed",
                human_review_required=False,
            )
        )
        db.add(
            models.VulnerabilityMatch(
                asset_id=asset.id,
                cve_id="CVE-2099-0001:bionic",
                package_name="openssl",
                installed_version="1.1.1-1ubuntu2.1~18.04.23",
                fixed_version="1.1.1-1ubuntu2.1~18.04.23+esm9",
                affected=True,
            )
        )
        db.commit()

        assert generate_remediation_tasks(db) == 1
        task = db.query(models.RemediationTask).one()
        assert task.status == "blocked"
        assert "sudo pro status" in task.remediation_command
        assert "Ubuntu Pro/ESM" in task.mitigation
    finally:
        db.close()
