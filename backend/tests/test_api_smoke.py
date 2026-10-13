from app import models


def seed_sample_data(session_factory):
    db = session_factory()
    try:
        vuln = models.VulnerabilityInfo(
            cve_id="CVE-2099-0001",
            title="Sample vulnerability",
            description="Sample description",
            cvss_score=8.5,
            cvss_severity="High",
            affected_package="openssl",
            fixed_version="3.0.2-0ubuntu1.18",
            source="Ubuntu Security API",
        )
        intel = models.ThreatIntelSource(
            cve_id="CVE-2099-0001",
            is_kev=True,
            epss_score=0.87,
            exploit_status="active",
        )
        asset = models.LinuxAsset(
            hostname="vm-test-01",
            distribution="ubuntu",
            exposure_level="public",
            business_level="core",
        )
        db.add_all([vuln, intel, asset])
        db.flush()

        db.add(
            models.VulnerabilityMatch(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                package_name="openssl",
                installed_version="3.0.2-0ubuntu1.10",
                fixed_version=vuln.fixed_version,
                affected=True,
                match_reason="Installed version is lower than fixed version",
                confidence=0.96,
            )
        )
        db.add(
            models.RiskAssessment(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                cvss_score=8.5,
                epss_score=0.87,
                kev_score=100,
                exposure_score=100,
                business_score=100,
                patch_score=90,
                final_score=91.75,
                risk_level="Critical",
                priority_rank=1,
                reason="Sample critical risk",
            )
        )
        db.add(
            models.RemediationTask(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                package_name="openssl",
                current_version="3.0.2-0ubuntu1.10",
                target_version=vuln.fixed_version,
                remediation_command="sudo apt install --only-upgrade openssl",
                verification_command="openssl version",
                status="pending",
            )
        )
        db.commit()
    finally:
        db.close()


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "LinuxGuard",
        "database": "ok",
    }


def test_health_endpoint_reports_database_failure(client, monkeypatch):
    from app import main

    class BrokenSession:
        def execute(self, _statement):
            raise OSError("database is unavailable")

        def close(self):
            pass

    monkeypatch.setattr(main, "SessionLocal", BrokenSession)

    response = client.get("/api/health")

    assert response.status_code == 503
    assert response.json()["status"] == "error"
    assert response.json()["database"] == "unavailable"


def test_agent_status_endpoint_does_not_return_secret(client):
    response = client.get("/api/analysis/status")

    assert response.status_code == 200
    assert "configured" in response.json()
    assert "api_key" not in response.json()


def test_dashboard_summary_reflects_seeded_data(client, session_factory):
    seed_sample_data(session_factory)

    response = client.get("/api/dashboard/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["total_vulnerabilities"] == 1
    assert data["kev_vulnerabilities"] == 1
    assert data["asset_count"] == 1
    assert data["affected_asset_count"] == 1
    assert data["pending_remediation_tasks"] == 1
    assert data["blocked_remediation_tasks"] == 0
    assert data["risk_level_distribution"] == {"Critical": 1}
    assert data["top_assets"][0]["hostname"] == "vm-test-01"
    assert data["top_vulnerabilities"][0]["cve_id"] == "CVE-2099-0001"


def test_update_remediation_task_status(client, session_factory):
    seed_sample_data(session_factory)

    response = client.patch("/api/remediation/tasks/1", json={"status": "verified"})

    assert response.status_code == 200
    assert response.json()["status"] == "verified"


def test_update_remediation_task_to_blocked(client, session_factory):
    seed_sample_data(session_factory)

    response = client.patch("/api/remediation/tasks/1", json={"status": "blocked"})

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"


def test_reject_invalid_remediation_status(client, session_factory):
    seed_sample_data(session_factory)

    response = client.patch("/api/remediation/tasks/1", json={"status": "done"})

    assert response.status_code == 422
