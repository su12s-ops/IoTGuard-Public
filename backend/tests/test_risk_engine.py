from app import models
from app.services.risk_engine import calculate_risk, risk_level


def test_risk_level_thresholds():
    assert risk_level(90) == "Critical"
    assert risk_level(70) == "High"
    assert risk_level(50) == "Medium"
    assert risk_level(49.9) == "Medium"
    assert risk_level(39.9) == "Low"


def test_calculate_risk_builds_decision_context(session_factory):
    db = session_factory()
    try:
        vuln = models.VulnerabilityInfo(
            cve_id="CVE-2099-0002",
            title="OpenSSL remote code execution",
            description="Remote code execution in OpenSSL",
            cvss_score=9.1,
            cvss_severity="Critical",
            affected_package="openssl",
            fixed_version="3.0.2-0ubuntu1.18",
            source="Ubuntu Security API",
        )
        intel = models.ThreatIntelSource(
            cve_id=vuln.cve_id,
            is_kev=True,
            epss_score=0.92,
            exploit_status="known-exploited",
        )
        asset = models.LinuxAsset(
            hostname="web-01",
            ip_address="10.0.0.5",
            distribution="ubuntu",
            exposure_level="public",
            business_level="core",
        )
        db.add_all([vuln, intel, asset])
        db.flush()

        db.add(
            models.AssetService(
                asset_id=asset.id,
                service_name="nginx",
                port=443,
                protocol="tcp",
                listen_address="0.0.0.0",
                process_name="nginx",
                is_public_exposed=True,
            )
        )
        db.add(
            models.VulnerabilityMatch(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                package_name="openssl",
                installed_version="3.0.2-0ubuntu1.10",
                fixed_version=vuln.fixed_version,
                affected=True,
                match_reason="Installed version is lower than fixed version",
                confidence=0.99,
            )
        )
        db.add(
            models.RuntimeEvent(
                asset_id=asset.id,
                hostname=asset.hostname,
                source="falco",
                event_type="execve",
                category="process_execution",
                severity="critical",
                severity_score=86,
                rule="Observed openssl execution",
                process_name="openssl",
                commandline="openssl version",
                tactic="Execution",
                technique="T1059",
                risk_signal="Observed package execution",
                raw_json="{}",
                occurred_at="2026-06-27T00:00:00Z",
            )
        )
        db.commit()

        count = calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()

        assert count == 1
        assert risk.affected_status == "potentially_affected"
        assert risk.reachable_status == "internet_exposed"
        assert risk.reachability_score >= 80
        assert risk.path_count >= 1
        assert risk.exposed_service_count == 1
        assert risk.runtime_status == "verified"
        # Component execution and external threat intelligence do not prove
        # exploitation on this specific device.
        assert risk.exploitability_status == "likely"
        # 候选阶段：基线决策保留在 preliminary_decision；final decision 保持未定（monitor）
        assert risk.preliminary_decision == "immediate_fix"
        assert risk.decision == "monitor"
        assert risk.decision_confidence == 0
        assert risk.review_status == "candidate"
        assert risk.runtime_score >= 70
        assert risk.priority_rank == 1
    finally:
        db.close()


def test_risk_ranking_returns_decision_fields(client, session_factory):
    db = session_factory()
    try:
        vuln = models.VulnerabilityInfo(
            cve_id="CVE-2099-0003",
            title="Bash privilege issue",
            description="Privilege escalation in bash",
            cvss_score=7.2,
            cvss_severity="High",
            affected_package="bash",
            fixed_version="5.1-1ubuntu1.2",
            source="Ubuntu Security API",
        )
        intel = models.ThreatIntelSource(cve_id=vuln.cve_id, epss_score=0.25, exploit_status="active")
        asset = models.LinuxAsset(
            hostname="app-01",
            distribution="ubuntu",
            exposure_level="internal",
            business_level="important",
        )
        db.add_all([vuln, intel, asset])
        db.flush()

        db.add(
            models.AssetService(
                asset_id=asset.id,
                service_name="sshd",
                port=22,
                protocol="tcp",
                listen_address="0.0.0.0",
                process_name="sshd",
                is_public_exposed=True,
            )
        )
        db.add(
            models.VulnerabilityMatch(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                package_name="bash",
                installed_version="5.1-1ubuntu1",
                fixed_version=vuln.fixed_version,
                affected=True,
                match_reason="Installed version is lower than fixed version",
                confidence=0.95,
            )
        )
        db.commit()
    finally:
        db.close()

    calc = client.post("/api/risk/calculate")
    assert calc.status_code == 200

    response = client.get("/api/risk/ranking")
    assert response.status_code == 200
    row = response.json()[0]
    assert row["decision"] in {"immediate_fix", "scheduled_fix", "monitor", "defer"}
    assert row["reachable_status"] in {"none", "linked", "internet_exposed"}
    assert row["path_count"] >= 1
    assert "reachability_reason" in row
    assert row["runtime_score"] >= 0
    assert "decision_reason" in row
