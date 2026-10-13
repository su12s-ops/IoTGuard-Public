from app import main, models
from app.services.experiment_lifecycle import build_archive_payload


def test_startup_cleanup_keeps_assets_and_targets(session_factory, monkeypatch):
    db = session_factory()
    asset = models.LinuxAsset(hostname="cleanup-host", distribution="ubuntu", os_version="24.04")
    db.add(asset)
    db.flush()
    match = models.VulnerabilityMatch(asset_id=asset.id, cve_id="CVE-TEST-0001", package_name="nginx")
    db.add_all([
        models.AssetPackage(asset_id=asset.id, package_name="nginx", package_version="1.0"),
        models.AssetService(asset_id=asset.id, service_name="nginx", port=80),
        models.DemoTarget(label="cleanup-target", target_type="container"),
        models.VulnerabilityInfo(cve_id="CVE-TEST-0001", title="Test", affected_package="nginx"),
        match,
        models.RuntimeEvent(asset_id=asset.id, hostname=asset.hostname, event_type="process"),
    ])
    db.flush()
    risk = models.RiskAssessment(match_id=match.id, asset_id=asset.id, cve_id="CVE-TEST-0001", package_name="nginx")
    db.add(risk)
    db.flush()
    db.add_all([
        models.AnalysisReport(review_run_id="cleanup-run", status="completed"),
        models.AgentAuditRecord(
            run_id="cleanup-run", risk_id=risk.id, object_id=f"risk-{risk.id}",
            agent_name="evidence_audit_agent", parse_status="valid",
        ),
        models.RemediationTask(
            risk_id=risk.id, asset_id=asset.id, cve_id="CVE-TEST-0001", package_name="nginx"
        ),
    ])
    db.commit()
    db.close()

    monkeypatch.setenv("LINUXGUARD_ARCHIVE_ON_STARTUP", "1")
    monkeypatch.setattr(main, "SessionLocal", session_factory)
    main._cleanup_derived_data()

    db = session_factory()
    try:
        assert db.query(models.LinuxAsset).count() == 1
        assert db.query(models.AssetPackage).count() == 1
        assert db.query(models.AssetService).count() == 1
        assert db.query(models.DemoTarget).count() == 1
        assert db.query(models.VulnerabilityInfo).count() == 0
        assert db.query(models.VulnerabilityMatch).count() == 0
        assert db.query(models.RiskAssessment).count() == 0
        assert db.query(models.AnalysisReport).count() == 0
        assert db.query(models.AgentAuditRecord).count() == 0
        assert db.query(models.RemediationTask).count() == 0
        assert db.query(models.RuntimeEvent).count() == 0
    finally:
        db.close()


def test_archive_payload_keeps_report_audit_and_risk_together(session_factory):
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="archive-host")
        db.add(asset)
        db.flush()
        match = models.VulnerabilityMatch(
            asset_id=asset.id, cve_id="CVE-TEST-0002", package_name="openssl", affected=True
        )
        db.add(match)
        db.flush()
        risk = models.RiskAssessment(
            match_id=match.id, asset_id=asset.id, cve_id=match.cve_id, package_name=match.package_name
        )
        db.add(risk)
        db.flush()
        db.add(models.AnalysisReport(review_run_id="archive-run", status="completed"))
        db.add(models.AgentAuditRecord(
            run_id="archive-run", risk_id=risk.id, object_id=f"risk-{risk.id}",
            agent_name="impact_assessment_agent", parse_status="valid",
        ))
        db.commit()

        payload = build_archive_payload(db)

        assert payload["schema_version"] == 3
        assert payload["summary"]["risks"] == 1
        assert payload["summary"]["analysis_reports"] == 1
        assert payload["summary"]["agent_audit_records"] == 1
        assert payload["risks"][0]["id"] == risk.id
        assert payload["analysis_reports"][0]["review_run_id"] == "archive-run"
        assert payload["agent_audit_records"][0]["risk_id"] == risk.id
    finally:
        db.close()
