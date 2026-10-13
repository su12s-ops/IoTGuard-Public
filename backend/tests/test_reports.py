import json

from app import models


def test_report_archives_can_be_listed_and_opened(client, monkeypatch, tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    archive_name = "exp-20260630-120000.json"
    archive_payload = {
        "archived_at": "2026-06-30T12:00:00+00:00",
        "summary": {
            "assets": 3,
            "vulnerabilities": 13,
            "matches": 5,
            "risks": 4,
            "tasks": 2,
            "events": 8,
        },
        "assets": [],
        "risks": [
            {"review_status": "pending_human_review", "preliminary_level": "High", "final_score": None, "risk_level": "Low"},
            {"review_status": "human_confirmed", "preliminary_level": "High", "final_score": 48, "risk_level": "Medium"},
        ],
        "events": [],
    }
    (archive_dir / archive_name).write_text(json.dumps(archive_payload), encoding="utf-8")
    monkeypatch.setenv("REPORT_ARCHIVE_DIR", str(archive_dir))

    listed = client.get("/api/reports/archives")
    assert listed.status_code == 200
    archives = listed.json()["archives"]
    assert len(archives) == 1
    assert archives[0]["filename"] == archive_name
    assert archives[0]["summary"]["events"] == 8
    assert archives[0]["summary"]["high_risks"] == 1

    opened = client.get(f"/api/reports/archives/{archive_name}")
    assert opened.status_code == 200
    assert opened.json()["summary"]["assets"] == 3

    downloaded = client.get(f"/api/reports/archives/{archive_name}/download")
    assert downloaded.status_code == 200
    assert "application/json" in downloaded.headers["content-type"]


def test_current_report_uses_preliminary_risk_until_final_conclusion(client, session_factory):
    db = session_factory()
    try:
        asset = models.LinuxAsset(hostname="report-host", distribution="ubuntu")
        vuln = models.VulnerabilityInfo(cve_id="CVE-2099-1000", title="Report risk", affected_package="nginx", source="Ubuntu Security API")
        intel = models.ThreatIntelSource(cve_id="CVE-2099-1000", is_kev=True)
        db.add_all([asset, vuln, intel])
        db.flush()
        db.add_all([
            models.RiskAssessment(
                asset_id=asset.id,
                cve_id=vuln.cve_id,
                priority_rank=1,
                preliminary_score=72,
                preliminary_level="High",
                preliminary_decision="scheduled_fix",
                review_status="pending_human_review",
                final_score=None,
                risk_level="Low",
            ),
            models.RiskAssessment(
                asset_id=asset.id,
                cve_id="CVE-2099-1001",
                priority_rank=2,
                preliminary_score=74,
                preliminary_level="High",
                review_status="human_confirmed",
                final_score=48,
                risk_level="Medium",
                decision="monitor",
            ),
        ])
        db.commit()
    finally:
        db.close()

    report = client.get("/api/reports/summary.json")
    assert report.status_code == 200
    assert report.json()["overview"]["high_risk_count"] == 1
    assert report.json()["overview"]["kev_vulnerability_count"] == 1
    assert report.json()["top_risks"][0]["has_final_conclusion"] is False

    csv_report = client.get("/api/reports/summary.csv")
    assert csv_report.status_code == 200
    assert "72.0,High,scheduled_fix" in csv_report.text
    assert "48.0,Medium,monitor" in csv_report.text
