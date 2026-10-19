"""Current asset summaries must not promote resolved audit history."""
import pytest

from app import models


@pytest.mark.parametrize("active,status", [(False, "resolved"), (True, "resolved"), (False, "inactive")])
def test_asset_summary_excludes_historical_high_risk(client, session_factory, active, status):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="asset-summary-test")
        db.add(asset)
        db.flush()
        asset_id = asset.id
        db.add_all([
            models.RiskAssessment(asset_id=asset_id, cve_id="CVE-2099-9001", active=active,
                                  review_status=status, risk_level="Critical", final_score=95),
            models.RiskAssessment(asset_id=asset_id, cve_id="CVE-2099-9002", active=True,
                                  review_status="human_confirmed", risk_level="Low", final_score=12),
        ])
        db.commit()
    response = client.get("/api/assets")
    assert response.status_code == 200
    row = next(row for row in response.json() if row["id"] == asset_id)
    assert (row["risk_level"], row["risk_score"], row["risk_assessment_status"]) == ("Low", 12, "current")
    with session_factory() as db:
        assert db.query(models.RiskAssessment).filter_by(asset_id=asset_id).count() == 2


def test_asset_without_current_assessment_is_unknown(client, session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="only-history")
        db.add(asset)
        db.flush()
        db.add(models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2099-9003", active=False,
                                    review_status="resolved", risk_level="Critical", final_score=95))
        db.add(models.LinuxAsset(hostname="never-assessed"))
        db.commit()
    response = client.get("/api/assets")
    assert response.status_code == 200
    assert len(response.json()) == 2
    for row in response.json():
        assert row["risk_assessment_status"] == "unassessed"
        assert row["risk_level"] is None
        assert row["risk_score"] is None
