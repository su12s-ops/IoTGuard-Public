import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import models
from app.database import SessionLocal, init_db


LEGACY_SAMPLE_HOSTNAMES = {"server-web-01", "server-db-01", "server-test-01"}


def cleanup_sample_assets() -> int:
    init_db()
    db = SessionLocal()
    try:
        sample_assets = db.query(models.LinuxAsset).filter(models.LinuxAsset.hostname.in_(LEGACY_SAMPLE_HOSTNAMES)).all()
        asset_ids = [asset.id for asset in sample_assets]
        if not asset_ids:
            return 0

        db.query(models.RemediationTask).filter(models.RemediationTask.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        db.query(models.RiskAssessment).filter(models.RiskAssessment.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        db.query(models.VulnerabilityMatch).filter(models.VulnerabilityMatch.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        db.query(models.AssetService).filter(models.AssetService.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        db.query(models.AssetPackage).filter(models.AssetPackage.asset_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        db.query(models.LinuxAsset).filter(models.LinuxAsset.id.in_(asset_ids)).delete(synchronize_session=False)
        db.commit()
        return len(asset_ids)
    finally:
        db.close()


if __name__ == "__main__":
    removed = cleanup_sample_assets()
    print(f"Legacy sample assets removed: {removed}")
