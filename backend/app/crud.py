from sqlalchemy.orm import Session

from app import models


def get_vulnerability_by_cve(db: Session, cve_id: str):
    return db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).first()


def get_asset_by_hostname(db: Session, hostname: str):
    return db.query(models.LinuxAsset).filter_by(hostname=hostname).first()


def reset_tables(db: Session, tables: list[type]):
    for table in tables:
        db.query(table).delete()
    db.commit()

