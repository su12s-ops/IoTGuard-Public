"""Standalone startup helper: archive the previous round, then clear derived data.

Kept for operators who run the cleanup outside the FastAPI lifespan. The compact
result snapshot is written to ``backend/data/archives`` (or REPORT_ARCHIVE_DIR)
before any row is deleted; device inventory, connections, sensors and policy are
retained.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import SessionLocal, init_db  # noqa: E402
from app import models  # noqa: E402
from app.services.experiment_lifecycle import clear_derived_data  # noqa: E402
from app.services.result_archive import write_result_archive  # noqa: E402


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        asset_count = db.query(models.LinuxAsset).count()
        if asset_count == 0:
            print("[archive] 数据库为空，跳过存档（全新状态）")
            return
        archive = write_result_archive(db, label="服务启动前自动存档", kind="startup")
        print(f"[archive] 本轮结果已存档: {archive['filename']} ({archive['size_bytes']} bytes)")
        counts = clear_derived_data(db)
        print(f"[archive] 已清理衍生数据 {sum(counts.values())} 条，保留 {asset_count} 个资产")
    finally:
        db.close()


if __name__ == "__main__":
    main()
