"""容器启动时：若数据库有上次实验数据，自动存档到 archives/exp-{时间戳}.json，然后清库（全新）。
存档不含前端展示，纯文件回溯。"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/app")

from app.database import SessionLocal, init_db  # noqa: E402
from app import models  # noqa: E402
from app.services.experiment_lifecycle import build_archive_payload, clear_derived_data  # noqa: E402
from app.services.report_service import get_archive_dir  # noqa: E402


def main():
    init_db()
    db = SessionLocal()
    try:
        asset_count = db.query(models.LinuxAsset).count()
        if asset_count == 0:
            print("[archive] 数据库为空, 跳过存档(全新状态)")
            return

        archive = build_archive_payload(db)

        archive_dir = get_archive_dir()
        os.makedirs(archive_dir, exist_ok=True)
        # 文件名仅由受控时间戳构成；显式校验防止任何 ../ 注入到归档路径。
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if not stamp.isdigit() and not stamp.replace("-", "").isdigit():
            raise ValueError(f"归档时间戳异常: {stamp!r}")
        archive_path = archive_dir / f"exp-{stamp}.json"
        if not archive_path.resolve().is_relative_to(Path(archive_dir).resolve()):
            raise ValueError("归档路径越界")
        with archive_path.open("w", encoding="utf-8") as f:
            json.dump(archive, f, ensure_ascii=False, indent=2, default=str)
        print(f"[archive] 上次实验已存档: {archive_path} (资产{archive['summary']['assets']}/漏洞{archive['summary']['vulnerabilities']}/事件{archive['summary']['events']})")

        clear_derived_data(db)
        print(f"[archive] 衍生数据已清零, 保留 {asset_count} 个资产库存, 进入全新实验状态")
    finally:
        db.close()


if __name__ == "__main__":
    main()
