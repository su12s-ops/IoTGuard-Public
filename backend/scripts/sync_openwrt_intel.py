"""Sync OpenWrt official GHSA advisories into the intelligence database.

Run from backend: python scripts/sync_openwrt_intel.py [--snapshot file.json]

默认在线抓取 api.github.com（钉扎 + 解析后 IP 边界校验 + 禁止重定向）；
--snapshot 读取已保存的官方快照（离线/气隙场景）。脚本只写公告与情报行，
不触发匹配与风险判定（分层：候选发现 → 匹配 → 风险创建各自独立执行）。
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.database import SessionLocal  # noqa: E402
from app.services import openwrt_intel  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=None,
                        help="已保存的官方快照 JSON（数组或 {rows: [...]}）；缺省在线抓取")
    parser.add_argument("--output", type=Path, default=None,
                        help="可选：把同步摘要写入 JSON 文件")
    args = parser.parse_args()

    if args.snapshot is not None:
        data = json.loads(args.snapshot.read_text(encoding="utf-8-sig"))
        rows = data if isinstance(data, list) else data["rows"]
        source = f"snapshot:{args.snapshot}"
    else:
        rows = openwrt_intel.fetch_advisory_rows(token=os.getenv("GITHUB_TOKEN") or None)
        source = "live:api.github.com"

    with SessionLocal() as db:
        summary = openwrt_intel.sync_openwrt_advisories(db, rows)
        db.commit()
    summary["source"] = source
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
