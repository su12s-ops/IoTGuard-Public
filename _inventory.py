# -*- coding: utf-8 -*-
"""生成 IoTGuard 全量文件清单（只读扫描，不改动任何项目文件）。"""
import csv
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import xlsxwriter

ROOT = Path(r"E:\IoTGuard-Public")
OUT_XLSX = ROOT / "FILE_INVENTORY_20261021.xlsx"
OUT_CSV = ROOT / "FILE_INVENTORY_20261021.csv"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def git_out(*args):
    proc = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True)
    return [x.decode("utf-8", "replace") for x in proc.stdout.split(b"\0") if x]


def git_text(*args):
    proc = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True)
    return proc.stdout.decode("utf-8", "replace").strip()


tracked = set(git_out("ls-files", "-z"))
untracked = set(git_out("ls-files", "--others", "--exclude-standard", "-z"))
ignored = set(git_out("ls-files", "--others", "--ignored", "--exclude-standard", "-z"))

modified = set()
for entry in git_out("status", "--porcelain", "-z"):
    if len(entry) > 3:
        code, path = entry[:2], entry[3:]
        if code != "??" and code.strip():
            modified.add(path)

HEAD = git_text("rev-parse", "--short", "HEAD")
BRANCH = git_text("branch", "--show-current")

for stale in (OUT_XLSX, OUT_CSV):
    if stale.exists():
        stale.unlink()

# ── 分类规则：顺序敏感，先匹配先生效 ──────────────────────────────
RULES = [
    ("exact", "backend/data/linuxguard.db", "运行数据", "保留", "当前业务库（约 4.4 GB），设备/风险/证据/审计的唯一来源"),
    ("exact", "backend/data/linuxguard.db-wal", "运行数据", "保留", "业务库 WAL，随主库存在"),
    ("exact", "backend/data/linuxguard.db-shm", "运行数据", "保留", "业务库共享内存索引"),
    ("exact", "backend/data/ebpf_events.jsonl", "运行数据", "待定", "eBPF 原始事件池 1.3 GB；已解析入库，删除只损失原始回溯"),
    ("prefix", "backend/data/collaboration_upgrade/", "实验残留", "删除", "旧代码基线副本 + preexisting 补丁，全库无任何引用"),
    ("prefix", "backend/apk-static/", "实验残留", "删除", "APK 实验基线副本与补丁，无引用"),
    ("prefix", "backend/reports/", "实验残留", "删除", "stage9* 历史测试输出（137 json / 28 db），非交付内容"),
    ("prefix", "backend/data/", "运行数据", "待定", "data 目录其余运行产物与日志"),
    ("prefix", "backend/.env", "配置", "保留", "本地凭据/.env，已被忽略，不可删"),
    ("prefix", "frontend/.env", "配置", "保留", "前端本地环境，已被忽略"),
    ("prefix", ".mimosa/", "工具状态", "待定", "Mimosa AI 协作工具的状态与历史，不是项目内容"),
    ("contains", "/.mimosa/", "工具状态", "待定", "Mimosa 工具状态目录"),
    ("contains", "__pycache__/", "生成物", "删除", "Python 字节码缓存，可重建"),
    ("prefix", ".pytest_cache/", "生成物", "删除", "pytest 缓存"),
    ("prefix", "frontend/dist/", "生成物", "删除", "前端构建产物，npm run build 可重建"),
    ("prefix", "frontend/test-results/", "生成物", "删除", "Playwright 测试产物"),
    ("prefix", "collector/native/build/", "生成物", "删除", "eBPF 编译产物，make 可重建"),
    ("prefix", "frontend/node_modules/", "依赖", "保留", "npm 依赖，npm ci 可重建但开发需要"),
    ("prefix", "reports/", "历史快照", "待定", "20.5 GB 历史验收证据（含 8 个 GB 级数据库副本），docs 中有引用"),
    ("prefix", "local-archive/", "历史快照", "待定", "10.4 GB 本地归档（2 套 venv + 12 组阶段快照），不入库"),
    ("prefix", "mockups/", "设计稿", "待定", "设计图稿与 HTML 原型，未入库"),
    ("prefix", "docs/design/", "设计稿", "保留", "文档引用的设计截图"),
    ("prefix", ".git/", "版本库", "保留", "Git 对象与索引"),
    ("prefix", ".github/", "仓库配置", "保留", "CI 与 Issue 模板"),
    ("prefix", "ai_collaboration/", "协作文档", "待定", "5 份阶段笔记 + 工具 hook，无代码引用"),
    ("exact", "_inventory.py", "临时工具", "删除", "本次盘点用的临时脚本"),
]


def classify(rel):
    lowered = rel
    for kind, pattern, category, verdict, reason in RULES:
        if kind == "exact" and rel == pattern:
            return category, verdict, reason
        if kind == "prefix" and rel.startswith(pattern):
            return category, verdict, reason
        if kind == "contains" and pattern in "/" + lowered:
            return category, verdict, reason
    if rel in tracked:
        return "源码", "保留", "已入库源码/文档"
    if rel in untracked:
        source_roots = ("backend/", "frontend/", "docs/", "scripts/", "collector/",
                        "deploy/", "firmware/", "simulator/", ".github/")
        if rel.startswith(source_roots) or "/" not in rel:
            return "未入库源码", "保留", "未提交的当前工作成果，建议 git add 而不是删除"
        return "未入库", "待定", "未纳入 Git 跟踪，需确认是否属于当前工作"
    if rel in ignored:
        return "其他忽略项", "待定", "被 .gitignore 忽略的本地文件"
    return "未入库", "待定", "未纳入 Git 跟踪"


rows = []
skipped = 0
for dirpath, dirnames, filenames in os.walk(ROOT):
    for name in filenames:
        full = Path(dirpath) / name
        try:
            stat = full.stat()
        except OSError:
            skipped += 1
            continue
        rel = full.relative_to(ROOT).as_posix()
        category, verdict, reason = classify(rel)
        if rel in modified:
            git_state = "已修改"
        elif rel in tracked:
            git_state = "已提交"
        elif rel in untracked:
            git_state = "未入库"
        elif rel in ignored:
            git_state = "已忽略"
        else:
            git_state = "未知"
        parts = rel.split("/")
        if len(parts) == 1:
            depth2 = "(根目录)"
        elif len(parts) == 2:
            depth2 = parts[0]
        else:
            depth2 = parts[0] + "/" + parts[1]
        rows.append({
            "path": rel,
            "name": name,
            "size_mb": round(stat.st_size / 1048576, 3),
            "size_bytes": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "category": category,
            "verdict": verdict,
            "reason": reason,
            "git_state": git_state,
            "top": parts[0] if len(parts) > 1 else "(根目录)",
            "depth2": depth2,
            "ext": ("." + name.rsplit(".", 1)[1].lower()) if "." in name else "",
        })

rows.sort(key=lambda r: (-r["size_bytes"], r["path"]))

total_files = len(rows)
total_mb = sum(r["size_bytes"] for r in rows) / 1048576

cat_stat = defaultdict(lambda: [0, 0])
verdict_stat = defaultdict(lambda: [0, 0])
for r in rows:
    cat_stat[r["category"]][0] += 1
    cat_stat[r["category"]][1] += r["size_bytes"]
    verdict_stat[r["verdict"]][0] += 1
    verdict_stat[r["verdict"]][1] += r["size_bytes"]

# ── 目录汇总（1 级 + 2 级）─────────────────────────────────────
dirs = defaultdict(lambda: {"files": 0, "size": 0, "cats": set(), "verdicts": set(),
                            "v": {"删除": [0, 0], "待定": [0, 0], "保留": [0, 0]}})
for r in rows:
    for key in {r["top"], r["depth2"]}:
        d = dirs[key]
        d["files"] += 1
        d["size"] += r["size_bytes"]
        d["cats"].add(r["category"])
        d["verdicts"].add(r["verdict"])
        d["v"][r["verdict"]][0] += 1
        d["v"][r["verdict"]][1] += r["size_bytes"]

ORDER = {"删除": 0, "待定": 1, "保留": 2}
dir_rows = []
for key, d in dirs.items():
    verdicts = d["verdicts"]
    if verdicts == {"删除"}:
        verdict = "删除"
    elif len(verdicts) == 1:
        verdict = next(iter(verdicts))
    elif "待定" in verdicts:
        verdict = "待定"
    else:
        verdict = "混合"
    dir_rows.append({
        "dir": key,
        "level": key.count("/") + 1,
        "files": d["files"],
        "mb": d["size"] / 1048576,
        "cats": "、".join(sorted(d["cats"])),
        "verdict": verdict,
        "v": d["v"],
    })
dir_rows.sort(key=lambda d: (d["level"], -d["mb"]))

# ── 写 XLSX ────────────────────────────────────────────────────
wb = xlsxwriter.Workbook(str(OUT_XLSX), {"constant_memory": False})
F = {
    "title": wb.add_format({"bold": True, "font_size": 15, "font_color": "#1F3864"}),
    "h": wb.add_format({"bold": True, "bg_color": "#1F3864", "font_color": "white", "border": 1, "align": "center", "valign": "vcenter", "text_wrap": True}),
    "txt": wb.add_format({"font_size": 10, "valign": "top"}),
    "num": wb.add_format({"font_size": 10, "num_format": "0.00", "valign": "top"}),
    "int": wb.add_format({"font_size": 10, "num_format": "#,##0", "valign": "top"}),
    "del": wb.add_format({"font_size": 10, "bg_color": "#FFC7CE", "valign": "top"}),
    "keep": wb.add_format({"font_size": 10, "bg_color": "#C6EFCE", "valign": "top"}),
    "hold": wb.add_format({"font_size": 10, "bg_color": "#FFEB9C", "valign": "top"}),
    "note": wb.add_format({"font_size": 10, "italic": True, "font_color": "#595959", "text_wrap": True, "valign": "top"}),
    "big": wb.add_format({"bold": True, "font_size": 11, "font_color": "#C00000"}),
}


def verdict_fmt(verdict):
    return {"删除": F["del"], "保留": F["keep"], "待定": F["hold"]}.get(verdict, F["txt"])


def write_table(ws, headers, widths, data, verdict_col=None, start_row=0):
    for c, (h, w) in enumerate(zip(headers, widths)):
        ws.write(start_row, c, h, F["h"])
        ws.set_column(c, c, w)
    ws.set_row(start_row, 30)
    for i, row in enumerate(data, start=1):
        for c, value in enumerate(row):
            fmt = F["txt"]
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                fmt = F["int"] if isinstance(value, int) else F["num"]
            if verdict_col is not None and c == verdict_col:
                fmt = verdict_fmt(str(value))
            ws.write(start_row + i, c, value, fmt)
    ws.autofilter(start_row, 0, start_row + len(data), len(headers) - 1)
    ws.freeze_panes(start_row + 1, 0)


# ① 说明 + 总览
ws = wb.add_worksheet("① 总览")
ws.set_column(0, 0, 26)
ws.set_column(1, 1, 14)
ws.set_column(2, 2, 14)
ws.set_column(3, 3, 12)
ws.set_column(4, 4, 70)
ws.write(0, 0, "IoTGuard 文件盘点与清理清单", F["title"])
ws.write(1, 0, f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　分支：{BRANCH or '(detached)'}　HEAD：{HEAD}", F["note"])
ws.write(2, 0, f"扫描根目录：{ROOT}　文件总数：{total_files:,}　总体积：{total_mb:,.1f} MB", F["note"])
ws.write(3, 0, "用法：在「④ 全部文件」按「清理建议」筛选；如需推翻某条，在「你的决定」列填 保留/删除，然后告诉我按该列执行。", F["note"])
ws.write(4, 0, f"扫描时无权限读取而跳过的文件：{skipped}", F["note"])
ws.write(5, 0, "建议删除：{:,} 个 / {:.1f} MB　待定：{:,} 个 / {:.1f} MB　保留：{:,} 个 / {:.1f} MB".format(
    verdict_stat["删除"][0], verdict_stat["删除"][1] / 1048576,
    verdict_stat["待定"][0], verdict_stat["待定"][1] / 1048576,
    verdict_stat["保留"][0], verdict_stat["保留"][1] / 1048576), F["note"])
ws.write(6, 0, "注意：reports/ 与 local-archive/ 合计约 30.8 GB，docs 里的验收报告引用了其中的证据，删除后无法追溯；backend/data/linuxguard.db 是当前业务库，任何情况下都不应删。", F["note"])
ws.write(7, 0, "分类依据：路径规则 + Git 跟踪状态（已提交/已修改/未入库/已忽略），不代表代码质量评估。", F["note"])

row = 9
for title, stat in (("按分类", cat_stat), ("按建议", verdict_stat)):
    ws.write(row, 0, title, F["title"])
    row += 1
    for c, h in enumerate(["项目", "文件数", "体积 MB"]):
        ws.write(row, c, h, F["h"])
    row += 1
    for key, (count, size) in sorted(stat.items(), key=lambda kv: -kv[1][1]):
        ws.write(row, 0, key, F["txt"])
        ws.write(row, 1, count, F["int"])
        ws.write(row, 2, round(size / 1048576, 1), F["num"])
        row += 1
    row += 1

# ② 目录汇总
ws2 = wb.add_worksheet("② 目录汇总")
data = []
for d in dir_rows:
    data.append([
        d["dir"], d["level"], d["files"], round(d["mb"], 2),
        d["v"]["删除"][0], round(d["v"]["删除"][1] / 1048576, 2),
        d["v"]["待定"][0], round(d["v"]["待定"][1] / 1048576, 2),
        d["v"]["保留"][0], round(d["v"]["保留"][1] / 1048576, 2),
        d["cats"],
    ])
headers = ["目录", "层级", "文件数", "体积 MB", "可删文件", "可删 MB",
           "待定文件", "待定 MB", "保留文件", "保留 MB", "包含分类"]
widths = [46, 6, 10, 11, 10, 10, 10, 10, 10, 10, 34]
for c, (h, w) in enumerate(zip(headers, widths)):
    ws2.write(0, c, h, F["h"])
    ws2.set_column(c, c, w)
ws2.set_row(0, 30)
for i, row in enumerate(data, start=1):
    for c, value in enumerate(row):
        fmt = F["txt"]
        if isinstance(value, int) and not isinstance(value, bool):
            fmt = F["int"]
        elif isinstance(value, float):
            fmt = F["num"]
        if c == 5 and row[5] > 0:
            fmt = F["del"]
        ws2.write(i, c, value, fmt)
ws2.autofilter(0, 0, len(data), len(headers) - 1)
ws2.freeze_panes(1, 1)

# ③ 待删候选
ws3 = wb.add_worksheet("③ 待删候选")
cand = [r for r in rows if r["verdict"] == "删除"]
data = [[r["path"], r["size_mb"], r["mtime"], r["category"], r["git_state"], r["reason"]] for r in cand]
write_table(ws3, ["相对路径", "大小 MB", "修改时间", "分类", "入库状态", "理由"], [78, 10, 17, 10, 9, 46], data)
ws3.write(0, 7, f"合计 {len(cand)} 个文件 / {sum(r['size_bytes'] for r in cand)/1048576:.1f} MB", F["big"])

# ④ 全部文件
ws4 = wb.add_worksheet("④ 全部文件")
data = [[i + 1, r["path"], r["name"], r["size_mb"], r["mtime"], r["category"], r["verdict"],
         r["reason"], r["git_state"], r["top"], ""] for i, r in enumerate(rows)]
write_table(ws4, ["#", "相对路径", "文件名", "大小 MB", "修改时间", "分类", "清理建议", "理由", "入库状态", "顶层目录", "你的决定"],
            [7, 78, 34, 10, 17, 10, 9, 46, 9, 14, 12], data, verdict_col=6)

# ⑤ 大文件
ws5 = wb.add_worksheet("⑤ 大文件 Top100")
big = [r for r in rows if r["size_bytes"] >= 50 * 1048576][:100]
data = [[i + 1, r["path"], r["size_mb"], r["mtime"], r["category"], r["verdict"], r["git_state"]] for i, r in enumerate(big)]
write_table(ws5, ["#", "相对路径", "大小 MB", "修改时间", "分类", "建议", "入库状态"], [6, 86, 11, 17, 12, 9, 10], data, verdict_col=5)

# ⑥ 未提交变更
ws6 = wb.add_worksheet("⑥ 未提交变更")
changed = [r for r in rows if r["git_state"] in ("已修改", "未入库")]
data = [[r["path"], r["size_mb"], r["mtime"], r["git_state"], r["category"], r["verdict"]] for r in changed]
write_table(ws6, ["相对路径", "大小 MB", "修改时间", "状态", "分类", "建议"], [86, 10, 17, 9, 10, 9], data, verdict_col=5)
ws6.write(0, 7, f"共 {len(changed)} 个：已修改 {sum(1 for r in changed if r['git_state']=='已修改')} / 未入库 {sum(1 for r in changed if r['git_state']=='未入库')}", F["big"])

wb.close()

# ── CSV（不含 node_modules / .git 的逐文件行，避免过大）──────────
with open(OUT_CSV, "w", newline="", encoding="utf-8-sig") as fh:
    writer = csv.writer(fh)
    writer.writerow(["相对路径", "文件名", "大小MB", "修改时间", "分类", "清理建议", "理由", "入库状态"])
    for r in rows:
        if r["path"].startswith(("frontend/node_modules/", ".git/")):
            continue
        writer.writerow([r["path"], r["name"], r["size_mb"], r["mtime"], r["category"], r["verdict"], r["reason"], r["git_state"]])

print(f"files={total_files} total_mb={total_mb:.1f} skipped={skipped}")
for k, (c, s) in sorted(verdict_stat.items(), key=lambda kv: -kv[1][1]):
    print(f"  {k}: {c} files, {s/1048576:.1f} MB")
for k, (c, s) in sorted(cat_stat.items(), key=lambda kv: -kv[1][1]):
    print(f"  [{k}] {c} files, {s/1048576:.1f} MB")
print(f"xlsx={OUT_XLSX}")
print(f"csv={OUT_CSV}")
