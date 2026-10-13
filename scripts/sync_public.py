#!/usr/bin/env python3
"""Private 到 Public 的单向同步器（IoTGuard 双仓工作流核心）。

流程（任一步失败即终止，绝不带病推送）：
  1. 校验 Private 工作区干净（保证已扫描即已推送）；
  2. 导出 Private 当前跟踪树（git archive HEAD，天然排除 .git 对象库与
     一切被忽略规则挡下的敏感文件）；
  3. 镜像 Public 工作目录（仅保留 Public 自身的 .git，维持独立历史）；
  4. 防泄露双保险：对 Public 工作目录执行禁止路径与敏感内容扫描，
     任何命中立即终止（不提交、不推送）；
  5. 增量提交并在提交信息中记录来源 Private 提交哈希，随后普通推送
     origin 主分支（绝不使用 force）。

目录推导（不硬编码本机路径）：Private 取本脚本所在仓库根；
Public 取环境变量 IOTGUARD_PUBLIC_DIR，缺省为 Private 根的同级
IoTGuard-Public 目录。网络代理沿用运行环境（如 HTTPS_PROXY）。
用法：python 本脚本，可选 --check 仅导出并扫描而不提交推送。
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIR = REPO_ROOT
PUBLIC_DIR = Path(os.environ.get("IOTGUARD_PUBLIC_DIR",
                                 str(REPO_ROOT.parent.joinpath("IoTGuard-Public"))))
PUBLIC_REMOTE = "https://github.com/su12s-ops/IoTGuard-Public.git"
GIT_AUTHOR_NAME = "IoTGuard Sync"
GIT_AUTHOR_EMAIL = "iotguard-sync@local"
ARCHIVE_NAME = "tree.tar"

# 禁止出现在 Public 的相对路径（目录前缀匹配）；忽略规则是第一道防线，此处兜底。
FORBIDDEN_PATHS = (
    "backend/.env", "backend/data", "reports", "asset_inventory.json",
    "frontend/test-results", ".mimosa", ".pytest_cache", "__pycache__",
)
FORBIDDEN_SUFFIXES = (".env", ".pem", ".key", ".p12", ".pfx", ".vmdk", ".vmx",
                      ".vmem", ".iso", ".img", ".db", ".log", ".pyc")
ALLOWED_ENV_FILES = ("backend/.env.example", "frontend/.env.example")

# 敏感内容模式（命中即终止推送）。
# 注意：各模式的字面量子串在源码中均以拼接构造，避免本文件自身触发扫描。
_H = "gh" + "p_"
_O = "gh" + "o_"
_P = "github" + "_pat_"
_K = "osint-" + "threat-intel"
_W = "wyh" + "lwj"
_C = "信安" + "作品赛"
_U = "Users[/\\\\]" + "29" + "04"
_IP1 = r"192\.168\.183\." + "129"
_IP2 = r"192\.168\.100\." + "118"
_CPU = "Ultra 5 " + "125H"
_FP = "SHA256:" + r"\+CaF"
_PK = "-----BEGIN " + "[A-Z ]*PRIVATE KEY-----"
SENSITIVE_PATTERNS = [
    re.compile(_H + r"[A-Za-z0-9]{30,}"),
    re.compile(_O + r"[A-Za-z0-9]{30,}"),
    re.compile(_P + r"[A-Za-z0-9_]{20,}"),
    re.compile("s" + "k-" + r"[A-Za-z0-9]{20,}"),
    re.compile("AKIA" + r"[0-9A-Z]{16}"),
    re.compile("xo" + "x" + r"[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile("AI" + "za" + r"[0-9A-Za-z_-]{30,}"),
    re.compile(_PK),
    # 项目历史环境标识（公开前整改的回归底线）
    re.compile(_W),
    re.compile(r"\bwy" + "h\b"),
    re.compile(_K),
    re.compile(_C),
    re.compile(_U),
    re.compile(_IP1),
    re.compile(_IP2),
    re.compile(_CPU),
    re.compile(_FP),
]
TEXT_SUFFIXES = {".py", ".js", ".vue", ".md", ".json", ".yml", ".yaml", ".sh",
                 ".txt", ".html", ".css", ".sql", ".ini", ".example", ".bat",
                 ".mjs", ".cfg", ""}


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    if check and result.returncode != 0:
        sys.stderr.write(f"[sync] 命令失败: {' '.join(cmd)}\n{result.stderr}\n")
        raise SystemExit(1)
    return result.stdout.strip()


def _validated_repo_dirs() -> tuple[Path, Path]:
    """入口校验两个工作目录：路径不含上跳段且互不相同；Private 必须已存在。"""
    private = PRIVATE_DIR.resolve()
    public = PUBLIC_DIR.resolve()
    for label, value in (("Private", private), ("Public", public)):
        if ".." in value.parts:
            raise SystemExit(f"[sync] {label} 目录路径非法: {value}")
    if not private.is_dir():
        raise SystemExit(f"[sync] Private 目录无效: {private}")
    if private == public:
        raise SystemExit("[sync] Private 与 Public 目录相同，拒绝执行")
    return private, public


def _validate_member(name: str) -> None:
    """归档成员名词法校验：拒绝绝对路径、盘符与上跳段。"""
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if normalized.startswith("/") or ".." in parts or ":" in parts[0]:
        raise SystemExit(f"[sync] 归档成员路径非法: {name!r}")


def export_tree(private: Path, public: Path) -> None:
    """导出 private HEAD 跟踪树并解包到 public（无中间文件）。

    成员名取自 `git ls-tree -r --name-only HEAD`（与归档内容一致），先经
    词法校验；随后 git archive 经 stdout 流式交给系统 tar 在 public 内解包。
    """
    listing = run(["git", "-C", str(private), "ls-tree", "-r", "--name-only", "HEAD"])
    for name in listing.splitlines():
        if name:
            _validate_member(name)
    git_proc = subprocess.Popen(
        ["git", "-C", str(private), "archive", "--format=tar", "HEAD"],
        stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-f", "-", "-C", str(public)],
                             stdin=git_proc.stdout, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
    if git_proc.stdout:
        git_proc.stdout.close()
    if git_proc.wait() != 0 or extract.returncode != 0:
        sys.stderr.write(f"[sync] 流式导出失败: {extract.stderr}\n")
        raise SystemExit(1)


def scan_public(public: Path) -> list[str]:
    """对 Public 工作目录做禁止路径与敏感内容扫描，返回命中清单。"""
    findings: list[str] = []
    root = public.resolve()
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if not path.is_file() or (rel_parts and rel_parts[0] == ".git"):
            continue
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWED_ENV_FILES:
            continue
        if any(rel == p or rel.startswith(p + "/") for p in FORBIDDEN_PATHS) \
                or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(f"禁止路径或后缀: {rel}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > 5_000_000:
            continue
        try:
            blob = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in SENSITIVE_PATTERNS:
            hit = pattern.search(blob)
            if hit:
                findings.append(f"敏感内容: {rel} 命中 {hit.group(0)[:40]!r}")
                break
    return findings


def mirror(public: Path) -> None:
    """清空 Public 工作目录（保留其 .git）以承接全新导出。"""
    root = public.resolve()
    for entry in root.iterdir():
        if entry.name == ".git":
            continue
        resolved = entry.resolve()
        if not resolved.is_relative_to(root):
            raise SystemExit(f"[sync] 镜像清理越界: {entry}")
        if entry.is_dir():
            shutil.rmtree(resolved)
        else:
            resolved.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync private HEAD to the public mirror repo")
    parser.add_argument("--check", action="store_true", help="仅导出并扫描，不提交推送")
    args = parser.parse_args()

    private, public = _validated_repo_dirs()
    if not private.joinpath(".git").is_dir():
        raise SystemExit(f"[sync] Private 仓库不存在: {private}")
    dirty = run(["git", "status", "--porcelain"], cwd=private)
    if dirty:
        sys.stderr.write("[sync] Private 工作区不干净，先提交后再同步：\n" + dirty[:800] + "\n")
        raise SystemExit(2)
    private_sha = run(["git", "rev-parse", "HEAD"], cwd=private)
    print(f"[sync] Private HEAD: {private_sha}")

    public.mkdir(parents=True, exist_ok=True)
    mirror(public)
    export_tree(private, public)
    findings = scan_public(public)
    if findings:
        sys.stderr.write("[sync] 敏感扫描命中，已终止（未提交未推送）：\n  - "
                         + "\n  - ".join(findings[:30]) + "\n")
        raise SystemExit(3)
    tracked = sum(1 for p in public.rglob("*") if p.is_file() and ".git" not in p.parts)
    print(f"[sync] 敏感扫描通过；Public 工作目录文件数: {tracked}")

    if args.check:
        print("[sync] --check 模式：未提交未推送")
        return 0

    if not public.joinpath(".git").is_dir():
        run(["git", "init", "-b", "main"], cwd=public)
    remotes = run(["git", "remote"], cwd=public)
    if "origin" not in remotes.split():
        run(["git", "remote", "add", "origin", PUBLIC_REMOTE], cwd=public)
    run(["git", "config", "user.name", GIT_AUTHOR_NAME], cwd=public)
    run(["git", "config", "user.email", GIT_AUTHOR_EMAIL], cwd=public)
    run(["git", "add", "-A"], cwd=public)
    staged = run(["git", "diff", "--cached", "--name-only"], cwd=public)
    if not staged:
        print(f"[sync] Public 已与 Private@{private_sha[:12]} 一致，无需提交")
        return 0
    count = len(staged.splitlines())
    run(["git", "commit", "-m", f"Sync from private@{private_sha}",
         "-m", f"Source-Commit: {private_sha}"], cwd=public)
    run(["git", "push", "origin", "main"], cwd=public)
    public_sha = run(["git", "rev-parse", "HEAD"], cwd=public)
    print(f"[sync] 完成：Public {public_sha}（{count} 个文件变更，来源 Private@{private_sha[:12]}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
