"""Build a clean, English-path LinuxGuard delivery directory and zip file."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CODE_ROOT = PROJECT_ROOT / "代码"
DELIVERY_ROOT = PROJECT_ROOT / "delivery"
DEFAULT_OUTPUT = DELIVERY_ROOT / "linuxguard-iot-20260930"

EXCLUDED_DIRECTORIES = {
    ".mimosa",
    ".codex",
    ".agents",
    "data",
    "private-artifacts",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".vite",
    "__pycache__",
    "node_modules",
    "dist",
    "test-results",
    "playwright-report",
    "coverage",
    "archives",
    "analysis_runs",
}
EXCLUDED_FILE_NAMES = {
    ".env",
    "ebpf_events.jsonl",
}
EXCLUDED_SUFFIXES = {
    ".db",
    ".db-shm",
    ".db-wal",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".pem",
    ".key",
    ".ipk",
    ".apk",
}


def _is_sensitive_env(name: str) -> bool:
    return name.startswith(".env.") and name != ".env.example"


def _ignore(_directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if (Path(_directory) / name).is_symlink():
            ignored.add(name)
            continue
        lower = name.lower()
        if name in EXCLUDED_DIRECTORIES or name in EXCLUDED_FILE_NAMES or _is_sensitive_env(name):
            ignored.add(name)
            continue
        if any(lower.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
            ignored.add(name)
    return ignored


def _validated_output(raw_output: Path) -> Path:
    output = raw_output.resolve()
    delivery_root = DELIVERY_ROOT.resolve()
    if output == delivery_root or delivery_root not in output.parents:
        raise SystemExit(f"Refusing delivery output outside {delivery_root}: {output}")
    if any(ord(char) > 127 for char in output.name):
        raise SystemExit("Delivery directory name must contain ASCII characters only")
    return output


def _copy_source(source: Path, destination: Path) -> None:
    if not source.exists():
        raise SystemExit(f"Required delivery source is missing: {source}")
    shutil.copytree(source, destination, ignore=_ignore)


def _sanitize_compose(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    content = content.replace("../代码/", "../")
    content = re.sub(
        r'(?m)^(\s*DEEPSEEK_API_KEY:)\s*.*$',
        r'\1 "${DEEPSEEK_API_KEY:-}"',
        content,
    )
    content = re.sub(
        r'(?m)^(\s*VM_PASS:)\s*.*$',
        r'\1 "${VM_PASS:-}"',
        content,
    )
    path.write_text(content, encoding="utf-8", newline="\n")


def _normalize_readme(source: Path, destination: Path) -> None:
    content = source.read_text(encoding="utf-8")
    content = content.replace("Docker配置", "docker")
    content = content.replace("代码/", "")
    content = content.replace("代码\\", "")
    content = content.replace("数据样本", "samples")
    destination.write_text(content, encoding="utf-8", newline="\n")


def _verify_delivery(output: Path) -> dict:
    forbidden: list[str] = []
    non_ascii_paths: list[str] = []
    secret_hits: list[str] = []
    files = [path for path in output.rglob("*") if path.is_file()]
    for path in files:
        relative = path.relative_to(output)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts) and relative != Path("backend/data/.gitkeep"):
            forbidden.append(str(relative))
        if path.name in EXCLUDED_FILE_NAMES or _is_sensitive_env(path.name):
            forbidden.append(str(relative))
        if any(path.name.lower().endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
            forbidden.append(str(relative))
        if any(any(ord(char) > 127 for char in part) for part in relative.parts):
            non_ascii_paths.append(str(relative))
        if path.suffix.lower() in {".py", ".js", ".vue", ".yml", ".yaml", ".md", ".txt", ".json", ""}:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if re.search(r"sk-[A-Za-z0-9]{16,}", text):
                secret_hits.append(str(relative))
    if forbidden or non_ascii_paths or secret_hits:
        raise SystemExit(json.dumps({
            "forbidden": forbidden,
            "non_ascii_paths": non_ascii_paths,
            "secret_hits": secret_hits,
        }, ensure_ascii=False, indent=2))
    return {
        "file_count": len(files),
        "total_bytes": sum(path.stat().st_size for path in files),
        "forbidden_file_count": 0,
        "non_ascii_path_count": 0,
        "secret_hit_count": 0,
    }


def build(output: Path, replace: bool = False) -> tuple[Path, Path]:
    output = _validated_output(output)
    if output.exists():
        if not replace:
            raise SystemExit(f"Output already exists; pass --replace: {output}")
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    for source, destination in (
        (CODE_ROOT / "backend", output / "backend"),
        (CODE_ROOT / "frontend", output / "frontend"),
        (CODE_ROOT / "collector", output / "collector"),
        (CODE_ROOT / "scripts", output / "scripts"),
        (PROJECT_ROOT / "Docker配置", output / "docker"),
        (PROJECT_ROOT / "数据样本", output / "samples"),
    ):
        _copy_source(source, destination)

    shutil.copy2(CODE_ROOT / "pytest.ini", output / "pytest.ini")
    shutil.copy2(PROJECT_ROOT / ".gitignore", output / ".gitignore")
    _normalize_readme(PROJECT_ROOT / "README.md", output / "README.md")
    _normalize_readme(PROJECT_ROOT / "IOT_UPGRADE_GUIDE.md", output / "IOT_UPGRADE_GUIDE.md")
    shutil.copy2(PROJECT_ROOT / "UPGRADE_PLAN.md", output / "UPGRADE_PLAN.md")
    _sanitize_compose(output / "docker" / "docker-compose.yml")

    data_dir = output / "backend" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / ".gitkeep").touch()

    verification = _verify_delivery(output)
    manifest = {
        "project": "LinuxGuard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "layout": ["backend", "frontend", "collector", "scripts", "docker", "samples"],
        "excluded": sorted(EXCLUDED_DIRECTORIES | EXCLUDED_FILE_NAMES | EXCLUDED_SUFFIXES),
        "verification": verification,
    }
    (output / "DELIVERY_MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n"
    )
    verification = _verify_delivery(output)

    archive_base = output.parent / output.name
    archive_path = archive_base.with_suffix(".zip")
    if archive_path.exists():
        archive_path.unlink()
    created = Path(shutil.make_archive(str(archive_base), "zip", root_dir=output.parent, base_dir=output.name))
    print(json.dumps({
        "output": str(output),
        "archive": str(created),
        "verification": verification,
    }, ensure_ascii=False, indent=2))
    return output, created


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    build(args.output, replace=args.replace)


if __name__ == "__main__":
    main()
