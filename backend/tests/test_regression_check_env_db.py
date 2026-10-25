"""v4 registered regression check: containerized DB location + env passthrough.

The 2026-10-25 containerized backend round keeps the product database at
LINUXGUARD_DATA_DIR (docker-compose declares /app/data), while the legacy
host deployments resolved it relative to the script location. The registered
check v4 prefers the env directory and keeps the legacy fallback; the harness
allowlists LINUXGUARD_DATA_DIR for registered check processes (a plain
directory path, never a secret). These tests pin both behaviours.

Timing follows the real receipt order: installation completed → verification
started → backend receives the fresh inventory (collected) → now.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.services.agent_harness import _check_env

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "local-archive" / "openwrt-repair-registry-20261025"
V4 = REGISTRY / "check_regression_cgi_io_v4.py"
pytestmark = pytest.mark.skipif(not V4.is_file(),
    reason="Local registered check v4 is gitignored; runs on the operator host")


def _target(collected_age: float = 30):
    now = datetime.now(timezone.utc)
    return {
        "host": "192.168.206.2", "asset_id": 4, "cve_id": "CVE-2026-62947",
        "package_name": "cgi-io", "expected_version": "2026.07.21~31cb3c89-r1",
        "installation_completed_at": (now - timedelta(seconds=collected_age + 120)).isoformat(),
        "verification_started_at": (now - timedelta(seconds=collected_age + 60)).isoformat(),
    }


def _naive(age_seconds: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")


def _seed(db_path: Path, collected: str, version="2026.07.21~31cb3c89-r1"):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        create table asset_package (asset_id int, package_name text, package_version text, installed_at text);
        create table linux_asset (id int, inventory_complete int, inventory_collected_at text);
        """
    )
    con.execute("insert into asset_package values (4, 'cgi-io', ?, 'x')", (version,))
    con.execute("insert into linux_asset values (4, 1, ?)", (collected,))
    con.commit()
    con.close()


def _run(script: Path = V4, env: dict | None = None, target: dict | None = None):
    out = subprocess.run([sys.executable, str(script)], input=json.dumps(target or _target()),
                         capture_output=True, text=True, timeout=45,
                         env=env if env is not None else os.environ)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_check_env_forwards_data_dir_and_filters_secrets(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_DATA_DIR", "/app/data")
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "secret-token")
    env = _check_env()
    assert env.get("LINUXGUARD_DATA_DIR") == "/app/data"
    assert env.get("PYTHONUTF8") == "1"
    assert "LINUXGUARD_CONTROL_TOKEN" not in env
    assert "LINUXGUARD_REPAIR_MANIFEST" not in env


def test_v4_prefers_env_data_dir_over_stale_legacy_layout(tmp_path: Path):
    token = uuid.uuid4().hex[:8]
    # Legacy layout carries a STALE inventory; env-provided dir is FRESH.
    _seed(tmp_path / f"m-{token}" / "backend" / "data" / "linuxguard.db", _naive(3600))
    container_dir = tmp_path / f"m-{token}" / "container-data"
    fresh = _naive(30)
    _seed(container_dir / "linuxguard.db", fresh)
    result = _run(env={**os.environ, "LINUXGUARD_DATA_DIR": str(container_dir)})
    assert result["passed"] is True
    assert result["evidence"]["inventory_collected_at"] == fresh
    assert result["evidence"]["inventory_fresh_within_15min"] is True


def test_v4_rejects_stale_inventory_via_env_dir(tmp_path: Path):
    container_dir = tmp_path / ("d-" + uuid.uuid4().hex[:8])
    _seed(container_dir / "linuxguard.db", _naive(3600))
    result = _run(env={**os.environ, "LINUXGUARD_DATA_DIR": str(container_dir)})
    assert result["passed"] is False
    assert result["evidence"]["inventory_fresh_within_15min"] is False


def test_v4_falls_back_to_legacy_layout_without_env(tmp_path: Path):
    root = tmp_path / ("m-" + uuid.uuid4().hex[:8])
    materials = root / "local-archive" / "openwrt-repair-registry-20261025"
    materials.mkdir(parents=True)
    script = materials / "check_regression_cgi_io_v4.py"
    script.write_text(V4.read_text(encoding="utf-8"), encoding="utf-8")
    _seed(root / "backend" / "data" / "linuxguard.db", _naive(30))
    env = {key: value for key, value in os.environ.items() if key != "LINUXGUARD_DATA_DIR"}
    result = _run(script, env=env)
    assert result["passed"] is True
    assert result["evidence"]["version_match"] is True
