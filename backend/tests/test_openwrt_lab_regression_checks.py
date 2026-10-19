"""Regression tests for the registered cgi-io lab repair check scripts.

DEFECT-20261019-regression-freshness-tz: v1 of the registered regression check
computed inventory freshness by subtracting a naive SQLite DATETIME string from
an aware datetime, which always raised TypeError and made the gate permanently
false. v2 interprets naive timestamps as UTC with unchanged semantics. These
tests drive both script files against synthetic SQLite databases so the defect
and the fix stay pinned.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MATERIALS = REPO / "local-archive" / "openwrt-closure-materials"
V1 = MATERIALS / "check_regression_cgi_io.py"
V2 = MATERIALS / "check_regression_cgi_io_v2.py"
pytestmark = pytest.mark.skipif(not (V1.is_file() and V2.is_file()),
    reason="Local historical scripts are gitignored; portable UTC/resume tests run separately")

TARGET = {
    "host": "192.168.206.2", "asset_id": 4, "cve_id": "CVE-2026-62947",
    "package_name": "cgi-io", "expected_version": "2026.07.21~31cb3c89-r1",
}


def _make_tree(tmp: Path) -> Path:
    root = tmp / ("m-" + uuid.uuid4().hex[:8])
    (root / "backend" / "data").mkdir(parents=True)
    # Mirror the real layout: scripts live two levels below the repo root so
    # their parents[2]/backend/data DB path resolves inside the tree.
    materials = root / "local-archive" / "openwrt-closure-materials"
    materials.mkdir(parents=True)
    shutil.copy(V1, materials / "check_regression_cgi_io.py")
    shutil.copy(V2, materials / "check_regression_cgi_io_v2.py")
    con = sqlite3.connect(root / "backend" / "data" / "linuxguard.db")
    con.executescript(
        """
        create table asset_package (asset_id int, package_name text, package_version text, installed_at text);
        create table linux_asset (id int, inventory_complete int, inventory_collected_at text);
        insert into asset_package values (4, 'cgi-io', '2026.07.21~31cb3c89-r1', 'x');
        insert into linux_asset values (4, 1, :collected);
        """
    )
    con.commit()
    con.close()
    return root


def _run(script: Path, root: Path, collected: str) -> dict:
    con = sqlite3.connect(root / "backend" / "data" / "linuxguard.db")
    con.execute("update linux_asset set inventory_collected_at=?", (collected,))
    con.commit()
    con.close()
    out = subprocess.run([sys.executable, str(script)], input=json.dumps(TARGET),
                         capture_output=True, text=True, timeout=45)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_v1_freshness_bug_reproduces_and_v2_handles_naive_utc(tmp_path: Path):
    fresh_naive = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S.%f")
    root = _make_tree(tmp_path)
    v1 = _run(root / "local-archive" / "openwrt-closure-materials" / "check_regression_cgi_io.py", root, fresh_naive)
    v2 = _run(root / "local-archive" / "openwrt-closure-materials" / "check_regression_cgi_io_v2.py", root, fresh_naive)
    # v1: TypeError path -> permanently false even on a 60s-old inventory.
    assert v1["passed"] is False
    assert v1["evidence"]["inventory_fresh_within_15min"] is False
    # v2: same input, unchanged semantics -> fresh inventory passes.
    assert v2["passed"] is True
    assert v2["evidence"]["version_match"] is True
    assert v2["evidence"]["inventory_fresh_within_15min"] is True


def test_v2_stale_naive_inventory_still_rejected(tmp_path: Path):
    stale_naive = (datetime.now(timezone.utc) - timedelta(seconds=3600)).strftime("%Y-%m-%d %H:%M:%S.%f")
    root = _make_tree(tmp_path)
    result = _run(root / "local-archive" / "openwrt-closure-materials" / "check_regression_cgi_io_v2.py", root, stale_naive)
    assert result["passed"] is False
    assert result["evidence"]["inventory_fresh_within_15min"] is False


def test_v2_version_mismatch_still_rejected(tmp_path: Path):
    fresh_naive = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S.%f")
    root = _make_tree(tmp_path)
    con = sqlite3.connect(root / "backend" / "data" / "linuxguard.db")
    con.execute("update asset_package set package_version='2025.12.11~658b14bd-r1'")
    con.commit()
    con.close()
    target = dict(TARGET)
    out = subprocess.run([sys.executable, str(root / "local-archive" / "openwrt-closure-materials" / "check_regression_cgi_io_v2.py")],
                         input=json.dumps(target), capture_output=True, text=True, timeout=45)
    result = json.loads(out.stdout)
    assert result["passed"] is False
    assert result["evidence"]["version_match"] is False
