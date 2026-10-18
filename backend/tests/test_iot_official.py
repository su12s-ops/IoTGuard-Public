import copy

import pytest

from app import models
from app.services.iot_official import import_snapshot, assess_snapshot, version_in_range


ROW = {"ghsa_id": "GHSA-82gq-cmqw-xgx2", "cve_id": "CVE-2026-76787",
       "html_url": "https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-82gq-cmqw-xgx2",
       "vulnerabilities": [{"vulnerable_version_range": ">= 2.4.0, <= 4.4.2",
                            "patched_versions": "4.5.0"}]}


@pytest.mark.parametrize("version,expression,expected", [
    ("4.4.2", ">= 2.4.0, <= 4.4.2", True),
    ("4.4.2", "< 4.4.2", False),
    ("4.4.2", "<= 4.4", None),
    ("4.4.2-rc1", "< 4.5.0", None),
    ("4.4.2", "< 3.0.0 || >= 4.0.0", None),
    ("4.4.2", "", None),
])
def test_conservative_ranges(version, expression, expected):
    assert version_in_range(version, expression) is expected


def test_import_is_idempotent_and_does_not_claim_fix(session_factory):
    with session_factory() as db:
        import_snapshot(db, "zephyr", [ROW])
        import_snapshot(db, "zephyr", [ROW])
        assert db.query(models.IotOfficialAdvisory).count() == 1
        result = assess_snapshot(db, "zephyr", "4.4.2")
        assert result["results"][0]["status"] == "potentially_affected"
        assert db.query(models.DeviceVulnerabilityMatch).count() == 0
        assert assess_snapshot(db, "zephyr", "4.5.0")["results"][0]["status"] == "not_in_reported_range"


def test_invalid_batch_makes_no_partial_writes(session_factory):
    bad = copy.deepcopy(ROW)
    bad["html_url"] = bad["html_url"].replace("github.com/", "github.com.attacker.example/")
    with session_factory() as db:
        with pytest.raises(ValueError):
            import_snapshot(db, "zephyr", [ROW, bad])
        assert db.query(models.IotOfficialAdvisory).count() == 0


def test_openwrt_does_not_compare_release_with_package_range(session_factory):
    row = copy.deepcopy(ROW)
    row["html_url"] = row["html_url"].replace("zephyrproject-rtos/zephyr", "openwrt/openwrt")
    with session_factory() as db:
        import_snapshot(db, "openwrt", [row])
        assert assess_snapshot(db, "openwrt", "25.12.6")["results"][0]["status"] == "insufficient_data"
        assert assess_snapshot(db, "zephyr", "4.4.2")["coverage_status"] == "unassessed"
