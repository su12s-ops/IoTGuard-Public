import copy

import pytest

from app import models
from app.services.iot_official import import_snapshot, assess_snapshot, version_in_range


ROW = {"ghsa_id": "GHSA-82gq-cmqw-xgx2", "cve_id": "CVE-2026-76787",
       "html_url": "https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-82gq-cmqw-xgx2",
       "vulnerabilities": [{"package": {"name": "zephyr"}, "vulnerable_version_range": ">= 2.4.0, <= 4.4.2",
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


def test_coverage_endpoint_is_read_only_and_reports_empty_snapshot(client):
    response = client.get("/api/devices/official-coverage/zephyr?version=4.4.2")
    assert response.status_code == 200
    assert response.json()["coverage_status"] == "unassessed"
    assert response.json()["count"] == 0
    assert client.get("/api/devices/official-coverage/ubuntu?version=24.04.0").status_code == 422


def test_agent_can_read_official_evidence_without_generic_cve_row(session_factory):
    from app.services.unified.agents_def import tool_query_intelligence_sources
    with session_factory() as db:
        import_snapshot(db, "zephyr", [ROW])
        result = tool_query_intelligence_sources(db, cve_id=ROW["cve_id"])
        evidence = result["sources"]["iot_official_snapshot"]
        assert not result["known_in_library"]
        assert evidence["status"] == "snapshot_available"
        assert evidence["records"][0]["source_url"] == ROW["html_url"]
        assert len(evidence["records"][0]["snapshot_sha256"]) == 64
        evidence_id = evidence["records"][0]["evidence_id"]
        assert db.query(models.OfficialCveRecord).filter_by(evidence_id=evidence_id).one().cve_id == ROW["cve_id"]
        assert db.query(models.DeviceVulnerabilityMatch).count() == 0


def test_snapshot_refresh_preserves_old_evidence_and_prefetch_exposes_registered_ids(session_factory):
    from app.services.unified.evidence_prep import _source_texts
    from app.services.unified.graph import RunContext, _vulnerability_evidence_validator
    from app.services.iot_official import registered_snapshot_records
    with session_factory() as db:
        import_snapshot(db, "zephyr", [ROW])
        first = registered_snapshot_records(db, ROW["cve_id"])[0]["evidence_id"]
        changed = {**ROW, "description": "Updated official clarification"}
        import_snapshot(db, "zephyr", [changed])
        second = registered_snapshot_records(db, ROW["cve_id"])[0]["evidence_id"]
        assert first != second
        assert db.query(models.OfficialCveRecord).count() == 2
        _, bundle = _source_texts(db, ROW["cve_id"], "", "zephyr")
        assert bundle["iot_official_snapshot"]["value"]["records"][0]["evidence_id"] == second
        validator = _vulnerability_evidence_validator(RunContext(
            db_factory=session_factory, trace_id="", packet_evidence_ids={second}))
        assert validator({"findings": [{"supporting_evidence_ids": [ROW["ghsa_id"]]}]})
        assert not validator({"findings": [{"supporting_evidence_ids": [second]}]})


def test_other_component_range_cannot_exclude_zephyr_kernel(session_factory):
    row = copy.deepcopy(ROW)
    row["vulnerabilities"][0]["package"]["name"] = "unrelated-library"
    with session_factory() as db:
        import_snapshot(db, "zephyr", [row])
        assert assess_snapshot(db, "zephyr", "4.5.0")["results"][0]["status"] == "insufficient_data"
