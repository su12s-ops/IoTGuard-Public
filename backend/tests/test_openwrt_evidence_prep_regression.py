"""Offline matcher → prep → prompt regression; temporary SQLite only, no API writes."""
import json
from pathlib import Path
from types import SimpleNamespace

from app import models
from app.services import openwrt_intel
from app.services.iot_devices import match_openwrt
from app.services.unified.evidence_prep import (
    MAX_SOURCE_RECORDS, _logical_payloads, _source_texts,
    build_evidence_prep_packet, collect_stances,
)
from app.services.unified.graph import _candidate_context, _vulnerability_prep_context
from app.services.unified.state import UnifiedAnalysisState


def test_openwrt_matcher_prep_context_preserves_official_evidence(session_factory):
    rows = json.loads((Path(__file__).parent / "fixtures" / "openwrt_ghsa_snapshot.json").read_text(encoding="utf-8"))
    with session_factory() as db:
        openwrt_intel.sync_openwrt_advisories(db, rows)
        asset = models.LinuxAsset(hostname="isolated-openwrt-prep", distribution="openwrt",
                                  os_version="25.12.6", inventory_complete=True)
        db.add(asset)
        db.flush()
        for package, installed in (("odhcpd-ipv6only", "2026.06.29~5d7be43f-r1"),
                                   ("ubusd", "2026.06.28~24864e78-r2")):
            db.add(models.AssetPackage(asset_id=asset.id, package_name=package,
                                        package_version=installed, package_manager="apk"))
        db.flush()
        db.expire(asset, ["packages"])
        match_openwrt(db, asset, None)
        db.flush()
        state = UnifiedAnalysisState(run_id="isolated-official-prep", target_ref=asset.hostname)
        candidates = []
        for match in db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id):
            risk = SimpleNamespace(match_id=match.id, asset_id=asset.id,
                                   package_name=match.package_name, cve_id=match.cve_id,
                                   affected_status=match.match_status)
            candidates.extend(_candidate_context(db, state, risk))
        packet = build_evidence_prep_packet(db, asset.hostname, "linux_host", candidates)
        state.evidence_prep = packet.model_dump()
        context = _vulnerability_prep_context(state)
        by_package = {item.package_name: item for item in packet.candidates}
        branch = by_package["odhcpd-ipv6only"]
        assert branch.match_status == "affected"
        assert branch.reason_code == "openwrt_branch_range_no_fix"
        assert branch.fixed_version == ""
        assert "未登记任何修复版本" in branch.match_reason
        assert branch.match_reason in context
        assert branch.reason_code in context
        assert branch.version_compare["result"] == "unknown"
        assert branch.version_compare["official_match_status"] == "affected"
        # A release-domain fix must not be compared against a date/commit package version.
        fixed = by_package["ubusd"]
        assert fixed.match_status == "fixed" and fixed.fixed_version == "24.10.4"
        assert fixed.version_compare["result"] == "unknown"
        for item in packet.candidates:
            entry = item.source_bundle["openwrt_advisory"]
            assert entry["value"] is not None
            records = entry["value"]["records"]
            assert 0 < len(records) <= MAX_SOURCE_RECORDS
            expected_package = "odhcpd" if item is branch else "ubusd"
            assert {record["package_name"] for record in records} == {expected_package}
            for record in records:
                original = openwrt_intel.records_for_match(db, item.cve_id, expected_package, asset.os_version)
                original = next(row for row in original if row.release == record["release"])
                note = openwrt_intel.notes_of(original)
                for key in ("scope", "official_range", "ghsa_id", "content_sha256", "fix_statement", "provenance"):
                    assert record[key] == note.get(key)
                assert record["source_url"] == original.source_url
                assert record["source"] == "openwrt_ghsa_normalized"
                assert record["source_url"] in context
                assert record["content_sha256"] in context
                assert record["official_range"] in context
        texts, _ = _source_texts(db, branch.cve_id, "", branch.package_name, asset.os_version)
        assert any("main" in text["text"] for text in texts)


def test_official_records_are_bounded_and_package_scoped(session_factory):
    with session_factory() as db:
        for index in range(MAX_SOURCE_RECORDS + 2):
            db.add(models.OpenWrtAdvisory(
                cve_id="CVE-2099-9998", package_name="example", release=f"release-{index}",
                affected_versions_json='["1.0"]', fixed_versions_json="[]",
                source_url=f"https://example.invalid/{index}", notes="manual"))
        db.add(models.OpenWrtAdvisory(
            cve_id="CVE-2099-9998", package_name="unrelated", release="release-13",
            source_url="https://example.invalid/unrelated"))
        db.flush()
        _, bundle = _source_texts(db, "CVE-2099-9998", "", "example", "release-13")
        value = bundle["openwrt_advisory"]["value"]
        assert value["records_truncated"] is True
        assert len(value["records"]) == MAX_SOURCE_RECORDS
        assert value["records"][0]["release"] == "release-13"
        assert {record["package_name"] for record in value["records"]} == {"example"}
        assert all(record["source"] == "operator_supplied_openwrt_advisory"
                   for record in value["records"])
        assert all(record["fixed_versions"] == [] for record in value["records"])


def test_legacy_records_survive_prep_projection(session_factory, monkeypatch):
    from app.services.unified import evidence_prep
    record = {"package_name": "example", "scope": "branch", "official_range": "main",
              "content_sha256": "a" * 64, "source_url": "https://example.invalid/official"}
    legacy = {"openwrt_advisory": {"status": "available", "records": [record]}}
    canonical = {"openwrt_advisory": {"status": "available", "value": {"records": [record]}}}
    assert _logical_payloads(legacy) == _logical_payloads(canonical)
    assert collect_stances(legacy) == collect_stances(canonical)
    monkeypatch.setattr(evidence_prep, "_source_texts", lambda *args, **kwargs: ([], legacy))
    with session_factory() as db:
        packet = build_evidence_prep_packet(db, "", "linux_host", [{"cve_id": "CVE-2099-9999"}])
    assert packet.candidates[0].source_bundle["openwrt_advisory"]["value"] == {"records": [record]}
