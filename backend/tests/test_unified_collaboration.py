"""Evidence protocol tests use temporary DBs; no LLM, live device or network."""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from app import models
from app.services.unified import collaboration as protocol
from app.services.unified.schemas import (
    AGENT_ASSET, AGENT_DECISION, AGENT_RUNTIME, AGENT_VULNERABILITY, ALL_AGENT_IDS,
)


def text_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def add_official(db, evidence_id="ADV-current", payload=None, cve="CVE-2026-1234"):
    raw = json.dumps(payload or {"cve": cve, "affected": "<2.0"}, sort_keys=True)
    row = models.OfficialCveRecord(evidence_id=evidence_id, cve_id=cve,
        source_url="https://vendor.invalid/advisory", raw_json=raw,
        content_sha256=text_hash(raw), evidence_status="available")
    db.add(row)
    return row


def add_runtime(db, evidence_id, asset_id, device_id="router-a", timestamp="2026-10-20T00:00:00Z"):
    row = models.SecurityEvidence(evidence_id=evidence_id, asset_id=asset_id, device_id=device_id,
        source="logread", evidence_type="process", timestamp=timestamp, process="daemon",
        evidence_hash=text_hash(evidence_id), raw_data='{"message":"started"}')
    db.add(row)
    return row


@pytest.fixture
def rig(session_factory):
    with session_factory() as db:
        asset = models.LinuxAsset(hostname="router-a", ip_address="192.0.2.1",
            distribution="openwrt", os_version="24.10.2", architecture="x86_64",
            inventory_complete=True, identity_source="ssh_inventory")
        other = models.LinuxAsset(hostname="router-b", ip_address="192.0.2.2")
        db.add_all([asset, other])
        db.flush()
        package = models.AssetPackage(asset_id=asset.id, package_name="daemon",
            package_version="1.0", architecture="x86_64")
        service = models.AssetService(asset_id=asset.id, service_name="daemon", port=1883,
            protocol="tcp", listen_address="0.0.0.0", process_name="daemon")
        raw = '{"packages":[["daemon","1.0"]],"receipt":"one"}'
        inventory = models.CollectionEvidence(evidence_id="INV-current", run_id="collection-one",
            asset_id=asset.id, raw_text=raw, content_sha256=text_hash(raw))
        asset.inventory_metadata_json = json.dumps({"inventory_evidence_id": inventory.evidence_id,
            "collection_run_id": inventory.run_id, "package_sources": ["opkg"]})
        risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2026-1234", package_name="daemon")
        db.add_all([package, service, inventory, risk])
        official = add_official(db)
        runtime = add_runtime(db, "SE-own", asset.id)
        add_runtime(db, "SE-alias", None, "192.0.2.1")
        add_runtime(db, "SE-other-bound", other.id)
        add_runtime(db, "SE-unrelated", None, "unrelated")
        db.commit()
        packet = {"target_ref": asset.hostname, "target_type": "linux_host", "as_of": "one",
            "asset_facts": {"profile": {"device_id": asset.hostname}, "components": []},
            "runtime_facts": {"freshness": {"process": {"freshness": "fresh", "age_hours": 1}},
                "coverage": {"status": "observed", "sensors": [{"source": "logread", "age_seconds": 3}]}},
            "candidates": [{"cve_id": risk.cve_id, "package_name": "daemon",
                "installed_version": "1.0", "fixed_version": "2.0",
                "source_bundle": {"vendor": {"status": "available", "source_updated_at": "one",
                    "value": {"evidence_id": official.evidence_id, "affected": "<2.0"}}}}]}
        yield SimpleNamespace(db=db, asset=asset, other=other, package=package, service=service,
            inventory=inventory, official=official, runtime=runtime, risk=risk, packet=packet)


def snapshot(rig, previous=None, packet=None, harness=None):
    return protocol.build_snapshot(rig.db, packet or rig.packet, "analysis-one",
        rig.risk.id, previous, harness)


def test_snapshot_registry_is_asset_scoped_complete_and_readonly(rig):
    first = snapshot(rig)
    assert set(first["evidence_registry"]) == {"INV-current", "ADV-current", "SE-own", "SE-alias"}
    assert first["asset_id"] == rig.asset.id and first["risk_id"] == rig.risk.id
    assert first["provenance"]["device_write_authority"] is False
    assert first["categories"]["inventory"]["components"][0]["version"] == "1.0"
    assert not first["integrity_errors"]
    assert protocol.validate_evidence_ids(["SE-other-bound"], first)
    assert protocol.validate_evidence_ids(["ADV-current"], first, kinds={"runtime"})
    assert not protocol.validate_evidence_ids(["SE-own"], first, kinds={"runtime"})


def test_snapshot_does_not_flush_pending_writes(rig):
    statements = []
    event.listen(rig.db.bind, "before_cursor_execute",
        lambda conn, cursor, statement, parameters, context, many: statements.append(statement))
    rig.db.autoflush = True
    rig.db.add(models.LinuxAsset(hostname="pending-must-stay-pending"))
    snapshot(rig)
    assert statements and all(sql.lstrip().upper().startswith("SELECT") for sql in statements)
    assert rig.db.new


def test_snapshot_rejects_risk_asset_confusion_and_missing_risk(rig):
    with pytest.raises(ValueError, match="snapshot_risk_asset_mismatch"):
        protocol.build_snapshot(rig.db, rig.packet, "bad", rig.risk.id, asset_ref=rig.other.hostname)
    with pytest.raises(ValueError, match="snapshot_risk_not_found"):
        protocol.build_snapshot(rig.db, rig.packet, "bad", 999999)


def test_snapshot_versions_are_detached_and_new_evidence_is_not_retroactive(rig):
    first = snapshot(rig)
    frozen = deepcopy(first)
    add_runtime(rig.db, "SE-new", rig.asset.id, timestamp="2026-10-20T01:00:00Z")
    rig.db.commit()
    second = snapshot(rig, first)
    assert first == frozen
    assert second["parent_snapshot_id"] == first["snapshot_id"]
    assert second["version"] == first["version"] + 1
    assert second["snapshot_id"] != first["snapshot_id"]
    assert protocol.validate_evidence_ids(["SE-new"], first)
    assert not protocol.validate_evidence_ids(["SE-new"], second)
    assert second["invalidated_roles"] == [AGENT_RUNTIME, AGENT_DECISION]
    second["categories"]["identity"]["hostname"] = "changed copy"
    assert first == frozen


def test_new_inventory_receipt_and_query_times_are_not_substantive(rig):
    harness = {"queried_at": "one", "snapshot_id": "old",
        "identity": {"inventory_sha256": "receipt-one", "inventory_hash": "normalized-same"}}
    first = snapshot(rig, harness=harness)
    new_raw = rig.inventory.raw_text.replace("one", "two")
    rig.db.add(models.CollectionEvidence(evidence_id="INV-new", asset_id=rig.asset.id,
        run_id="collection-two", raw_text=new_raw, content_sha256=text_hash(new_raw)))
    metadata = json.loads(rig.asset.inventory_metadata_json)
    metadata.update(inventory_evidence_id="INV-new", collection_run_id="collection-two")
    rig.asset.inventory_metadata_json = json.dumps(metadata)
    rig.db.commit()
    packet = deepcopy(rig.packet)
    packet["as_of"] = "two"
    packet["runtime_facts"]["freshness"]["process"]["age_hours"] = 2
    packet["runtime_facts"]["coverage"]["sensors"][0]["age_seconds"] = 9
    packet["candidates"][0]["source_bundle"]["vendor"]["source_updated_at"] = "two"
    harness["queried_at"] = "two"
    harness["snapshot_id"] = "new"
    harness["identity"]["inventory_sha256"] = "receipt-two"
    second = snapshot(rig, first, packet, harness)
    assert second["substantive_change"] is False
    assert second["changed_fields"] == second["invalidated_roles"] == []
    assert second["evidence_changes"] == {"added": ["INV-new"], "removed": ["INV-current"]}
    assert second["content_sha256"] != first["content_sha256"]


def test_corrupt_inventory_is_not_registered_and_invalidates_its_consumers(rig):
    first = snapshot(rig)
    rig.inventory.raw_text = "tampered without updating hash"
    rig.db.commit()
    second = snapshot(rig, first)
    assert "INV-current" not in second["evidence_registry"]
    assert any(error.startswith("inventory_missing_wrong_asset_or_corrupt:") for error in second["integrity_errors"])
    assert "inventory.evidence_integrity" in second["changed_fields"]
    assert second["invalidated_roles"] == [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_DECISION]


def test_inventory_reference_from_another_asset_is_rejected(rig):
    rig.inventory.asset_id = rig.other.id
    rig.db.commit()
    result = snapshot(rig)
    assert "INV-current" not in result["evidence_registry"]
    assert result["integrity_errors"]


def test_official_corruption_and_unrelated_cve_do_not_enter_registry(rig):
    rig.official.raw_json = "tampered"
    add_official(rig.db, "ADV-unrelated", cve="CVE-2026-9999")
    rig.db.commit()
    result = snapshot(rig)
    assert "ADV-current" not in result["evidence_registry"]
    assert "ADV-unrelated" not in result["evidence_registry"]
    assert result["integrity_errors"] == ["official_corrupt:ADV-current"]


def test_official_same_payload_new_receipt_keeps_history_without_replay(rig):
    first = snapshot(rig)
    add_official(rig.db, "ADV-copy")
    rig.db.commit()
    second = snapshot(rig, first)
    assert {"ADV-current", "ADV-copy"} <= set(second["evidence_registry"])
    assert second["evidence_changes"]["added"] == ["ADV-copy"]
    assert not second["substantive_change"]


def test_changed_official_content_replays_only_vulnerability_and_decision(rig):
    first = snapshot(rig)
    add_official(rig.db, "ADV-new", {"affected": "<3.0"})
    rig.db.commit()
    second = snapshot(rig, first)
    assert second["invalidated_roles"] == [AGENT_VULNERABILITY, AGENT_DECISION]
    assert all(path.startswith("official.") for path in second["changed_fields"])


def test_inventory_change_is_not_misclassified_as_new_official_evidence(rig):
    first = snapshot(rig)
    rig.package.package_version = "1.1"
    rig.db.commit()
    packet = deepcopy(rig.packet)
    packet["candidates"][0].update(installed_version="1.1", matched_rows=17,
        version_compare={"result": "affected", "installed_version": "1.1"})
    second = snapshot(rig, first, packet)
    assert second["invalidated_roles"] == [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_DECISION]
    assert all(path.startswith("inventory.") for path in second["changed_fields"])


@pytest.mark.parametrize("field,value,expected", [
    ("service", 8883, ALL_AGENT_IDS),
    ("identity", "arm64", ALL_AGENT_IDS),
    ("freshness", "stale", [AGENT_RUNTIME, AGENT_DECISION]),
    ("coverage", "missing", [AGENT_RUNTIME, AGENT_DECISION]),
    ("harness", "unsupported", [AGENT_DECISION]),
])
def test_precise_category_invalidation(rig, field, value, expected):
    first = snapshot(rig)
    packet = deepcopy(rig.packet)
    harness = None
    if field == "service":
        rig.service.port = value
    elif field == "identity":
        rig.asset.architecture = value
    elif field == "freshness":
        packet["runtime_facts"]["freshness"]["process"]["freshness"] = value
    elif field == "coverage":
        packet["runtime_facts"]["coverage"]["status"] = value
    else:
        harness = {"adapter": value}
    rig.db.commit()
    second = snapshot(rig, first, packet, harness)
    assert second["invalidated_roles"] == expected


def test_runtime_same_id_content_change_is_detected(rig):
    first = snapshot(rig)
    rig.runtime.commandline = "unexpected shell"
    rig.db.commit()
    second = snapshot(rig, first)
    assert second["evidence_changes"] == {"added": [], "removed": []}
    assert second["invalidated_roles"] == [AGENT_RUNTIME, AGENT_DECISION]
    assert first["evidence_registry"]["SE-own"]["observation_sha256"] != second["evidence_registry"]["SE-own"]["observation_sha256"]


def test_full_inventory_and_runtime_registry_exceed_prompt_bounds(rig):
    for number in range(70):
        rig.db.add(models.AssetPackage(asset_id=rig.asset.id, package_name=f"component-{number:03}", package_version="1"))
        add_runtime(rig.db, f"SE-full-{number:03}", rig.asset.id)
    rig.db.commit()
    first = snapshot(rig)
    assert len(first["categories"]["inventory"]["components"]) == 71
    assert len(first["evidence_registry"]) == 74
    context = protocol.compact_context(AGENT_RUNTIME, first)
    assert len(context["available_evidence_ids"]) == 60
    assert context["evidence_ids_truncated"] is True
    package = rig.db.query(models.AssetPackage).filter_by(package_name="component-069").one()
    package.package_version = "2"
    rig.db.commit()
    second = snapshot(rig, first)
    assert second["invalidated_roles"] == [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_DECISION]


def test_iot_snapshot_uses_complete_database_inventory(session_factory):
    with session_factory() as db:
        device = models.IotDevice(device_id="zephyr-node", ip="192.0.2.8", os="Zephyr", firmware_version="3.7.0")
        db.add(device)
        db.flush()
        for number in range(65):
            db.add(models.IotDeviceComponent(device_row_id=device.id, component_name=f"part-{number:03}", version="1"))
        db.commit()
        packet = {"target_ref": device.device_id, "target_type": "iot_device", "asset_facts": {"components": []}}
        first = protocol.build_snapshot(db, packet, "iot-run")
        assert first["asset_id"] is None
        assert first["categories"]["identity"]["firmware_version"] == "3.7.0"
        assert len(first["categories"]["inventory"]["components"]) == 65


def test_snapshot_can_resolve_target_using_pinned_connection(rig):
    connection = models.DeviceConnection(asset_id=rig.asset.id, host="192.0.2.9", host_key_sha256="SHA256:fixture")
    rig.db.add(connection)
    rig.db.commit()
    result = protocol.build_snapshot(rig.db, {"target_ref": connection.host}, "connection-run", rig.risk.id)
    assert result["asset_id"] == rig.asset.id


def test_immutable_reducer_is_idempotent_and_copies_nested_values():
    left = [{"snapshot_id": "old", "nested": {"value": 1}}]
    right = [{"snapshot_id": "new", "nested": {"value": 2}}]
    result = protocol.merge_immutable(left, left + right)
    assert len(result) == 2
    result[0]["nested"]["value"] = 99
    assert left[0]["nested"]["value"] == 1
    assert protocol.merge_immutable({"x": {"value": 1}}, {"x": {"value": 1}}) == {"x": {"value": 1}}
    with pytest.raises(ValueError, match="immutable_record_conflict"):
        protocol.merge_immutable(left, [{"snapshot_id": "old", "nested": {"value": 2}}])
    with pytest.raises(ValueError, match="immutable_record_conflict"):
        protocol.merge_immutable({"old": 1}, {"old": 2})
    with pytest.raises(ValueError, match="immutable_record_id_required"):
        protocol.merge_immutable([], [{}])


def draft(message_type="CHALLENGE", **overrides):
    return {"message_type": message_type, "receiver": AGENT_VULNERABILITY,
        "claim": "The observed branch differs from the reported affected branch.",
        "evidence_ids": ["INV-current"],
        "requested_action": "Compare the installed branch with the cited vendor range.", **overrides}


@pytest.mark.parametrize("message_type", protocol.MESSAGE_TYPES)
def test_all_message_types_are_structured_and_bound_to_authenticated_context(rig, message_type):
    current = snapshot(rig)
    raw = [draft(message_type)]
    frozen = deepcopy(raw)
    accepted, errors = protocol.validate_messages(raw, AGENT_ASSET, current)
    assert not errors and len(accepted) == 1
    assert raw == frozen
    assert accepted[0]["sender"] == AGENT_ASSET
    assert accepted[0]["snapshot_id"] == current["snapshot_id"]
    assert accepted[0]["message_id"].startswith("CM-")
    assert protocol.validate_messages(raw, AGENT_ASSET, current)[0] == accepted


@pytest.mark.parametrize("override,error", [
    ({"sender": AGENT_DECISION}, "sender_spoofing"),
    ({"snapshot_id": "stale"}, "stale_message_snapshot"),
    ({"evidence_ids": ["fabricated"]}, "evidence_not_in_snapshot"),
    ({"evidence_ids": ["SE-other-bound"]}, "evidence_not_in_snapshot"),
    ({"evidence_ids": []}, "evidence_required_for_assertion"),
    ({"receiver": AGENT_ASSET}, "self_message_not_collaboration"),
    ({"receiver": "all"}, "directed_message_receiver_required"),
    ({"requested_action": "  "}, "concrete_requested_action_required"),
    ({"claim": "  "}, "message_claim_required"),
    ({"finding_id": "invented"}, "unknown_challenged_finding"),
    ({"shell": "do not execute"}, "extra_forbidden"),
])
def test_messages_reject_untrusted_or_empty_collaboration(rig, override, error):
    accepted, errors = protocol.validate_messages([draft(**override)], AGENT_ASSET, snapshot(rig))
    assert not accepted and any(error in item for item in errors)


def test_message_budget_and_content_deduplication(rig):
    accepted, errors = protocol.validate_messages([draft()] * 13, AGENT_ASSET, snapshot(rig))
    assert len(accepted) == 1
    assert errors == ["message_budget_exceeded:12"]


def test_findings_preserve_claims_references_basis_and_failed_validation(rig):
    current = snapshot(rig)
    output = {"findings": [{"cve_id": "CVE-2026-1234", "applicability": "not_affected",
        "version_impact": "not_affected", "supporting_evidence_ids": ["ADV-current", "invented"],
        "confidence": 0.8, "rationale": "Vendor excludes the installed branch."}]}
    findings = protocol.build_findings(AGENT_VULNERABILITY, output, current)
    assert findings[0]["evidence_ids"] == ["ADV-current"]
    assert findings[0]["confidence_basis"] == "Vendor excludes the installed branch."
    assert findings[0]["evidence_validation"] == "failed"
    assert findings[0]["unresolved_questions"] == ["evidence_not_in_snapshot:invented"]
    assert protocol.compact_context(AGENT_DECISION, current, findings)["shared_findings"] == []
    assert output["findings"][0]["supporting_evidence_ids"][-1] == "invented"


def test_findings_distinguish_judgment_change_from_receipt_change_and_model_variance(rig):
    first = snapshot(rig)
    output = {"behavior_level": "NORMAL", "runtime_status": "contextual",
        "exploitation_relation": "service_active_only", "evidence_freshness": "fresh",
        "evidence_ids": ["SE-own"], "confidence": 0.7}
    old = protocol.build_findings(AGENT_RUNTIME, output, first)
    unchanged = snapshot(rig, first)
    current = protocol.build_findings(AGENT_RUNTIME, output, unchanged, old)
    assert current[0]["material_change"] is False
    assert current[0]["model_variance"] is False
    revised = {**output, "runtime_status": "not_observed"}
    variance = protocol.build_findings(AGENT_RUNTIME, revised, unchanged, old)
    assert variance[0]["material_change"] is False
    assert variance[0]["model_variance"] is True
    packet = deepcopy(rig.packet)
    packet["runtime_facts"]["freshness"]["process"]["freshness"] = "stale"
    refreshed = snapshot(rig, first, packet)
    revised["evidence_freshness"] = "stale"
    actual = protocol.build_findings(AGENT_RUNTIME, revised, refreshed, old)
    assert actual[0]["material_change"] is True
    assert actual[0]["model_variance"] is False


def test_compact_context_contains_only_current_valid_findings_and_role_inbox(rig):
    current = snapshot(rig)
    findings = protocol.build_findings(AGENT_ASSET, {"device_id": "router-a", "evidence_quality": "sufficient"}, current)
    stale = deepcopy(findings[0])
    stale["snapshot_id"] = "old-snapshot"
    accepted, _ = protocol.validate_messages([draft()], AGENT_ASSET, current)
    context = protocol.compact_context(AGENT_VULNERABILITY, current, findings + [stale], accepted)
    assert context["shared_findings"] == findings
    assert context["messages"] == accepted
    assert set(context["available_evidence_ids"]) == {"INV-current", "ADV-current"}
    assert set(context["category_hashes"]) == {"identity", "inventory", "official"}
    assert "raw_text" not in json.dumps(context) and "raw_data" not in json.dumps(context)
    context["shared_findings"][0]["claim"] = "changed copy"
    assert findings[0]["claim"] != "changed copy"


def test_evidence_collection_recognizes_reference_fields_only():
    value = {"evidence_ids": ["one"], "findings": [{"supporting_evidence_ids": ["two"],
        "nested": {"evidence_id": "three"}}], "description": "SE-not-a-reference"}
    assert protocol.collect_evidence_ids(value) == {"one", "two", "three"}
