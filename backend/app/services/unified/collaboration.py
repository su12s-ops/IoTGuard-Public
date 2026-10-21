"""Versioned evidence and bounded collaboration inside the existing LangGraph.

No new store, agent, collection capability or execution authority is introduced.
Snapshots are JSON values persisted by UnifiedAnalysisRun.state_json; previous
versions must be retained by the caller. Registry entries refer to existing
CollectionEvidence, OfficialCveRecord and SecurityEvidence rows.

``categories_hashes`` excludes receipt-only changes; ``changed_fields`` records
semantic paths, while ``evidence_changes`` records reference additions/removals.
The latter alone never invalidates a role or increases its confidence. Freshness
bucket and coverage changes do invalidate runtime conclusions, even when no new
event arrived. Live approvals and token state must always be rechecked by Harness.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import or_

from app import models
from app.services.unified.schemas import (
    AGENT_ASSET, AGENT_DECISION, AGENT_RUNTIME, AGENT_VULNERABILITY, ALL_AGENT_IDS,
)

PROTOCOL_VERSION = "four-agent-collaboration-v1"
MESSAGE_TYPES = ("FINDING", "QUESTION", "CHALLENGE", "EVIDENCE_REQUEST",
                 "EVIDENCE_UPDATE", "CONFLICT", "RESOLUTION", "PLAN_FEEDBACK")
_ROLE_CATEGORIES = {
    AGENT_ASSET: ("identity", "inventory"),
    AGENT_VULNERABILITY: ("identity", "inventory", "official"),
    AGENT_RUNTIME: ("identity", "runtime"),
    AGENT_DECISION: ("identity", "inventory", "official", "runtime", "harness"),
}
_INVALIDATES = {
    "identity": ALL_AGENT_IDS,
    "inventory": [AGENT_ASSET, AGENT_VULNERABILITY, AGENT_DECISION],
    "official": [AGENT_VULNERABILITY, AGENT_DECISION],
    "runtime": [AGENT_RUNTIME, AGENT_DECISION],
    "harness": [AGENT_DECISION],
}
_RECEIPT_FIELDS = frozenset({
    "as_of", "created_at", "updated_at", "fetched_at", "source_updated_at", "queried_at",
    "age_seconds", "age_hours", "collected_at", "received_at",
    "inventory_evidence_id", "collection_run_id", "evidence_id", "evidence_ids",
    "snapshot_id", "snapshot_sha256",
})


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))


def fingerprint(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _time(value: Any) -> str:
    if isinstance(value, datetime):
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return value.isoformat()
    return str(value or "")


def _load(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _semantic(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _semantic(item) for key, item in sorted(value.items()) if key not in _RECEIPT_FIELDS}
    if isinstance(value, list):
        return [_semantic(item) for item in value]
    return value


def _paths(before: Any, after: Any, prefix: str) -> list[str]:
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in sorted(set(before) | set(after)):
            path = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                result.append(path)
            else:
                result.extend(_paths(before[key], after[key], path))
        return result
    if isinstance(before, list) and isinstance(after, list):
        result = []
        for index in range(max(len(before), len(after))):
            path = f"{prefix}[{index}]"
            if index >= len(before) or index >= len(after):
                result.append(path)
            else:
                result.extend(_paths(before[index], after[index], path))
        return result
    return [prefix]


def affected_roles(changed_fields: list[str]) -> list[str]:
    affected = set()
    for path in changed_fields:
        affected.update(_INVALIDATES.get(path.split(".", 1)[0].split("[", 1)[0], ALL_AGENT_IDS))
        # Service changes can affect runtime interpretation as well as exposure.
        if path.startswith("inventory.services"):
            affected.add(AGENT_RUNTIME)
    return [role for role in ALL_AGENT_IDS if role in affected]


def snapshot_diff(previous: dict | None, current: dict) -> dict:
    previous = previous or {}
    fields = _paths(previous.get("categories", {}), current.get("categories", {}), "")
    old_ids = set(previous.get("evidence_registry") or {})
    new_ids = set(current.get("evidence_registry") or {})
    return {
        "changed_fields": fields,
        "substantive_change": bool(fields),
        "invalidated_roles": affected_roles(fields),
        "evidence_changes": {"added": sorted(new_ids - old_ids), "removed": sorted(old_ids - new_ids)},
    }


def _resolve_asset(db, asset_ref: str, risk_id):
    risk = db.get(models.RiskAssessment, risk_id) if risk_id else None
    if risk_id and risk is None:
        raise ValueError("snapshot_risk_not_found")
    asset = db.query(models.LinuxAsset).filter(or_(models.LinuxAsset.hostname == asset_ref,
                                                  models.LinuxAsset.ip_address == asset_ref)).first() if asset_ref else None
    device = db.query(models.IotDevice).filter(or_(models.IotDevice.device_id == asset_ref,
                                                 models.IotDevice.ip == asset_ref)).first() if asset_ref else None
    if device and asset is None and device.ip:
        asset = db.query(models.LinuxAsset).filter_by(ip_address=device.ip).first()
        if asset is None:
            connection = db.query(models.DeviceConnection).filter_by(host=device.ip).first()
            asset = db.get(models.LinuxAsset, connection.asset_id) if connection and connection.asset_id else None
    if asset is None and asset_ref:
        connection = db.query(models.DeviceConnection).filter_by(host=asset_ref).first()
        asset = db.get(models.LinuxAsset, connection.asset_id) if connection and connection.asset_id else None
    if risk:
        risk_asset = db.get(models.LinuxAsset, risk.asset_id)
        if asset is not None and risk.asset_id != asset.id:
            raise ValueError("snapshot_risk_asset_mismatch")
        if asset is None and asset_ref and risk_asset and asset_ref not in {risk_asset.hostname, risk_asset.ip_address}:
            raise ValueError("snapshot_target_asset_mismatch")
        asset = risk_asset
    return asset, device, risk


def build_snapshot(db, packet: dict, run_id: str, risk_id=None, previous=None, harness=None,
                   *, asset_ref: str | None = None, target_type: str | None = None) -> dict:
    # A caller may have pending unrelated changes. A read-only snapshot must not
    # flush those changes as a side effect of its SELECTs.
    with db.no_autoflush:
        return _build_snapshot(db, packet, run_id, risk_id, previous, harness,
                               asset_ref=asset_ref, target_type=target_type)


def _build_snapshot(db, packet: dict, run_id: str, risk_id=None, previous=None, harness=None,
                    *, asset_ref: str | None = None, target_type: str | None = None) -> dict:
    """Read a complete reference registry; never fetch or mutate external evidence.

    The full runtime registry pins every eligible ID present at snapshot creation.
    Prompt summaries remain bounded. Newly arriving IDs require a new snapshot.
    Raw text is verified for collection/official records and is never copied here.
    """
    packet = deepcopy(packet or {})
    asset_ref = asset_ref if asset_ref is not None else str(packet.get("target_ref") or "")
    target_type = target_type or packet.get("target_type") or "linux_host"
    asset, device, risk = _resolve_asset(db, asset_ref, risk_id)
    asset_id = asset.id if asset else None
    created_at = datetime.now(timezone.utc).isoformat()
    registry: dict[str, dict] = {}
    errors: list[str] = []
    metadata = _load(asset.inventory_metadata_json) if asset else {}
    provenance = (packet.get("asset_facts") or {}).get("inventory_provenance") or {}
    inventory_id = metadata.get("inventory_evidence_id") or provenance.get("inventory_evidence_id")
    if inventory_id:
        row = db.query(models.CollectionEvidence).filter_by(evidence_id=inventory_id, asset_id=asset_id).first() if asset else None
        if row and row.content_sha256 and _text_hash(row.raw_text) == row.content_sha256:
            registry[row.evidence_id] = {"kind": "inventory", "source": "collection_evidence",
                "collected_at": _time(row.collected_at), "content_sha256": row.content_sha256,
                "asset_id": row.asset_id, "source_run_id": row.run_id, "integrity": "verified"}
        else:
            errors.append(f"inventory_missing_wrong_asset_or_corrupt:{inventory_id}")
    candidates = packet.get("candidates") or []
    cves = {str(item.get("cve_id") or "").split(":")[0] for item in candidates}
    if risk:
        cves.add(risk.cve_id.split(":")[0])
    cves.discard("")
    official_latest = {}
    if cves:
        rows = db.query(models.OfficialCveRecord).filter(models.OfficialCveRecord.cve_id.in_(cves)).order_by(models.OfficialCveRecord.id).all()
        for row in rows:
            if row.evidence_status != "available":
                continue
            if not row.content_sha256 or _text_hash(row.raw_json) != row.content_sha256:
                errors.append(f"official_corrupt:{row.evidence_id}")
                continue
            registry[row.evidence_id] = {"kind": "official", "source": row.source_url,
                "collected_at": _time(row.fetched_at), "content_sha256": row.content_sha256,
                "asset_id": asset_id, "cve_id": row.cve_id, "source_run_id": "", "integrity": "verified"}
            official_latest[f"{row.cve_id}|{row.source_url}"] = row.content_sha256
    keys = {asset_ref}
    if asset:
        keys.update((asset.hostname, asset.ip_address))
    if device:
        keys.update((device.device_id, device.device_name, device.ip))
    keys.discard("")
    query = db.query(models.SecurityEvidence)
    # Explicit asset attribution wins over a coincident hostname/IP.
    if asset:
        query = query.filter(or_(models.SecurityEvidence.asset_id == asset.id,
            models.SecurityEvidence.asset_id.is_(None) & models.SecurityEvidence.device_id.in_(keys)))
    elif device:
        query = query.filter(models.SecurityEvidence.asset_id.is_(None), models.SecurityEvidence.device_id.in_(keys))
    else:
        query = query.filter(False)
    runtime = []
    for row in query.order_by(models.SecurityEvidence.id).all():
        observation = {column.name: getattr(row, column.name) for column in row.__table__.columns
                       if column.name not in {"id", "created_at", "evidence_id", "evidence_hash"}}
        observed_hash = fingerprint(observation)
        registry[row.evidence_id] = {"kind": "runtime", "source": row.source,
            "collected_at": _time(row.created_at), "observed_at": row.timestamp,
            "content_sha256": row.evidence_hash or observed_hash, "observation_sha256": observed_hash,
            "asset_id": row.asset_id, "source_run_id": "",
            "integrity": "database_content_hash" if row.evidence_hash else "snapshot_observation_hash"}
        runtime.append({"observed_at": row.timestamp, "source": row.source,
                        "observation_sha256": observed_hash})
    profile = (packet.get("asset_facts") or {}).get("profile") or {}
    identity = {"asset_id": asset_id, "risk_id": risk_id, "device_id": device.device_id if device else profile.get("device_id", asset_ref),
                "target_ref": asset_ref, "target_type": target_type}
    if asset:
        identity.update(hostname=asset.hostname, distribution=asset.distribution, os_version=asset.os_version,
                        identity_source=asset.identity_source, firmware_version=asset.firmware_version,
                        architecture=asset.architecture, kernel_version=asset.kernel_version,
                        device_model=asset.device_model, mac_address=asset.mac_address,
                        identity_confidence=asset.identity_confidence, exposure_level=asset.exposure_level,
                        business_level=asset.business_level)
        inventory = {"components": sorted([{"name": row.package_name, "version": row.package_version,
            "architecture": row.architecture, "package_manager": row.package_manager}
            for row in asset.packages], key=_json),
            "services": sorted([{"name": row.service_name, "port": row.port, "protocol": row.protocol,
                "listen_address": row.listen_address, "process": row.process_name,
                "public": bool(row.is_public_exposed)} for row in asset.services], key=_json),
            "complete": bool(asset.inventory_complete),
            "package_sources": sorted(metadata.get("package_sources") or []),
            "openssl_implementation": metadata.get("openssl_implementation") or {},
            "cached_apt_policy": metadata.get("apt_policy") or {}}
    elif device:
        identity.update({key: getattr(device, key) for key in
                         ("device_type", "vendor", "model", "firmware_version", "os",
                          "ip", "identity_source", "identity_confidence")})
        inventory = {"components": sorted([{key: getattr(row, key) for key in
            ("component_name", "component_type", "version", "cpe", "source")}
            for row in device.components], key=_json),
            "services": sorted([{key: getattr(row, key) for key in
            ("port", "transport", "service_type", "product", "version", "banner",
             "auth_state", "status")} for row in device.services], key=_json)}
    else:
        identity.update(_semantic(profile))
        inventory = {key: _semantic((packet.get("asset_facts") or {}).get(key))
                     for key in ("components", "services", "components_truncated")}
    inventory["candidate_versions"] = sorted([
        {key: item.get(key, "") for key in ("cve_id", "package_name", "installed_version")}
        for item in candidates], key=_json)
    inventory["evidence_integrity"] = ("verified" if inventory_id in registry
                                       else "invalid" if inventory_id else "unregistered")
    # Version/branch/backport comparisons and urgency are derived from several
    # categories. Their inputs belong here; their outputs must not make an
    # inventory-only change look like a newly published official advisory.
    official_candidates = sorted([_semantic({key: item.get(key) for key in
        ("cve_id", "package_name", "fixed_version", "intel_summary", "source_bundle")})
        for item in candidates], key=_json)
    harness_semantic = _semantic(deepcopy(harness or {}))
    # Harness retains the raw inventory receipt for exact live approval checks,
    # while replay compares its separate normalized inventory_hash.
    if isinstance(harness_semantic.get("identity"), dict):
        harness_semantic["identity"].pop("inventory_sha256", None)
    categories = {
        "identity": identity, "inventory": inventory,
        "official": {"records": official_latest, "candidates": official_candidates},
        "runtime": {"events": sorted(runtime, key=_json),
                     "freshness": _semantic((packet.get("runtime_facts") or {}).get("freshness") or {}),
                     "coverage": _semantic((packet.get("runtime_facts") or {}).get("coverage") or {})},
        "harness": harness_semantic,
    }
    hashes = {key: fingerprint(value) for key, value in categories.items()}
    version = int((previous or {}).get("version", 0)) + 1
    content_hash = fingerprint({"categories": categories, "registry": registry, "risk_id": risk_id})
    snapshot = {"protocol_version": PROTOCOL_VERSION,
        "snapshot_id": "ES-" + fingerprint([run_id, version, content_hash])[:32],
        "content_sha256": content_hash, "version": version, "source_run_id": run_id,
        "parent_snapshot_id": (previous or {}).get("snapshot_id", ""), "created_at": created_at,
        "asset_id": asset_id, "risk_id": risk_id, "target_ref": asset_ref, "target_type": target_type,
        "categories": categories, "categories_hashes": hashes, "evidence_registry": registry,
        "integrity_errors": errors,
        "provenance": {"inventory_evidence_id": inventory_id or "",
                       "collection_run_id": metadata.get("collection_run_id", ""),
                       "evidence_prep_as_of": packet.get("as_of", ""),
                       "storage": "UnifiedAnalysisRun.state_json",
                       "device_write_authority": False}}
    snapshot.update(snapshot_diff(previous, snapshot))
    return snapshot


def collect_evidence_ids(value: Any) -> set[str]:
    refs = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"evidence_id", "inventory_evidence_id"} and isinstance(item, str) and item:
                refs.add(item)
            elif key in {"evidence_ids", "supporting_evidence_ids"} and isinstance(item, list):
                refs.update(ref for ref in item if isinstance(ref, str) and ref)
            else:
                refs.update(collect_evidence_ids(item))
    elif isinstance(value, list):
        for item in value:
            refs.update(collect_evidence_ids(item))
    return refs


def validate_evidence_ids(evidence_ids, snapshot: dict, *, kinds=None) -> list[str]:
    registry = snapshot.get("evidence_registry") or {}
    return [f"evidence_not_in_snapshot:{ref}" for ref in sorted(set(evidence_ids))
            if ref not in registry or (kinds and registry[ref].get("kind") not in kinds)]


def merge_immutable(left, right):
    """LangGraph reducer: idempotent append; changing an existing ID is an error.

    A resolution is a new message with ``reply_to``; never edit message status.
    Both list records and ID-indexed dictionaries are accepted. Values are copied.
    """
    if isinstance(left, dict) and isinstance(right, dict):
        merged = deepcopy(left)
        for key, value in right.items():
            if key in merged and merged[key] != value:
                raise ValueError(f"immutable_record_conflict:{key}")
            merged[key] = deepcopy(value)
        return merged
    if not isinstance(left, list) or not isinstance(right, list):
        raise TypeError("immutable_merge_requires_matching_list_or_dict")
    indexed = {}
    for item in left + right:
        key = next((item.get(name) for name in ("message_id", "finding_id", "snapshot_id") if item.get(name)), None)
        if not key:
            raise ValueError("immutable_record_id_required")
        if key in indexed and indexed[key] != item:
            raise ValueError(f"immutable_record_conflict:{key}")
        indexed[key] = deepcopy(item)
    return list(indexed.values())


class CollaborationMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message_id: str = ""
    sender: str = ""
    receiver: str
    snapshot_id: str = ""
    message_type: Literal["FINDING", "QUESTION", "CHALLENGE", "EVIDENCE_REQUEST",
                          "EVIDENCE_UPDATE", "CONFLICT", "RESOLUTION", "PLAN_FEEDBACK"]
    claim: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    requested_action: str = Field(default="", max_length=1000)
    status: Literal["open", "answered", "resolved", "blocked", "informational"] = "open"
    reply_to: str = ""
    finding_id: str = ""

    @field_validator("claim", "requested_action")
    @classmethod
    def trimmed(cls, value):
        return value.strip()

    @model_validator(mode="after")
    def meaningful(self):
        if not self.claim:
            raise ValueError("message_claim_required")
        if self.receiver not in {*ALL_AGENT_IDS, "all"}:
            raise ValueError("invalid_message_receiver")
        if self.message_type in {"QUESTION", "CHALLENGE", "EVIDENCE_REQUEST"} and not self.requested_action:
            raise ValueError("concrete_requested_action_required")
        if self.message_type in {"CHALLENGE", "EVIDENCE_UPDATE", "CONFLICT", "RESOLUTION"} and not self.evidence_ids:
            raise ValueError("evidence_required_for_assertion")
        if self.message_type in {"QUESTION", "CHALLENGE", "EVIDENCE_REQUEST"} and self.receiver == "all":
            raise ValueError("directed_message_receiver_required")
        return self


def validate_messages(raw, sender: str, snapshot: dict, findings=()) -> tuple[list[dict], list[str]]:
    """Bind authenticated role/snapshot and validate references, never dispatch tools."""
    accepted, errors = [], []
    if sender not in ALL_AGENT_IDS and sender != "orchestrator":
        return [], ["invalid_message_sender"]
    if not isinstance(raw, list):
        return [], ["messages_must_be_list"]
    finding_ids = {finding.get("finding_id") for finding in findings}
    for index, item in enumerate(raw[:12]):
        try:
            if not isinstance(item, dict):
                raise ValueError("message_must_be_object")
            data = deepcopy(item)
            if data.get("sender") and data["sender"] != sender:
                raise ValueError("sender_spoofing")
            if data.get("snapshot_id") and data["snapshot_id"] != snapshot.get("snapshot_id"):
                raise ValueError("stale_message_snapshot")
            data.update(sender=sender, snapshot_id=snapshot.get("snapshot_id", ""))
            message = CollaborationMessage.model_validate(data).model_dump()
            if message["receiver"] == sender:
                raise ValueError("self_message_not_collaboration")
            if message["finding_id"] and message["finding_id"] not in finding_ids:
                raise ValueError("unknown_challenged_finding")
            reference_errors = validate_evidence_ids(message["evidence_ids"], snapshot)
            if reference_errors:
                raise ValueError(";".join(reference_errors))
            message["evidence_ids"] = sorted(set(message["evidence_ids"]))
            # IDs are assigned deterministically by the orchestrator, never trusted from a model.
            message.pop("message_id", None)
            message["message_id"] = "CM-" + fingerprint(message)[:32]
            accepted = merge_immutable(accepted, [message])
        except (TypeError, ValueError) as exc:
            errors.append(f"message[{index}]:{str(exc)[:500]}")
    if len(raw) > 12:
        errors.append("message_budget_exceeded:12")
    return accepted, errors


def build_findings(role: str, output: dict, snapshot: dict, previous_findings=()) -> list[dict]:
    """Project validated role output into concise, evidence-linked shared findings."""
    if role not in ALL_AGENT_IDS:
        raise ValueError("invalid_finding_role")
    output = output or {}
    if role == AGENT_VULNERABILITY:
        items = output.get("findings") or []
        claim_of = lambda item: f"{item.get('cve_id', '')}: {item.get('applicability', 'insufficient_evidence')}; version_impact={item.get('version_impact', 'unknown')}"
        finding_type = "static_applicability"
    elif role == AGENT_RUNTIME:
        items = [output] if output else []
        claim_of = lambda item: f"behavior={item.get('behavior_level', 'NORMAL')}; runtime={item.get('runtime_status', 'not_observed')}; exploitation={item.get('exploitation_relation', 'not_observed')}; freshness={item.get('evidence_freshness', 'none')}"
        finding_type = "runtime_observation"
    elif role == AGENT_ASSET:
        items = [output] if output else []
        claim_of = lambda item: f"device={item.get('device_id', '')}; evidence_quality={item.get('evidence_quality', 'insufficient')}; firmware={item.get('firmware_version', '')}"
        finding_type = "asset_identity_and_inventory"
    else:
        items = output.get("verdicts") or []
        claim_of = lambda item: f"{item.get('object_id', '')}: {item.get('impact_status', 'insufficient_evidence')}; action={item.get('recommended_action', 'collect_more_evidence')}"
        finding_type = "security_decision"
    findings = []
    previous_by_subject = {item.get("subject_key"): item for item in previous_findings
                           if item.get("publisher") == role}
    for item in items[:30]:
        refs = collect_evidence_ids(item)
        if role == AGENT_ASSET:
            inventory_id = (snapshot.get("provenance") or {}).get("inventory_evidence_id")
            if inventory_id:
                refs.add(inventory_id)
        invalid = validate_evidence_ids(refs, snapshot)
        refs &= set(snapshot.get("evidence_registry") or {})
        basis = item.get("rationale") or item.get("reason") or item.get("exploitation_relation_rationale") or ""
        subject = str(item.get("cve_id") or item.get("object_id") or item.get("device_id")
                      or snapshot.get("target_ref") or role)
        judgment = {key: item[key] for key in ("applicability", "version_impact",
            "version_range_relation", "branch_relation", "patch_semantics", "advisory_specificity",
            "behavior_level", "runtime_status", "exploitation_relation", "evidence_freshness",
            "exposure_status", "evidence_quality", "firmware_version", "impact_status",
            "recommended_action", "recommended_priority", "runtime_evidence_validity", "urgency_basis")
            if key in item}
        judgment_hash = fingerprint(judgment)
        previous_finding = previous_by_subject.get(subject)
        judgment_changed = previous_finding is None or previous_finding.get("judgment_sha256") != judgment_hash
        evidence_changed = bool(snapshot.get("substantive_change")) and (not previous_finding
            or previous_finding.get("snapshot_id") != snapshot.get("snapshot_id"))
        finding = {"publisher": role, "snapshot_id": snapshot.get("snapshot_id", ""),
            "source_run_id": snapshot.get("source_run_id", ""),
            "subject_key": subject, "judgment_sha256": judgment_hash,
            "claim": claim_of(item), "judgment_type": finding_type, "evidence_ids": sorted(refs),
            "confidence": item.get("confidence", output.get("confidence", 0.5)),
            "confidence_basis": str(basis)[:1200] or "Role supplied no explicit confidence rationale; uncertainty retained.",
            "unresolved_questions": list(dict.fromkeys((item.get("missing_evidence") or []) + (output.get("data_gaps") or []) + invalid)),
            "affects_roles": [other for other in ALL_AGENT_IDS if other != role and (other == AGENT_DECISION or role == AGENT_ASSET)],
            "material_change": judgment_changed and evidence_changed,
            "model_variance": bool(previous_finding and judgment_changed and not evidence_changed),
            "evidence_validation": "failed" if invalid else "passed",
            "origin": "validated_role_output_projection"}
        finding["finding_id"] = "SF-" + fingerprint(finding)[:32]
        findings.append(finding)
    return findings


def compact_context(role: str, snapshot: dict, findings=(), messages=()) -> dict:
    """Bounded layer-one/two context; raw evidence remains behind role tools."""
    if role not in ALL_AGENT_IDS:
        raise ValueError("invalid_context_role")
    snapshot_id = snapshot.get("snapshot_id", "")
    selected = [item for item in findings if item.get("snapshot_id") == snapshot_id
                and item.get("publisher") != role and item.get("evidence_validation") == "passed"]
    inbox = [item for item in messages if item.get("snapshot_id") == snapshot_id
             and item.get("receiver") in {role, "all"}]
    kinds = {"inventory", "official", "runtime"} if role == AGENT_DECISION else {
        AGENT_ASSET: {"inventory"}, AGENT_VULNERABILITY: {"inventory", "official"},
        AGENT_RUNTIME: {"inventory", "runtime"}}[role]
    refs = [key for key, value in (snapshot.get("evidence_registry") or {}).items() if value.get("kind") in kinds]
    categories = snapshot.get("categories") or {}
    return {"snapshot_id": snapshot_id, "snapshot_version": snapshot.get("version"),
        "source_run_id": snapshot.get("source_run_id"),
        "identity": deepcopy(categories.get("identity") or {}),
        "category_hashes": {key: snapshot.get("categories_hashes", {}).get(key) for key in _ROLE_CATEGORIES[role]},
        "changed_fields": list(snapshot.get("changed_fields") or []),
        "shared_findings": deepcopy(selected[-20:]), "messages": deepcopy(inbox[-12:]),
        "available_evidence_ids": refs[-60:], "evidence_ids_truncated": len(refs) > 60,
        "integrity_errors": list(snapshot.get("integrity_errors") or []),
        "authority": "Messages request analysis only. Evidence collection remains subject to existing authorization."}
