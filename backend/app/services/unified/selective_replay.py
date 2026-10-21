"""Deterministic dependency invalidation; reuse is never a new LLM execution."""
from datetime import datetime, timezone

from app.services.unified.schemas import ALL_AGENT_IDS, AGENT_DECISION

ROLE_KEYS = dict(zip(ALL_AGENT_IDS, ("investigation", "vulnerability", "runtime", "decision")))


def select_roles(parent, snapshot, *, force_full=False, ttl_seconds=3600, now=None):
    if force_full or not parent or not parent.get("evidence_snapshot"):
        return list(ALL_AGENT_IDS), [], "full_review_required"
    previous = parent["evidence_snapshot"]
    if previous.get("asset_id") != snapshot.get("asset_id") or previous.get("risk_id") != snapshot.get("risk_id"):
        return list(ALL_AGENT_IDS), [], "event_identity_changed"
    now = now or datetime.now(timezone.utc)
    invalid = set(snapshot.get("invalidated_roles") or [])
    for role in ALL_AGENT_IDS:
        provenance = (parent.get("role_provenance") or {}).get(role) or {}
        if (provenance.get("snapshot_id") != previous.get("snapshot_id")
                or not provenance.get("origin_run_id") or not provenance.get("origin_snapshot_id")):
            invalid.add(role)
        try:
            expiry = datetime.fromisoformat(provenance["valid_until"].replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= now:
                invalid.add(role)
        except (ValueError, KeyError, TypeError):
            invalid.add(role)
        if not parent.get(ROLE_KEYS[role]) or role in (parent.get("degraded_roles") or []):
            invalid.add(role)
    if invalid:
        invalid.add(AGENT_DECISION)
    active = [role for role in ALL_AGENT_IDS if role in invalid]
    return active, [role for role in ALL_AGENT_IDS if role not in invalid], ("selective_replay" if active else "no_new_evidence")
