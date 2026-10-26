"""Bounded prompt projections; raw inventory and integrity hashes stay intact."""
from copy import deepcopy
import hashlib
import json


def bind_runtime_snapshot(db, snapshot):
    """Keep tool reads inside the evidence set the report validator accepts.

    Session-local ORM criteria also constrain process-tree subqueries. New
    arrivals remain in the database for the next analysis; nothing is deleted.
    """
    from sqlalchemy import event
    from sqlalchemy.orm import with_loader_criteria
    from app import models
    ids = tuple(key for key, value in (snapshot.get("evidence_registry") or {}).items()
                if value.get("kind") == "runtime")
    criterion = models.SecurityEvidence.evidence_id.in_(ids)
    def constrain(execution):
        if execution.is_select:
            execution.statement = execution.statement.options(with_loader_criteria(
                models.SecurityEvidence, criterion, include_aliases=True))
    event.listen(db, "do_orm_execute", constrain)


def conservative_runtime_status(report, snapshot):
    """Restrict an otherwise normal report to the freshness its IDs prove.

    Never upgrade freshness, normalize attack claims, or repair invented IDs.
    The unchanged schema and subsequent fact validator still reject all other
    contradictions. Caller retains both raw and effective reports for audit.
    """
    if report.get("behavior_level") != "NORMAL" or report.get("runtime_status") != "verified":
        return report
    if report.get("exploitation_relation") in {"confirmed_exploitation", "cve_related_evidence", "suspicious_unlinked"}:
        return report
    refs = report.get("evidence_ids") or []
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        return report
    if report.get("notes") is not None and not isinstance(report["notes"], list):
        return report
    ids = set(refs)
    registry = snapshot.get("evidence_registry") or {}
    if not ids or any(registry.get(key, {}).get("kind") != "runtime" for key in ids):
        return report
    freshness = {registry[key].get("fresh") for key in ids}
    derived = "mixed" if freshness == {True, False} else "stale" if freshness == {False} else None
    if not derived or report.get("evidence_freshness") != derived:
        return report
    result = deepcopy(report)
    result["runtime_status"] = "stale_verified"
    result["notes"] = list(result.get("notes") or []) + [
        "程序保守归类：引用快照证据含过期项，runtime_status 从 verified 改为 stale_verified；未提升新鲜度或利用判断。"]
    return result


def inventory_provenance(value):
    result = deepcopy(value)
    for key in ("package_sources", "apt_policy", "openssl_implementation"):
        raw = result.get(key)
        if raw is None:
            continue
        encoded = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
        items = raw if isinstance(raw, list) else [raw]
        sample = []
        for item in items[:8]:
            text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, default=str)
            sample.append(text[:180] + (" [TRUNCATED]" if len(text) > 180 else ""))
        result[key] = {"items": sample, "total_items": len(items),
            "original_chars": len(encoded), "sha256": hashlib.sha256(encoded.encode()).hexdigest(),
            "truncated": len(items) > 8 or any(len(str(item)) > 180 for item in items[:8]),
            "note": "Prompt sample only; full source is retained in the inventory receipt. Missing sample items do not imply absence."}
    return result


def asset_quality_dependencies(runtime):
    """Device-report validity depends on coverage/freshness, not traffic counters."""
    coverage = runtime.get("coverage") or {}
    return {"coverage": {"status": coverage.get("status"), "sensors": sorted([
        {key: sensor.get(key) for key in ("sensor_id", "source", "status", "dropped_events")}
        for sensor in coverage.get("sensors", [])], key=lambda x: x.get("sensor_id") or "")},
        "freshness": {aspect: (value.get("freshness") if isinstance(value, dict) else value)
                      for aspect, value in (runtime.get("freshness") or {}).items()},
        "has_data_gaps": bool(runtime.get("data_gaps"))}


def runtime_observations(db, snapshot, limit=6):
    """Fetch real rows already registered in this snapshot; never new events.

    Candidate-related entries take priority over unrelated fresh traffic. This
    is a sample, never proof that an unshown event or attack does not exist.
    """
    from app import models
    from app.services.unified.collaboration import fingerprint
    registry = snapshot.get("evidence_registry") or {}
    entries = [(key, value) for key, value in registry.items() if value.get("kind") == "runtime"]
    entries.sort(key=lambda item: ("related" in item[1].get("included_reason", ""),
                                   item[1].get("observed_at") or ""), reverse=True)
    candidates = [key for key, _ in entries[:32]]
    rows = {row.evidence_id: row for row in db.query(models.SecurityEvidence).filter(
        models.SecurityEvidence.evidence_id.in_(candidates)).all()} if candidates else {}
    observations, invalid = [], 0
    for key in candidates:
        row = rows.get(key)
        if row is None:
            invalid += 1
            continue
        raw = {column.name: getattr(row, column.name) for column in row.__table__.columns
               if column.name not in {"id", "created_at", "evidence_id", "evidence_hash"}}
        if fingerprint(raw) != registry[key].get("observation_sha256"):
            invalid += 1
            continue
        view = {name: getattr(row, name) for name in ("evidence_id", "source", "evidence_type",
            "timestamp", "process", "pid", "parent_process", "operation", "destination_ip", "destination_port")}
        for name in ("commandline", "file_path", "description"):
            text = getattr(row, name) or ""
            view[name] = text[:160]
            if len(text) > 160:
                view[name + "_truncated"] = True
        view["snapshot_fresh"] = registry[key].get("fresh")
        observations.append(view)
        if len(observations) >= limit:
            break
    return {"source": "snapshot_registered_security_evidence", "events": observations,
            "registered_total": len(entries), "sampled": len(observations) < len(entries),
            "invalid_or_missing": invalid,
            "note": "有界原始行为样例，不是全量日志。未展示或未观察到的行为不能判为不存在；需要细节时使用只读工具。"}
