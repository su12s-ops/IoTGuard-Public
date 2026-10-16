"""Compatibility facade for the per-risk fixed expert audit pipeline.

The former free/aggregate group-chat implementation was removed. Public API
entry points now come from :mod:`event_review_pipeline`. A few private helpers
remain for historical callers and tests, but none can apply one verdict to all
risk rows.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app import models
from app.services.event_review_pipeline import *  # noqa: F401,F403
from app.services.event_review_pipeline import (
    MAX_RETRIES,
    _configured,
    _explain_candidate_selection,
    _extract_json,
    _persist_run_progress,
    build_evidence_packet,
)
from app.services.risk_engine import risk_level


VALID_VERDICTS = {"confirmed", "upgraded", "downgraded", "insufficient_evidence"}
MAX_RISK_ADJUSTMENT = 30.0


async def _run_review_pipeline(*_args, **_kwargs):
    """Removed legacy hook retained only so old monkeypatches do not crash."""
    raise RuntimeError("legacy group-chat pipeline was removed")


def _validate_object_verdict(
    obj_verdict: dict[str, Any],
    candidate_object_ids: set[str],
    all_evidence_ids: set[str],
) -> tuple[bool, str]:
    object_id = str(obj_verdict.get("object_id", ""))
    if not object_id:
        return False, "缺少 object_id"
    if object_id not in candidate_object_ids:
        return False, f"object_id={object_id!r} 不在本次候选集合中"
    verdict = str(obj_verdict.get("verdict", ""))
    if verdict not in VALID_VERDICTS:
        return False, f"verdict={verdict!r} 非法"
    try:
        confidence = float(obj_verdict.get("confidence", 0))
        adjustment = float(obj_verdict.get("risk_adjustment", 0))
    except (TypeError, ValueError):
        return False, "confidence/risk_adjustment 必须是数字"
    if not 0 <= confidence <= 1:
        return False, "confidence 必须在 0-1 之间"
    if not 0 <= adjustment <= MAX_RISK_ADJUSTMENT:
        return False, "risk_adjustment 超出兼容范围"
    if verdict in {"confirmed", "insufficient_evidence"} and adjustment != 0:
        return False, f"verdict={verdict} 时 risk_adjustment 必须为 0"
    evidence_ids = obj_verdict.get("evidence_ids", [])
    if not isinstance(evidence_ids, list):
        return False, "evidence_ids 必须是数组"
    unknown = [item for item in evidence_ids if item not in all_evidence_ids]
    if unknown:
        return False, f"evidence_id={unknown[0]!r} 不存在"
    if confidence < 0.75 and not obj_verdict.get("human_review_required"):
        return False, "置信度低于阈值时必须 human_review_required=true"
    if verdict == "insufficient_evidence" and not obj_verdict.get("human_review_required"):
        return False, "证据不足时必须 human_review_required=true"
    if obj_verdict.get("conflicts") and not obj_verdict.get("human_review_required"):
        return False, "存在冲突时必须 human_review_required=true"
    return True, ""


def _validate_all_verdicts(object_verdicts, candidate_object_ids, all_evidence_ids):
    valid, failed, seen = [], [], set()
    for verdict in object_verdicts:
        oid = str(verdict.get("object_id", ""))
        if oid in seen:
            failed.append((verdict, f"object_id={oid!r} 重复出现"))
            continue
        seen.add(oid)
        ok, error = _validate_object_verdict(verdict, candidate_object_ids, all_evidence_ids)
        (valid if ok else failed).append(verdict if ok else (verdict, error))
    return valid, failed


def _risk_for_compat_object(db: Session, object_id: str):
    if object_id.startswith("risk-"):
        try:
            return db.get(models.RiskAssessment, int(object_id.removeprefix("risk-")))
        except ValueError:
            return None
    parts = object_id.removeprefix("asset-").split("-", 1)
    if len(parts) != 2:
        return None
    try:
        asset_id = int(parts[0])
    except ValueError:
        return None
    rows = db.query(models.RiskAssessment).filter_by(asset_id=asset_id, cve_id=parts[1]).all()
    return rows[0] if len(rows) == 1 else None


def _apply_object_verdicts(db: Session, valid_verdicts, candidate_object_ids, failed_agents=None):
    """Legacy verdict adapter, still strictly bound to one object per verdict."""
    from app import config
    if config.UNIFIED_PIPELINE_MODE == "on":
        raise ValueError("system_b_formal_writer_disabled")
    stats = {"updated": 0, "not_found": 0, "human_review": 0}
    for verdict in valid_verdicts:
        oid = str(verdict.get("object_id", ""))
        if oid not in candidate_object_ids:
            stats["not_found"] += 1
            continue
        risk = _risk_for_compat_object(db, oid)
        if risk is None:
            stats["not_found"] += 1
            continue
        confidence = float(verdict.get("confidence", 0) or 0)
        name = verdict.get("verdict", "")
        human = bool(verdict.get("human_review_required")) or confidence < 0.75 or name == "insufficient_evidence"
        adjustment = float(verdict.get("risk_adjustment", 0) or 0)
        # Compatibility helper preserves legacy labels for historical callers;
        # the real pipeline writes pending_human_review/auto_confirmed.
        risk.review_status = "human_review" if human else "completed"
        risk.review_verdict = name
        risk.review_confidence = confidence
        risk.review_adjustment = adjustment
        risk.review_evidence_ids = json.dumps(verdict.get("evidence_ids", []), ensure_ascii=False)
        risk.review_conflicts = json.dumps(verdict.get("conflicts", []), ensure_ascii=False)
        risk.review_missing_evidence = json.dumps(verdict.get("missing_evidence", []), ensure_ascii=False)
        risk.review_reason = verdict.get("reason", "")
        risk.review_failed_agents = json.dumps(failed_agents or [], ensure_ascii=False)
        risk.review_completed_at = datetime.now(timezone.utc)
        risk.human_review_required = human
        if human:
            risk.final_score = None
            risk.risk_level = None
            risk.decision = None
            stats["human_review"] += 1
        else:
            baseline = float(risk.preliminary_score or 0)
            final = baseline + adjustment if name == "upgraded" else baseline - adjustment if name == "downgraded" else baseline
            final = max(0.0, min(100.0, final))
            risk.final_score = round(final, 2)
            risk.risk_level = risk_level(final)
            risk.decision = "immediate_fix" if final >= 70 else "scheduled_fix" if final >= 50 else "monitor"
        stats["updated"] += 1
    db.commit()
    return stats


def apply_review_verdict(db: Session, verdict: dict[str, Any] | None, status: str = "completed") -> int:
    """Reject unbound legacy aggregate verdicts; accept only explicit object_id."""
    if not verdict or not verdict.get("object_id") or status == "skipped":
        return 0
    return _apply_object_verdicts(db, [verdict], {str(verdict["object_id"])})["updated"]


def _build_object_evidence_packages(db: Session, selected_risks=None):
    candidates = selected_risks or (
        db.query(models.RiskAssessment)
        .filter(models.RiskAssessment.review_status.in_(["candidate", "reanalysis_required"]))
        .all()
    )
    objects, evidence_map, skipped = [], {}, []
    for risk in candidates:
        if not risk.match_id:
            matches = db.query(models.VulnerabilityMatch).filter_by(
                asset_id=risk.asset_id, cve_id=risk.cve_id, active=True
            ).all()
            if len(matches) == 1:
                risk.match_id = matches[0].id
                risk.package_name = matches[0].package_name
                db.flush()
        try:
            packet = build_evidence_packet(db, risk)
        except Exception as exc:
            skipped.append(str(exc))
            continue
        obj = packet.model_dump()
        obj["package"] = {
            "name": packet.package_match["package_name"],
            "installed_version": packet.package_match["installed_version"],
            "fixed_version": packet.package_match["fixed_version"],
        }
        epss_percent = round(float(risk.epss_score or 0), 4)
        score = float(packet.vulnerability.get("cvss_score") or 0)
        severity = "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "Unknown"
        obj["intelligence"] = {
            **packet.threat_intelligence,
            "epss_probability_0_to_1": round(epss_percent / 100, 6),
            "epss_percent_0_to_100": epss_percent,
        }
        obj["vulnerability"]["cvss_severity_by_score"] = severity
        obj["vulnerability"]["vendor_severity"] = packet.vulnerability.get("vendor_severity", "Unknown")
        obj["evidence_items"] = []
        for item in packet.evidence_items:
            legacy_type = "threat_intel" if item.evidence_type == "ubuntu_security" else item.evidence_type
            legacy = {"evidence_id": item.evidence_id, "type": legacy_type, **item.content}
            if item.evidence_type == "ubuntu_security":
                legacy.update(obj["intelligence"])
                legacy.pop("epss_score", None)
            obj["evidence_items"].append(legacy)
            evidence_map[item.evidence_id] = legacy
        # Preserve the historical aggregate shape while the authoritative
        # pipeline retains separate, source-scoped intelligence evidence.
        legacy_intel = {"evidence_id": f"EV-{risk.id}-INTEL-COMPAT", "type": "threat_intel", **obj["intelligence"]}
        legacy_intel.pop("epss_score", None)
        obj["evidence_items"].append(legacy_intel)
        evidence_map[legacy_intel["evidence_id"]] = legacy_intel
        objects.append(obj)
    db.commit()
    return objects, evidence_map, skipped


async def _run_coordinator_agent(specialist_outputs, context, model_client):
    """Historical JSON retry adapter; the real coordinator is typed per event."""
    from autogen_core.models import UserMessage

    started = time.perf_counter()
    raw = ""
    for attempt in range(MAX_RETRIES + 1):
        response = await model_client.create(messages=[UserMessage(
            content=f"Return JSON object_verdicts. Context={context}; experts={json.dumps(specialist_outputs, ensure_ascii=False)}",
            source=AGENT_COORDINATOR,
        )], json_output=True)
        raw = str(getattr(response, "content", response) or "")
        parsed = _extract_json(raw)
        if parsed and isinstance(parsed.get("object_verdicts"), list) and parsed["object_verdicts"]:
            return {
                "status": "completed", "attempts": attempt + 1,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "output_valid": True, "output": parsed, "raw_text": raw, "error": "",
            }
    return {
        "status": "failed", "attempts": MAX_RETRIES + 1,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "output_valid": False, "output": None, "raw_text": raw,
        "error": "JSON parse failed after directed retries",
    }
