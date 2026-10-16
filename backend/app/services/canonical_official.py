"""Canonical official CVE record import for applicability corrections.

Ubuntu applies upstream fixes as distro backports, so an upstream/NVD version
range alone cannot establish applicability on a release branch. The per-release
status table from the official Ubuntu Security API is authoritative for Ubuntu
assets. This service fetches one official record per CVE id (no per-CVE logic,
no hardcoded exceptions) and stores it through the same CanonicalProvider path
as the online sync, so corrections and first-time collection behave identically.

Evidence status is honest by construction: a release absent from the official
record stays absent (unknown), never inferred; fetch failures are returned to
the caller instead of being papered over.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from app import models

from app.services.real_intel_collector import _http_json
from app.services.ubuntu_security_collector import (
    RELEASE_CODENAMES,
    UBUNTU_CVE_DETAIL,
    _upsert_ubuntu_vulnerability,
)
from app.services.vulnerability_intelligence.base import classify_error
from app.services.vulnerability_intelligence.canonical_provider import CanonicalProvider


CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
TRACKED_CODENAMES = frozenset(RELEASE_CODENAMES.values())


class OfficialRecordUnavailable(RuntimeError):
    def __init__(self, cve_id: str, status: str, detail: str):
        super().__init__(f"{cve_id}: {status}: {detail}")
        self.cve_id = cve_id
        self.status = status
        self.detail = detail


def official_record_url(cve_id: str) -> str:
    if not CVE_ID_PATTERN.fullmatch(cve_id or ""):
        raise ValueError(f"CVE 编号格式无效: {cve_id!r}")
    return UBUNTU_CVE_DETAIL.format(cve_id=cve_id)


def fetch_official_record(cve_id: str) -> dict[str, Any]:
    """Fetch the official record; raises OfficialRecordUnavailable on failure."""
    url = official_record_url(cve_id)
    try:
        data = _http_json(url, headers={"User-Agent": "LinuxGuard/0.1"}, timeout=20, retries=1)
    except Exception as exc:
        raise OfficialRecordUnavailable(cve_id, classify_error(exc), str(exc)[:300]) from exc
    if not isinstance(data, dict) or data.get("id", "").upper() != cve_id.upper():
        raise OfficialRecordUnavailable(cve_id, "invalid_record", "响应不是该 CVE 的官方记录")
    return data


def record_statuses(cve_id: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten the official record into per (package, release) status entries."""
    entries: list[dict[str, Any]] = []
    for package in data.get("packages", []) or []:
        name = (package.get("name") or "").strip()
        if not name:
            continue
        for status in package.get("statuses", []) or []:
            release = (status.get("release_codename") or "").strip()
            if release not in TRACKED_CODENAMES:
                continue
            raw_status = (status.get("status") or "").strip().lower()
            fixed_version = (status.get("description") or "").strip() if raw_status == "released" else ""
            notice_fixes = []
            for notice in data.get("notices", []) or []:
                if cve_id not in (notice.get("cves_ids") or []):
                    continue
                for pkg in (notice.get("release_packages") or {}).get(release, []):
                    if pkg.get("is_source") and pkg.get("name") == name and pkg.get("version"):
                        notice_fixes.append({"notice": notice["id"], "version": pkg["version"]})
            versions = {n["version"] for n in notice_fixes}
            effective = raw_status
            if not fixed_version and raw_status in {"needed", "deferred", "pending"} and len(versions) == 1:
                fixed_version = next(iter(versions))
                effective = "released"
            entries.append({
                "cve_id": cve_id, "package": name, "release": release,
                "raw_status": raw_status, "fixed_version": fixed_version,
                "effective_status": effective, "notice_fixes": notice_fixes,
                "status_note": "CVE 状态表尚未列修复版本；同一 CVE、发行版、源包的 USN 提供修复版本，保留两者原始状态" if effective != raw_status else "",
            })
    return entries


def import_official_records(
    db: Session,
    cve_ids: list[str],
    *,
    progress=None,
) -> dict[str, dict[str, Any]]:
    """Import official Canonical status records for the given CVE ids.

    Returns per-CVE provenance: evidence status, fetched_at, content sha256 and
    the (release, package) entries actually stored. Nothing is invented for
    releases the official record does not mention.
    """
    provider = CanonicalProvider()
    results: dict[str, dict[str, Any]] = {}
    todo = sorted({(cve_id or "").strip().upper() for cve_id in cve_ids if cve_id})
    def fetch(cve):
        if not CVE_ID_PATTERN.fullmatch(cve):
            return None
        try:
            return fetch_official_record(cve)
        except OfficialRecordUnavailable as exc:
            return exc
    # Network work precedes all writes: slow official sources must not hold the
    # SQLite writer lock and block unrelated product collection or trace writes.
    with ThreadPoolExecutor(max_workers=4) as pool:
        fetched = dict(zip(todo, pool.map(fetch, todo)))
    for index, cve_id in enumerate(todo, 1):
        if progress:
            progress(cve_id, index, len(todo))
        if not CVE_ID_PATTERN.fullmatch(cve_id):
            results[cve_id] = {"evidence_status": "invalid_id", "url": "", "entries": []}
            continue
        url = official_record_url(cve_id)
        try:
            data = fetched[cve_id]
            if isinstance(data, OfficialRecordUnavailable):
                raise data
        except OfficialRecordUnavailable as exc:
            failed = models.OfficialCveRecord(evidence_id="ADV-" + uuid.uuid4().hex,
                cve_id=cve_id, source_url=url, evidence_status=exc.status, error=exc.detail)
            db.add(failed)
            results[cve_id] = {
                "evidence_status": exc.status, "url": url, "error": exc.detail, "entries": [],
                "evidence_id": failed.evidence_id,
            }
            continue
        payload = hashlib.sha256(
            json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        evidence = models.OfficialCveRecord(evidence_id="ADV-" + uuid.uuid4().hex,
            cve_id=cve_id, source_url=url, content_sha256=payload,
            raw_json=json.dumps(data, sort_keys=True, ensure_ascii=False), evidence_status="available")
        db.add(evidence)
        db.flush()
        data = {**data, "_provenance": {"evidence_id": evidence.evidence_id,
            "source_url": url, "content_sha256": payload,
            "fetched_at": evidence.fetched_at.isoformat()}}
        entries: list[dict[str, Any]] = []
        stored_any = False
        for item in record_statuses(cve_id, data):
            raw_status = item["effective_status"]
            if raw_status == "released" and not item["fixed_version"]:
                item["stored"] = False
                item["skip"] = "released_without_fixed_version"
                entries.append(item)
                continue
            scoped_data = {**data, "_status_provenance": {"canonical_table_status": item["raw_status"],
                "notice_fixes": item["notice_fixes"], "status_note": item["status_note"]}}
            provider.store(
                db, scoped_data, item["package"], item["release"], raw_status, item["fixed_version"],
            )
            _upsert_ubuntu_vulnerability(
                db, data, item["package"], item["fixed_version"], item["release"], raw_status,
            )
            item["stored"] = True
            entries.append(item)
            stored_any = True
        results[cve_id] = {
            "evidence_status": "imported" if stored_any else "no_tracked_release_status",
            "url": url,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "content_sha256": payload,
            "evidence_id": evidence.evidence_id,
            "priority": (data.get("priority") or ""),
            "cvss3": data.get("cvss3"),
            "notices": data.get("notices_ids", []) or [],
            "entries": entries,
        }
    db.flush()
    return results


def verify_and_correct(db: Session, cve_ids: list[str]) -> dict:
    """Official re-evaluation is explicit; historical shadow output is immutable."""
    from app.services.matching_engine import run_matching
    from app.services.risk_engine import calculate_risk
    from app.services.vulnerability_intelligence.service import base_cve_id
    wanted = {base_cve_id(c) for c in cve_ids}
    before = []
    for risk in db.query(models.RiskAssessment).filter_by(active=True).all():
        if base_cve_id(risk.cve_id) not in wanted:
            continue
        match = db.get(models.VulnerabilityMatch, risk.match_id)
        asset = db.get(models.LinuxAsset, risk.asset_id)
        if not asset or asset.distribution != "ubuntu" or not match:
            continue
        before.append((risk.id, asset.id, base_cve_id(risk.cve_id), match.package_name,
            {k: getattr(match, k) for k in ("id", "cve_id", "match_status", "reason_code", "fixed_version", "evidence_fingerprint")},
            [r.run_id for r in db.query(models.UnifiedAnalysisRun).filter_by(risk_id=risk.id).all()]))
    results = import_official_records(db, cve_ids)
    db.commit()
    successful = [c for c, result in results.items() if result["evidence_status"] == "imported"]
    if successful:
        run_matching(db, cve_ids=successful)
        calculate_risk(db, cve_ids=successful)
    corrections = []
    for risk_id, asset_id, cve, package, old, runs in before:
        if cve not in successful:
            continue
        active = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset_id, package_name=package, active=True).all()
        current = next((m for m in active if base_cve_id(m.cve_id) == cve), None)
        if current is None or (current.match_status == old["match_status"] and current.fixed_version == old["fixed_version"]):
            continue
        after = {k: getattr(current, k) for k in ("id", "cve_id", "match_status", "reason_code", "fixed_version", "evidence_fingerprint")}
        correction = models.ApplicabilityCorrection(asset_id=asset_id, risk_id=risk_id,
            official_evidence_id=results[cve]["evidence_id"], before_json=json.dumps(old), after_json=json.dumps(after),
            historical_run_ids_json=json.dumps(runs),
            reason="Canonical 对实际发行版和源包的状态优先于 NVD 上游版本范围；历史影子结果保留，旧计划不得据此执行。")
        db.add(correction)
        db.flush()
        corrections.append(correction.id)
    db.commit()
    return {"records": results, "correction_ids": corrections}
