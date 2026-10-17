from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import models
from app.database import SessionLocal, get_db
from app.services.kylin_security_collector import sync_kylin_asset_intelligence
from app.services.matching_engine import run_matching
from app.services.real_intel_collector import sync_real_vulnerabilities
from app.services.remediation_engine import generate_remediation_tasks
from app.services.task_runner import get_job, start_job
from app.services.risk_engine import calculate_risk
from app.services.ubuntu_security_collector import sync_ubuntu_asset_intelligence
from app.services.vulnerability_intelligence.service import get_source_bundle

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

from pydantic import BaseModel, Field
from app.services.device_access import require_control
from app.services.canonical_official import verify_and_correct


class OfficialVerificationInput(BaseModel):
    cve_ids: list[str] = Field(min_length=1, max_length=200)


@router.post("/official/verify", dependencies=[Depends(require_control)])
def verify_official(payload: OfficialVerificationInput, db: Session = Depends(get_db)):
    return verify_and_correct(db, payload.cve_ids)


@router.get("/official/records")
def official_records(cve_id: str, db: Session = Depends(get_db)):
    from app.services.vulnerability_intelligence.service import base_cve_id
    import json
    cve = base_cve_id(cve_id)
    records = db.query(models.OfficialCveRecord).filter_by(cve_id=cve).order_by(models.OfficialCveRecord.id.desc()).limit(200).all()
    ids = [r.evidence_id for r in records]
    corrections = db.query(models.ApplicabilityCorrection).filter(models.ApplicabilityCorrection.official_evidence_id.in_(ids)).all()
    return {"records": [{"evidence_id": r.evidence_id, "source_url": r.source_url,
        "content_sha256": r.content_sha256, "evidence_status": r.evidence_status,
        "fetched_at": r.fetched_at, "error": r.error, "record": json.loads(r.raw_json)} for r in records],
        "corrections": [{"id": c.id, "asset_id": c.asset_id, "risk_id": c.risk_id,
            "official_evidence_id": c.official_evidence_id, "before": json.loads(c.before_json),
            "after": json.loads(c.after_json), "historical_run_ids": json.loads(c.historical_run_ids_json),
            "reason": c.reason, "created_at": c.created_at} for c in corrections]}


def serialize_vulnerability(vuln: models.VulnerabilityInfo, db: Session | None = None):
    parts = vuln.cve_id.split(":")
    release = parts[1] if len(parts) > 1 else ""
    sources = get_source_bundle(
        db, vuln.cve_id, release=release, package_name=vuln.affected_package
    ) if db else {}
    return {
        "id": vuln.id,
        "cve_id": vuln.cve_id,
        "title": vuln.title,
        "description": vuln.description,
        "cvss_score": vuln.cvss_score,
        "cvss_severity": vuln.cvss_severity,
        "cwe_id": vuln.cwe_id,
        "affected_product": vuln.affected_product,
        "affected_package": vuln.affected_package,
        "fixed_version": vuln.fixed_version,
        "published_date": vuln.published_date,
        "source": vuln.source,
        "references": vuln.references,
        "remediation": vuln.remediation,
        "is_kev": vuln.intel.is_kev if vuln.intel else False,
        "epss_score": vuln.intel.epss_score if vuln.intel else 0,
        "exploit_status": vuln.intel.exploit_status if vuln.intel else "unknown",
        "poc_available": vuln.intel.poc_available if vuln.intel else False,
        "intelligence_sources": sources,
    }


def _run_analysis(db: Session, progress=None, cve_ids: list[str] | None = None) -> dict[str, int]:
    analysis = {"matches": 0, "risks": 0, "tasks": 0}
    if progress:
        progress("Running package matching")
    analysis["matches"] = run_matching(db, cve_ids=cve_ids)
    if progress:
        progress("Calculating risk ranking")
    analysis["risks"] = calculate_risk(db, cve_ids=cve_ids)
    if progress:
        progress("Generating remediation tasks")
    analysis["tasks"] = generate_remediation_tasks(db)
    return analysis


@router.get("/jobs/{job_id}")
def get_sync_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("")
def list_vulnerabilities(severity: str | None = None, kev: bool | None = None, q: str | None = None, db: Session = Depends(get_db)):
    query = db.query(models.VulnerabilityInfo)
    if severity:
        query = query.filter(models.VulnerabilityInfo.cvss_severity == severity)
    if q:
        query = query.filter(models.VulnerabilityInfo.cve_id.contains(q.upper()))
    rows = [serialize_vulnerability(item, db) for item in query.order_by(models.VulnerabilityInfo.cvss_score.desc()).all()]
    if kev is not None:
        rows = [row for row in rows if row["is_kev"] == kev]
    return rows


@router.post("/sync-real", dependencies=[Depends(require_control)])
def sync_real(
    keyword: str = "linux",
    days: int = 30,
    limit: int = 100,
    replace: bool = False,
    run_analysis: bool = True,
    async_mode: bool = True,
    db: Session = Depends(get_db),
):
    if days < 1 or days > 120:
        raise HTTPException(status_code=400, detail="days must be between 1 and 120")
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    if async_mode:
        def runner(progress):
            local_db = SessionLocal()
            try:
                result = sync_real_vulnerabilities(
                    local_db,
                    keyword=keyword,
                    days=days,
                    limit=limit,
                    replace=replace,
                    progress=progress,
                )
                analysis = {"matches": 0, "risks": 0, "tasks": 0}
                if run_analysis:
                    analysis = _run_analysis(local_db, progress=progress, cve_ids=result.changed_cve_ids)
                return {
                    "message": "Real vulnerability intelligence synced",
                    "keyword": keyword,
                    "days": days,
                    "limit": limit,
                    "replace": replace,
                    "run_analysis": run_analysis,
                    "total_from_nvd": result.total_from_nvd,
                    "saved": result.saved,
                    "kev_marked": result.kev_marked,
                    "epss_enriched": result.epss_enriched,
                    "analysis": analysis,
                    "warnings": result.warnings,
                }
            finally:
                local_db.close()

        job = start_job(
            "sync-real",
            runner,
            params={
                "keyword": keyword,
                "days": days,
                "limit": limit,
                "replace": replace,
                "run_analysis": run_analysis,
            },
        )
        return JSONResponse(status_code=202, content=job)

    result = sync_real_vulnerabilities(db, keyword=keyword, days=days, limit=limit, replace=replace)
    analysis = {"matches": 0, "risks": 0, "tasks": 0}
    if run_analysis:
        analysis = _run_analysis(db, cve_ids=result.changed_cve_ids)
    return {
        "message": "Real vulnerability intelligence synced",
        "keyword": keyword,
        "days": days,
        "limit": limit,
        "replace": replace,
        "run_analysis": run_analysis,
        "total_from_nvd": result.total_from_nvd,
        "saved": result.saved,
        "kev_marked": result.kev_marked,
        "epss_enriched": result.epss_enriched,
        "analysis": analysis,
        "warnings": result.warnings,
    }


@router.post("/sync-ubuntu-assets", dependencies=[Depends(require_control)])
def sync_ubuntu_assets(
    max_packages_per_asset: int = 24,
    limit_per_package: int = 100,
    replace: bool = False,
    run_analysis: bool = True,
    async_mode: bool = True,
    db: Session = Depends(get_db),
):
    if max_packages_per_asset < 1 or max_packages_per_asset > 80:
        raise HTTPException(status_code=400, detail="max_packages_per_asset must be between 1 and 80")
    if limit_per_package < 1 or limit_per_package > 100:
        raise HTTPException(status_code=400, detail="limit_per_package must be between 1 and 100")
    if async_mode:
        def runner(progress):
            local_db = SessionLocal()
            try:
                result = sync_ubuntu_asset_intelligence(
                    local_db,
                    max_packages_per_asset=max_packages_per_asset,
                    limit_per_package=limit_per_package,
                    replace=replace,
                    progress=progress,
                )
                analysis = {"matches": 0, "risks": 0, "tasks": 0}
                if run_analysis:
                    analysis = _run_analysis(local_db, progress=progress, cve_ids=result.changed_cve_ids)
                affected_count = local_db.query(models.VulnerabilityMatch).filter_by(affected=True).count()
                return {
                    "message": "Ubuntu asset-aware vulnerability intelligence synced",
                    "assets_checked": result.assets_checked,
                    "packages_checked": result.packages_checked,
                    "saved": result.saved,
                    "kev_marked": result.kev_marked,
                    "epss_enriched": result.epss_enriched,
                    "affected_matches": affected_count,
                    "replace": replace,
                    "run_analysis": run_analysis,
                    "analysis": analysis,
                    "warnings": result.warnings,
                }
            finally:
                local_db.close()

        job = start_job(
            "sync-ubuntu-assets",
            runner,
            params={
                "max_packages_per_asset": max_packages_per_asset,
                "limit_per_package": limit_per_package,
                "replace": replace,
                "run_analysis": run_analysis,
            },
        )
        return JSONResponse(status_code=202, content=job)

    result = sync_ubuntu_asset_intelligence(
        db,
        max_packages_per_asset=max_packages_per_asset,
        limit_per_package=limit_per_package,
        replace=replace,
    )
    analysis = {"matches": 0, "risks": 0, "tasks": 0}
    if run_analysis:
        analysis = _run_analysis(db, cve_ids=result.changed_cve_ids)
    affected_count = db.query(models.VulnerabilityMatch).filter_by(affected=True).count()
    return {
        "message": "Ubuntu asset-aware vulnerability intelligence synced",
        "assets_checked": result.assets_checked,
        "packages_checked": result.packages_checked,
        "saved": result.saved,
        "kev_marked": result.kev_marked,
        "epss_enriched": result.epss_enriched,
        "affected_matches": affected_count,
        "replace": replace,
        "run_analysis": run_analysis,
        "analysis": analysis,
        "warnings": result.warnings,
    }


@router.post("/sync-kylin-assets", dependencies=[Depends(require_control)])
def sync_kylin_assets(
    max_packages_per_asset: int = 24,
    limit_per_package: int = 40,
    replace: bool = False,
    run_analysis: bool = True,
    async_mode: bool = True,
    db: Session = Depends(get_db),
):
    """按麒麟（银河麒麟/openKylin）资产已安装软件包同步漏洞情报。

    数据源为 NVD CPE 包级映射（麒麟官方暂无公开 CVE JSON 接口），
    修复版本以上游边界作参考，最终以麒麟官方安全公告为准。
    """
    if max_packages_per_asset < 1 or max_packages_per_asset > 80:
        raise HTTPException(status_code=400, detail="max_packages_per_asset must be between 1 and 80")
    if limit_per_package < 1 or limit_per_package > 100:
        raise HTTPException(status_code=400, detail="limit_per_package must be between 1 and 100")
    if async_mode:
        def runner(progress):
            local_db = SessionLocal()
            try:
                result = sync_kylin_asset_intelligence(
                    local_db,
                    max_packages_per_asset=max_packages_per_asset,
                    limit_per_package=limit_per_package,
                    replace=replace,
                    progress=progress,
                )
                analysis = {"matches": 0, "risks": 0, "tasks": 0}
                if run_analysis:
                    analysis = _run_analysis(local_db, progress=progress, cve_ids=result.changed_cve_ids)
                affected_count = local_db.query(models.VulnerabilityMatch).filter_by(affected=True).count()
                return {
                    "message": "Kylin asset-aware vulnerability intelligence synced",
                    "assets_checked": result.assets_checked,
                    "packages_checked": result.packages_checked,
                    "saved": result.saved,
                    "kev_marked": result.kev_marked,
                    "epss_enriched": result.epss_enriched,
                    "affected_matches": affected_count,
                    "replace": replace,
                    "run_analysis": run_analysis,
                    "analysis": analysis,
                    "warnings": result.warnings,
                    "notices": result.notices,
                }
            finally:
                local_db.close()

        job = start_job(
            "sync-kylin-assets",
            runner,
            params={
                "max_packages_per_asset": max_packages_per_asset,
                "limit_per_package": limit_per_package,
                "replace": replace,
                "run_analysis": run_analysis,
            },
        )
        return JSONResponse(status_code=202, content=job)

    result = sync_kylin_asset_intelligence(
        db,
        max_packages_per_asset=max_packages_per_asset,
        limit_per_package=limit_per_package,
        replace=replace,
    )
    analysis = {"matches": 0, "risks": 0, "tasks": 0}
    if run_analysis:
        analysis = _run_analysis(db, cve_ids=result.changed_cve_ids)
    affected_count = db.query(models.VulnerabilityMatch).filter_by(affected=True).count()
    return {
        "message": "Kylin asset-aware vulnerability intelligence synced",
        "assets_checked": result.assets_checked,
        "packages_checked": result.packages_checked,
        "saved": result.saved,
        "kev_marked": result.kev_marked,
        "epss_enriched": result.epss_enriched,
        "affected_matches": affected_count,
        "replace": replace,
        "run_analysis": run_analysis,
        "analysis": analysis,
        "warnings": result.warnings,
        "notices": result.notices,
    }


@router.get("/{cve_id}")
def get_vulnerability(cve_id: str, db: Session = Depends(get_db)):
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return serialize_vulnerability(vuln, db)
