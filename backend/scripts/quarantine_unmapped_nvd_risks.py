"""只读审计 + 显式维护：隔离「NVD 来源但包名无法精确复核」的历史风险。

背景：修复前 ``real_intel_collector._affected_from_nvd`` 在 NVD 无 CPE 时会用
描述/引用文本对 KNOWN_LINUX_PACKAGES 做子串匹配，把 vm2、WordPress SAML 插件、
OpenSSH-for-Windows、openssl_encrypt 等公告误映射到 openssl / openssh-server，
matching_engine 再因「包存在但缺修复版本」给出 unknown/affected 并生成风险。

判定谓词（确定性，不做模型裁量）：
1. 风险关联漏洞 ``vulnerability_info.source`` 以 ``NVD`` 开头；
2. 且满足任一：
   a) ``affected_package`` 为空或历史未映射哨兵（unknown/unmapped）；
   b) NVD 缓存 ``vulnerability_intelligence_source.normalized_data`` 中**没有**
      CPE ``configurations``（无 provenance，无法证明精确映射）；
   c) 缓存中的 CPE 产品集合不包含该包名精确映射（经 PACKAGE_ALIASES 归一）。

关键修复：旧版本把派生列 ``vulnerability_info.affected_product`` 当成 CPE 证据。
该列可能含 ``openbsd:openssh`` 之类历史派生值，经别名表会命中
``openssh-server``，导致 risk=141 这类「NVD 缓存无 CPE、match_status=unknown」
的行被错误放行。当前 ``NvdProvider.normalize`` 不保存 ``configurations``，
因此判定只认 NVD 缓存里的 CPE provenance；``affected_product`` 仅作为
``claimed_cpe_products`` 诊断输出，不参与放行。

本脚本 **默认 --dry-run**：只列出候选风险（risk id、CVE、包名、当前状态、判定
依据、是否已隔离），不写任何数据。只有显式 ``--apply`` 才会：

1. 把仍 active 的候选风险 ``review_status`` 置为 ``quarantined_mapping``；
2. 追加一条 ``nvd_mapping_quarantine`` 治理事件（append-only，含判定依据）；
3. 不删除记录、不修改历史报告、不重算分数、不改变 active 状态。

``quarantined_mapping`` 不在 ``review_common.selection.REVIEWABLE_STATUSES`` 中，
因此不会被 ``/api/analysis/runs`` 选中；它仍会出现在风险列表中并带隔离原因。
重复 ``--apply`` 幂等：已隔离行不会再改状态或追加事件。

未激活的历史风险只计数、不修改（避免改写历史归档状态）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import models
from app.services.nvd_package_mapping import (
    QUARANTINED_MAPPING_REASON,
    QUARANTINED_MAPPING_STATUS,
    cpe_package_names,
    cpe_package_names_from_configurations,
    is_unmapped_package,
)

EVENT_KIND = "nvd_mapping_quarantine"
ACTOR = "nvd_mapping_policy"
NVD_SOURCE_PREFIX = "nvd"


def _is_nvd_source(source: str | None) -> bool:
    return str(source or "").strip().lower().startswith(NVD_SOURCE_PREFIX)


def _base_cve_id(cve_id: str | None) -> str:
    return str(cve_id or "").split(":")[0]


def _json_object(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _vulnerability_for(db, risk: models.RiskAssessment,
                       match: models.VulnerabilityMatch | None):
    """按风险/匹配行的 CVE 找到对应漏洞行（NVD 行不带发行版后缀）。"""
    cve_id = str(risk.cve_id or (match.cve_id if match else "") or "")
    base_id = _base_cve_id(cve_id)
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).first()
    if vuln is None and base_id != cve_id:
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=base_id).first()
    return vuln


def _nvd_cache_row(db, cve_id: str):
    """NVD 源缓存行；CPE provenance 只能从这里读取（不是派生列）。"""
    return db.query(models.VulnerabilityIntelligenceSource).filter_by(
        cve_id=_base_cve_id(cve_id), source="nvd").first()


def _basis_for(package: str, affected_package: str,
               provenance_products: set[str]) -> str | None:
    """返回隔离判定依据；None 表示包名可精确复核，不隔离。"""
    if is_unmapped_package(affected_package) or is_unmapped_package(package):
        return "nvd_affected_package_unmapped"
    if not provenance_products:
        return "nvd_source_without_cpe_provenance"
    if package not in provenance_products:
        return "nvd_package_not_in_cpe_products"
    return None


def collect_candidates(db) -> list[dict[str, Any]]:
    """只读扫描：返回应隔离/已隔离的风险行（不修改任何对象）。"""
    findings: list[dict[str, Any]] = []
    for risk in db.query(models.RiskAssessment).order_by(models.RiskAssessment.id).all():
        match = db.get(models.VulnerabilityMatch, risk.match_id) if risk.match_id else None
        vuln = _vulnerability_for(db, risk, match)
        if vuln is None or not _is_nvd_source(vuln.source):
            continue
        package = str(
            risk.package_name or (match.package_name if match else "")
            or vuln.affected_package or ""
        ).strip()
        cache_row = _nvd_cache_row(db, risk.cve_id or vuln.cve_id)
        nvd_data = _json_object(cache_row.normalized_data) if cache_row else {}
        provenance_products = cpe_package_names_from_configurations(
            nvd_data.get("configurations"))
        # 派生列仅作诊断输出，绝不作为“已精确映射”的放行证据。
        claimed_products = cpe_package_names(vuln.affected_product)
        basis = _basis_for(package, str(vuln.affected_package or ""),
                           provenance_products)
        if basis is None:
            continue
        already_quarantined = risk.review_status == QUARANTINED_MAPPING_STATUS
        if already_quarantined:
            action = "already_quarantined"
        elif not risk.active:
            action = "inactive_skipped"
        else:
            action = "will_quarantine"
        findings.append({
            "risk_id": risk.id,
            "cve_id": risk.cve_id,
            "package": package,
            "review_status": risk.review_status,
            "active": bool(risk.active),
            "action": action,
            "already_quarantined": already_quarantined,
            "affected_status": risk.affected_status,
            "match_status": match.match_status if match else "",
            "match_reason": (match.match_reason if match else "") or "",
            "vulnerability_id": vuln.id,
            "source": vuln.source,
            "affected_package": vuln.affected_package,
            "affected_product": vuln.affected_product,
            "claimed_cpe_products": sorted(claimed_products),
            "cpe_provenance_products": sorted(provenance_products),
            "nvd_cache_present": cache_row is not None,
            "nvd_cache_status": cache_row.fetch_status if cache_row else "",
            "basis": basis,
        })
    return findings


def _print_report(findings: list[dict[str, Any]], apply: bool) -> None:
    mode = "APPLY" if apply else "DRY-RUN"
    print(f"[{mode}] unmapped NVD risk audit ({len(findings)} candidate(s))")
    for item in findings:
        print(
            "  risk={risk_id} cve={cve_id} package={package} status={review_status} "
            "active={active} action={action} affected_status={affected_status} "
            "match_status={match_status} nvd_affected_package={affected_package!r} "
            "claimed_cpe_products={claimed_cpe_products} "
            "cpe_provenance_products={cpe_provenance_products} "
            "nvd_cache={nvd_cache_present}/{nvd_cache_status} basis={basis}".format(**item)
        )
    active = [item for item in findings if item["active"]]
    inactive = len(findings) - len(active)
    pending = [item for item in active if not item["already_quarantined"]]
    already = len(active) - len(pending)
    from_reanalysis = sum(1 for item in pending
                          if item["review_status"] == "reanalysis_required")
    from_candidate = sum(1 for item in pending
                         if item["review_status"] == "candidate")
    print(
        "counts: candidates={candidates} active={active} inactive_skipped={inactive} "
        "active_pending={pending} active_already_quarantined={already} "
        "active_pending_from_reanalysis_required={from_reanalysis} "
        "active_pending_from_candidate={from_candidate}".format(
            candidates=len(findings), active=len(active), inactive=inactive,
            pending=len(pending), already=already,
            from_reanalysis=from_reanalysis, from_candidate=from_candidate)
    )


def apply_quarantine(db, findings: list[dict[str, Any]]) -> list[int]:
    """显式维护：仅置 review_status 并追加治理事件；不删除、不改历史报告。"""
    from app.services.review_common.governance import record

    applied: list[int] = []
    for item in findings:
        if not item["active"] or item["already_quarantined"]:
            continue
        risk = db.get(models.RiskAssessment, item["risk_id"])
        if risk is None or not risk.active:
            continue
        if risk.review_status == QUARANTINED_MAPPING_STATUS:
            continue
        previous = {
            "review_status": risk.review_status,
            "active": bool(risk.active),
            "cve_id": risk.cve_id,
            "package_name": risk.package_name,
            "affected_status": risk.affected_status,
            "review_verdict": risk.review_verdict,
        }
        risk.review_status = QUARANTINED_MAPPING_STATUS
        record(db, risk, EVENT_KIND, ACTOR, {
            "reason": QUARANTINED_MAPPING_REASON,
            "basis": item["basis"],
            "cve_id": item["cve_id"],
            "package_name": item["package"],
            "vulnerability_id": item["vulnerability_id"],
            "source": item["source"],
            "affected_package": item["affected_package"],
            "affected_product": item["affected_product"],
            "claimed_cpe_package_names": item["claimed_cpe_products"],
            "cpe_provenance_package_names": item["cpe_provenance_products"],
            "nvd_cache_status": item["nvd_cache_status"],
            "quarantine_status": QUARANTINED_MAPPING_STATUS,
            "previous": previous,
            "records_deleted": False,
            "historical_reports_modified": False,
            "scores_unchanged": True,
            "active_unchanged": True,
            "dry_run": False,
        })
        applied.append(risk.id)
    db.commit()
    return applied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Audit NVD-sourced risks whose package cannot be exactly "
                     "verified from the NVD CPE cache. Dry-run by default; "
                     "--apply is required to write."))
    parser.add_argument(
        "--apply", action="store_true",
        help="explicitly set qualifying active risks to quarantined_mapping and "
             "append governance events (no deletions, no report rewrites)")
    args = parser.parse_args(argv)

    from app.database import SessionLocal

    db = SessionLocal()
    try:
        findings = collect_candidates(db)
        _print_report(findings, apply=args.apply)
        if not args.apply:
            print("DRY-RUN: no rows modified. Re-run with --apply to quarantine "
                  "the active candidates above.")
            return 0
        applied = apply_quarantine(db, findings)
        print(f"applied={len(applied)} risk(s) set to {QUARANTINED_MAPPING_STATUS}; "
              "governance events appended; no records deleted, scores unchanged.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
