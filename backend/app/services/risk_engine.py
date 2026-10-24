import json

from sqlalchemy.orm import Session

from app import models
from app.services.ebpf_event_collector import load_runtime_events
from app.services.nvd_package_mapping import QUARANTINED_MAPPING_STATUS
from app.services.reachability import analyze_reachability
from app.services.runtime_context import package_related_to_service, service_name
from app.services.runtime_evidence import evaluate_runtime_evidence
from app.services.vulnerability_intelligence.service import (
    base_cve_id,
    get_source_bundle,
    intelligence_fingerprint,
)


EXPOSURE_SCORE = {"public": 100, "dmz": 80, "internal": 50, "isolated": 20}
BUSINESS_SCORE = {"core": 100, "important": 80, "normal": 50, "test": 20}
DECISION_ORDER = {"immediate_fix": 0, "scheduled_fix": 1, "monitor": 2, "defer": 3}


def risk_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _related_services(asset: models.LinuxAsset, package_name: str) -> list[models.AssetService]:
    return [service for service in asset.services if package_related_to_service(package_name, service_name(service))]


def _exploitability_status(
    reachable_status: str,
    runtime_status: str,
    runtime_strength: float,
    intel: models.ThreatIntelSource | None,
    exposure_score: float,
) -> str:
    epss = float(intel.epss_score if intel else 0)
    known_exploited = bool(intel and (intel.is_kev or intel.exploit_status in {"active", "known-exploited"}))
    if runtime_status == "verified" and reachable_status == "internet_exposed" and (
        known_exploited or runtime_strength >= 72 or exposure_score >= 80
    ):
        return "likely"
    if reachable_status == "internet_exposed" and (
        runtime_status in {"verified", "contextual"} or known_exploited or epss >= 0.7 or runtime_strength >= 60
    ):
        return "likely"
    if reachable_status == "linked" and (
        runtime_status in {"verified", "contextual"} or known_exploited or epss >= 0.3 or runtime_strength >= 55
    ):
        return "likely"
    if reachable_status != "none" or known_exploited or epss >= 0.3 or exposure_score >= 80:
        return "plausible"
    return "unlikely"


def _decision(
    exploitability_status: str,
    reachable_status: str,
    runtime_status: str,
    patch_available: bool,
    runtime_strength: float,
    exposure_score: float,
    business_score: float,
) -> tuple[str, str]:
    if not patch_available:
        if exploitability_status in {"active", "likely"}:
            return "monitor", "当前尚无可用修复版本，建议持续监控并提前准备缓解措施。"
        if exploitability_status == "plausible":
            return "monitor", "当前存在一定暴露面，但暂无补丁，建议保持重点关注。"
        return "defer", "当前证据较弱，且暂时没有可用补丁。"

    if exploitability_status == "active":
        return "immediate_fix", "运行时证据和暴露面共同表明该漏洞已具备较强可利用条件。"
    if exploitability_status == "likely" and max(exposure_score, business_score) >= 80:
        return "immediate_fix", "该资产业务重要性较高，且漏洞较可能被利用，建议立即修复。"
    if exploitability_status in {"likely", "plausible"} and (
        reachable_status != "none" or runtime_status in {"contextual", "verified"} or runtime_strength >= 55
    ):
        return "scheduled_fix", "该漏洞与当前环境相关，建议在下一补丁窗口内完成修复。"
    if runtime_status == "not_observed" and reachable_status == "none":
        return "monitor", "软件包版本命中；尚未观察到相关路径，应补充采集覆盖和可达性证据，不能据此排除风险。"
    return "monitor", "建议持续观察，等待更强的运行时证据或可达性证据出现。"


def _decision_confidence(
    decision: str,
    exploitability_status: str,
    runtime_status: str,
    runtime_strength: float,
    runtime_confidence: float,
    reachable_status: str,
    patch_available: bool,
    exposure_score: float,
    business_score: float,
) -> float:
    confidence = {
        "immediate_fix": 0.72,
        "scheduled_fix": 0.62,
        "monitor": 0.5,
        "defer": 0.56,
    }[decision]
    confidence += runtime_confidence * 0.18
    confidence += min(0.12, runtime_strength / 500)
    if reachable_status == "internet_exposed":
        confidence += 0.08
    elif reachable_status == "linked":
        confidence += 0.04
    if patch_available and decision != "defer":
        confidence += 0.05
    if exploitability_status == "active":
        confidence += 0.08
    elif exploitability_status == "likely":
        confidence += 0.05
    if max(exposure_score, business_score) >= 80:
        confidence += 0.04
    if runtime_status == "waiting":
        confidence -= 0.12
    return round(max(0.35, min(0.97, confidence)), 2)


def _decision_score(decision: str) -> float:
    return {
        "immediate_fix": 100.0,
        "scheduled_fix": 75.0,
        "monitor": 45.0,
        "defer": 20.0,
    }[decision]


def _build_reason(
    affected_status: str,
    reachable_status: str,
    runtime_status: str,
    exploitability_status: str,
    decision: str,
    patch_available: bool,
) -> str:
    parts = [
        f"受影响状态={affected_status}",
        f"可达性状态={reachable_status}",
        f"运行时状态={runtime_status}",
        f"可利用性状态={exploitability_status}",
        f"处置决策={decision}",
        "补丁=可用" if patch_available else "补丁=不可用",
    ]
    return "; ".join(parts)


def _recompute_rank_in_engine(db: Session, asset_id: int | None = None) -> int:
    """依据最终分数（无最终结论时按候选/基线分数）重新计算优先级排名。

    Asset-scoped calculation ranks only that asset. Ranking against the whole
    fleet and writing the resulting positions back into one asset's rows made
    the same risk appear as rank 32/44/107 because other assets occupied the
    gaps; the operator-visible order inside an asset must come from that
    asset's own scope. A fleet calculation (asset_id=None) still ranks all.
    """
    query = db.query(models.RiskAssessment)
    if asset_id:
        query = query.filter(models.RiskAssessment.asset_id == asset_id)
    rows = query.all()
    ranked = sorted(
        rows,
        key=lambda item: (
            -(item.final_score or item.preliminary_score or 0),
            -(item.runtime_score or 0),
        ),
    )
    for index, row in enumerate(ranked, 1):
        row.priority_rank = index
    db.commit()
    return len(ranked)


# ═══════════════════════════════════════════════════════════════════════════
# Delivery candidate engine (exact match-bound, incremental implementation)
# ═══════════════════════════════════════════════════════════════════════════

def _candidate_facts(
    match: models.VulnerabilityMatch,
    asset: models.LinuxAsset,
    runtime: dict,
    source_fingerprint: str = "",
) -> dict:
    """重评判据的事实载荷：只含与风险结论相关的可复核事实。

    刻意排除三类随采集周期必然变化、但不构成事实变化的输入：
    - asset.updated_at / 采集时间戳（每次清单写入必变）；
    - 运行时事件 ID 与权重（持续遥测下 top-N 选取必然轮换、新鲜度桶随
      时间漂移——属于采集时间/原始文本变化）。
    覆盖类事实以 runtime.status（waiting/contextual/verified/not_observed
    的覆盖等级）保留：证据从无到有、从上下文到直接命中的跃迁仍是事实变化。
    """
    import json

    service_state = sorted(
        (
            service.service_name,
            service.port,
            service.protocol,
            service.listen_address,
            bool(service.is_public_exposed),
        )
        for service in asset.services
    )
    return {
        "match_id": match.id,
        "match_fingerprint": match.evidence_fingerprint,
        "installed_version": match.installed_version,
        "fixed_version": match.fixed_version,
        "match_status": match.match_status,
        "package_name": match.package_name,
        "asset_exposure": asset.exposure_level,
        "asset_business": asset.business_level,
        "asset_os_version": asset.os_version,
        "inventory_complete": bool(asset.inventory_complete),
        "services": service_state,
        "runtime_status": runtime.get("status", "waiting"),
        "source_fingerprint": source_fingerprint,
    }


def _facts_hash(payload: dict) -> str:
    import hashlib
    import json

    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _legacy_facts_changed(risk: models.RiskAssessment, values: dict) -> bool:
    """旧算法行（candidate_facts_json 为空）的一次性迁移比对。

    旧指纹哈希把采集时间戳和事件 ID 混入事实，无法与事实载荷直接比较；
    迁移时先比较风险行自身留存的事实型字段（受影响判定、运行时覆盖
    等级、适用性来源、发行版优先级），任一变化仍按事实变化处理。
    未被行字段覆盖的事实类（修复版本出现/消失、服务集变化等）在本次
    迁移中存在盲窗，由 candidate_facts_rebaseline 治理事件留痕；
    自本次起行上写入事实载荷，后续比较恢复精确。
    """
    row_facts = {
        "affected_status": risk.affected_status,
        "runtime_status": risk.runtime_status,
        "applicability_source": risk.applicability_source,
        "ubuntu_priority": risk.ubuntu_priority,
    }
    new_facts = {
        "affected_status": values.get("affected_status"),
        "runtime_status": values.get("runtime_status"),
        "applicability_source": values.get("applicability_source"),
        "ubuntu_priority": values.get("ubuntu_priority"),
    }
    return any(str(row_facts[key]) != str(new_facts[key]) for key in row_facts)


def _reset_for_reanalysis(risk: models.RiskAssessment, reason: str) -> None:
    risk.review_status = "reanalysis_required"
    risk.review_verdict = ""
    risk.review_confidence = 0
    risk.review_adjustment = 0
    risk.review_evidence_ids = "[]"
    risk.review_conflicts = "[]"
    risk.review_missing_evidence = "[]"
    risk.review_reason = reason
    risk.review_completed_at = None
    risk.human_review_required = False
    risk.review_failed_agents = "[]"
    risk.evidence_packet_json = "{}"
    risk.agent_results_json = "{}"
    risk.conflict_result_json = "{}"
    risk.audit_policy_reasons = "[]"
    risk.recommended_priority = ""
    risk.recommended_action = ""
    risk.risk_direction = "maintain"
    risk.final_score = None
    risk.risk_level = None
    risk.decision = None
    risk.reanalysis_count = int(risk.reanalysis_count or 0) + 1


def _block_open_remediation_tasks(
    db: Session,
    risk: models.RiskAssessment,
    reason: str,
) -> None:
    """Fail closed when the evidence that authorized a task is no longer current."""
    if not risk.id:
        return
    tasks = db.query(models.RemediationTask).filter_by(risk_id=risk.id).all()
    for task in tasks:
        if task.status in {"verified", "resolved"}:
            continue
        task.status = "blocked"
        task.mitigation = f"{reason} 原处置任务已暂停，重新裁定并授权后方可继续。"


def _likelihood_level(epss_probability: float) -> str:
    if epss_probability >= 0.7:
        return "high"
    if epss_probability >= 0.3:
        return "elevated"
    if epss_probability >= 0.1:
        return "moderate"
    return "low"


def calculate_risk(db: Session, cve_ids: list[str] | None = None, asset_id: int | None = None) -> int:
    """Upsert candidates within the requested asset/CVE scope, retaining history."""
    match_query = db.query(models.VulnerabilityMatch).filter(
        models.VulnerabilityMatch.active.is_(True), models.VulnerabilityMatch.affected.is_(True)
    )
    if asset_id:
        match_query = match_query.filter(models.VulnerabilityMatch.asset_id == asset_id)
    matches = match_query.order_by(models.VulnerabilityMatch.id).all()
    target_cves = {base_cve_id(item) for item in cve_ids or []}
    if target_cves:
        matches = [match for match in matches if base_cve_id(match.cve_id) in target_cves]
    runtime_events = load_runtime_events(db=db, limit=5000)
    current_match_ids: set[int] = set()
    processed = 0

    for match in matches:
        asset = db.get(models.LinuxAsset, match.asset_id)
        vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=match.cve_id).first()
        intel = db.query(models.ThreatIntelSource).filter_by(cve_id=match.cve_id).first()
        if not asset or not vuln:
            continue
        current_match_ids.add(match.id)

        release = match.cve_id.split(":")[1] if ":" in match.cve_id else ""
        source_bundle = get_source_bundle(
            db, match.cve_id, release=release, package_name=match.package_name
        )
        canonical = source_bundle["canonical"]["value"]
        nvd = source_bundle["nvd"]["value"]
        cisa = source_bundle["cisa_kev"]["value"]
        epss_source = source_bundle["epss"]["value"]
        nvd_cvss = nvd.get("cvss", {}) if isinstance(nvd.get("cvss"), dict) else {}
        raw_cvss = float(nvd_cvss.get("score") or vuln.cvss_score or 0)
        epss_probability = float(epss_source.get("score") or (intel.epss_score if intel else 0) or 0)
        known_exploited = bool(cisa.get("is_kev") or (intel and intel.is_kev))
        cvss = round(raw_cvss / 10 * 100, 2)
        epss = round(epss_probability * 100, 2)
        kev = 100.0 if known_exploited else 0.0
        ubuntu_priority = canonical.get("priority", "unknown") if canonical else "unknown"
        priority_floor = {"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0}.get(
            ubuntu_priority, 0.0
        )
        technical_score = max(cvss, priority_floor)
        technical_severity = nvd_cvss.get("severity") or vuln.cvss_severity or "Unknown"
        likelihood_level = _likelihood_level(epss_probability)
        exposure = float(EXPOSURE_SCORE.get(asset.exposure_level, 50))
        business = float(BUSINESS_SCORE.get(asset.business_level, 50))
        patch = 100.0 if match.fixed_version else 35.0
        affected_status = match.match_status or "unknown"
        if affected_status == "unknown" and match.affected and match.installed_version and match.fixed_version:
            # Compatibility for rows created before match_status existed.
            affected_status = "potentially_affected"

        reachability = analyze_reachability(asset, match.package_name, list(asset.services))
        related_services = _related_services(asset, match.package_name)
        runtime = evaluate_runtime_evidence(asset, match.package_name, related_services, runtime_events)
        runtime_status = runtime["status"]
        runtime_strength = float(runtime["strength_score"])
        runtime_confidence = float(runtime["confidence"])
        reachable_status = reachability["status"]

        exploitability_status = _exploitability_status(
            reachable_status, runtime_status, runtime_strength, intel, exposure
        )
        decision, decision_reason = _decision(
            exploitability_status,
            reachable_status,
            runtime_status,
            bool(match.fixed_version),
            runtime_strength,
            exposure,
            business,
        )
        decision_confidence = _decision_confidence(
            decision,
            exploitability_status,
            runtime_status,
            runtime_strength,
            runtime_confidence,
            reachable_status,
            bool(match.fixed_version),
            exposure,
            business,
        )
        # CVSS/Ubuntu priority establish technical impact. EPSS changes the
        # likelihood multiplier and KEV adds a bounded exploitation uplift;
        # the three concepts are not summed into one pseudo-severity.
        likelihood_multiplier = {
            "low": 0.78,
            "moderate": 0.92,
            "elevated": 1.08,
            "high": 1.22,
        }[likelihood_level]
        exploitation_multiplier = 1.18 if known_exploited else 1.0
        static_score = round(min(100.0, technical_score * likelihood_multiplier * exploitation_multiplier), 2)
        environment_score = round(
            exposure * 0.4 + business * 0.3 + reachability["score"] * 0.2 + runtime_strength * 0.1,
            2,
        )
        actionability_score = round(_decision_score(decision) * 0.65 + patch * 0.2 + runtime_strength * 0.15, 2)
        context_multiplier = 0.65 + environment_score / 200.0
        action_multiplier = 0.9 + actionability_score / 1000.0
        baseline_score = round(min(100.0, static_score * context_multiplier * action_multiplier), 2)
        source_fingerprint = intelligence_fingerprint(db, match.cve_id)
        facts_payload = _candidate_facts(match, asset, runtime, source_fingerprint)
        fingerprint = _facts_hash(facts_payload)
        facts_json = json.dumps(facts_payload, ensure_ascii=False, sort_keys=True, default=str)
        risk_factors = {
            "ubuntu_applicability": {
                "source": "canonical" if canonical else "nvd_fallback",
                "status": canonical.get("status", affected_status) if canonical else affected_status,
                "priority": ubuntu_priority,
                "package": match.package_name,
                "release": canonical.get("release", release) if canonical else release,
            },
            "technical_severity": {
                "source": "nvd" if nvd else vuln.source,
                "cvss_score": raw_cvss,
                "cvss_vector": nvd_cvss.get("vector", ""),
                "severity": technical_severity,
            },
            "exploit_likelihood": {
                "source": "epss",
                "probability": epss_probability,
                "percentile": epss_source.get("percentile", 0),
                "level": likelihood_level,
            },
            "known_exploitation": {
                "source": "cisa_kev",
                "is_kev": known_exploited,
                "date_added": cisa.get("date_added", ""),
                "due_date": cisa.get("due_date", ""),
            },
            "environment": {
                "exposure": asset.exposure_level,
                "runtime_status": runtime_status,
                "reachable_status": reachable_status,
            },
            "source_timestamps": {
                name: data.get("source_updated_at") or data.get("fetched_at")
                for name, data in source_bundle.items()
            },
        }

        values = {
            "asset_id": asset.id,
            "cve_id": match.cve_id,
            "package_name": match.package_name,
            "candidate_fingerprint": fingerprint,
            "candidate_facts_json": facts_json,
            "active": True,
            "cvss_score": cvss,
            "epss_score": epss,
            "kev_score": kev,
            "exposure_score": exposure,
            "business_score": business,
            "patch_score": patch,
            "static_score": static_score,
            "runtime_score": round(runtime_strength, 2),
            "environment_score": environment_score,
            "actionability_score": actionability_score,
            "reachability_score": reachability["score"],
            "path_count": reachability["path_count"],
            "exposed_service_count": reachability["exposed_service_count"],
            "affected_status": affected_status,
            "reachable_status": reachable_status,
            "runtime_status": runtime_status,
            "exploitability_status": exploitability_status,
            # Candidate confidence is contextual input only; final decision
            # confidence is written after coordinator + backend audit policy.
            "decision_confidence": 0,
            "reachability_reason": reachability["reason"],
            "decision_reason": "候选基线：待固定智能体流水线与后端审计策略确认",
            "preliminary_score": baseline_score,
            "preliminary_level": risk_level(baseline_score),
            "preliminary_decision": decision,
            "preliminary_reason": f"{decision_reason} {runtime['conclusion']}".strip(),
            "reason": _build_reason(
                affected_status, reachable_status, runtime_status, exploitability_status,
                "monitor", bool(match.fixed_version)
            ),
            "applicability_source": "canonical" if canonical else "nvd_fallback",
            "ubuntu_priority": ubuntu_priority,
            "technical_severity": technical_severity,
            "likelihood_level": likelihood_level,
            "known_exploited": known_exploited,
            "risk_factors_json": json.dumps(risk_factors, ensure_ascii=False, sort_keys=True),
        }

        risk = db.query(models.RiskAssessment).filter_by(match_id=match.id).one_or_none()
        if risk is None:
            risk = models.RiskAssessment(
                match_id=match.id,
                review_status="candidate",
                human_review_required=False,
                final_score=None,
                risk_level=None,
                decision=None,
                **values,
            )
            db.add(risk)
        else:
            from app.services.review_common.governance import correction
            if correction(db, risk):
                # A contradicted historical match is permanently ineligible.
                # New applicability requires a new evidence-backed risk object.
                continue
            # 事实比对：新算法行直接比较事实载荷；旧算法行（无载荷）先按
            # 行上留存的事实字段做一次迁移比对，仍一致则仅重建基线、不
            # 失效结论——旧哈希混入采集时间戳与事件 ID，其失配不能归因于
            # 事实变化，按其重置即「无事实变化也强制重跑全部角色」。
            legacy_row = not (risk.candidate_facts_json or "").strip()
            if legacy_row:
                changed = _legacy_facts_changed(risk, values) or not risk.active
            else:
                changed = risk.candidate_facts_json != facts_json or not risk.active
            for name, value in values.items():
                setattr(risk, name, value)
            if changed:
                from app.services.review_common.governance import record, snapshot, invalidate_prior_authorizations
                if risk.review_status == QUARANTINED_MAPPING_STATUS:
                    # 隔离状态是“包名来源无法精确复核”的治理结论，不因运行时
                    # 证据变化被重置回可研判状态；保留隔离直至人工重新映射。
                    record(db, risk, "quarantine_preserved_on_fact_change", "risk_engine", {
                        "original": snapshot(risk),
                        "reason": "candidate_facts_changed_but_mapping_quarantine_preserved"})
                else:
                    record(db, risk, "risk_reanalysis_reset", "risk_engine", {
                        "original": snapshot(risk), "reason": "candidate_facts_changed",
                        "facts": facts_payload,
                        "original_direction_semantics": "legacy_or_previous_contract"})
                    invalidate_prior_authorizations(db, risk, "candidate_facts_changed")
                    _reset_for_reanalysis(risk, "候选关键证据发生变化，需重新研判。")
                    _block_open_remediation_tasks(db, risk, "候选关键证据发生变化。")
            elif legacy_row and risk.candidate_fingerprint:
                from app.services.review_common.governance import record
                record(db, risk, "candidate_facts_rebaseline", "risk_engine", {
                    "reason": "legacy_fingerprint_migrated_to_fact_payload",
                    "row_facts_unchanged": True,
                    "facts": facts_payload,
                    "inventory_sha256": asset.inventory_sha256 or "",
                    "inventory_collected_at": str(asset.inventory_collected_at or "")})
            elif risk.review_status not in {"candidate", "reanalysis_required"}:
                # 事实未变且存在当期结论：保留结论，但记录本次核对的清单与
                # 情报基线，保证“结论基于哪份证据”可追溯（来源追溯）。
                from app.services.review_common.governance import record
                record(db, risk, "candidate_facts_unchanged", "risk_engine", {
                    "reason": "candidate_facts_identical",
                    "facts": facts_payload,
                    "inventory_sha256": asset.inventory_sha256 or "",
                    "inventory_collected_at": str(asset.inventory_collected_at or "")})
        processed += 1

    # Historical risks are retained. They become inactive/resolved when their
    # exact match is no longer in the affected set.
    risk_query = db.query(models.RiskAssessment).filter(models.RiskAssessment.active.is_(True))
    if asset_id:
        risk_query = risk_query.filter(models.RiskAssessment.asset_id == asset_id)
    for risk in risk_query.all():
        if target_cves and base_cve_id(risk.cve_id) not in target_cves:
            continue
        if risk.match_id in current_match_ids:
            continue
        asset = db.get(models.LinuxAsset, risk.asset_id)
        if asset and asset.distribution == "openwrt":
            # Inventory-only changes cannot bypass the Harness regression and
            # business checks. Successful Harness verification closes the risk.
            risk.review_status = "verification"
            risk.human_review_required = True
            risk.review_reason = "软件匹配已变化；仍需设备任务完成漏洞回归与业务验证，不能仅凭版本变化关闭风险。"
            _block_open_remediation_tasks(db, risk, "等待设备任务独立验证。")
            continue
        risk.active = False
        risk.review_status = "resolved" if risk.review_status in {"auto_confirmed", "human_confirmed", "remediation_ready", "verification"} else "inactive"
        risk.review_reason = "本轮精确匹配不再命中；历史风险保留。"
        _block_open_remediation_tasks(db, risk, "候选事件已不再命中。")

    db.commit()
    _recompute_rank_in_engine(db, asset_id=asset_id)
    return processed
