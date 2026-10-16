"""Resolve real output citations and append pending comparison-review audit records.

Does not certify human review, change formal fields, authorize or execute repairs.
"""
from __future__ import annotations

import hashlib
import copy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app import config, models
from app.database import SessionLocal
from app.services import trace_service as tracing
from app.services.unified import investigation as I
from m46_production_readiness import formal_snapshot

OUT = ROOT / "reports/m46-work"


def refs(value):
    found = set()
    if isinstance(value, dict):
        for key, entry in value.items():
            if key in {"supporting_evidence_ids", "evidence_ids"} and isinstance(entry, list):
                found.update(str(v) for v in entry)
            elif key == "evidence_id" and entry:
                found.add(str(entry))
            else:
                found.update(refs(entry))
    elif isinstance(value, list):
        for entry in value:
            found.update(refs(entry))
    return found


def main():
    assert config.UNIFIED_PIPELINE_MODE == "off"
    assert os.getenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0") == "0"
    assert os.getenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0") == "0"
    reports = {name: json.loads((OUT / (name + ".json")).read_text(encoding="utf-8"))
               for name in ("curl", "openssl", "openwrt", "reanalysis")}
    with SessionLocal() as db:
        before = formal_snapshot(db)
        checked = []
        for name, report in reports.items():
            row = db.query(models.UnifiedAnalysisRun).filter_by(run_id=report["run_id"]).one()
            assert row.status == "completed" and row.mode == "shadow"
            agents = json.loads(row.agents_json)
            assert all(agents[role]["status"] == "succeeded" for role in I.ALL_AGENT_IDS)
            state = json.loads(row.state_json)
            cited = set()
            for key in ("investigation", "vulnerability", "runtime", "decision"):
                cited.update(refs(state.get(key)))
            evidence = []
            for ref in sorted(cited):
                if ref.startswith("SE-"):
                    record = db.query(models.SecurityEvidence).filter_by(evidence_id=ref).one_or_none()
                    assert record is not None, ref
                elif ref.startswith(("INV-", "PRE-")):
                    record = db.query(models.CollectionEvidence).filter_by(evidence_id=ref).one_or_none()
                    assert record and hashlib.sha256(record.raw_text.encode()).hexdigest() == record.content_sha256, ref
                elif ref.startswith("ADV-"):
                    record = db.query(models.OfficialCveRecord).filter_by(evidence_id=ref, evidence_status="available").one_or_none()
                    assert record and hashlib.sha256(record.raw_json.encode()).hexdigest() == record.content_sha256, ref
                else:
                    raise AssertionError("unhandled_citation:" + ref)
                evidence.append(ref)
            # Appended validation references make all original citations navigable,
            # including historical M4.6 runs made before nested Trace refs were fixed.
            tracing.emit(db, row.trace_id, "delivery_evidence_validation", actor="deterministic_validator", status="succeeded",
                payload={"run_id": row.run_id, "evidence_count": len(evidence), "human_review_completed": False}, evidence_refs=evidence)
            resolved = tracing.evidence_for_trace(db, row.trace_id)
            assert all(e["resolved"] for e in resolved["evidence"])
            checked.append({"case": name, "run_id": row.run_id, "trace_id": row.trace_id,
                "evidence_count": len(evidence), "evidence_ids": evidence, "agents": {k: v["status"] for k, v in agents.items()}})
        old = json.loads((OUT / "system-b.json").read_text(encoding="utf-8"))
        link = db.query(models.InvestigationRequest).filter_by(reanalysis_run_id=reports["reanalysis"]["run_id"]).one()
        outcome = json.loads(link.result_json)
        assert outcome["substantive_update"] is False
        for contribution in outcome["agents"].values():
            capped = copy.deepcopy(contribution["after"])
            I.clamp_confidence(contribution["before"], capped)
            assert capped == contribution["after"], "confidence_increased_without_new_facts"
        old_checks = {}
        for rid in ("126", "12"):
            output = old[rid]["outcome"]
            known = {v["evidence_id"] for v in old[rid]["packet"]["evidence_items"]}
            cited = refs(output.get("results")) | refs(output.get("coordinator"))
            assert cited <= known, cited - known
            old_checks[rid] = {"resolved": True, "packet_ids": sorted(known), "cited_ids": sorted(cited)}
        review = {"status": "pending_human_review", "human_reviewer": None, "human_review_completed": False,
            "findings": ["System B risk126 将 upgrade_minor 解释为软件升级方向；统一链保持证据风险方向，两者不能自动视为同义或以旧链作真值。",
                "历史 risk12 的上游跨分支 Critical 基线与 Canonical noble openssl not-affected 不符；已失活，严禁复活该修复建议。",
                "OpenWrt 零候选不等于全局无漏洞；运行时覆盖/公告覆盖缺口继续保留。"],
            "evidence_ids": sorted({ref for row in checked for ref in row["evidence_ids"] if ref.startswith("ADV-")})}
        for name in ("curl", "openssl"):
            tracing.emit(db, reports[name]["trace_id"], "comparison_review_required", actor="deterministic_validator",
                status="pending_human_review", payload=review, evidence_refs=review["evidence_ids"])
        assert before == formal_snapshot(db)
        result = {"runs": checked, "system_b_citations": old_checks, "manual_review_record": review,
            "formal_unchanged": True, "formal_hash": before, "flag": "off", "repair_switches": ["0", "0"]}
        (OUT / "delivery-validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"runs": len(checked), "resolved_citations": sum(r["evidence_count"] for r in checked), "formal_unchanged": True}))


if __name__ == "__main__": main()
