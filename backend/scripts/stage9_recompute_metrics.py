"""Stage 9B 后处理：用离线重建的证据包修正评价指标（不调用 LLM）。

修正两处实验 Harness 检查器的伪报来源：
1. 证据包按 case 键去重碰撞 → 改按 object_id(risk-N) 精确匹配；
2. packet 未按 "evidence_packet" 包裹导致 exposure/impact 检查落空 → 正确传参。

产出：reports/stage9-agent-audit/corrected_metrics.json
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

AGG = BACKEND_DIR / "reports" / "stage9-agent-audit" / "aggregate.json"

# Fixture 真值相关的"承重证据"类别（引用准确性评测口径）
LOAD_BEARING = {"package_version", "vulnerability_advisory", "vulnerability_intelligence_source",
                "network_exposure", "runtime_event", "security_evidence", "vendor_applicability"}


def rebuild_packets(with_runtime: bool) -> dict[int, dict]:
    """重建 Fixture 并按 risk_id 捕获证据包与规则基线（确定性，无 LLM）。"""
    tmp = tempfile.mkdtemp(prefix="stage9-repack-")
    os.environ["LINUXGUARD_DATA_DIR"] = tmp
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models  # noqa: F401
    from app.database import Base
    from app.services.event_review_pipeline import build_evidence_packet
    from stage9_agent_effectiveness_audit import build_fixture

    engine = create_engine(f"sqlite:///{tmp}/repack.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    build_fixture(db, with_runtime=with_runtime)
    packets = {}
    for risk in db.query(models.RiskAssessment).all():
        packets[risk.id] = {
            "packet": build_evidence_packet(db, risk).model_dump(),
            "case": risk.cve_id.split(":")[0],
            "preliminary": risk.preliminary_score,
            "preliminary_level": risk.preliminary_level,
            "preliminary_decision": risk.preliminary_decision,
        }
    db.close()
    engine.dispose()
    return packets


def event_risk_id(event: dict) -> int | None:
    for name in ("impact_assessment_agent", "evidence_audit_agent",
                 "exposure_runtime_agent", "decision_coordinator_agent"):
        result = (event.get("agent_results") or {}).get(name) or {}
        object_id = str(result.get("object_id") or "")
        if object_id.startswith("risk-"):
            try:
                return int(object_id.removeprefix("risk-"))
            except ValueError:
                continue
    return None


def corrected_checks(event: dict, packet: dict) -> dict:
    """对照该事件真实证据包的确定性矛盾检查 + 引用指标。"""
    problems: list[str] = []
    packet_ids = {item.get("evidence_id") for item in packet.get("evidence_items") or []}

    has_runtime_events = any(item.get("evidence_type") == "runtime_event"
                             for item in packet.get("runtime_evidence") or [])
    services = (packet.get("service_context") or {}).get("services") or []
    public_listener = any(s.get("public") for s in services)
    match = packet.get("package_match") or {}

    runtime_result = event.get("agent_results", {}).get("exposure_runtime_agent") or {}
    if runtime_result.get("runtime_status") == "verified" and not has_runtime_events:
        problems.append("runtime_status=verified 但证据包无 runtime_event 条目")
    if runtime_result.get("exposure_status") == "internet_reachable" and not public_listener:
        problems.append("exposure_status=internet_reachable 但资产无公网监听服务")
    if runtime_result.get("exposure_status") == "unreachable" and public_listener:
        problems.append("exposure_status=unreachable 但资产存在公网监听服务")

    impact = event.get("agent_results", {}).get("impact_assessment_agent") or {}
    if impact.get("impact_status") == "confirmed_affected":
        if match.get("match_status") in {"not_affected", "fixed"}:
            problems.append("impact=confirmed_affected 但确定性匹配为不受影响")
        if not match.get("installed_version"):
            problems.append("impact=confirmed_affected 但缺装机版本")

    cited: set[str] = set()
    cited_total = 0
    load_bearing_cited = 0
    per_agent_citations = {}
    types_by_id = {item.get("evidence_id"): item.get("evidence_type")
                   for item in packet.get("evidence_items") or []}
    for name, result in (event.get("agent_results") or {}).items():
        if not isinstance(result, dict):
            continue
        ids = set()
        for field in ("valid_evidence_ids", "conflicting_evidence_ids",
                      "supporting_evidence_ids", "counter_evidence_ids"):
            ids.update(result.get(field) or [])
        cited.update(ids)
        per_agent_citations[name] = {
            "cited": sorted(ids),
            "unknown_ids": sorted(ids - packet_ids),
        }
    cited_total = len(cited)
    load_bearing_cited = sum(1 for eid in cited if types_by_id.get(eid) in LOAD_BEARING)
    return {
        "problems": problems,
        "cited_total": cited_total,
        "cited_load_bearing": load_bearing_cited,
        "unknown_cited": sorted(cited - packet_ids),
        "packet_evidence_total": len(packet_ids),
        "per_agent_citations": per_agent_citations,
    }


def main():
    data = json.loads(AGG.read_text(encoding="utf-8"))
    packets_c = rebuild_packets(with_runtime=True)
    packets_b = rebuild_packets(with_runtime=False)

    corrected = {"note": "按 object_id(risk-N) 对齐证据包后的修正指标", "runs": {}}
    for run_key, packets in (("C", packets_c), ("B", packets_b)):
        rows = []
        totals = {"problems": 0, "unknown_cited": 0, "events": 0,
                  "cited_total": 0, "cited_load_bearing": 0}
        for event in (data.get(run_key) or {}).get("events", []):
            risk_id = event_risk_id(event)
            meta = packets.get(risk_id) if risk_id is not None else None
            if meta is None:
                rows.append({"case": event.get("case"), "risk_id": risk_id,
                             "error": "packet_not_matched"})
                continue
            checks = corrected_checks(event, meta["packet"])
            totals["problems"] += len(checks["problems"])
            totals["unknown_cited"] += len(checks["unknown_cited"])
            totals["cited_total"] += checks["cited_total"]
            totals["cited_load_bearing"] += checks["cited_load_bearing"]
            totals["events"] += 1
            rows.append({
                "case": event.get("case"), "risk_id": risk_id,
                "preliminary_score": meta["preliminary"],
                "preliminary_decision": meta["preliminary_decision"],
                **checks,
            })
        corrected["runs"][run_key] = {"totals": totals, "events": rows}

    # 规则基线 vs 智能体结论对照（误匹配候选 E3 的假阳性对照）
    baseline = data.get("A_baseline_with_runtime", {})
    corrected["rules_baseline"] = baseline

    out = AGG.parent / "corrected_metrics.json"
    out.write_text(json.dumps(corrected, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({key: value.get("totals") for key, value in corrected["runs"].items()},
                     ensure_ascii=False, indent=1))
    print("written:", out)


if __name__ == "__main__":
    main()
