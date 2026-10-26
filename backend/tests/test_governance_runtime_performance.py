import json
from types import SimpleNamespace

from app import models
from app.routers.risk import ranking
from app.services.review_common import governance


def seed(db):
    asset = models.LinuxAsset(hostname="audit-device")
    db.add(asset)
    db.flush()
    risk = models.RiskAssessment(asset_id=asset.id, cve_id="CVE-2099-1000", active=True)
    db.add(risk)
    db.commit()
    return risk


def test_ranking_uses_audit_metadata_without_parsing_or_returning_history(session_factory):
    with session_factory() as db:
        risk = seed(db)
        # A malformed historical body must not break the metadata projection.
        event = models.RiskGovernanceEvent(risk_id=risk.id, kind="native_assessment", actor="test", contract_version=governance.CONTRACT,
                                          payload_json="not JSON " + "x" * 1000000)
        db.add(event)
        db.commit()
        db.expunge_all()
        result = ranking(asset_id=0, include_details=False, db=db)
        assert len(result) == 1
        assert not result[0]["details_included"]
        assert "evidence_packet" not in result[0]
        explanation = result[0]["governance"]
        assert not explanation["event_payloads_included"]
        assert explanation["events"][0]["payload_available"]
        assert "payload" not in explanation["events"][0]
        assert len(json.dumps(result, default=str)) < 10000


def test_assessment_uses_immutable_run_snapshot_not_live_history(session_factory, monkeypatch):
    monkeypatch.setattr("app.services.unified.investigation.evidence_view",
                        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must use run snapshot")))
    with session_factory() as db:
        risk = seed(db)
        state = SimpleNamespace(
            evidence_snapshot={"snapshot_id": "ES-frozen", "content_sha256": "frozen",
                               "categories_hashes": {"runtime": "original"},
                               "evidence_registry": {"SE-old": {"kind": "runtime"}}},
            evidence_prep={}, baseline={}, vulnerability={}, runtime={}, runtime_program_fallback={})
        first = json.loads(governance.assessment_record(db, risk, SimpleNamespace(run_id="UA-first"), state).payload_json)
        db.add(models.SecurityEvidence(evidence_id="SE-new", evidence_hash="new", asset_id=risk.asset_id,
                                       description="unrelated event after model started"))
        db.commit()
        second = json.loads(governance.assessment_record(db, risk, SimpleNamespace(run_id="UA-second"), state).payload_json)
        assert first["facts_hash"] == second["facts_hash"]
        assert second["facts_schema"] == "m5-facts-v3"
        assert second["evidence_receipt"]["snapshot_id"] == "ES-frozen"
        assert len(json.dumps(second)) < 15000
        state.evidence_snapshot["categories_hashes"]["runtime"] = "changed"
        third = json.loads(governance.assessment_record(db, risk, SimpleNamespace(run_id="UA-third"), state).payload_json)
        assert third["facts_hash"] != second["facts_hash"]
