"""M4.4 专项：真实 CVE 适用性纠正与产品内采集节点委托。

全部使用合成 fixture 与 mocked SSH/HTTP；不代表任何真实连接或真实设备数据。
"""
import hashlib
import json
from types import SimpleNamespace

import pytest

from app import models
from app.services import device_access
from app.services.canonical_official import (
    OfficialRecordUnavailable,
    import_official_records,
    official_record_url,
    record_statuses,
)
from app.services.matching_engine import run_matching, UNVERIFIED_UPSTREAM_REASON
from app.services.risk_engine import calculate_risk


# ── P0：跨发行分支上游版本误匹配的诚实标注与官方记录纠正 ─────────────────────


def _seed_noble(db, cve_id="CVE-2026-63073", installed="3.0.13-0ubuntu3.16", fixed="3.4.7"):
    asset = models.LinuxAsset(hostname="noble-host", distribution="ubuntu", os_name="Ubuntu",
                              os_version="24.04", exposure_level="internal", business_level="important")
    db.add(asset)
    db.flush()
    db.add(models.AssetPackage(asset_id=asset.id, package_name="openssl", package_version=installed))
    db.add(models.VulnerabilityInfo(cve_id=cve_id, title="upstream", affected_package="openssl",
                                    fixed_version=fixed, source="NVD CVE API"))
    db.commit()
    return asset


def _official_record(cve_id="CVE-2026-63073", noble_status="not-affected", noble_note="3.4+ only"):
    return {
        "id": cve_id, "priority": "low", "cvss3": 9.8, "notices_ids": ["USN-8678-1"],
        "updated_at": "2026-09-02T00:00:00Z",
        "packages": [{"name": "openssl", "statuses": [
            {"release_codename": "noble", "status": noble_status, "description": noble_note},
            {"release_codename": "resolute", "status": "released", "description": "3.5.5-1ubuntu3.4"},
        ]}],
    }


def test_cross_branch_upstream_match_is_annotated_unverified(session_factory):
    db = session_factory()
    try:
        asset = _seed_noble(db)
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).one()
        assert match.match_status == "potentially_affected"
        assert match.reason_code == UNVERIFIED_UPSTREAM_REASON
        assert match.confidence == pytest.approx(0.55)
        assert "回移植" in match.match_reason and "Canonical" in match.match_reason
    finally:
        db.close()


def test_official_not_affected_record_corrects_cross_branch_match(session_factory, monkeypatch):
    db = session_factory()
    try:
        asset = _seed_noble(db)
        run_matching(db)
        calculate_risk(db)
        old_match = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).one()
        old_risk = db.query(models.RiskAssessment).filter_by(match_id=old_match.id).one()

        record = _official_record()
        monkeypatch.setattr("app.services.canonical_official.fetch_official_record", lambda cve: record)
        results = import_official_records(db, ["CVE-2026-63073"])
        db.commit()
        outcome = results["CVE-2026-63073"]
        assert outcome["evidence_status"] == "imported"
        assert outcome["url"].endswith("/CVE-2026-63073.json")
        assert outcome["content_sha256"]
        noble_entries = [e for e in outcome["entries"] if e["release"] == "noble"]
        assert noble_entries and noble_entries[0]["raw_status"] == "not-affected" and noble_entries[0]["stored"]

        run_matching(db)
        calculate_risk(db)
        rows = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).all()
        by_cve = {row.cve_id: row for row in rows}
        # 历史 potentially_affected 行保留（审计），不再活跃
        assert old_match.cve_id in by_cve
        assert by_cve[old_match.cve_id].active is False
        assert by_cve[old_match.cve_id].reason_code == "not_seen_in_latest_recalculation"
        scoped = by_cve["CVE-2026-63073:noble:openssl"]
        assert scoped.active is True
        assert scoped.match_status == "not_affected"
        assert scoped.reason_code == "canonical_not_affected"
        assert scoped.affected is False
        db.refresh(old_risk)
        assert old_risk.active is False
        assert "不再命中" in old_risk.review_reason
        # canonical 记录可通过产品内查询取回（溯源）
        from app.services.vulnerability_intelligence.service import canonical_applicability
        applicability = canonical_applicability(db, "CVE-2026-63073", "noble", "openssl")
        assert applicability and applicability["status"] == "not_affected"
        assert applicability["canonical_status"] == "not-affected"
    finally:
        db.close()


def test_official_needed_status_stays_affected_until_fixed(session_factory, monkeypatch):
    db = session_factory()
    try:
        asset = _seed_noble(db, cve_id="CVE-2026-9999")
        monkeypatch.setattr("app.services.canonical_official.fetch_official_record",
                            lambda cve: _official_record(cve_id="CVE-2026-9999", noble_status="needs-triage", noble_note=""))
        # noble 状态 needs-triage 属于受影响未修复 → 存储为 under_investigation 而非凭空排除
        results = import_official_records(db, ["CVE-2026-9999"])
        db.commit()
        assert results["CVE-2026-9999"]["evidence_status"] == "imported"
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).one()
        assert match.cve_id == "CVE-2026-9999:noble:openssl"
        assert match.match_status == "under_investigation"
        assert match.affected is True
    finally:
        db.close()


def test_official_fetch_failure_is_recorded_not_papered_over(session_factory, monkeypatch):
    db = session_factory()
    try:
        _seed_noble(db, cve_id="CVE-2026-9111")

        def unavailable(cve):
            raise OfficialRecordUnavailable(cve, "network_error", "synthetic outage")
        monkeypatch.setattr("app.services.canonical_official.fetch_official_record", unavailable)
        results = import_official_records(db, ["CVE-2026-9111"])
        assert results["CVE-2026-9111"]["evidence_status"] == "network_error"
        assert "synthetic outage" in results["CVE-2026-9111"]["error"]
        # 官方记录缺失 → 不产生任何 canonical 行（不虚构已核实事实）
        assert db.query(models.VulnerabilityIntelligenceSource).filter_by(source="canonical").count() == 0
    finally:
        db.close()


def test_official_url_and_status_flattening_validation():
    with pytest.raises(ValueError):
        official_record_url("not-a-cve")
    assert official_record_url("CVE-2026-63073") == "https://ubuntu.com/security/cves/CVE-2026-63073.json"
    entries = record_statuses("CVE-2026-63073", _official_record())
    assert {e["release"] for e in entries} == {"noble", "resolute"}
    resolute = [e for e in entries if e["release"] == "resolute"][0]
    assert resolute["fixed_version"] == "3.5.5-1ubuntu3.4"
    # 未跟踪发行版（如 esm）被过滤
    record = _official_record()
    record["packages"][0]["statuses"].append({"release_codename": "esm-apps", "status": "needed"})
    assert {e["release"] for e in record_statuses("CVE-2026-63073", record)} == {"noble", "resolute"}


# ── P1：产品内采集节点委托（pull 协议；Windows 拒绝本地执行、可转交）──────────


@pytest.fixture
def node_rig(client, session_factory, control_headers, monkeypatch, tmp_path):
    """合成 OpenWrt 资产 + 连接；不加载任何真实私钥。"""
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.168.50.1/32")
    monkeypatch.setattr(device_access, "collector_node",
                        lambda: {"id": "backend-dev", "platform": "Windows", "mode": "standard"})
    placeholder = tmp_path / "NOT_A_PRIVATE_KEY.fixture"
    placeholder.write_text("SYNTHETIC PLACEHOLDER ONLY", encoding="utf-8")
    monkeypatch.setenv("LINUXGUARD_DEVICE_SYNTHETIC_KEY", str(placeholder))
    packages = []
    for index in range(3):
        name = "synthetic-pkg-%03d" % index
        version = "1.0.0-r%d" % index
        raw = name + "-" + version + " x86_64 {fixture/src} (MIT) [installed]"
        packages.append({"name": name, "version": version, "architecture": "x86_64",
                         "source": "fixture/src", "license": "MIT", "status": "installed", "raw": raw})
    document = {"schema_version": "1.0", "asset_id": "SYNTHETIC-M44-001", "asset_type": "synthetic_router",
                "collection_method": "offline", "generated_at": "2026-01-01T00:00:00Z",
                "device": {"hostname": "synthetic-openwrt", "model": "SYNTHETIC ONLY", "board_name": "synthetic-board",
                           "kernel": "6.12.94", "firmware": {"distribution": "OpenWrt", "version": "25.12.5", "target": "x86/64"}},
                "software_inventory": {"source": "apk list --installed", "raw_count": 3, "package_count": 3,
                                       "parse_error_count": 0, "packages": packages}}
    asset = client.post("/api/assets/upload", files={"file": ("synthetic.json", json.dumps(document).encode())},
                        headers=control_headers).json()["asset"]
    connection_id = client.post("/api/iot/connections", json={
        "asset_id": asset["id"], "host": "192.168.50.1", "auth_type": "ssh_key",
        "key_path_env": "LINUXGUARD_DEVICE_SYNTHETIC_KEY", "host_key_sha256": "SHA256:" + "A" * 43},
        headers=control_headers).json()["id"]
    return SimpleNamespace(client=client, factory=session_factory, asset=asset, connection_id=connection_id,
                           headers=control_headers, document=document)


def _collector_output(document):
    board = {"board_name": document["device"]["board_name"], "model": "SYNTHETIC ONLY", "kernel": "6.12.94",
             "release": {"version": "25.12.5", "target": "x86/64"}}
    packages = document["software_inventory"]["packages"]
    return ("===== META =====\nhostname: synthetic-openwrt\narchitecture: x86_64\nmac_address: 02:00:00:00:00:41\n"
            "===== OS_RELEASE =====\nID=openwrt\nNAME=OpenWrt\nVERSION_ID=25.12.5\n"
            "===== KERNEL =====\n6.12.94\n===== SYSTEM_BOARD =====\n" + json.dumps(board) +
            "\n===== APK_PACKAGES =====\n" + "\n".join(p["name"] + " " + p["version"] for p in packages) +
            "\n===== APK_PACKAGE_DETAILS =====\n" + "\n".join(p["raw"] for p in packages) +
            "\n===== INVENTORY_STATUS =====\npackages_complete: true\npackage_count: 3\n"
            "===== OPEN_PORTS =====\nfixture-ssh|22|tcp|0.0.0.0|fixture-ssh\n"
            "===== DHCP_LEASES =====\n")


def _create_run(rig, request_id):
    path = "/api/iot/connections/" + str(rig.connection_id) + "/collection-runs"
    response = rig.client.post(path, json={"request_id": request_id}, headers=rig.headers)
    assert response.status_code == 200, response.text
    return response.json()


def _execute_run(rig, run):
    path = "/api/iot/collection-runs/" + run["id"] + "/execute"
    response = rig.client.post(path, headers=rig.headers)
    assert response.status_code == 200, response.text
    return response.json()


def _asset(rig):
    return rig.client.get("/api/assets/" + str(rig.asset["id"]), headers=rig.headers).json()


def _result_payload(status, assignment, output=None, fingerprint_verified=True, collector=None):
    payload = {"node_id": "ubuntu-lab-node", "node_platform": "Linux", "status": status,
               "host_fingerprint_verified": fingerprint_verified,
               "ssh_authentication": "succeeded" if fingerprint_verified else "unknown"}
    if status == "failed":
        payload.update({"error_code": collector or "host_key_mismatch", "detail": "synthetic failure"})
        return payload
    payload.update({"collector_sha256": collector or assignment["collector_sha256"],
                    "inventory_text": output,
                    "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                    "output_bytes": len(output.encode())})
    return payload


def _submit(db, run_id, payload):
    from fastapi import HTTPException
    from app.routers.iot import collection_node_result
    try:
        return collection_node_result(run_id, SimpleNamespace(model_dump=lambda: payload), db)
    except HTTPException as exc:
        raise ValueError(str(exc.detail)) from exc


def _claim(db, node_id="ubuntu-lab-node", platform="Linux"):
    from fastapi import HTTPException
    from app.routers.iot import collection_node_claim
    try:
        return collection_node_claim(node_id, platform, db)["assignment"]
    except HTTPException as exc:
        raise ValueError(str(exc.detail)) from exc


def test_windows_without_remote_node_still_refused(node_rig):
    outcome = _execute_run(node_rig, _create_run(node_rig, "no-remote-refusal"))
    assert outcome["status"] == "failed"
    assert outcome["result"]["error_code"] == "node_platform_invalid"
    with node_rig.factory() as db:
        assert db.query(models.AssetPackage).count() == 3   # 旧清单未被触碰
        assert db.query(models.HarnessAssetLock).count() == 0


def test_windows_with_remote_node_queues_and_node_claims_and_reports(node_rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "ubuntu-lab-node")
    preflight_path = "/api/iot/connections/" + str(node_rig.connection_id) + "/preflight"
    preflight = node_rig.client.get(preflight_path, headers=node_rig.headers).json()
    assert preflight["checks"]["node_platform"] is False
    assert preflight["checks"]["remote_node_configured"] is True
    assert preflight["ready"] is True   # 远程节点登记后具备采集能力

    run = _create_run(node_rig, "remote-delegate")
    outcome = _execute_run(node_rig, run)
    assert outcome["status"] == "queued_remote"
    assert outcome["result"]["asset_collection"] == "queued_remote"
    assert outcome["result"]["queued_for_node"] == "ubuntu-lab-node"
    with node_rig.factory() as db:
        assert db.get(models.LinuxAsset, node_rig.asset["id"]).identity_source != "pinned_ssh_inventory"

    # 节点领取：身份不一致被拒；平台非 Linux 被拒；一致则原子领取
    with pytest.raises(ValueError):
        _claim(node_rig.factory(), node_id="wrong-node")
    with pytest.raises(ValueError):
        _claim(node_rig.factory(), platform="Windows")
    assignment = _claim(node_rig.factory())
    assert assignment and assignment["run_id"] == outcome["id"]
    connection = assignment["connection"]
    assert connection["host"] == "192.168.50.1"
    assert connection["key_path_env"] == "LINUXGUARD_DEVICE_SYNTHETIC_KEY"
    assert connection["host_key_sha256"].startswith("SHA256:")
    assert "PRIVATE KEY" not in json.dumps(assignment)
    assert assignment["authorized_cidrs"] == ["192.168.50.1/32"]
    script_hash = hashlib.sha256(assignment["collector_script"].encode()).hexdigest()
    assert script_hash == assignment["collector_sha256"]
    assert _claim(node_rig.factory()) is None   # 无第二个任务可领取

    # 结果回传：成功路径走与本地采集相同的入库与身份核验
    output = _collector_output(node_rig.document)
    done = _submit(node_rig.factory(), outcome["id"], _result_payload("succeeded", assignment, output))
    assert done["status"] == "completed", done["error"]
    assert done["result"]["asset_collection"] == "succeeded"
    assert done["result"]["execution_node"] == "ubuntu-lab-node"
    assert done["result"]["ssh_host_identity"] == "verified"
    asset = _asset(node_rig)
    assert asset["identity_source"] == "pinned_ssh_inventory"
    assert len(asset["packages"]) == 3
    with node_rig.factory() as db:
        assert db.query(models.HarnessAssetLock).count() == 0
    # 幂等：重复回传不重复入库
    again = _submit(node_rig.factory(), outcome["id"], _result_payload("succeeded", assignment, output))
    assert again["status"] == "completed"
    with node_rig.factory() as db:
        assert db.query(models.AssetPackage).count() == 3


def test_node_failure_and_unverified_attestation_never_touch_inventory(node_rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "ubuntu-lab-node")

    # 失败路径：指纹不一致 → 明确失败码入库，资产零变化
    run = _execute_run(node_rig, _create_run(node_rig, "remote-failure"))
    assert run["status"] == "queued_remote"
    _claim(node_rig.factory())
    failed = _submit(node_rig.factory(), run["id"],
                     _result_payload("failed", None, fingerprint_verified=False))
    assert failed["status"] == "failed"
    assert failed["result"]["error_code"] == "host_key_mismatch"
    assert failed["result"]["asset_collection"] == "failed"
    with node_rig.factory() as db:
        assert db.query(models.HarnessAssetLock).count() == 0
    original = _asset(node_rig)

    # 成功路径但未通过指纹核验 → 服务端拒绝入库
    run2 = _execute_run(node_rig, _create_run(node_rig, "remote-unverified"))
    assignment2 = _claim(node_rig.factory())
    output = _collector_output(node_rig.document)
    rejected = _submit(node_rig.factory(), run2["id"],
                       _result_payload("succeeded", assignment2, output, fingerprint_verified=False))
    assert rejected["status"] == "failed"
    assert rejected["result"]["error_code"] == "host_identity_not_attested"
    assert _asset(node_rig) == original

    # Collector 摘要不一致 → 拒绝
    run3 = _execute_run(node_rig, _create_run(node_rig, "remote-hash"))
    _claim(node_rig.factory())
    mismatch = _submit(node_rig.factory(), run3["id"],
                       _result_payload("succeeded", None, output, collector="f" * 64))
    assert mismatch["status"] == "failed"
    assert mismatch["result"]["error_code"] == "collector_changed"
    with node_rig.factory() as db:
        assert db.query(models.AssetPackage).count() == 3


def test_claim_requires_registered_node(node_rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "")
    with pytest.raises(ValueError):
        _claim(node_rig.factory())


def test_upstream_higher_version_does_not_prove_ubuntu_fixed(session_factory):
    with session_factory() as db:
        asset = _seed_noble(db, installed="9.0.0", fixed="3.4.7")
        run_matching(db)
        match = db.query(models.VulnerabilityMatch).filter_by(asset_id=asset.id).one()
        assert match.match_status == "unknown" and match.affected
        assert match.reason_code == UNVERIFIED_UPSTREAM_REASON


def test_scoped_cve_prep_uses_release_not_package_and_preserves_official_evidence(session_factory, monkeypatch):
    from app.services.unified.evidence_prep import build_evidence_prep_packet
    with session_factory() as db:
        asset = _seed_noble(db)
        monkeypatch.setattr("app.services.canonical_official.fetch_official_record", lambda c: _official_record())
        result = import_official_records(db, ["CVE-2026-63073"])
        db.commit()
        packet = build_evidence_prep_packet(db, asset.hostname, "linux_host", [{
            "cve_id": "CVE-2026-63073:noble:openssl", "package_name": "openssl",
            "installed_version": "3.0.13-0ubuntu3.16", "fixed_version": ""}])
        fact = packet.candidates[0]
        assert fact.vendor_patch["release_status"] == "not_affected"
        assert result["CVE-2026-63073"]["evidence_id"] in json.dumps(fact.source_bundle)
        raw = db.query(models.OfficialCveRecord).one()
        assert json.loads(raw.raw_json)["packages"] == _official_record()["packages"]


@pytest.mark.parametrize("field,value,code", [
    ("output_sha256", "0" * 64, "output_integrity_failed"),
    ("output_bytes", 1, "output_integrity_failed"),
    ("ssh_authentication", "unknown", "authentication_not_attested"),
])
def test_remote_result_integrity_is_required(node_rig, monkeypatch, field, value, code):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "ubuntu-lab-node")
    run = _execute_run(node_rig, _create_run(node_rig, "bad-" + field))
    assignment = _claim(node_rig.factory())
    payload = _result_payload("succeeded", assignment, _collector_output(node_rig.document))
    payload[field] = value
    done = _submit(node_rig.factory(), run["id"], payload)
    assert done["status"] == "failed" and done["result"]["error_code"] == code
    assert _asset(node_rig)["identity_source"] != "pinned_ssh_inventory"


def test_node_token_and_claim_binding_required(node_rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "ubuntu-lab-node")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_TOKEN", "synthetic-node-token")
    path = "/api/iot/collection-node/claim?node_id=ubuntu-lab-node&node_platform=Linux"
    assert node_rig.client.get(path, headers=node_rig.headers).status_code == 401
    assert node_rig.client.get(path, headers={"X-Collection-Node-Token": "synthetic-node-token"}).status_code == 200
    run = _execute_run(node_rig, _create_run(node_rig, "unclaimed-submit"))
    with pytest.raises(ValueError):
        _submit(node_rig.factory(), run["id"], _result_payload("failed", None))


def test_correction_keeps_historical_shadow_and_raw_record(session_factory, monkeypatch):
    from app.services.canonical_official import verify_and_correct
    with session_factory() as db:
        _seed_noble(db)
        run_matching(db)
        calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()
        historic = models.UnifiedAnalysisRun(run_id="synthetic-history", task_type="risk_review",
            target_ref="noble-host", target_type="linux_host", risk_id=risk.id, mode="shadow",
            decision_json='{"historical": true}')
        db.add(historic)
        db.commit()
        monkeypatch.setattr("app.services.canonical_official.fetch_official_record", lambda c: _official_record())
        result = verify_and_correct(db, ["CVE-2026-63073"])
        assert len(result["correction_ids"]) == 1
        correction = db.get(models.ApplicabilityCorrection, result["correction_ids"][0])
        assert json.loads(correction.after_json)["match_status"] == "not_affected"
        assert "synthetic-history" in correction.historical_run_ids_json
        assert historic.decision_json == '{"historical": true}'


def test_usn_exact_cve_release_package_fix_is_kept_with_original_status():
    record = _official_record(noble_status="needed", noble_note="")
    record["notices"] = [{"id": "USN-SYNTHETIC-1", "cves_ids": [record["id"]],
        "release_packages": {"noble": [{"is_source": True, "name": "openssl", "version": "3.0.13-0ubuntu3.99"}]}}]
    noble = next(r for r in record_statuses(record["id"], record) if r["release"] == "noble")
    assert noble["raw_status"] == "needed" and noble["effective_status"] == "released"
    assert noble["fixed_version"] == "3.0.13-0ubuntu3.99" and noble["status_note"]
    # A notice about another CVE or release cannot supply this branch's fix.
    record["notices"][0]["cves_ids"] = ["CVE-2099-0000"]
    noble = next(r for r in record_statuses(record["id"], record) if r["release"] == "noble")
    assert not noble["fixed_version"] and noble["effective_status"] == "needed"


def test_plan_guard_matches_source_binaries_and_separates_sensor_health():
    from app.services.unified.plan_guard import annotate_plan
    state = {"baseline": {"object_id": "risk-1"}, "evidence_prep": {
        "asset_facts": {"inventory_provenance": {"package_sources": ["libcurl4t64:amd64|curl|8.5.0"]}},
        "candidates": [{"package_name": "curl", "fixed_version": "8.5.0-2ubuntu10.16",
            "vendor_patch": {"release_status": "released"}, "version_compare": {"result": "affected"}}]}}
    plan = {"actions": [{"action": "update_package", "target": "libcurl4t64", "params": {"version": "8.5.0-2ubuntu10.16"}},
                        {"action": "restart_service", "target": "falco"}]}
    result = annotate_plan(state, plan, ["ADV-synthetic", "INV-synthetic"])
    assert result["technical_gate"]["status"] == "pending_human_review"
    assert result["action_classification"][1]["category"] == "collector_health_recovery"
    plan["actions"][0]["target"] = "openssl"
    result = annotate_plan(state, plan, [])
    assert "fix_target_not_affected_component" in result["technical_gate"]["reasons"]


def test_ubuntu_node_local_inventory_requires_bound_identity(node_rig, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "ubuntu-lab-node")
    with node_rig.factory() as db:
        asset = models.LinuxAsset(hostname="synthetic-ubuntu-node", distribution="ubuntu", os_name="Ubuntu", os_version="24.04")
        db.add(asset); db.flush()
        conn = models.DeviceConnection(asset_id=asset.id, host="192.168.50.1", port=2222,
            username="synthetic", auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_SYNTHETIC_KEY",
            host_key_sha256="SHA256:" + "A" * 43, enabled=True)
        db.add(conn); db.commit()
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID", str(asset.id))
        from app.services import collection_tasks as c
        run = c.execute(db, c.create_run(db, conn.id, "node-local"))
        assignment = c.claim_for_node(db, "ubuntu-lab-node", "Linux")
        assert assignment["execution"] == "node_local"
        output = 'hostname: synthetic-ubuntu-node\narchitecture: x86_64\n===== OS_RELEASE =====\nID=ubuntu\nNAME=Ubuntu\nVERSION_ID=24.04\n===== DPKG_PACKAGES =====\nii curl 8.5.0-2ubuntu10.15 amd64\n'
        payload = _result_payload("succeeded", assignment, output, fingerprint_verified=False)
        payload["local_hostname"] = asset.hostname
        payload["ssh_authentication"] = "not_applicable"
        done = c.submit_result(db, run.id, payload)
        assert done.status == "completed"
        db.refresh(asset)
        assert asset.identity_source == "authenticated_collection_node"
        from app.routers.iot import connection_dict
        assert connection_dict(conn, db)["identity_verified"] is True
        assert connection_dict(conn, db)["identity_source"] == "authenticated_collection_node"
        audit = json.loads(done.result_json)
        assert audit["ssh_host_identity"] == "not_applicable"
        assert db.query(models.CollectionEvidence).filter_by(evidence_id=audit["inventory_evidence_id"]).one().raw_text == output


def test_official_evidence_single_record_shape_and_refreshed_snapshot_are_valid(session_factory):
    from app.services.unified.graph import _decision_known_ids, _vulnerability_evidence_validator, RunContext
    from app.services.unified.state import empty_state
    with session_factory() as db:
        asset = _seed_noble(db)
        run_matching(db); calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()
        for eid,cve in [("ADV-current", "CVE-2026-63073"), ("ADV-refreshed", "CVE-2026-63073"), ("ADV-other", "CVE-2099-9999")]:
            db.add(models.OfficialCveRecord(evidence_id=eid, cve_id=cve, source_url="https://ubuntu.com/security/cves/" + cve + ".json", evidence_status="available"))
        db.commit()
        state = empty_state("synthetic", "risk_review", asset.hostname, "linux_host", "shadow")
        state.evidence_prep = {"candidates": [{"source_bundle": {"canonical": {"value": {"evidence_id": "ADV-current"}}}}]}
        known = _decision_known_ids(state)
        assert "ADV-current" in known
        ctx = RunContext(db_factory=session_factory, trace_id="", risk=risk, packet_evidence_ids=known)
        validator = _vulnerability_evidence_validator(ctx)
        assert not validator({"findings": [{"supporting_evidence_ids": ["ADV-refreshed"]}]})
        assert validator({"findings": [{"supporting_evidence_ids": ["ADV-other"]}]})
        assert validator({"findings": [{"supporting_evidence_ids": ["ADV-fabricated"]}]})


def test_harness_shadow_link_is_provenance_and_never_authorization(session_factory):
    from app.services import agent_harness as h
    with session_factory() as db:
        asset = _seed_noble(db)
        run_matching(db); calculate_risk(db)
        risk = db.query(models.RiskAssessment).one()
        candidate = models.UnifiedAnalysisRun(run_id="synthetic-harness-shadow", risk_id=risk.id,
            task_type="risk_review", target_type="linux_host", target_ref=asset.hostname, mode="shadow", status="completed",
            plan_json=json.dumps({"original_evidence_ids": ["ADV-synthetic"]}))
        db.add(candidate); db.commit()
        run = h.create_run(db, asset.id, risk.id, goal="investigate", shadow_run_id=candidate.run_id)
        assert json.loads(run.plan_json)["shadow_candidate"]["authorization"] == "none"
        done = h.execute(db, run)
        assert done.status in {"completed", "needs_evidence"}
        assert not done.approval_hash
        repair = h.create_run(db, asset.id, risk.id, goal="repair", shadow_run_id=candidate.run_id)
        assert repair.status == "blocked"
        with pytest.raises(ValueError): h.approve(db, repair, repair.plan_hash, "synthetic", "synthetic check only")
        with pytest.raises(ValueError): h.execute(db, repair)


def test_schema_echo_cannot_become_successful_empty_runtime_report(session_factory):
    from app.services.unified.agent_base import UnifiedToolLoopAgent
    from app.services.unified.agents_def import RUNTIME_ANALYST_SPEC
    from app.services.unified.schemas import RuntimeAnalysisReport
    class Client:
        def __init__(self): self.calls = 0
        def complete(self, messages, tools=None):
            self.calls += 1
            data = RuntimeAnalysisReport.model_json_schema() if self.calls == 1 else {
                "scope": "synthetic-host", "runtime_status": "stale_verified", "evidence_freshness": "stale",
                "data_gaps": ["synthetic stale evidence; no claim of exploitation"]}
            return {"content": json.dumps(data), "tool_calls": []}
    client = Client()
    with session_factory() as db:
        result = UnifiedToolLoopAgent(RUNTIME_ANALYST_SPEC, client).run(db, context="synthetic regression only")
        assert client.calls == 2 and result.status == "succeeded"
        assert result.output["scope"] == "synthetic-host"
        assert result.output["runtime_status"] == "stale_verified"
