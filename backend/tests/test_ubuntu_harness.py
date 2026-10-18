"""Isolated Ubuntu adapter tests. No network, VM, apt writes or real CVE data."""
import copy
import hashlib
import importlib.util
import json
from types import SimpleNamespace
import time

import pytest

from app import models
from app.services import agent_harness as h, ubuntu_repair as u, collection_tasks as c
from app.services import canonical_official

OLD = "8.5.0-2ubuntu10.15"
NEW = "8.5.0-2ubuntu10.16"
CVE = "CVE-2026-999999"


@pytest.fixture
def rig(session_factory, monkeypatch):
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "test-node")
    monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_TOKEN", "isolated-token")
    monkeypatch.setenv("LINUXGUARD_DISCOVERY_CIDRS", "192.0.2.0/24")
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0")
    with session_factory() as db:
        a = models.LinuxAsset(hostname="test-ubuntu", distribution="ubuntu", os_version="24.04", architecture="x86_64", inventory_complete=True,
            inventory_metadata_json=json.dumps({"package_sources": [f"{p}|curl|{OLD}" for p in ("curl", "libcurl4t64:amd64")]}))
        a.packages = [models.AssetPackage(package_name=p, package_version=OLD, package_manager="dpkg", architecture="amd64") for p in ("curl", "libcurl4t64:amd64")]
        db.add(a)
        db.flush()
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_LOCAL_ASSET_ID", str(a.id))
        conn = models.DeviceConnection(asset_id=a.id, host="192.0.2.10", username="tester", enabled=True,
            auth_type="ssh_key", key_path_env="LINUXGUARD_DEVICE_TEST_KEY", host_key_sha256="SHA256:" + "A" * 43)
        match = models.VulnerabilityMatch(asset_id=a.id, cve_id=CVE + ":noble:curl", package_name="curl", affected=True,
            fixed_version=NEW, evidence_fingerprint="test-fingerprint", active=True)
        db.add_all([conn, match])
        db.flush()
        risk = models.RiskAssessment(asset_id=a.id, match_id=match.id, cve_id=match.cve_id,
            package_name="curl", active=True, review_status="human_confirmed", human_review_required=False)
        db.add(risk)
        data = {"id": CVE, "packages": [{"name": "curl", "statuses": [{"release_codename": "noble", "status": "needed"}]}],
            "notices": [{"id": "USN-TEST-1", "cves_ids": [CVE], "release_packages": {"noble": [
                {"is_source": True, "name": "curl", "version": NEW},
                *[{"is_source": False, "name": p, "version": NEW} for p in ("curl", "libcurl4t64")]]}}]}
        raw = json.dumps(data, sort_keys=True, ensure_ascii=False)
        db.add(models.OfficialCveRecord(cve_id=CVE, evidence_id="ADV-test", raw_json=raw, evidence_status="available",
            content_sha256=hashlib.sha256(raw.encode()).hexdigest(), source_url=canonical_official.official_record_url(CVE)))
        db.commit()
        yield SimpleNamespace(db=db, asset=a, risk=risk, connection=conn, match=match)


def create(rig):
    run = h.create_run(rig.db, rig.asset.id, rig.risk.id, goal="repair")
    assert run.status == "awaiting_preflight", run.plan_json
    return run


def observation(plan, ready=True):
    identity = {**plan["identity"], "machine_id_sha256": "a" * 64, "architecture": "amd64"}
    return {"identity": identity, "packages": plan["targets"], "candidate_versions": {p["binary"]: NEW for p in plan["targets"]},
        "changes": [{"binary": p["binary"], "old": OLD, "new": NEW} for p in plan["targets"]],
        "candidate_metadata": {}, "policy": {}, "ready": ready, "issues": [] if ready else ["official_candidate_unavailable"],
        "package_ready": ready, "execution_context": {"effective_uid": 0},
        "observed_at": time.time(), "simulation": "test only", "removals": [], "rollback": {"snapshot_restore": "not_checked_by_guest"}}


def submit(rig, run, output):
    plan = json.loads(run.plan_json)
    c.claim_for_node(rig.db, "test-node", "Linux")
    audit = json.loads(run.result_json)["dispatch"]
    text = json.dumps(output) if not isinstance(output, str) else output
    return c.submit_result(rig.db, run.id, {"node_id": "test-node", "node_platform": "Linux", "local_hostname": "test-ubuntu",
        "status": "succeeded", "collector_sha256": audit["script_sha256"], "inventory_text": text,
        "output_sha256": hashlib.sha256(text.encode()).hexdigest(), "output_bytes": len(text.encode())})


def preflight(rig, ready=True):
    run = create(rig)
    plan = json.loads(run.plan_json)
    u.queue(rig.db, run, "dry_run")
    submit(rig, run, {"preflight": observation(plan, ready)})
    assert run.status == ("awaiting_approval" if ready else "preflight_failed"), run.error
    return run


def test_dry_run_plan_hash_and_separate_approval(rig):
    original = h.review_signature(rig.risk)
    run = create(rig)
    old_hash = run.plan_hash
    plan = json.loads(run.plan_json)
    with pytest.raises(ValueError):
        h.approve(rig.db, run, old_hash, "tester", "too early")
    u.queue(rig.db, run, "dry_run")
    submit(rig, run, {"preflight": observation(plan)})
    assert run.plan_hash != old_hash and run.approval_hash == ""
    with pytest.raises(ValueError):
        h.approve(rig.db, run, old_hash, "tester", "wrong plan")
    with pytest.raises(ValueError):
        h.execute(rig.db, run)
    h.approve(rig.db, run, run.plan_hash, "tester", "independent test approval")
    execute_entry = h.execute   # module attribute alias: no raw SQL anywhere in this file
    with pytest.raises(ValueError, match="隔离副本写未授权"):
        execute_entry(rig.db, run)
    assert h.review_signature(rig.risk) == original
    assert rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id, side_effect=True).count() == 0


def test_preflight_trace_resolves_raw_evidence_and_marks_missing(rig):
    from app.services import trace_service as tracing
    run = preflight(rig)
    plan = json.loads(run.plan_json)
    trace = tracing.start_trace(rig.db, task_type="harness_repair", target_type="asset", target_ref=str(rig.asset.id))
    refs = [plan["preflight_evidence_id"], plan["official"]["evidence_id"], "PRE-missing"]
    tracing.emit(rig.db, trace.trace_id, "ubuntu_operation_finished", evidence_refs=refs)
    rows = {e["evidence_id"]: e for e in tracing.evidence_for_trace(rig.db, trace.trace_id)["evidence"]}
    assert rows[refs[0]]["resolved"] and rows[refs[0]]["evidence_type"] == "ubuntu_preflight"
    assert rows[refs[0]]["content_sha256"]
    assert rows[refs[1]]["resolved"] and not rows[refs[2]]["resolved"]


@pytest.mark.parametrize("mutation", ["node", "asset_binding", "disabled", "distribution", "identity", "script", "plan"])
def test_changed_target_refused_before_dispatch(rig, monkeypatch, mutation):
    run = create(rig)
    if mutation == "node":
        monkeypatch.setenv("LINUXGUARD_COLLECTION_NODE_ID", "wrong")
    elif mutation == "asset_binding":
        rig.connection.asset_id += 100
    elif mutation == "disabled":
        rig.connection.enabled = False
    elif mutation == "distribution":
        rig.asset.distribution = "openwrt"
    elif mutation == "identity":
        rig.asset.hostname = "other"
    elif mutation == "script":
        monkeypatch.setattr(u, "MAINTENANCE", u.COLLECTOR)
    else:
        run.plan_json = run.plan_json.replace("ubuntu-apt-v1", "ubuntu-apt-v0")
    rig.db.commit()
    with pytest.raises(ValueError):
        u.queue(rig.db, run, "dry_run")
    assert rig.db.query(models.HarnessAssetLock).count() == 0


def test_unavailable_official_package_blocks_approval(rig):
    run = preflight(rig, ready=False)
    with pytest.raises(ValueError):
        h.approve(rig.db, run, run.plan_hash, "test", "cannot override")
    assert json.loads(run.result_json)["dry_run"]["issues"]


def test_wrong_node_and_tampered_result_rejected(rig):
    run = create(rig)
    u.queue(rig.db, run, "dry_run")
    with pytest.raises(ValueError):
        c.claim_for_node(rig.db, "wrong-node", "Linux")
    c.claim_for_node(rig.db, "test-node", "Linux")
    with pytest.raises(ValueError):
        u.submit(rig.db, run, {"node_id": "wrong", "node_platform": "Linux"})
    u.submit(rig.db, run, {"node_id": "test-node", "node_platform": "Linux", "status": "succeeded", "inventory_text": "{}"})
    assert run.status == "preflight_failed" and "integrity" in run.error


def test_pending_review_still_cannot_execute_approved_plan(rig, monkeypatch):
    rig.risk.review_status = "pending_human_review"
    rig.risk.human_review_required = True
    rig.db.commit()
    run = preflight(rig)
    h.approve(rig.db, run, run.plan_hash, "tester", "test plan only")
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "1")
    monkeypatch.setenv("LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE", str(rig.asset.id))
    with pytest.raises(ValueError, match="风险授权"):
        h.execute(rig.db, run)


def test_shared_asset_lock_and_budget(rig):
    a, b = create(rig), create(rig)
    u.queue(rig.db, a, "dry_run")
    with pytest.raises(ValueError, match="并发"):
        u.queue(rig.db, b, "dry_run")
    rig.db.query(models.HarnessAssetLock).delete()
    b.status = "awaiting_preflight"
    for _ in range(16):
        rig.db.add(models.HarnessToolCall(run_id=b.id, tool="test", arguments_json="{}"))
    rig.db.commit()
    with pytest.raises(ValueError, match="预算"):
        u.queue(rig.db, b, "dry_run")
    assert rig.db.query(models.HarnessAssetLock).count() == 0


def inventory_text(rig, versions):
    return "hostname: test-ubuntu\narchitecture: x86_64\n===== OS_RELEASE =====\nID=ubuntu\nVERSION_ID=24.04\n===== DPKG_PACKAGES =====\n" + "\n".join(
        f"ii {p.package_name} {v} amd64" for p, v in zip(rig.asset.packages, versions)) + "\n===== PACKAGE_SOURCES =====\n" + "\n".join(
        f"{p.package_name}|curl|{v}" for p, v in zip(rig.asset.packages, versions)) + "\n"


@pytest.mark.parametrize("versions,status", [([NEW, NEW], "fixed_version_verified"), ([OLD, OLD], "version_unchanged"), ([NEW, OLD], "partial_update")])
def test_actual_recollection_official_rematch_preserves_risk(rig, monkeypatch, versions, status):
    run = preflight(rig)
    plan = json.loads(run.plan_json)
    original = {k: getattr(rig.risk, k) for k in rig.risk.__table__.columns.keys()}
    original_match = {k: getattr(rig.match, k) for k in rig.match.__table__.columns.keys()}
    monkeypatch.setattr(canonical_official, "import_official_records", lambda *args: {})
    post = {"identity": plan["identity"], "packages": [{**p, "version": v, "source_version": v} for p, v in zip(plan["targets"], versions)]}
    result = u.rematch(rig.db, run, plan, post, inventory_text(rig, versions))
    assert result["status"] == status
    assert result["verified"] == (versions == [NEW, NEW])
    assert original == {k: getattr(rig.risk, k) for k in original}
    assert original_match == {k: getattr(rig.match, k) for k in original_match}
    assert rig.db.query(models.CollectionEvidence).count() >= 2


def test_success_exit_without_post_evidence_never_fixed(rig, monkeypatch):
    run = preflight(rig)
    h.approve(rig.db, run, run.plan_hash, "tester", "test only")
    run.status = "running"
    result = json.loads(run.result_json)
    result["dispatch"].update(operation="execute", execution_node="test-node")
    run.result_json = json.dumps(result)
    output = json.dumps({"exit_code": 0, "after": {"identity": {}, "packages": []}})
    audit = result["dispatch"]
    u.submit(rig.db, run, {"node_id": "test-node", "node_platform": "Linux", "local_hostname": "test-ubuntu", "status": "succeeded",
        "collector_sha256": audit["script_sha256"], "inventory_text": output,
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(), "output_bytes": len(output.encode())})
    assert run.status == "verification_required"
    assert rig.risk.active and rig.risk.review_status != "resolved"
    with pytest.raises(ValueError):
        h.execute(rig.db, run)
    with pytest.raises(ValueError, match="快照"):
        h.rollback(rig.db, run, run.plan_hash, "tester", "test only")


def test_verify_requires_real_execution_attempt(rig):
    run = preflight(rig)
    run.status = "interrupted"
    rig.db.commit()
    with pytest.raises(ValueError, match="尚未尝试"):
        h.execute(rig.db, run, verify_only=True)


@pytest.mark.parametrize("exit_code,versions,expected", [(0, [NEW, NEW], "verified"), (1, [NEW, OLD], "verification_required"), (0, [OLD, OLD], "verification_required")])
def test_approved_execution_automatically_collects_rematches_and_keeps_history(rig, monkeypatch, exit_code, versions, expected):
    run = preflight(rig)
    h.approve(rig.db, run, run.plan_hash, "test-operator", "isolated test double only")
    plan = json.loads(run.plan_json)
    # Stage-10 contract: the isolated clone path needs ONLY the lab switch plus
    # the exact clone asset scope; the device master stays 0 on purpose.
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "1")
    monkeypatch.setenv("LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE", str(rig.asset.id))
    # Permit verification is exercised separately against the real validator;
    # this test substitutes it and the VM response, never executes apt.
    import importlib.util
    original_loader = importlib.util.module_from_spec
    def fixture_module(spec):
        module = original_loader(spec)
        real_exec = spec.loader.exec_module
        def load(m):
            real_exec(m)
            m.permit = lambda *a: {"test_double": True}
        spec.loader.exec_module = load
        return module
    monkeypatch.setattr(importlib.util, "module_from_spec", fixture_module)
    monkeypatch.setattr(canonical_official, "import_official_records", lambda *a: {})
    before = h.review_signature(rig.risk)
    h.execute(rig.db, run)
    assert run.status == "queued_remote"
    post = {"identity": plan["identity"], "packages": [{**p, "version": v, "source_version": v} for p, v in zip(plan["targets"], versions)]}
    text = json.dumps({"exit_code": exit_code, "after": post, "snapshot_permit": {"test_double": True}}) + u.SEPARATOR + inventory_text(rig, versions)
    submit(rig, run, text)
    assert run.status == expected, run.error
    assert h.review_signature(rig.risk) == before
    assert json.loads(run.result_json)["verification"]["verified"] == (expected == "verified")
    assert rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id, side_effect=True).count() == 1
    assert rig.db.query(models.HarnessAssetLock).count() == 0


def test_fresh_official_unavailable_keeps_risk_open(rig, monkeypatch):
    run = preflight(rig)
    plan = json.loads(run.plan_json)
    def unavailable(db, *a):
        db.add(models.OfficialCveRecord(cve_id=CVE, evidence_id="ADV-failed", evidence_status="unavailable",
            source_url=canonical_official.official_record_url(CVE)))
    monkeypatch.setattr(canonical_official, "import_official_records", unavailable)
    post = {"identity": plan["identity"], "packages": [{**p, "version": NEW, "source_version": NEW} for p in plan["targets"]]}
    with pytest.raises(ValueError, match="official_evidence_unavailable"):
        u.rematch(rig.db, run, plan, post, inventory_text(rig, [NEW, NEW]))
    assert rig.risk.active and rig.risk.review_status != "resolved"


def test_interrupted_dispatch_expires_without_replay(rig):
    from datetime import timedelta
    run = create(rig)
    u.queue(rig.db, run, "dry_run")
    run.updated_at = models.utcnow() - timedelta(minutes=20)
    rig.db.commit()
    assert h.recover_interrupted(rig.db) == 1
    assert run.status == "interrupted" and rig.db.query(models.HarnessAssetLock).count() == 0
    with pytest.raises(ValueError):
        h.execute(rig.db, run)


@pytest.fixture
def maintenance():
    spec = importlib.util.spec_from_file_location("maintenance_test", u.MAINTENANCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("uid", [0, 1000])
def test_preflight_distinguishes_packages_from_execution_privileges(maintenance, monkeypatch, uid):
    ident = {"hostname": "clone", "distribution": "ubuntu", "release": "24.04",
             "codename": "noble", "architecture": "amd64", "machine_id_sha256": "a" * 64}
    package = {"name": "curl", "binary": "curl", "version": OLD, "source": "curl",
               "source_version": OLD, "architecture": "amd64"}
    policy = f"curl:\n  Candidate: {NEW}\n     {NEW} 500\n        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n"
    calls = []
    def fixture_command(args, timeout=45):
        calls.append(args)
        if args[:2] == ["apt-cache", "show"]:
            return 0, f"Source: curl\nVersion: {NEW}\nSHA256: {'b' * 64}\n", ""
        if args[:2] == ["apt-get", "--simulate"]:
            return 0, f"Inst curl [{OLD}] ({NEW} Ubuntu:24.04/noble-security [amd64])\n", ""
        if args[:2] == ["dpkg", "--compare-versions"]:
            return 0, "", ""
        raise AssertionError(args)
    def fixture_checked(args, timeout=45):
        if args[:2] == ["apt-cache", "policy"]:
            return policy
        assert args in (["dpkg", "--audit"], ["apt-mark", "showhold"])
        return ""
    monkeypatch.setattr(maintenance, "identity", lambda: ident)
    monkeypatch.setattr(maintenance, "source_packages", lambda: [package])
    monkeypatch.setattr(maintenance, "command", fixture_command)
    monkeypatch.setattr(maintenance, "checked", fixture_checked)
    monkeypatch.setattr(maintenance.os, "geteuid", lambda: uid, raising=False)
    monkeypatch.setattr(maintenance.os, "statvfs", lambda _: SimpleNamespace(f_bavail=1024**3, f_frsize=1), raising=False)
    pre = maintenance.inspect({"identity": ident, "targets": [package], "fixed_version": NEW})
    assert pre["package_ready"] is True
    assert pre["ready"] is (uid == 0)
    assert pre["issues"] == ([] if uid == 0 else ["root_execution_node_required"])
    assert pre["execution_context"] == {"effective_uid": uid}
    assert all(args[:2] != ["dpkg", "--install"] for args in calls)


@pytest.mark.parametrize("context", [None, {}, {"effective_uid": 1000}, {"effective_uid": False}, {"effective_uid": "0"}])
def test_nonroot_or_legacy_preflight_cannot_enter_approval(rig, context):
    run = create(rig)
    observed = observation(json.loads(run.plan_json))
    if context is None:
        observed.pop("execution_context")
    else:
        observed["execution_context"] = context
    u.queue(rig.db, run, "dry_run")
    submit(rig, run, {"preflight": observed})
    assert run.status == "preflight_failed"
    assert json.loads(run.plan_json)["preflight"]["package_ready"] is True
    assert "root_execution_node_required" in json.loads(run.plan_json)["preflight"]["issues"]
    with pytest.raises(ValueError):
        h.approve(rig.db, run, run.plan_hash, "tester", "must not approve")
    assert not run.approval_hash


def test_legacy_approved_plan_cannot_queue_execution(rig):
    run = preflight(rig)
    plan = json.loads(run.plan_json)
    plan["preflight"].pop("execution_context")
    run.plan_json, run.plan_hash = h.encode(plan), h.digest(plan)
    rig.db.commit()
    h.approve(rig.db, run, run.plan_hash, "tester", "legacy fixture approval")
    with pytest.raises(ValueError, match="root_execution_node_required"):
        u.queue(rig.db, run, "execute")
    assert not rig.db.query(models.HarnessToolCall).filter_by(run_id=run.id, side_effect=True).count()


def test_node_losing_root_stops_before_any_commands(maintenance, monkeypatch):
    monkeypatch.setattr(maintenance.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(maintenance, "inspect", lambda _: pytest.fail("must reject before inspecting or downloading"))
    with pytest.raises(ValueError, match="root_execution_node_required"):
        maintenance.execute({})


@pytest.mark.parametrize("url,suite,expected", [
    ("http://security.ubuntu.com/ubuntu", "noble-security", True),
    ("https://archive.ubuntu.com/ubuntu", "noble-updates", True),
    ("https://security.ubuntu.com.evil.invalid/ubuntu", "noble-security", False),
    ("http://archive.ubuntu.com/ubuntu", "jammy-security", False),
    ("http://untrusted.invalid/ubuntu", "noble-security", False)])
def test_fixed_official_candidate_policy(maintenance, url, suite, expected):
    policy = f"curl:\n  Candidate: {NEW}\n  Version table:\n     {NEW} 500\n        500 {url} {suite}/main amd64 Packages\n *** {OLD} 100\n        100 /var/lib/dpkg/status\n"
    assert maintenance.official_candidate(policy, "curl", NEW, "noble") is expected


def test_node_permit_bound_to_asset_machine_plan_and_expiry(maintenance, tmp_path, monkeypatch):
    # Lab permit depends on the lab switch only; the OpenWrt device master must
    # never substitute for it (disjoint write domains).
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "1")
    grant = {"asset_id": 7, "machine_id_sha256": "a" * 64, "plan_hash": "b" * 64, "isolated_clone": True,
             "restore_verified": True, "snapshot_id": "test-snapshot", "approved_by": "operator", "expires_at": time.time() + 60}
    path = tmp_path / "permit.json"
    path.write_text(json.dumps(grant))
    monkeypatch.setenv("LINUXGUARD_UBUNTU_LAB_PERMIT", str(path))
    maintenance.permit({"asset_id": 7, "plan_hash": "b" * 64}, {"machine_id_sha256": "a" * 64})
    for field in ("asset_id", "machine_id_sha256", "plan_hash", "isolated_clone", "restore_verified", "expires_at"):
        broken = {**grant, field: 0}
        path.write_text(json.dumps(broken))
        with pytest.raises(ValueError):
            maintenance.permit({"asset_id": 7, "plan_hash": "b" * 64}, {"machine_id_sha256": "a" * 64})
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "0")
    with pytest.raises(ValueError, match="ubuntu_lab_writes_disabled"):
        maintenance.permit({"asset_id": 7, "plan_hash": "b" * 64}, {"machine_id_sha256": "a" * 64})


def test_backend_lab_write_scope_is_fail_closed(rig, monkeypatch):
    run = preflight(rig)
    h.approve(rig.db, run, run.plan_hash, "tester", "isolated test double only")
    # Lab switch on but this backend never declared the clone asset scope.
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "0")
    monkeypatch.setenv("LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR", "1")
    monkeypatch.setenv("LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE", "")
    with pytest.raises(ValueError, match="ubuntu_lab_asset_scope_not_declared"):
        u.queue(rig.db, run, "execute")
    # The OpenWrt device master must not unlock the Ubuntu lab path either.
    monkeypatch.setenv("LINUXGUARD_ENABLE_DEVICE_REPAIR", "1")
    with pytest.raises(ValueError, match="ubuntu_lab_asset_scope_not_declared"):
        u.queue(rig.db, run, "execute")
    # Declaring the scope is what unlocks queueing (permit double-check follows).
    monkeypatch.setenv("LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE", str(rig.asset.id))
    import importlib.util
    original_loader = importlib.util.module_from_spec
    def fixture_module(spec):
        module = original_loader(spec)
        real_exec = spec.loader.exec_module
        def load(m):
            real_exec(m)
            m.permit = lambda *a: {"test_double": True}
        spec.loader.exec_module = load
        return module
    monkeypatch.setattr(importlib.util, "module_from_spec", fixture_module)
    monkeypatch.setattr(canonical_official, "import_official_records", lambda *a: {})
    queued = u.queue(rig.db, run, "execute")
    assert queued.status == "queued_remote"


@pytest.mark.parametrize("problem", ["none", "extra_dependency", "checksum", "identity"])
def test_node_installs_only_exact_verified_archives(maintenance, monkeypatch, problem):
    package = {"name": "curl", "binary": "curl", "version": OLD, "source": "curl", "source_version": OLD, "architecture": "amd64"}
    content = b"TEST ONLY archive, never a real deb"
    sha = hashlib.sha256(content).hexdigest()
    ident = {"machine_id_sha256": "a" * 64}
    before = {"ready": True, "identity": ident, "packages": [package], "candidate_versions": {"curl": NEW},
        "changes": [{"binary": "curl", "old": OLD, "new": NEW}], "candidate_metadata": {"curl": "SHA256: " + sha}}
    monkeypatch.setattr(maintenance, "inspect", lambda req: before)
    monkeypatch.setattr(maintenance, "permit", lambda *args: {"test_double": True})
    monkeypatch.setattr(maintenance.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(maintenance, "identity", lambda: {"machine_id_sha256": "wrong"} if problem == "identity" else ident)
    monkeypatch.setattr(maintenance, "source_packages", lambda: [package])
    calls = []
    def fixture_command(args, timeout=45):
        calls.append(args)
        if args[0] == "apt-get":
            from pathlib import Path
            folder = Path(next(a.split("=", 1)[1] for a in args if a.startswith("Dir::Cache::archives=")))
            (folder / "curl.deb").write_bytes(b"tampered" if problem == "checksum" else content)
            if problem == "extra_dependency":
                (folder / "unapproved.deb").write_bytes(content)
            return 0, "download test double", ""
        if args[0] == "dpkg-deb":
            name = "unapproved" if "unapproved.deb" in args[2] else "curl"
            return 0, f"Package: {name}\nVersion: {NEW}\nArchitecture: amd64\n", ""
        if args[:2] == ["dpkg", "--install"]:
            return 0, "install test double", ""
        raise AssertionError(args)
    monkeypatch.setattr(maintenance, "command", fixture_command)
    request = {"preflight": before, "fixed_version": NEW}
    if problem == "none":
        result = maintenance.execute(request)
        assert result["archives"][0]["sha256"] == sha and result["verification_pending"]
    else:
        with pytest.raises(ValueError):
            maintenance.execute(request)
    writes = [a for a in calls if a[:2] == ["dpkg", "--install"]]
    assert len(writes) == (1 if problem == "none" else 0)


def test_ubuntu_api_denies_missing_control_and_wrong_asset(client, rig):
    response = client.post("/api/harness/runs", json={"asset_id": rig.asset.id, "risk_id": rig.risk.id, "goal": "repair"})
    assert response.status_code in {401, 503}
    other = models.LinuxAsset(hostname="wrong-asset", distribution="ubuntu", os_version="24.04")
    rig.db.add(other)
    rig.db.commit()
    with pytest.raises(ValueError, match="不属于"):
        h.create_run(rig.db, other.id, rig.risk.id, goal="repair")
