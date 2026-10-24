"""Enrichment progress is optional and must not change provider work."""
import pytest

from app.services import ubuntu_security_collector as c


@pytest.fixture
def providers(monkeypatch):
    calls = []
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(c, "cves_needing_refresh", lambda db, ids, source: ids)
    monkeypatch.setattr(c, "fetch_nvd_by_cve", lambda cid: calls.append(("nvd", cid)) or [])
    monkeypatch.setattr(c, "fetch_cisa_kev", lambda: calls.append(("kev",)) or {})
    monkeypatch.setattr(c, "fetch_epss", lambda ids: calls.append(("epss", ids)) or {})
    monkeypatch.setattr(c.NvdProvider, "store_items", lambda *args: calls.append(("store_nvd",)))
    monkeypatch.setattr(c.CisaKevProvider, "store_catalog", lambda *args: calls.append(("store_kev",)))
    monkeypatch.setattr(c.EpssProvider, "store_rows", lambda *args: calls.append(("store_epss",)))
    monkeypatch.setattr(c, "apply_fused_intelligence", lambda db, ids: calls.append(("fuse", ids)))
    monkeypatch.setattr(c, "source_rows", lambda *args: {})
    monkeypatch.setattr(c.time, "sleep", lambda seconds: calls.append(("sleep", seconds)))
    monkeypatch.setattr(c, "mark_provider_failure", lambda *args: calls.append(("failure", args[2])))
    return calls


def test_progress_reports_substages_and_counts_without_reducing_requests(providers):
    events = []
    ids = ["CVE-2026-1002:noble:curl", "CVE-2026-1001", "CVE-2026-1001:noble:openssl"]
    assert c._enrich_intel(None, ids, progress=lambda *args: events.append(args)) == (0, 0)
    assert [item for item in providers if item[0] == "nvd"] == [
        ("nvd", "CVE-2026-1001"), ("nvd", "CVE-2026-1002")]
    assert ("sleep", 6.0) in providers
    assert ("fuse", ["CVE-2026-1001", "CVE-2026-1002"]) in providers
    for provider in ("NVD", "KEV", "EPSS"):
        assert any(message.startswith(provider + " enrichment: starting") for message, _, _ in events)
        assert any(message == provider + " enrichment: completed" for message, _, _ in events)
    assert ("NVD enrichment: fetched 2/2 CVEs", 2, 2) in events
    assert events[-1] == ("Intelligence enrichment: completed", 2, 2)


@pytest.mark.parametrize("call_style", ["legacy", "positional_force", "broken_callback"])
def test_old_signature_and_callback_failure_preserve_work(providers, call_style):
    ids = ["CVE-2026-1001"]
    if call_style == "legacy":
        result = c._enrich_intel(None, ids)
    elif call_style == "positional_force":
        result = c._enrich_intel(None, ids, True)
    else:
        def broken(*args):
            raise RuntimeError("UI disconnected")
        result = c._enrich_intel(None, ids, progress=broken)
    assert result == (0, 0)
    assert all(any(item[0] == provider for item in providers) for provider in ("nvd", "kev", "epss", "fuse"))
    assert not any(item[0] == "failure" for item in providers)


def test_provider_failure_visible_and_remaining_sources_continue(providers, monkeypatch):
    def fail(cid):
        raise TimeoutError("synthetic timeout")
    monkeypatch.setattr(c, "fetch_nvd_by_cve", fail)
    events = []
    c._enrich_intel(None, ["CVE-2026-1001"], progress=lambda *args: events.append(args))
    assert ("failure", "nvd") in providers
    assert any("NVD enrichment: failed" in message for message, _, _ in events)
    assert any(item[0] == "epss" for item in providers)
    assert any(item[0] == "fuse" for item in providers)


def test_empty_input_progress_and_fusion_preserved(providers):
    events = []
    assert c._enrich_intel(None, [], progress=lambda *args: events.append(args)) == (0, 0)
    assert ("fuse", []) in providers
    assert events[-1] == ("Intelligence enrichment: completed", 0, 0)
