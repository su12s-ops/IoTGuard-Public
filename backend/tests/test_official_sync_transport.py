"""Official transport pagination is bounded before any snapshot is committed."""
import io
import json
from types import SimpleNamespace

import pytest

from app.services import openwrt_intel as intel


class Page(io.BytesIO):
    status = 200

    def __init__(self, rows, link=""):
        super().__init__(json.dumps(rows).encode())
        self.headers = {"Link": link}


def install_transport(monkeypatch, pages):
    requested = []
    def open_page(request, **kwargs):
        requested.append(request.full_url)
        return pages[len(requested) - 1]
    monkeypatch.setattr(intel, "build_opener", lambda *args: SimpleNamespace(open=open_page))
    monkeypatch.setattr(intel, "_assert_pinned_public_https", lambda url: None)
    return requested


@pytest.mark.parametrize("path", ["repos/zephyrproject-rtos/zephyr", "repositories/59771425"])
def test_zephyr_follows_same_repository_page(monkeypatch, path):
    url = f"https://api.github.com/{path}/security-advisories?page=2"
    calls = install_transport(monkeypatch, [Page([{"ghsa_id": "one"}], f'<{url}>; rel="next"'), Page([{"ghsa_id": "two"}])])
    assert len(intel.fetch_advisory_rows(ecosystem="zephyr")) == 2
    assert calls[1] == url


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/openwrt/openwrt/security-advisories?per_page=100",
    "https://api.github.com/repos/other/repo/security-advisories?page=2",
    "https://api.github.com/repositories/59771425/security-advisories?page=2",
])
def test_reject_cycle_or_cross_repository_before_request(monkeypatch, url):
    calls = install_transport(monkeypatch, [Page([], f'<{url}>; rel="next"')])
    with pytest.raises(RuntimeError, match="pagination"):
        intel.fetch_advisory_rows()
    assert len(calls) == 1


@pytest.mark.parametrize("rows", [{"error": "rate limited"}, [None], [{}] * 101])
def test_invalid_page_never_becomes_snapshot(monkeypatch, rows):
    install_transport(monkeypatch, [Page(rows)])
    with pytest.raises(RuntimeError, match="invalid advisory page"):
        intel.fetch_advisory_rows()
