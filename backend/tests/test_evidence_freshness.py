from datetime import datetime, timedelta, timezone
import pytest
from app.services.evidence_freshness import freshness

NOW = datetime(2026, 10, 19, 9, tzinfo=timezone.utc)
INSTALL = NOW - timedelta(minutes=3)
START = NOW - timedelta(minutes=1)

@pytest.mark.parametrize("collected", [
    (NOW-timedelta(seconds=30)).replace(tzinfo=None).isoformat(),
    (NOW-timedelta(seconds=30)).isoformat(),
    (NOW-timedelta(seconds=30)).astimezone(timezone(timedelta(hours=8))).isoformat(),
])
def test_utc_representations(collected):
    assert freshness(collected, INSTALL, START, NOW)["passed"]

@pytest.mark.parametrize("collected,installed,started", [
    (None, INSTALL, START), ("", INSTALL, START), ("invalid", INSTALL, START),
    (NOW-timedelta(hours=1), INSTALL-timedelta(hours=2), START-timedelta(hours=2)),
    (NOW+timedelta(seconds=1), INSTALL, START),
    (INSTALL-timedelta(seconds=1), INSTALL, START),
    (START-timedelta(seconds=1), INSTALL, START),
    (NOW, None, START), (NOW, INSTALL, None),
])
def test_fail_closed(collected, installed, started):
    assert not freshness(collected, installed, started, NOW)["passed"]

def test_device_clock_does_not_override_backend_receipt():
    # A future device wall clock is never used as the backend receipt time.
    assert freshness(NOW-timedelta(seconds=1), INSTALL, START, NOW)["passed"]
    assert not freshness(NOW+timedelta(hours=8), INSTALL, START, NOW)["passed"]

def test_original_typeerror_reproduced():
    with pytest.raises(TypeError):
        NOW - datetime.fromisoformat("2026-10-19 08:59:30")
