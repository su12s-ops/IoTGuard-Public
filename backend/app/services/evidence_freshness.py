"""Backend receipt times are UTC; device wall clocks are not freshness clocks."""
from datetime import datetime, timezone


def utc(value):
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def freshness(collected, installed, started, now=None):
    try:
        now = utc(now or datetime.now(timezone.utc))
        collected, installed, started = map(utc, (collected, installed, started))
        age = (now - collected).total_seconds()
        passed = installed < collected and installed <= started <= collected <= now and age < 900
        return {"passed": passed, "age_seconds": age,
                "after_installation": collected > installed,
                "after_verification_start": collected >= started,
                "timestamp_basis": "backend_received_at"}
    except (ValueError, TypeError, OverflowError):
        return {"passed": False, "reason": "missing_or_invalid_timestamp"}
