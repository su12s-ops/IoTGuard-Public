"""测试 _extract_json 容错边界情况。"""
import sys
sys.path.insert(0, '.')
from app.services.agent_group_chat import _extract_json


def test_trailing_comma():
    content = '{"verdict": "confirmed", "confidence": 0.9, "risk_adjustment": 0, "reason": "test",}'
    result = _extract_json(content)
    assert result is not None
    assert result["verdict"] == "confirmed"


def test_trailing_chinese():
    content = '{"verdict": "upgraded", "confidence": 0.85, "risk_adjustment": 15, "reason": "test"}\n以上是我的裁定。'
    result = _extract_json(content)
    assert result is not None
    assert result["verdict"] == "upgraded"


def test_code_fence():
    content = '```json\n{"verdict": "downgraded", "confidence": 0.7, "risk_adjustment": 10, "reason": "ok"}\n```'
    result = _extract_json(content)
    assert result is not None
    assert result["verdict"] == "downgraded"


def test_no_marker_pure_json():
    content = '{"verdict": "insufficient_evidence", "confidence": 0.3, "risk_adjustment": 0, "reason": "x"}'
    result = _extract_json(content)
    assert result is not None
    assert result["verdict"] == "insufficient_evidence"


def test_garbage_returns_none():
    content = "this is not json at all"
    result = _extract_json(content)
    assert result is None


def test_commas_in_arrays():
    content = '{"verdict": "confirmed", "confidence": 0.95, "risk_adjustment": 0, "evidence_ids": ["a-1", "b-2",], "conflicts": ["x", "y",], "reason": "ok"}'
    result = _extract_json(content)
    assert result is not None
    assert result["verdict"] == "confirmed"


def test_array_in_object():
    content = '{"object_verdicts": [{"object_id": "asset-1-CVE-2026", "verdict": "upgraded", "confidence": 0.86, "risk_adjustment": 12, "reason": "test"}], "overall_summary": "ok"}'
    result = _extract_json(content)
    assert result is not None
    assert len(result["object_verdicts"]) == 1
    assert result["object_verdicts"][0]["verdict"] == "upgraded"
