"""任务 B1 回归：官方公告自由文本有界化（只截断自由文本，保留结构化事实）。

覆盖：
- description ≤ 2000 / summary ≤ 500，截断标记含原始字符数；
- scope/official_range/source_url/ghsa_id/content_sha256/snapshot_sha256/
  fix_statement 等结构化字段逐字保留（content_sha256 是官方原文完整性凭据，
  不因展示层截断重算）；
- 18,012 字符 PoC description 的 evidence_prep 包体积显著下降；
- 截断不改变候选的 match_status/reason_code，不修改输入 bundle；
- 截断幂等，未超限文本不添加标记。

仅使用合成官方载荷与隔离 SQLite，不触网、不写真实库。
"""
from __future__ import annotations

import json

from app.services.unified import evidence_prep
from app.services.unified.evidence_prep import (
    MAX_FREE_TEXT_CHARS,
    TEXT_TRUNCATION_KEY,
    bound_free_text,
    build_evidence_prep_packet,
)

POC_DESCRIPTION_CHARS = 18_012
SUMMARY_CHARS = 780

STRUCTURED_KEYS = (
    "ecosystem", "advisory_id", "ghsa_id", "cve_id", "evidence_id",
    "source_url", "snapshot_sha256", "content_sha256", "scope",
    "official_range", "fix_statement", "affected_versions", "fixed_versions",
    "package_name",
)


def _long_text(total: int, unit: str) -> str:
    """构造指定字符数的成段文本（模拟含 PoC 代码的官方公告）。"""
    body = (unit + "\n") * (total // (len(unit) + 1) + 1)
    return body[:total]


def _official_record(description_chars: int = POC_DESCRIPTION_CHARS,
                     summary_chars: int = SUMMARY_CHARS) -> dict:
    return {
        "ecosystem": "openwrt",
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2099-7001",
        "evidence_id": "ADV-IOT-" + "e" * 48,
        "source_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "snapshot_sha256": "s" * 64,
        "content_sha256": "c" * 64,
        "scope": "release",
        "official_range": ">= 24.10.0, < 24.10.4",
        "fix_statement": {
            "text": "Fixed in OpenWrt 24.10.4 and later.",
            "fixed": "24.10.4",
            "covers_later_releases": True,
        },
        "affected_versions": [">= 24.10.0, < 24.10.4"],
        "fixed_versions": ["24.10.4"],
        "package_name": "odhcpd-ipv6only",
        "description": _long_text(description_chars, "print('poc'); exploit_step()"),
        "summary": _long_text(summary_chars, "summary paragraph"),
    }


def test_free_text_is_bounded_and_structured_facts_survive():
    record = _official_record()
    original_description = record["description"]
    original_summary = record["summary"]

    bounded = bound_free_text({"records": [record]})
    out = bounded["records"][0]

    # 自由文本有界 + 显式标记 + 原始字符数
    assert len(out["description"]) <= MAX_FREE_TEXT_CHARS["description"]
    assert len(out["summary"]) <= MAX_FREE_TEXT_CHARS["summary"]
    assert "[TRUNCATED" in out["description"]
    assert "[TRUNCATED" in out["summary"]
    assert str(POC_DESCRIPTION_CHARS) in out["description"]
    assert str(SUMMARY_CHARS) in out["summary"]
    assert out["description"].startswith(original_description[:200])
    assert out["summary"].startswith(original_summary[:200])

    # 结构化事实与哈希逐字保留（含嵌套 fix_statement）
    for key in STRUCTURED_KEYS:
        assert out[key] == record[key], key
    assert out["content_sha256"] == "c" * 64
    assert out["snapshot_sha256"] == "s" * 64

    # 结构化字段即使超长也不被截断（fix_statement 是研判必需事实）
    long_statement = _official_record()
    long_statement["fix_statement"] = {
        "text": "F" * 2500, "fixed": "24.10.4", "covers_later_releases": True}
    assert bound_free_text(long_statement)["fix_statement"] == long_statement["fix_statement"]

    # 原始字符数与上限进入可审计元数据
    meta = out[TEXT_TRUNCATION_KEY]["description"]
    assert meta["original_chars"] == POC_DESCRIPTION_CHARS
    assert meta["limit"] == MAX_FREE_TEXT_CHARS["description"]
    assert 0 < meta["kept_chars"] < POC_DESCRIPTION_CHARS

    # 输入不被原地修改（源 bundle 仍可用于确定性语义提取）
    assert record["description"] == original_description
    assert record["summary"] == original_summary
    assert TEXT_TRUNCATION_KEY not in record


def test_truncation_is_idempotent_and_skips_short_text():
    record = _official_record(description_chars=120, summary_chars=80)
    once = bound_free_text({"records": [record]})
    twice = bound_free_text(once)
    assert twice == once
    assert "[TRUNCATED" not in once["records"][0]["description"]
    assert TEXT_TRUNCATION_KEY not in once["records"][0]


def test_top_level_payload_free_text_is_bounded_but_status_survives():
    payload = {
        "status": "available",
        "cpe_status": "affected",
        "description": _long_text(3000, "top-level description"),
        "summary": _long_text(900, "top-level summary"),
        "source_url": "https://example.invalid/advisory",
    }
    out = bound_free_text(payload)
    assert len(out["description"]) <= MAX_FREE_TEXT_CHARS["description"]
    assert len(out["summary"]) <= MAX_FREE_TEXT_CHARS["summary"]
    assert "[TRUNCATED" in out["description"]
    assert out["status"] == "available"
    assert out["cpe_status"] == "affected"
    assert out["source_url"] == payload["source_url"]


def test_prep_packet_bounds_official_text_without_losing_match_semantics(
        session_factory, monkeypatch):
    record = _official_record()
    bundle = {
        "iot_official_snapshot": {
            "status": "snapshot_available",
            "value": {"records": [record]},
        },
    }
    texts = [{"source": "iot_official_snapshot.record", "text": record["description"]}]
    monkeypatch.setattr(evidence_prep, "_source_texts", lambda *args, **kwargs: (texts, bundle))

    with session_factory() as db:
        packet = build_evidence_prep_packet(db, "", "linux_host", [{
            "cve_id": "CVE-2099-7001",
            "package_name": "odhcpd-ipv6only",
            "installed_version": "2026.06.29~5d7be43f-r1",
            "fixed_version": "",
            "match_status": "affected",
            "reason_code": "openwrt_branch_range_no_fix",
            "match_reason": "官方范围未登记任何修复版本",
        }])
        candidate = packet.candidates[0]
        projected = candidate.source_bundle["iot_official_snapshot"]["value"]["records"][0]

        # 候选语义字段完整（截断不得导致 match_status/reason_code 丢失）
        assert candidate.match_status == "affected"
        assert candidate.reason_code == "openwrt_branch_range_no_fix"
        assert candidate.match_reason

        # 预取包中的官方记录：自由文本有界、结构化事实与哈希完整
        assert len(projected["description"]) <= MAX_FREE_TEXT_CHARS["description"]
        assert "[TRUNCATED" in projected["description"]
        assert projected["content_sha256"] == record["content_sha256"]
        assert projected["source_url"] == record["source_url"]
        assert projected["ghsa_id"] == record["ghsa_id"]
        assert projected["scope"] == record["scope"]
        assert projected["official_range"] == record["official_range"]
        assert projected["fix_statement"] == record["fix_statement"]

        raw_size = len(json.dumps(bundle, ensure_ascii=False))
        packet_size = len(json.dumps(packet.model_dump(), ensure_ascii=False))
        assert raw_size > POC_DESCRIPTION_CHARS
        assert packet_size < raw_size * 0.5, (packet_size, raw_size)
