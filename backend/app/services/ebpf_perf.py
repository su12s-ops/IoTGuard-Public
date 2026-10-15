"""eBPF 2.0 P2-1 性能评测：指标计算（纯函数，无 I/O、无 app 依赖）。

语义约定（与采集可靠性语义一致）：
- 数值 0 = 真实为零；底层无法测得的一律 None → 上层呈现 unavailable，
  绝不把未知写成 0%；
- 丢失对账只对"已声明制造的行为"进行：expected 未知时不给丢失率
  （lost_rate=None），只给实测捕获数；
- 延迟分布 P50/P95/P99 取最近邻秩（nearest-rank），样本数与截断信息
  一并返回，不隐藏样本规模。
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any


def percentile(values: list[float], pct: float) -> float | None:
    """最近邻秩百分位：pct∈(0,100]。空样本返回 None（无数据≠0）。"""
    if not values or not (0 < pct <= 100):
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def latency_stats_ms(samples_ms: list[float]) -> dict[str, Any]:
    """端到端延迟汇总：P50/P95/P99 + 均值 + 样本数（无样本时全部 None）。"""
    if not samples_ms:
        return {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None,
                "mean_ms": None, "max_ms": None,
                "note": "无有效延迟样本（unavailable，非零延迟）"}
    return {
        "count": len(samples_ms),
        "p50_ms": round(percentile(samples_ms, 50), 3),
        "p95_ms": round(percentile(samples_ms, 95), 3),
        "p99_ms": round(percentile(samples_ms, 99), 3),
        "mean_ms": round(sum(samples_ms) / len(samples_ms), 3),
        "max_ms": round(max(samples_ms), 3),
    }


def eps(count: int | None, window_seconds: float | None) -> float | None:
    """吞吐速率：count 或窗口未知时返回 None（不可虚构速率）。"""
    if count is None or not window_seconds or window_seconds <= 0:
        return None
    return round(count / window_seconds, 2)


def parse_created_at(value: Any) -> datetime | None:
    """服务端持久化时间（SQLite naive UTC DateTime）。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def parse_event_time(value: Any) -> datetime | None:
    """事件自带时间戳（occurred_at 字符串，多格式尽力解析）。"""
    text = str(value or "").strip()
    if not text:
        return None
    # epoch 纳秒（bpftrace nsecs since boot 经 postprocess 已是 ISO；此处兜底）
    if text.isdigit() and len(text) >= 17:
        try:
            return datetime.fromtimestamp(int(text) / 1e9, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def end_to_end_latency_ms(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """对 (occurred_at, created_at) 行集计算采集→持久化延迟分布。

    时间不可解析的行计入 unparsed_count（如实，不进入分布也不虚构为 0）；
    created_at 早于事件时间（时钟回拨/同刻）按 0 计（同一机器顺序处理）。
    """
    samples: list[float] = []
    unparsed = 0
    for row in rows:
        occurred = parse_event_time(row.get("occurred_at") or row.get("timestamp"))
        created = parse_created_at(row.get("created_at"))
        if occurred is None or created is None:
            unparsed += 1
            continue
        samples.append(max(0.0, (created - occurred).total_seconds() * 1000.0))
    stats = latency_stats_ms(samples)
    stats["unparsed_time_count"] = unparsed
    return stats


def loss_reconciliation(expected: int | None, captured: int | None,
                        stored: int | None, probe_reported_lost: int | None) -> dict[str, Any]:
    """丢失对账：三个独立来源交叉，绝不互相虚构。

    - expected：负载发生器声明的已制造行为数（None=无受控负载，如观察态采集）；
    - captured：探针原始捕获数；
    - stored：服务端最终入库数；
    - probe_reported_lost：探针自身 stderr 丢失计数（None=未报告=unavailable）。
    """
    result: dict[str, Any] = {
        "expected_made": expected,
        "captured": captured,
        "stored": stored,
        "probe_reported_lost": probe_reported_lost,
    }
    if captured is not None and stored is not None:
        result["transport_gap"] = max(0, captured - stored)  # 捕获后未入库（传输/解析层）
    if expected is not None and captured is not None:
        lost_pre_capture = max(0, expected - captured)
        result["lost_pre_capture"] = lost_pre_capture
        result["loss_rate_pre_capture"] = round(lost_pre_capture / expected, 6) if expected else 0.0
    if expected is None:
        result["loss_rate"] = None
        result["note"] = "无受控负载基准：只呈现捕获/入库数，不给丢失率（不虚构）"
    return result


def summarize_run(mode: str, *, window_seconds: float | None,
                  captured: int | None, stored_new: int | None, stored_duplicates: int | None,
                  forwarder_metrics: dict[str, Any] | None,
                  latency: dict[str, Any] | None,
                  loss: dict[str, Any] | None,
                  resources: dict[str, Any] | None,
                  environment: dict[str, Any],
                  notes: list[str] | None = None) -> dict[str, Any]:
    """单次评测运行的汇总结构（原始指标由调用方另行落盘，本函数只汇总）。"""
    return {
        "mode": mode,
        "environment": environment,
        "window_seconds": window_seconds,
        "capture_eps": eps(captured, window_seconds),
        "ingest_eps": eps(stored_new, window_seconds),
        "stored_new": stored_new,
        "stored_duplicates": stored_duplicates,
        "forwarder_metrics": forwarder_metrics or {},
        "latency": latency or {},
        "loss": loss or {},
        "resources": resources or {},
        "notes": notes or [],
    }


def cpu_seconds(utime_ticks: int | None, stime_ticks: int | None,
                clock_ticks_per_s: float = 100.0) -> float | None:
    """/proc/<pid>/stat utime+stime（jiffies→秒）；字段缺失返回 None。"""
    if utime_ticks is None or stime_ticks is None:
        return None
    return round((utime_ticks + stime_ticks) / clock_ticks_per_s, 3)
