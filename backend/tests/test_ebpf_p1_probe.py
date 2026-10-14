"""eBPF 2.0 P1 专项测试：探针增强（P1-1 可独立验证部分）。

覆盖：
1.  新格式 execve：argv / start_time / 合成会话键 / boot_id 字段适配
2.  argv NULL 边界（\\x1e 终止）——绝不越界读入 envp（真实内核已复现该风险）
3.  argv 含 "|"、空格等字符的解析保真
4.  旧格式（P0 及之前）三类事件解析不变（向后兼容，不虚构新字段）
5.  会话键确定性：同 pid+start_time+boot 同键；pid 复用 / 跨 boot 可区分
6.  坏行跳过、控制字符清洗、时间换算
7.  后端入库：process_start_time / process_exec_id / boot_id 落列，
    commandline 与 SecurityEvidence 携带 argv
8.  argv 参与事件身份（幂等重传不重复；argv 变化是不同事件）
9.  旧事件上传不受影响（无新列值、无 argv）
10. timeline 按合成会话键聚合（exec+connect 同组；pid 复用分组不同）
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from app import models
from app.ebpf_identity import stable_event_fingerprint
from app.services import ebpf_event_collector as collector
from app.services.runtime_telemetry import timeline

BACKEND_DIR = Path(__file__).resolve().parents[1]
COLLECTOR_DIR = BACKEND_DIR.parent / "collector"

_spec = importlib.util.spec_from_file_location(
    "ebpf_capture_postprocess", COLLECTOR_DIR / "ebpf_capture_postprocess.py")
postprocess = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(postprocess)

SEP, NUL = "\x1f", "\x1e"


def _p1_execve_line(pid=100, ppid=90, start="12345678901", argv=None):
    argv_section = argv if argv is not None else (
        f"/usr/bin/wget{SEP}http://127.0.0.1/x{SEP}{NUL}{SEP}{NUL}")
    return f"LG|execve|45296280000000000|{pid}|{ppid}|0|wget|{start}|{argv_section}"


def _convert(line, hostname="lab-host", boot_id="bbbbbbbb-cafe", boot_epoch=1700000000):
    return postprocess.convert_lines([line], hostname, boot_id=boot_id, boot_epoch=boot_epoch)


# ── 1/2/3. 新格式 execve 解析 ────────────────────────────────────────────────

def test_new_execve_carries_argv_start_time_and_session_key():
    event = _convert(_p1_execve_line())[0]
    assert event["event_type"] == "execve"
    assert event["argv"] == ["/usr/bin/wget", "http://127.0.0.1/x"]
    assert "/usr/bin/wget http://127.0.0.1/x" in event["commandline"]
    assert event["process_start_time"] == "12345678901"
    assert event["process_exec_id"] == "lg-bbbbbbbb-100-12345678901"
    assert event["boot_id"].startswith("bbbbbbbb")
    assert event["raw"]["argv"] == ["/usr/bin/wget", "http://127.0.0.1/x"]
    assert event["raw"]["start_time"] == 12345678901


def test_argv_null_marker_stops_and_never_leaks_envp():
    # 真实内核验证发现的隐患：NULL 之后继续读会得到 envp（USER=/HOME=…）。
    # 内核侧守卫 + \x1e 终止标记必须把这类值挡在 argv 之外。
    section = (f"/bin/true{SEP}{NUL}{SEP}USER=root{SEP}HOME=/root"
               f"{SEP}{NUL}")
    event = _convert(_p1_execve_line(argv=section))[0]
    assert event["argv"] == ["/bin/true"]
    assert "USER=root" not in json.dumps(event)
    assert "HOME=/root" not in json.dumps(event)


def test_argv_pipe_and_spaces_survive_parsing():
    section = (f"/bin/sh{SEP}-c{SEP}echo a|b && echo c"
               f"{SEP}{NUL}")
    event = _convert(_p1_execve_line(argv=section))[0]
    assert event["argv"] == ["/bin/sh", "-c", "echo a|b && echo c"]


# ── 4. 旧格式向后兼容 ───────────────────────────────────────────────────────

def test_legacy_formats_produce_unchanged_events():
    legacy = [
        "LG|execve|45296280000000000|100|90|1000|bash|/usr/bin/sudo|/bin/bash",
        "LG|connect|45296280000000001|101|1000|curl|10.0.0.5|443",
        "LG|openat|45296280000000002|102|100|1000|sudo|/etc/passwd|read",
    ]
    events = postprocess.convert_lines(
        legacy, "lab-host", boot_id="boot-uuid", boot_epoch=1700000000)
    assert [e["event_type"] for e in events] == ["execve", "connect", "openat"]
    for event in events:
        assert "argv" not in event
        assert "process_start_time" not in event
        assert "process_exec_id" not in event
        assert "boot_id" not in event  # 旧格式保持 P0 事件身份逐字段一致
        assert "start_time" not in event["raw"]
    assert events[0]["commandline"] == "/usr/bin/sudo"
    assert events[2]["severity"] == "info" and events[2]["file_path"] == "/etc/passwd"


# ── 5/6. 会话键确定性与健壮性 ───────────────────────────────────────────────

def test_session_id_deterministic_and_pid_reuse_distinct():
    sid = postprocess.synthetic_session_id
    assert sid(7, "111", "abcd1234-0000") == sid(7, "111", "abcd1234-0000")
    assert sid(7, "111", "abcd1234-0000") != sid(7, "222", "abcd1234-0000")  # pid 复用
    assert sid(7, "111", "abcd1234-0000") != sid(7, "111", "ffff0000-9999")  # 跨重启


def test_bad_lines_skipped_and_control_chars_sanitized():
    section = (f"/bin/sh{SEP}-c\x01printf bad"
               f"{SEP}{NUL}")
    lines = [
        "not-lg-line",
        "LG|execve|bad|pid|x|y|z",
        "LG|unknown|1|2|3",
        _p1_execve_line(argv=section),
        "",
    ]
    events = postprocess.convert_lines(lines, "h", boot_id="u", boot_epoch=1700000000)
    assert len(events) == 1
    assert events[0]["argv"] == ["/bin/sh", "-c printf bad"]


def test_timestamp_converts_monotonic_nsecs_with_boot_epoch():
    event = _convert(_p1_execve_line())[0]
    assert event["timestamp"] == "2025-04-22T04:31:20+00:00"


# ── 7/8/9. 后端入库与身份参与 ───────────────────────────────────────────────

def _enhanced_payload(hostname="lab-p1", pid=100, start="12345678901", argv=None, **extra):
    argv = argv if argv is not None else ["/usr/bin/wget", "http://127.0.0.1/x"]
    payload = {
        "timestamp": "2026-10-14T12:00:00Z", "hostname": hostname,
        "source": "ebpf_bpftrace", "event_type": "execve",
        "process_name": "wget", "parent_process": "bash",
        "commandline": " ".join(argv),
        "user": "root", "process_id": pid, "parent_process_id": 90,
        "process_start_time": start,
        "process_exec_id": postprocess.synthetic_session_id(pid, start, "boot-p1"),
        "boot_id": "boot-p1", "severity": "info",
        "argv": argv,
        "raw": {"kind": "execve", "uid": 0, "comm": "wget", "filename": "/usr/bin/wget",
                "hostname": hostname, "timestamp": "2026-10-14T12:00:00Z",
                "boot_id": "boot-p1", "start_time": int(start), "argv": argv},
    }
    payload.update(extra)
    return payload


def test_persist_sets_p1_columns_and_evidence_carries_argv(session_factory):
    db = session_factory()
    collector.append_events([_enhanced_payload()], db=db)
    row = db.query(models.RuntimeEvent).one()
    assert row.process_start_time == "12345678901"
    assert row.process_exec_id == "lg-bootp1-100-12345678901"
    assert row.boot_id == "boot-p1"
    assert "http://127.0.0.1/x" in row.commandline
    evidence = db.query(models.SecurityEvidence).one()
    assert evidence.evidence_type == "process"
    assert "http://127.0.0.1/x" in evidence.commandline
    assert "http://127.0.0.1/x" in json.loads(evidence.raw_data)["argv"]


def test_argv_participates_in_identity(session_factory):
    db = session_factory()
    collector.append_events([_enhanced_payload()], db=db)
    collector.append_events([_enhanced_payload()], db=db)  # 同事件重传 → 幂等
    other = _enhanced_payload(argv=["/usr/bin/wget", "http://127.0.0.2/y"])
    collector.append_events([other], db=db)  # argv 不同 → 不同事件
    assert db.query(models.RuntimeEvent).count() == 2


def test_legacy_upload_keeps_p1_columns_empty(session_factory):
    db = session_factory()
    legacy = postprocess.convert_lines(
        ["LG|execve|45296280000000000|100|90|0|bash|/usr/bin/sudo|/bin/bash"],
        "lab-legacy", boot_id="legacy-boot", boot_epoch=1700000000)[0]
    normalized = collector.append_events([legacy], db=db)[0]
    assert normalized["process_start_time"] == "" and normalized["process_exec_id"] == ""
    row = db.query(models.RuntimeEvent).one()
    assert row.process_start_time == "" and row.process_exec_id == ""
    assert stable_event_fingerprint(legacy)  # 身份基=完整报文（归一化后 raw=payload）


# ── 10. timeline 会话聚合 ───────────────────────────────────────────────────

def test_timeline_groups_by_synthetic_exec_id_and_pid_reuse(session_factory):
    db = session_factory()
    asset = models.LinuxAsset(hostname="lab-p1", ip_address="10.1.1.1", device_type="linux_server")
    db.add(asset)
    db.commit()
    events = [
        _enhanced_payload(pid=200, start="111"),
        _enhanced_payload(pid=200, start="111",
                          event_type="connect", destination="10.2.2.2", port=443,
                          commandline="wget -> 10.2.2.2:443", process_name="wget"),
        _enhanced_payload(pid=200, start="999"),  # 同 pid、不同 start_time（复用）
    ]
    collector.append_events(events, db=db)
    result = timeline(db, asset.id)
    grouped = [p for p in result["processes"] if p["basis"] == "exec_id"]
    assert len(grouped) == 2  # exec 与 connect 同会话键同组；pid 复用独立成组
    keys = [p["id"] for p in grouped]
    exec_key = f"{asset.id}:exec:lg-bootp1-200-111"
    assert keys.count(exec_key) == 1
    members = next(p for p in grouped if p["id"] == exec_key)
    assert len(members["event_ids"]) == 2  # execve + connect 归入同一会话
