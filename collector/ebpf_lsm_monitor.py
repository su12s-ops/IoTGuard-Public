#!/usr/bin/env python3
"""eBPF LSM 实验监控（Linux 侧）。

职责：
1. 探测内核 BPF LSM 能力（securityfs 的 lsm 列表是否含 bpf、BTF 是否可用、
   bpftrace 能否列出 lsm:* 探针），结果打印并写入安全临时文件；
   上报后端由操作人员执行脚本打印出的 curl 命令完成（脚本自身不做网络请求）。
2. observe 模式（默认）：若内核支持，用 bpftrace 挂载 lsm:file_open LSM 钩子，
   以 JSONL 输出观察证据（只观察，绝不阻断）。
3. enforce 模式：真正的阻断需要 libbpf 编译的 BPF 程序在 LSM 钩子上返回 -EPERM，
   bpftrace 无法安全实现该语义。本脚本明确拒绝进入 enforce 并退出，绝不假装已阻断。

所有输出文件均通过 tempfile 安全 API 原子创建。
用法: sudo python3 ebpf_lsm_monitor.py [--mode observe] [--duration 60]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

OUTPUT_DIR = "/tmp/linuxguard-lsm"

OBSERVE_PROBE = r"""
lsm:file_open
/strstartswith(str(args->file->f_path.dentry->d_name.name), "passwd") ||
 strstartswith(str(args->file->f_path.dentry->d_name.name), "shadow") ||
 strstartswith(str(args->file->f_path.dentry->d_name.name), "mosquitto") ||
 strstartswith(str(args->file->f_path.dentry->d_name.name), "iotguard")/
{
  printf("LG-LSM|observe|%llu|%d|%u|%s|%s\n",
    nsecs, pid, uid, comm, str(args->file->f_path.dentry->d_name.name));
}
"""


def kernel_capability() -> dict:
    detail: dict[str, object] = {}
    # 1) lsm 列表（securityfs 可能未挂载，尝试挂载）
    try:
        subprocess.run(["mount", "-t", "securityfs", "securityfs", "/sys/kernel/security"],
                       capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass
    lsm_list = ""
    try:
        with open("/sys/kernel/security/lsm", encoding="utf-8") as fh:
            lsm_list = fh.read().strip()
    except OSError:
        detail["lsm_list_error"] = "无法读取 /sys/kernel/security/lsm（securityfs 未挂载或内核不支持）"
    detail["lsm_list"] = lsm_list
    bpf_lsm_in_list = "bpf" in [item.strip() for item in lsm_list.split(",")] if lsm_list else False
    # 2) BTF
    try:
        with open("/sys/kernel/btf/vmlinux", "rb") as fh:
            fh.read(4)
        detail["btf"] = "available"
    except OSError:
        detail["btf"] = "missing"
    # 3) bpftrace 能否枚举 lsm 探针
    bpftrace = shutil.which("bpftrace")
    lsm_probes = 0
    if bpftrace:
        try:
            result = subprocess.run([bpftrace, "-l", "lsm:*"], capture_output=True,
                                    text=True, timeout=30)
            lsm_probes = sum(1 for line in result.stdout.splitlines() if line.startswith("lsm:"))
        except (OSError, subprocess.SubprocessError) as exc:
            detail["bpftrace_lsm_error"] = str(exc)
    detail["bpftrace_lsm_probes"] = lsm_probes
    supported = bool(bpf_lsm_in_list and lsm_probes > 0)
    detail["supported"] = supported
    if not supported:
        detail["reason"] = (
            "内核未以 lsm=...,bpf 启动（当前列表: %s）或 bpftrace 无法枚举 lsm 探针；"
            "LSM 钩子挂载不可用，enforce 语义无法实现。"
            % (lsm_list or "未知")
        )
    return {"supported": supported, "lsm_list": lsm_list, "detail": json.dumps(detail, ensure_ascii=False)}


def write_capability_file(capability: dict) -> str:
    payload = {
        "device_id": os.environ.get("LINUXGUARD_DEVICE_ID", os.uname().nodename),
        "bpf_lsm_supported": capability["supported"],
        "lsm_list": capability["lsm_list"],
        "detail": capability["detail"],
    }
    fd, path = tempfile.mkstemp(prefix="capability-", suffix=".json", dir=OUTPUT_DIR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def observe_mode(duration: int, capability: dict) -> int:
    if not capability["supported"]:
        print("[LG-LSM] 内核不支持 BPF LSM，LSM 钩子（含 observe）不可用；"
              "请继续使用 ebpf_trace_capture.sh（kprobe/tracepoint 路线）。", file=sys.stderr)
        return 3
    bpftrace = shutil.which("bpftrace")
    if not bpftrace:
        print("[LG-LSM] 缺少 bpftrace", file=sys.stderr)
        return 2
    print(f"[LG-LSM] observe 模式挂载 lsm:file_open 钩子（{duration}s，只观察不阻断）...")
    process = subprocess.Popen([bpftrace, "-q", "-e", OBSERVE_PROBE],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + duration
    count = 0
    fd, out_path = tempfile.mkstemp(prefix="observe-", suffix=".jsonl", dir=OUTPUT_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            assert process.stdout is not None
            while time.monotonic() < deadline:
                line = process.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line.startswith("LG-LSM|"):
                    continue
                _, _, nsecs, pid, uid, comm, name = line.split("|")
                out.write(json.dumps({
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(nsecs) / 1e9)),
                    "source": "ebpf_lsm", "event_type": "lsm_file_open",
                    "process_name": comm, "process_id": int(pid), "user": uid,
                    "file_path": f"(lsm observe) {name}", "severity": "info",
                    "rule": "LG-LSM observe file_open",
                    "raw": {"hook": "file_open", "uid": int(uid)},
                }, ensure_ascii=False) + "\n")
                count += 1
    finally:
        process.terminate()
    print(f"[LG-LSM] observe 结束，共 {count} 条 LSM 观察证据 -> {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="eBPF LSM 实验监控")
    parser.add_argument("--mode", choices=["observe", "enforce"], default="observe")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    capability = kernel_capability()
    print("[LG-LSM] 内核能力探测:", json.dumps(capability, ensure_ascii=False, indent=2))
    capability_file = write_capability_file(capability)
    print(f"[LG-LSM] 能力结果已写入 {capability_file}；上报后端请执行：")
    print('  curl -X POST -H "X-Control-Token: <TOKEN>" -H "Content-Type: application/json" \\')
    print(f'       -d @{capability_file} <API_BASE>/runtime/lsm/capability')

    if args.mode == "enforce":
        print("[LG-LSM] enforce 需 libbpf 编译的 LSM 程序返回 -EPERM 才具备真实阻断语义，"
              "当前发布不包含该程序；拒绝进入 enforce，保持 observe。", file=sys.stderr)
        return 4
    return observe_mode(args.duration, capability)


if __name__ == "__main__":
    sys.exit(main())
