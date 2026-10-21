#!/bin/sh
# Read-only capability inventory. Actual verifier/attach tests remain required.
printf 'kernel='; uname -r
printf 'machine='; uname -m
printf 'uid='; id -u
for path in /sys/kernel/btf/vmlinux /proc/config.gz; do
    if test -r "$path"; then printf 'readable=%s\n' "$path"; else printf 'unavailable=%s\n' "$path"; fi
done
for hook in syscalls/sys_enter_execve syscalls/sys_exit_execve syscalls/sys_enter_openat syscalls/sys_exit_openat syscalls/sys_enter_connect syscalls/sys_exit_connect sched/sched_process_exec sched/sched_process_exit; do
    if test -r "/sys/kernel/tracing/events/$hook/id" || test -r "/sys/kernel/debug/tracing/events/$hook/id"; then
        printf 'hook_present=%s\n' "$hook"
    else
        printf 'hook_unavailable=%s\n' "$hook"
    fi
done
if test -r /proc/config.gz; then
    zcat /proc/config.gz | grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|FTRACE_SYSCALLS|BPF_EVENTS)=' || true
elif test -r "/boot/config-$(uname -r)"; then
    grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|FTRACE_SYSCALLS|BPF_EVENTS)=' "/boot/config-$(uname -r)" || true
fi
