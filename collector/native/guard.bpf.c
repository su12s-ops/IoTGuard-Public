#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"
char LICENSE[] SEC("license") = "GPL";
const volatile unsigned int collector_pid;
const volatile unsigned long long namespace_dev, namespace_ino;
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, IG_COUNTERS);
    __type(key, unsigned int); __type(value, unsigned long long); } counters SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, unsigned int); __type(value, struct ig_event); } scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768);
    __type(key, unsigned long long); __type(value, struct ig_event); } pending SEC(".maps");
struct epoch { unsigned long long start, exec; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768);
    __type(key, unsigned int); __type(value, struct epoch); } epochs SEC(".maps");
static __always_inline void count(unsigned int key) {
    unsigned long long *v = bpf_map_lookup_elem(&counters, &key);
    if (v) (*v)++;
}
static __always_inline int in_scope(void) {
    struct bpf_pidns_info ns = {};
    return !bpf_get_ns_current_pid_tgid(namespace_dev, namespace_ino, &ns, sizeof(ns)) && ns.tgid != collector_pid;
}
static __always_inline struct ig_event *begin(unsigned int kind) {
    unsigned long long id = bpf_get_current_pid_tgid();
    if (!in_scope()) return 0;
    unsigned int zero = 0;
    struct ig_event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent, group_leader);
    e->abi = IG_ABI; e->kind = kind; e->pid = id >> 32; e->tid = (unsigned int)id;
    e->uid = bpf_get_current_uid_gid(); e->time_ns = bpf_ktime_get_ns();
    e->start_ns = BPF_CORE_READ(leader, start_time);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->parent_start_ns = BPF_CORE_READ(parent, start_time);
    struct epoch *ep = bpf_map_lookup_elem(&epochs, &e->pid);
    if (ep && ep->start == e->start_ns) e->exec_ns = ep->exec;
    ep = bpf_map_lookup_elem(&epochs, &e->ppid);
    if (ep && ep->start == e->parent_start_ns) e->parent_exec_ns = ep->exec;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    return e;
}
static __always_inline void save(struct ig_event *e) {
    unsigned long long id = bpf_get_current_pid_tgid();
    count(IG_OBSERVED);
    if (bpf_map_update_elem(&pending, &id, e, BPF_ANY)) count(IG_MAP_ERRORS);
}
static __always_inline void emit(struct ig_event *e) {
    if (bpf_ringbuf_output(&events, e, sizeof(*e), 0)) count(IG_RING_LOST);
    else count(IG_EMITTED);
}
static __always_inline void path_read(char *dst, const void *src, struct ig_event *e) {
    long n = bpf_probe_read_user_str(dst, 256, src);
    if (n < 0) { count(IG_READ_ERRORS); e->truncated |= 2; }
    if (n == 256) e->truncated |= 1;
}
SEC("tracepoint/syscalls/sys_enter_execve")
int exec_enter(struct trace_event_raw_sys_enter *ctx) {
    struct ig_event *e = begin(IG_EXEC); if (!e) return 0;
    path_read(e->path, (void *)ctx->args[0], e);
    const char **argv = (void *)ctx->args[1];
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        const char *arg = 0;
        if (bpf_probe_read_user(&arg, sizeof(arg), argv + i)) { count(IG_READ_ERRORS); e->truncated |= 2; break; }
        if (!arg) break;
        long n = bpf_probe_read_user_str(e->argv[i], 48, arg);
        if (n < 0) { count(IG_READ_ERRORS); e->truncated |= 2; }
        if (n == 48) e->truncated |= 1;
        if (i == 3) {
            const char *extra = 0;
            if (!bpf_probe_read_user(&extra, sizeof(extra), argv + 4) && extra) e->truncated |= 1;
        }
    }
    save(e); return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int open_enter(struct trace_event_raw_sys_enter *ctx) {
    struct ig_event *e = begin(IG_OPEN); if (!e) return 0;
    path_read(e->path, (void *)ctx->args[1], e);
    e->flags = ctx->args[2]; save(e); return 0;
}
SEC("tracepoint/syscalls/sys_enter_connect")
int connect_enter(struct trace_event_raw_sys_enter *ctx) {
    struct ig_event *e = begin(IG_CONNECT); if (!e) return 0;
    unsigned char addr[28] = {};
    unsigned int len = ctx->args[2];
    if (len >= 28) len = 28;
    if (len < 2 || bpf_probe_read_user(addr, len, (void *)ctx->args[1])) {
        count(IG_READ_ERRORS); e->truncated |= 2;
    } else {
        __builtin_memcpy(&e->family, addr, 2);
        if (len >= 8 && e->family == 2) __builtin_memcpy(e->address, addr + 4, 4);
        else if (len >= 24 && e->family == 10) __builtin_memcpy(e->address, addr + 8, 16);
        if (len >= 4) e->port = ((unsigned short)addr[2] << 8) | addr[3];
    }
    save(e); return 0;
}
static __always_inline int finish(struct trace_event_raw_sys_exit *ctx, unsigned int kind) {
    unsigned long long id = bpf_get_current_pid_tgid();
    if (!in_scope()) return 0;
    struct ig_event *e = bpf_map_lookup_elem(&pending, &id);
    /* Successful exec is emitted at sched_process_exec, including execveat. */
    if (!e) { if (kind != IG_EXEC || ctx->ret < 0) count(IG_UNMATCHED); return 0; }
    if (e->kind == kind) { e->retval = ctx->ret; e->time_ns = bpf_ktime_get_ns(); emit(e); }
    bpf_map_delete_elem(&pending, &id); return 0;
}
SEC("tracepoint/syscalls/sys_exit_execve")
int exec_exit(struct trace_event_raw_sys_exit *ctx) { return finish(ctx, IG_EXEC); }
SEC("tracepoint/syscalls/sys_exit_openat")
int open_exit(struct trace_event_raw_sys_exit *ctx) { return finish(ctx, IG_OPEN); }
SEC("tracepoint/syscalls/sys_exit_connect")
int connect_exit(struct trace_event_raw_sys_exit *ctx) { return finish(ctx, IG_CONNECT); }
SEC("tracepoint/sched/sched_process_exec")
int exec_success(struct trace_event_raw_sched_process_exec *ctx) {
    struct ig_event *e = begin(IG_EXEC); if (!e) return 0;
    unsigned long long id = bpf_get_current_pid_tgid();
    unsigned long long old_id = (id & 0xffffffff00000000ULL) | (unsigned int)ctx->old_pid;
    struct ig_event *old = bpf_map_lookup_elem(&pending, &old_id);
    if (old && old->kind == IG_EXEC) {
        __builtin_memcpy(e->argv, old->argv, sizeof(e->argv)); e->truncated = old->truncated;
    } else { count(IG_OBSERVED); e->truncated |= 4; }
    unsigned int offset = ctx->__data_loc_filename & 0xffff;
    long n = bpf_probe_read_kernel_str(e->path, sizeof(e->path), (void *)ctx + offset);
    if (n < 0) { count(IG_READ_ERRORS); e->truncated |= 2; }
    if (n == sizeof(e->path)) e->truncated |= 1;
    e->exec_ns = e->time_ns;
    struct epoch ep = { e->start_ns, e->exec_ns };
    if (bpf_map_update_elem(&epochs, &e->pid, &ep, BPF_ANY)) count(IG_MAP_ERRORS);
    emit(e); bpf_map_delete_elem(&pending, &old_id); return 0;
}
SEC("tracepoint/sched/sched_process_exit")
int task_exit(void *ctx) {
    unsigned long long id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending, &id);
    unsigned int pid = id >> 32;
    if (pid == (unsigned int)id) bpf_map_delete_elem(&epochs, &pid);
    return 0;
}
