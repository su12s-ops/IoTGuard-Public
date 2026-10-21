#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "event.h"
#include "guard.skel.h"

static volatile sig_atomic_t stopping;
static struct guard_bpf *skel;
static const char *health_path;
static char hostname[256], boot[64];
static unsigned long long received, delivered, output_errors, abi_errors;
static int io_failed, metrics_ready;
static unsigned long long clock_ns(clockid_t id) {
    struct timespec ts; clock_gettime(id, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static void stop_signal(int sig) { (void)sig; stopping = 1; }
static void json_string(FILE *f, const char *s, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n && s[i]; i++) {
        unsigned char c = s[i];
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 32 || c >= 127) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}
/* Publish by rename: readers never observe half-written JSON. */
static int health(const char *phase) {
    unsigned long long totals[IG_COUNTERS] = {};
    int cpus = libbpf_num_possible_cpus();
    if (metrics_ready && cpus > 0) {
        unsigned long long *values = calloc(cpus, sizeof(*values));
        if (!values) return -1;
        for (unsigned int k = 0; k < IG_COUNTERS; k++) {
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &k, values)) {
                free(values); return -1;
            }
            for (int i = 0; i < cpus; i++) totals[k] += values[i];
        }
        free(values);
    }
    char *temp = NULL;
    if (asprintf(&temp, "%s.XXXXXX", health_path) < 0) return -1;
    int fd = mkstemp(temp);
    if (fd < 0) { free(temp); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(temp); free(temp); return -1; }
    const char *status = !strcmp(phase, "running") ? "running" :
                         !strcmp(phase, "stopped") ? "stopped" : "degraded";
    if (!strcmp(status, "running") && (totals[IG_RING_LOST] || totals[IG_MAP_ERRORS] ||
        totals[IG_READ_ERRORS] || totals[IG_UNMATCHED] || output_errors || abi_errors)) status = "degraded";
    fprintf(f, "{\"status\":\"%s\",\"phase\":\"%s\",\"pid\":%d,\"dropped_events\":", status, phase, getpid());
    if (metrics_ready) fprintf(f, "%llu", totals[IG_RING_LOST]); else fputs("null", f);
    fprintf(f, ",\"capabilities\":{\"driver\":\"libbpf_core\",\"phase\":\"%s\","
        "\"schema_version\":1,\"syscall_results\":true,\"observe_only\":true,"
        "\"path_resolution\":\"syscall_argument\",\"coverage\":\"execve and successful execveat; openat; connect syscall\","
        "\"kernel_observed\":%llu,\"kernel_emitted\":%llu,\"ring_lost\":%llu,"
        "\"map_errors\":%llu,\"read_errors\":%llu,\"unmatched_exits\":%llu,"
        "\"userspace_received\":%llu,\"stdout_delivered\":%llu,\"stdout_errors\":%llu,\"abi_errors\":%llu},"
        "\"detail\":\"Kernel counters cover attached hooks only; stdout delivery is not WAL/server acknowledgement\"}\n",
        phase, totals[0], totals[1], totals[2], totals[3], totals[4], totals[5],
        received, delivered, output_errors, abi_errors);
    int rc = fflush(f);
    if (!rc) rc = fsync(fd);
    if (fclose(f)) rc = -1;
    if (!rc) rc = rename(temp, health_path);
    if (rc) unlink(temp);
    free(temp); return rc;
}
static int output(const char *line, size_t size) {
    size_t offset = 0;
    unsigned long long deadline = clock_ns(CLOCK_MONOTONIC) + 2000000000ULL;
    while (offset < size) {
        ssize_t n = write(STDOUT_FILENO, line + offset, size - offset);
        if (n > 0) { offset += n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN && clock_ns(CLOCK_MONOTONIC) < deadline) {
            struct pollfd p = { .fd = STDOUT_FILENO, .events = POLLOUT }; poll(&p, 1, 100); continue;
        }
        output_errors++; io_failed = 1; stopping = 1; return -1;
    }
    delivered++; return 0;
}
static int on_event(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (io_failed) { output_errors++; return 0; }
    received++;
    struct ig_event *e = data;
    if (size != sizeof(*e) || e->abi != IG_ABI || e->kind < IG_EXEC || e->kind > IG_CONNECT) {
        abi_errors++; io_failed = 1; stopping = 1; return -1;
    }
    unsigned long long mono = clock_ns(CLOCK_MONOTONIC), wall = clock_ns(CLOCK_REALTIME);
    unsigned long long event_wall = wall - (mono - e->time_ns);
    time_t seconds = event_wall / 1000000000ULL;
    struct tm tm; gmtime_r(&seconds, &tm);
    char date[32], ip[INET6_ADDRSTRLEN] = "";
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &tm);
    if (e->family == AF_INET || e->family == AF_INET6) inet_ntop(e->family, e->address, ip, sizeof(ip));
    const char *operation = e->kind == IG_EXEC ? "exec" : e->kind == IG_OPEN ? "open" : "connect";
    const char *type = e->kind == IG_EXEC ? "execve" : e->kind == IG_OPEN ? "openat" : "connect";
    const char *result = e->retval >= 0 ? "success" : e->retval == -EINPROGRESS ? "pending" : "failure";
    char *line = NULL; size_t len = 0;
    FILE *f = open_memstream(&line, &len); if (!f) { io_failed = 1; stopping = 1; return -1; }
    fprintf(f, "{\"schema_version\":1,\"source\":\"c_ebpf\",\"pid_scope\":\"host_kernel\",\"timestamp\":\"%s.%09lluZ\",\"hostname\":", date, event_wall % 1000000000ULL);
    json_string(f, hostname, sizeof(hostname)); fputs(",\"boot_id\":", f); json_string(f, boot, sizeof(boot));
    fprintf(f, ",\"event_type\":\"%s\",\"operation\":\"%s\",\"result\":\"%s\",\"errno\":%lld,\"retval\":%lld,"
        "\"process_id\":%u,\"thread_id\":%u,\"parent_process_id\":%u,\"user\":\"%u\","
        "\"process_start_time\":\"%llu\",\"process_instance_id\":\"%s-%u-%llu\",\"process_exec_id\":",
        type, operation, result, e->retval < 0 ? -e->retval : 0, e->retval, e->pid, e->tid, e->ppid, e->uid,
        e->start_ns, boot, e->pid, e->start_ns);
    if (e->exec_ns) fprintf(f, "\"%s-%u-%llu-%llu\"", boot, e->pid, e->start_ns, e->exec_ns); else fputs("\"\"", f);
    fputs(",\"parent_exec_id\":", f);
    if (e->parent_exec_ns) fprintf(f, "\"%s-%u-%llu-%llu\"", boot, e->ppid, e->parent_start_ns, e->parent_exec_ns); else fputs("\"\"", f);
    fputs(",\"process_name\":", f); json_string(f, e->comm, sizeof(e->comm));
    fputs(",\"executable\":", f); json_string(f, e->kind == IG_EXEC ? e->path : "", sizeof(e->path));
    fputs(",\"file_path\":", f); json_string(f, e->kind == IG_OPEN ? e->path : "", sizeof(e->path));
    fputs(",\"argv\":[", f);
    for (int i = 0; i < 4 && e->argv[i][0]; i++) { if (i) fputc(',', f); json_string(f, e->argv[i], 48); }
    fputs("],\"commandline\":", f); json_string(f, e->path, sizeof(e->path));
    fprintf(f, ",\"destination\":\"%s\",\"port\":%u,\"severity\":\"info\","
        "\"rule\":\"IoTGuard %s syscall %s\",\"raw\":{\"monotonic_ns\":%llu,\"flags\":%u,"
        "\"family\":%u,\"truncation_flags\":%u,\"path_scope\":\"syscall_argument_not_canonical\","
        "\"result_scope\":\"syscall_return; open is not read/write; connect pending is not established\"}}\n",
        ip, e->port, operation, result, e->time_ns, e->flags, e->family, e->truncated);
    if (fclose(f)) { free(line); io_failed = 1; stopping = 1; return -1; }
    int rc = output(line, len); free(line); return rc;
}
int main(int argc, char **argv) {
    unsigned long duration = 0;
    if (argc < 2 || argc > 3) { fprintf(stderr, "usage: %s HEALTH_FILE [duration_seconds; 0=continuous]\n", argv[0]); return 2; }
    health_path = argv[1];
    if (argc == 3) { char *end; errno = 0; duration = strtoul(argv[2], &end, 10); if (errno || *end || argv[2][0] == '-') return 2; }
    umask(0077);
    char *lock_path = NULL; if (asprintf(&lock_path, "%s.lock", health_path) < 0) return 2;
    int lock = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600); free(lock_path);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB)) { fprintf(stderr, "sensor already active or state path inaccessible\n"); return 2; }
    gethostname(hostname, sizeof(hostname) - 1);
    FILE *bf = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!bf || !fgets(boot, sizeof(boot), bf)) return 2;
    fclose(bf); boot[strcspn(boot, "\r\n")] = 0;
    signal(SIGINT, stop_signal); signal(SIGTERM, stop_signal); signal(SIGPIPE, SIG_IGN);
    int flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) < 0) return 2;
    struct rlimit mem = { RLIM_INFINITY, RLIM_INFINITY }; setrlimit(RLIMIT_MEMLOCK, &mem);
    int rc = 1; struct ring_buffer *ring = NULL;
    if (health("starting")) goto out;
    skel = guard_bpf__open(); if (!skel) goto out;
    skel->rodata->collector_pid = getpid();
    struct stat ns;
    if (stat("/proc/self/ns/pid", &ns)) goto out;
    skel->rodata->namespace_dev = ns.st_dev;
    skel->rodata->namespace_ino = ns.st_ino;
    if (guard_bpf__load(skel)) goto out;
    metrics_ready = 1;
    ring = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
    if (!ring || guard_bpf__attach(skel)) goto out;
    if (health("running")) goto out;
    unsigned long long start = clock_ns(CLOCK_MONOTONIC), next = start;
    rc = 0;
    while (!stopping && (!duration || (clock_ns(CLOCK_MONOTONIC) - start) / 1000000000ULL < duration)) {
        int n = ring_buffer__poll(ring, 200);
        if (n < 0 && n != -EINTR) { rc = 1; break; }
        if (clock_ns(CLOCK_MONOTONIC) >= next) {
            if (health("running")) { rc = 1; break; }
            next = clock_ns(CLOCK_MONOTONIC) + 1000000000ULL;
        }
    }
out:
    if (skel) guard_bpf__detach(skel);
    if (ring && !io_failed) { if (ring_buffer__consume(ring) < 0) rc = 1; }
    if (io_failed) rc = 1;
    if (health(rc ? "failed" : "stopped")) rc = 1;
    ring_buffer__free(ring); guard_bpf__destroy(skel); close(lock);
    return rc;
}
