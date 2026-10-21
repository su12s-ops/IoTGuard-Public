#ifndef IOTGUARD_EVENT_H
#define IOTGUARD_EVENT_H
#define IG_ABI 1
enum ig_kind { IG_EXEC = 1, IG_OPEN = 2, IG_CONNECT = 3 };
enum ig_counter { IG_OBSERVED, IG_EMITTED, IG_RING_LOST, IG_MAP_ERRORS,
                  IG_READ_ERRORS, IG_UNMATCHED, IG_COUNTERS };
struct ig_event {
    unsigned long long time_ns, start_ns, exec_ns, parent_start_ns, parent_exec_ns;
    long long retval;
    unsigned int abi, kind, pid, tid, ppid, uid, flags, truncated;
    unsigned short family, port;
    unsigned char address[16];
    char comm[16], path[256], argv[4][48];
};
#endif
