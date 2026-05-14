#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcement_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct runeguard_exec_key);
    __type(value, __u32);
} blocked_execs SEC(".maps");

static __always_inline void submit_event(__u32 event_type, __u32 decision, const char *target)
{
    struct runeguard_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = event_type;
    event->decision = decision;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (target) {
        bpf_probe_read_kernel_str(event->target, sizeof(event->target), target);
    }

    bpf_ringbuf_submit(event, 0);
}

static __always_inline bool enforce_mode(void)
{
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&enforcement_enabled, &key);
    return enabled && *enabled == 1;
}

static __always_inline void basename_key(const char *path, struct runeguard_exec_key *key)
{
    int start = 0;

    for (int i = 0; i < RUNEGUARD_TARGET_LEN; i++) {
        if (path[i] == '/') {
            start = i + 1;
        }
        if (path[i] == '\0') {
            break;
        }
    }

    for (int i = 0; i < RUNEGUARD_EXEC_NAME_LEN - 1; i++) {
        char c = path[start + i];
        key->name[i] = c;
        if (c == '\0') {
            break;
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[0];
    submit_event(RUNEGUARD_EVENT_EXECVE, RUNEGUARD_DECISION_AUDIT, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *pathname = (const char *)ctx->args[1];
    submit_event(RUNEGUARD_EVENT_OPENAT, RUNEGUARD_DECISION_AUDIT, pathname);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(RUNEGUARD_EVENT_CONNECT, RUNEGUARD_DECISION_AUDIT, NULL);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(runeguard_file_open, struct file *file)
{
    submit_event(
        RUNEGUARD_EVENT_LSM_FILE_OPEN,
        enforce_mode() ? RUNEGUARD_DECISION_ALLOW : RUNEGUARD_DECISION_AUDIT,
        NULL
    );
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(runeguard_bprm_check, struct linux_binprm *bprm)
{
    char filename[RUNEGUARD_TARGET_LEN] = {};
    struct runeguard_exec_key key = {};
    __u32 *blocked;

    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(bprm, filename));
    basename_key(filename, &key);
    blocked = bpf_map_lookup_elem(&blocked_execs, &key);
    if (enforce_mode() && blocked && *blocked == 1) {
        submit_event(RUNEGUARD_EVENT_LSM_BPRM_CHECK, RUNEGUARD_DECISION_BLOCK, filename);
        return -13;
    }

    submit_event(
        RUNEGUARD_EVENT_LSM_BPRM_CHECK,
        enforce_mode() ? RUNEGUARD_DECISION_ALLOW : RUNEGUARD_DECISION_AUDIT,
        filename
    );
    return 0;
}
