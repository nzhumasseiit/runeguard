#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>

#define ARG_LEN 256

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3,
};

struct event_t {
    u32 pid;
    u32 uid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char target[ARG_LEN];
};

BPF_PERF_OUTPUT(events);

static int submit_event(struct pt_regs *ctx, u32 event_type, const char __user *target) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.event_type = event_type;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (target) {
        bpf_probe_read_user_str(event.target, sizeof(event.target), target);
    }

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_execve(struct pt_regs *ctx) {
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
    return submit_event(ctx, EVENT_EXECVE, filename);
}

int trace_openat(struct pt_regs *ctx) {
    const char __user *pathname = (const char __user *)PT_REGS_PARM2(ctx);
    return submit_event(ctx, EVENT_OPENAT, pathname);
}

int trace_connect(struct pt_regs *ctx) {
    return submit_event(ctx, EVENT_CONNECT, NULL);
}
