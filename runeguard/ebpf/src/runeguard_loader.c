#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "events.h"
#include "runeguard.skel.h"

static volatile sig_atomic_t exiting = 0;

struct options {
    bool enforce;
    const char *policy_path;
};

static const struct argp_option opts[] = {
    {"mode", 'm', "MODE", 0, "trace or enforce"},
    {"policy", 'p', "PATH", 0, "RuneGuard policy path"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct options *options = state->input;

    switch (key) {
    case 'm':
        if (strcmp(arg, "enforce") == 0) {
            options->enforce = true;
        } else if (strcmp(arg, "trace") == 0) {
            options->enforce = false;
        } else {
            argp_error(state, "mode must be trace or enforce");
        }
        break;
    case 'p':
        options->policy_path = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "RuneGuard libbpf/CO-RE loader",
};

static void handle_signal(int signo)
{
    exiting = 1;
}

static const char *event_name(unsigned int type)
{
    switch (type) {
    case RUNEGUARD_EVENT_EXECVE:
        return "execve";
    case RUNEGUARD_EVENT_OPENAT:
        return "openat";
    case RUNEGUARD_EVENT_CONNECT:
        return "connect";
    case RUNEGUARD_EVENT_LSM_FILE_OPEN:
        return "lsm_file_open";
    case RUNEGUARD_EVENT_LSM_BPRM_CHECK:
        return "lsm_bprm_check";
    default:
        return "unknown";
    }
}

static const char *decision_name(unsigned int decision)
{
    switch (decision) {
    case RUNEGUARD_DECISION_ALLOW:
        return "ALLOW";
    case RUNEGUARD_DECISION_BLOCK:
        return "BLOCK";
    default:
        return "AUDIT";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct runeguard_event *event = data;

    printf(
        "{\"pid\":%u,\"uid\":%u,\"event\":\"%s\",\"decision\":\"%s\",\"comm\":\"%s\",\"target\":\"%s\"}\n",
        event->pid,
        event->uid,
        event_name(event->event_type),
        decision_name(event->decision),
        event->comm,
        event->target
    );
    fflush(stdout);
    return 0;
}

static int block_exec(struct runeguard_bpf *skel, const char *name)
{
    struct runeguard_exec_key key = {};
    unsigned int value = 1;

    snprintf(key.name, sizeof(key.name), "%s", name);
    return bpf_map__update_elem(
        skel->maps.blocked_execs,
        &key,
        sizeof(key),
        &value,
        sizeof(value),
        BPF_ANY
    );
}

static int seed_default_exec_policy(struct runeguard_bpf *skel)
{
    const char *blocked[] = {"rm", "curl", "nc", "scp", "ssh"};

    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        int err = block_exec(skel, blocked[i]);
        if (err) {
            return err;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct options options = {
        .enforce = false,
        .policy_path = "policies/default.yaml",
    };
    struct runeguard_bpf *skel;
    struct ring_buffer *rb = NULL;
    unsigned int key = 0;
    unsigned int enforce = 0;
    int err;

    argp_parse(&argp, argc, argv, 0, NULL, &options);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = runeguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open and load RuneGuard eBPF object\n");
        return 1;
    }

    enforce = options.enforce ? 1 : 0;
    err = bpf_map__update_elem(
        skel->maps.enforcement_enabled,
        &key,
        sizeof(key),
        &enforce,
        sizeof(enforce),
        BPF_ANY
    );
    if (err) {
        fprintf(stderr, "failed to set enforcement mode: %s\n", strerror(-err));
        goto cleanup;
    }

    err = seed_default_exec_policy(skel);
    if (err) {
        fprintf(stderr, "failed to seed default eBPF exec policy: %s\n", strerror(-err));
        goto cleanup;
    }

    err = runeguard_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach RuneGuard eBPF programs: %s\n", strerror(-err));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    fprintf(stderr, "RuneGuard eBPF %s mode active with policy %s\n",
            options.enforce ? "enforce" : "trace", options.policy_path);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll failed: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    runeguard_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
