#ifndef RUNEGUARD_EVENTS_H
#define RUNEGUARD_EVENTS_H

#define RUNEGUARD_COMM_LEN 16
#define RUNEGUARD_TARGET_LEN 256
#define RUNEGUARD_EXEC_NAME_LEN 64

enum runeguard_event_type {
    RUNEGUARD_EVENT_EXECVE = 1,
    RUNEGUARD_EVENT_OPENAT = 2,
    RUNEGUARD_EVENT_CONNECT = 3,
    RUNEGUARD_EVENT_LSM_FILE_OPEN = 4,
    RUNEGUARD_EVENT_LSM_BPRM_CHECK = 5,
};

enum runeguard_decision {
    RUNEGUARD_DECISION_AUDIT = 0,
    RUNEGUARD_DECISION_ALLOW = 1,
    RUNEGUARD_DECISION_BLOCK = 2,
};

struct runeguard_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int event_type;
    unsigned int decision;
    char comm[RUNEGUARD_COMM_LEN];
    char target[RUNEGUARD_TARGET_LEN];
};

struct runeguard_exec_key {
    char name[RUNEGUARD_EXEC_NAME_LEN];
};

#endif
