# RuneGuard seccomp-BPF Enforcement

seccomp is a Linux kernel feature that restricts which syscalls a process can
make. RuneGuard uses it as a kernel-boundary backstop below userspace, libc, and
the agent.

## How It Works

```bash
runeguard run --seccomp -- python agent.py
```

1. RuneGuard forks a child process.
2. In the child, before exec, RuneGuard calls `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
3. RuneGuard applies a seccomp-BPF program with `prctl(PR_SET_SECCOMP, ...)`.
4. `exec` runs the agent under the filter.
5. Child processes spawned by the agent inherit the filter.

## Requirements

- Linux kernel >= 3.5
- x86_64 in v1
- no root required for the current `PR_SET_NO_NEW_PRIVS` flow

## What Gets Blocked

v1 blocks a hardcoded set of syscalls that a coding agent should not need:

- `ptrace`
- `kexec_load`
- `reboot`
- `mount`

Path-level and command-level enforcement is handled by the MCP proxy,
LD_PRELOAD shim, and policy daemon. seccomp provides a hard kernel-level
backstop for dangerous syscall classes.

## Combining With LD_PRELOAD

```bash
runeguard daemon start &
runeguard run --preload --seccomp -- python agent.py
```

## Known Limitations

- seccomp cannot inspect string path arguments without ptrace/user notification
- ARM64 support requires arch-specific syscall numbers
- this is a backstop, not a complete sandbox profile
