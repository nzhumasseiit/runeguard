# Security Boundary

RuneGuard protects local and CI coding-agent runs from secret access,
destructive commands, and network exfiltration.

## Primary Boundary

The primary enforcement boundary is the Docker sandbox backend:

- non-root user
- read-only root filesystem
- read-only filtered workspace by default
- explicit writable mounts only
- network disabled by default
- all Linux capabilities dropped
- `no-new-privileges`
- CPU, memory, and PID limits

## Not A Hard Boundary

Policy/proxy mode is not a hard security boundary. It only controls actions that
are routed through RuneGuard.

The LD_PRELOAD shim is experimental and bypassable by static binaries, direct
syscalls, or processes that do not load the shim.

The eBPF layer is currently audit and visibility work. It is not the primary
enforcement mechanism.

## Current Limit

Docker sandbox mode is the first serious enforcement layer. Treat it as the
default for running untrusted or prompt-influenced agent commands.
