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

## Optional Landlock Backend

On Linux systems with Landlock support, `runeguard run --backend landlock -- ...`
applies filesystem restrictions before executing the command. Landlock allows
read access to RuneGuard's filtered workspace view and write access only to
policy `writable_paths`.

Landlock is fail-closed by default. If it cannot initialize, RuneGuard exits
unless the user explicitly passes `--allow-weak-fallback`.

## Not A Hard Boundary

Policy/proxy mode is not a hard security boundary. It only controls actions that
are routed through RuneGuard.

The LD_PRELOAD shim is experimental and bypassable by static binaries, direct
syscalls, or processes that do not load the shim.

The eBPF layer now uses libbpf/CO-RE source and a standalone loader interface.
Its enforcement mode can deny configured executable basenames through BPF LSM.
It requires Linux BPF LSM support and host privileges to load BPF programs.
Treat it as experimental until policy maps cover the full RuneGuard policy
surface.

## Current Limit

Docker sandbox mode is the first serious enforcement layer. Treat it as the
default for running untrusted or prompt-influenced agent commands.
