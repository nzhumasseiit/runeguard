# Architecture

RuneGuard v1 has six small layers.

## Policy

`runeguard.policy.Policy` loads YAML and turns requested actions into decisions:

- `ALLOW`
- `BLOCK`
- `REQUIRE_APPROVAL`

The default policy supports:

- protected file paths
- allowed HTTP domains
- blocked shell command patterns
- tools that always require human approval
- allowed environment variable metadata
- maximum file size metadata for integrations

## Proxy

`runeguard.proxy.RuneGuardProxy` wraps a tool function.

Flow:

1. receive `tool_name` and action arguments
2. ask `Policy.decide(...)`
3. log the decision
4. block or call the wrapped function

This keeps policy decisions separate from the tool implementation.

## Daemon

`runeguard.daemon.RuneGuardDaemon` exposes policy decisions over a local Unix socket.

Request shape:

```json
{"tool_name": "open", "pathname": ".env"}
```

Response shape:

```json
{"type": "BLOCK", "reason": "protected path access: .env", "allow": false}
```

The daemon is used by the LD_PRELOAD shim and can also be used by external integrations.

## LD_PRELOAD Shim

`runeguard/shim/preload.c` intercepts selected libc calls for dynamically linked Linux processes:

- `open`
- `openat`
- `execve`
- `connect`

The shim asks the daemon for a decision through `RUNEGUARD_SOCKET`. By default it fails closed if the daemon is unavailable. Set `RUNEGUARD_FAIL_CLOSED=0` to use the simple local fallback policy.

Limitations:

- Linux only
- does not affect statically linked binaries
- does not stop direct syscalls that bypass intercepted libc functions
- does not replace sandboxing

## CLI

The CLI exposes the policy and sandbox layers for testers:

- `runeguard init` creates a starter `runeguard.yaml` and `.runeguard/` state directory
- `runeguard doctor` checks Docker, OS, seccomp/Landlock hints, and policy presence
- `runeguard check` loads and prints a policy summary
- `runeguard demo` runs the poisoned README scenario
- `runeguard eval` evaluates one action without executing it
- `runeguard run -- <command>` runs a command in the Docker sandbox backend
- `runeguard run --backend host -- <command>` gates a host subprocess through shell policy
- `runeguard run --backend host --preload -- <command>` launches a host command with the shim
- `runeguard daemon start` starts the policy daemon
- `runeguard shim build` builds the Linux shim
- `runeguard ebpf trace` starts BCC/eBPF syscall tracing

## Docker Sandbox

`runeguard.core.docker.DockerSandboxRunner` is the first serious sandbox backend.

Default behavior:

- bind-mounts only the selected workspace at `/workspace` read-only
- mounts policy `writable_paths` separately as writable bind mounts
- runs with the caller's uid/gid when possible
- disables networking with `--network none`
- applies memory, CPU, and process limits
- drops Linux capabilities
- sets `no-new-privileges`
- uses `--read-only` for the container root filesystem
- adds tmpfs mounts for `/tmp` and `/run`

The Docker backend avoids mounting user home directories and common secret
locations such as `~/.ssh`, `~/.aws`, and `~/.config`. The unsafe compatibility
flag `--unsafe-writable-workspace` restores the old writable workspace mount
when a tool cannot yet operate with policy-driven writable paths.

## Agent Helpers

`runeguard.agents` contains small adapter classes for routing agent tool calls through `RuneGuardProxy`.

Current helpers:

- `GuardedAgent`
- `GuardedLangChainTools`
- `GuardedToolRegistry`

## eBPF Tracer

`runeguard.ebpf` contains a BCC loader and probe source for Linux syscall visibility:

- `execve`
- `openat`
- `connect`

The v1 eBPF layer is visibility-first. It prints structured events and is intended to become the runtime verification layer.

## Audit Logs

`--audit-log <path>` appends JSONL decision records. Payload-like fields are redacted so logs are useful for debugging without casually dumping secrets.

## Security Boundary

Policy/proxy mode is not a hard security boundary because it only controls
actions routed through RuneGuard. The LD_PRELOAD shim is experimental and
bypassable. Docker sandbox mode is the first step toward stronger enforcement.
The eBPF layer observes behavior but does not enforce policy yet.
