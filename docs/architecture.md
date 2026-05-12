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

The CLI exposes the policy layer for testers:

- `runeguard check` loads and prints a policy summary
- `runeguard demo` runs the poisoned README scenario
- `runeguard eval` evaluates one action without executing it
- `runeguard run -- <command>` gates a subprocess through shell policy
- `runeguard run --preload -- <command>` launches a command with the shim
- `runeguard daemon start` starts the policy daemon
- `runeguard shim build` builds the Linux shim
- `runeguard ebpf trace` starts BCC/eBPF syscall tracing

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

The strongest v1 boundary is still routed tool-call enforcement through `RuneGuardProxy`. The shim expands coverage for Linux child processes but is not a complete sandbox. The eBPF layer observes behavior but does not enforce policy yet.
