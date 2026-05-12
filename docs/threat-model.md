# Threat Model

RuneGuard protects local and CI coding-agent runs from secret access,
destructive commands, and network exfiltration. It combines policy decisions
with a Docker sandbox backend for stronger process isolation.

## Assets

- local secrets such as `.env`, SSH keys, API tokens, and service credentials
- source code and private repository contents
- shell access on a developer machine, CI runner, or sandbox
- outbound network access that could be used for exfiltration
- audit logs that may become incident evidence

## Attacker

The main attacker is prompt injection or malicious project content that influences an otherwise useful coding agent.

Examples:

- a README tells the agent to read `.env`
- a dependency file asks the agent to run a destructive command
- a generated instruction asks the agent to POST files to an external domain
- a tool response tries to smuggle a second action inside normal-looking output

## In Scope For v1

- deciding whether a requested file action should be allowed
- deciding whether a requested shell command should be allowed
- deciding whether a requested HTTP action targets an allowed domain
- running commands in a Docker container with non-root execution
- mounting the workspace read-only by default
- allowing only policy-defined writable workspace paths
- denying network access by default in Docker sandbox mode
- applying simple Docker memory, CPU, and process limits
- enforcing selected Linux libc calls through an LD_PRELOAD shim when a process is launched with `runeguard run --backend host --preload`
- observing selected Linux syscalls with BCC/eBPF
- logging every allow/block decision in human-readable output and optional JSONL audit logs
- making bypass attempts easy to reproduce with `runeguard eval`

## Out Of Scope For v1

- kernel-level sandboxing outside Docker's configured isolation
- stopping actions that do not go through RuneGuard, Docker sandbox mode, the shim, or a future enforcement layer
- complete process tree isolation outside the selected backend
- network packet enforcement or firewalling
- preventing LD_PRELOAD bypasses such as static binaries, direct syscalls, or privileged runtime changes
- malicious local users
- proving that an LLM understood or obeyed policy

## Security Claim

RuneGuard has policy/proxy modes for routed tool calls and a Docker sandbox mode
as the first stronger enforcement backend.

Policy/proxy mode alone is not a hard security boundary. The LD_PRELOAD shim is
experimental and bypassable. Docker sandbox mode provides a real process
boundary, but it should still be treated as an early sandbox backend. The eBPF
layer is currently for visibility and future verification, not primary
enforcement.
