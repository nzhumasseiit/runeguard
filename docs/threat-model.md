# Threat Model

RuneGuard v1 focuses on policy decisions around actions an AI coding agent asks to perform, plus Linux process interception and visibility foundations.

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
- enforcing selected Linux libc calls through an LD_PRELOAD shim when a process is launched with `runeguard run --preload`
- observing selected Linux syscalls with BCC/eBPF
- logging every allow/block decision in human-readable output and optional JSONL audit logs
- making bypass attempts easy to reproduce with `runeguard eval`

## Out Of Scope For v1

- kernel-level sandboxing
- stopping actions that do not go through RuneGuard, the shim, or a future enforcement layer
- full process tree isolation
- network packet enforcement or firewalling
- preventing LD_PRELOAD bypasses such as static binaries, direct syscalls, or privileged runtime changes
- malicious local users
- proving that an LLM understood or obeyed policy

## Security Claim

RuneGuard v1 is a policy enforcement layer for routed tool calls, with an experimental Linux LD_PRELOAD shim for child-process interception.

It is not a sandbox. If an agent can directly access the filesystem, shell, or network through another path that avoids the proxy and shim, RuneGuard cannot reliably stop that action yet. The eBPF layer is currently for visibility and future verification, not enforcement.
