# Roadmap

## v1: Breakable Policy Layer

Goal: give early users a real thing to run, attack, and critique.

Included:

- policy loading and validation
- file, shell, and HTTP policy decisions
- poisoned README demo
- dry action evaluation with `runeguard eval`
- Unix socket policy daemon
- Linux LD_PRELOAD shim for `open`, `openat`, `execve`, and `connect`
- BCC/eBPF syscall tracer foundation
- basic agent integration helpers
- JSONL audit logs
- explicit threat model and limitations

## Next: Agent Integrations

Goal: make RuneGuard useful with real coding-agent workflows.

Candidate integrations:

- MCP server mode
- GitHub Actions example
- local devbox example
- richer framework adapters beyond the initial LangChain/OpenAI-style helpers

## Later: Runtime Verification

Goal: compare declared tool intent with observed system behavior.

Candidate work:

- process correlation
- network observation
- filesystem observation
- eBPF-based policy verification
- hard enforcement strategy for Linux beyond LD_PRELOAD

## Not A Goal

RuneGuard should not pretend to be a full sandbox until it has a real isolation boundary. The project should stay honest about that line.
