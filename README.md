# RuneGuard

Runtime enforcement layer for AI agents.

RuneGuard sits between AI agents and their tools, enforcing what agents are allowed to do across files, shell commands, APIs, and system boundaries.

Unlike prompt-level guardrails, RuneGuard verifies actions at runtime.

## Early demo goal

An agent is asked to summarize a repo. A poisoned prompt tries to make it read `.env` and exfiltrate secrets.

RuneGuard blocks the action and logs the attempted violation.

## Planned layers

- Tool-call policy enforcement
- Audit logs
- eBPF-backed runtime verification
- Tool intent vs system behavior correlation

## Status

Early prototype.
