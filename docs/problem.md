# Problem

Coding agents can read files, run shell commands, call APIs, and move data
across trust boundaries.

RuneGuard exists to protect local and CI coding-agent runs from:

- secret access
- destructive commands
- network exfiltration

Prompt-only guardrails are not enough because the model can still request unsafe
actions. RuneGuard adds runtime checks and a Docker sandbox boundary around the
agent's execution environment.
