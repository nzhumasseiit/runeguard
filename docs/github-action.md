# RuneGuard GitHub Action

Add one block to any GitHub Actions workflow to enforce RuneGuard policy on
AI coding agents running in CI.

## Quickstart

```yaml
steps:
  - uses: actions/checkout@v4

  - name: Run AI agent with RuneGuard
    uses: runeguard/action@v1
    with:
      command: python scripts/run_agent.py
```

That's it. RuneGuard installs itself, wraps your agent command, and uploads an
audit log artifact. If the agent tried to read `.env`, exfiltrate secrets, or
run a blocked shell command, the step fails with a clear error.

## With a custom policy file

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
    policy: policies/ci-strict.yaml
```

## With the MCP proxy (Claude Code, Cursor)

For agents that communicate over MCP, wrap the MCP server instead of the agent:

```yaml
- uses: runeguard/action@v1
  with:
    command: >
      runeguard mcp proxy
      --policy policies/ci-strict.yaml
      --
      npx @modelcontextprotocol/server-filesystem /workspace
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `command` | (required) | Agent command to run |
| `policy` | `""` | Path to policy YAML file |
| `profile` | `ci` | Built-in profile: `ci`, `strict`, `permissive` |
| `audit-log` | `.runeguard/audit.jsonl` | Audit log path |
| `upload-audit` | `true` | Upload audit as artifact |
| `fail-on-block` | `true` | Fail step if anything was blocked |
| `backend` | `host` | `host` or `docker` |
| `runeguard-version` | `""` | Pin a version |

## Outputs

| Output | Description |
|--------|-------------|
| `blocked` | `"true"` if anything was blocked |
| `block-count` | Number of blocked actions |
| `audit-log-path` | Path to the audit log |

## Reading block results in downstream steps

```yaml
- uses: runeguard/action@v1
  id: runeguard
  with:
    command: python scripts/run_agent.py
    fail-on-block: "false"   # Don't fail, just report

- name: Comment on PR with block summary
  if: steps.runeguard.outputs.blocked == 'true'
  run: |
    echo "RuneGuard blocked ${{ steps.runeguard.outputs.block-count }} action(s)"
```

## Uploading audit logs to a hosted policy server (future)

When `app.runeguard.dev` is live, add your API key to secrets and the action
will upload the audit log automatically:

```yaml
- uses: runeguard/action@v1
  with:
    command: python scripts/run_agent.py
  env:
    RUNEGUARD_API_KEY: ${{ secrets.RUNEGUARD_API_KEY }}
```
