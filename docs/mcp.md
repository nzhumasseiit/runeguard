# RuneGuard MCP Integration

RuneGuard supports two MCP modes.

## Mode 1: Transparent Proxy

Sits in front of an existing MCP server. The agent connects to RuneGuard,
which forwards allowed calls to the real server and blocks the rest.

```bash
runeguard mcp proxy -- npx @modelcontextprotocol/server-filesystem /workspace
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "runeguard",
      "args": [
        "mcp",
        "proxy",
        "--policy",
        "policies/default.yaml",
        "--",
        "npx",
        "@modelcontextprotocol/server-filesystem",
        "/workspace"
      ]
    }
  }
}
```

The agent sees a normal filesystem MCP server. RuneGuard intercepts every
`tools/call` message, checks it against policy, and either forwards it or
returns a structured JSON-RPC error.

## Mode 2: Standalone Server

RuneGuard exposes its own policy-checked tools as an MCP server directly.

```bash
runeguard mcp serve --policy policies/default.yaml
```

MCP client config:

```json
{
  "mcpServers": {
    "runeguard": {
      "command": "runeguard",
      "args": ["mcp", "serve"]
    }
  }
}
```

Exposed tools:

- `read_file`
- `write_file`
- `shell`

## What Gets Blocked

All blocking is driven by the same policy file as the rest of RuneGuard:

- `read_file` on `.env`, `~/.ssh/`, `secrets/`
- `shell` with `rm -rf`, `curl`, `nc`, `scp`
- `http_post` to non-allowlisted domains

## Audit Logs

```bash
runeguard mcp proxy --audit-log .runeguard/mcp_audit.jsonl -- npx ...
```
