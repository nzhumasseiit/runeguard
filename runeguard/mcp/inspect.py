import json
from dataclasses import dataclass, field
from pathlib import Path

from runeguard.redaction import redact_value


@dataclass
class MCPServerInfo:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


def inspect_mcp_config(path: Path) -> list[MCPServerInfo]:
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers", data.get("servers", data))
    if not isinstance(servers, dict):
        raise ValueError("MCP config must contain an object of servers")

    inspected = []
    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        command = str(config.get("command", ""))
        args = [str(arg) for arg in config.get("args", []) if isinstance(arg, (str, int, float))]
        env = config.get("env", {})
        env_keys = sorted(env.keys()) if isinstance(env, dict) else []
        risks = _risks(command, args, env if isinstance(env, dict) else {})
        inspected.append(MCPServerInfo(str(name), command, args, env_keys, risks))
    return inspected


def render_mcp_inspection(servers: list[MCPServerInfo], *, json_output: bool = False) -> str:
    payload = [server.__dict__ for server in servers]
    if json_output:
        return json.dumps(redact_value(payload), indent=2, sort_keys=True)

    if not servers:
        return "No MCP servers found."

    lines = ["Name  Command  Args  Env  Risks", "----  -------  ----  ---  -----"]
    for server in servers:
        lines.append(
            f"{server.name}  {server.command or '-'}  {' '.join(server.args) or '-'}  {', '.join(server.env_keys) or '-'}  {', '.join(server.risks) or 'none'}"
        )
    return "\n".join(lines)


def _risks(command: str, args: list[str], env: dict) -> list[str]:
    risks = []
    command_lower = command.lower()
    if not command:
        risks.append("missing command")
    if command_lower.startswith(("/tmp/", "/var/tmp/")) or ".." in command:
        risks.append("suspicious command path")
    if command_lower in {"sh", "bash", "zsh", "python", "node", "npx"}:
        risks.append("interpreter launch")
    joined_args = " ".join(args).lower()
    if any(token in joined_args for token in ("http://", "https://", "curl", "wget")):
        risks.append("network-capable args")
    for key, value in env.items():
        combined = f"{key}={value}"
        if any(marker in combined.upper() for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
            risks.append("env may include secrets")
            break
    return risks
