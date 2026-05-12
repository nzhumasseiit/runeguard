"""
RuneGuard as a standalone MCP server with policy-checked tools.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..policy import Policy
from ..proxy import RuneGuardProxy


TOOL_DEFINITIONS = [
    {
        "name": "read_file",
        "description": "Read a file from disk. Blocked by RuneGuard policy for protected paths.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path to read"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Blocked by RuneGuard policy for protected paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "shell",
        "description": "Run a shell command. Blocked by RuneGuard policy for dangerous patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]


class RuneGuardMCPServer:
    """Minimal MCP server that serves policy-checked tools over stdio JSON-RPC."""

    def __init__(self, policy: Policy, *, audit_log: str | None = None):
        self.proxy = RuneGuardProxy(policy, audit_log=audit_log)

    def serve(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            response = None
            try:
                msg = json.loads(line)
                response = self._handle(msg)
            except Exception as exc:
                response = self._error(None, -32700, str(exc))

            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

    def _handle(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "runeguard", "version": "1.0.0"},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOL_DEFINITIONS},
            }

        if method == "tools/call":
            return self._handle_tool_call(msg_id, msg.get("params", {}))

        if method.startswith("notifications/"):
            return None

        return self._error(msg_id, -32601, f"Method not found: {method}")

    def _handle_tool_call(self, msg_id: Any, params: dict) -> dict:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        try:
            if tool_name == "read_file":
                result = self.proxy.call(
                    "read_file",
                    lambda path: Path(path).read_text(encoding="utf-8"),
                    **arguments,
                )
            elif tool_name == "write_file":
                self.proxy.call(
                    "write_file",
                    lambda path, content: Path(path).write_text(content, encoding="utf-8"),
                    **arguments,
                )
                result = f"Written: {arguments.get('path')}"
            elif tool_name == "shell":
                completed = self.proxy.call(
                    "shell",
                    lambda command: subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False,
                    ),
                    **arguments,
                )
                result = completed.stdout + completed.stderr
            else:
                return self._error(msg_id, -32601, f"Unknown tool: {tool_name}")

        except PermissionError as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"[BLOCKED by RuneGuard] {exc}"}],
                    "isError": True,
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": str(result)}],
                "isError": False,
            },
        }

    def _error(self, msg_id: Any, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }


def main():
    import typer

    app = typer.Typer(help="RuneGuard standalone MCP server.")

    @app.command()
    def serve(
        policy: str = typer.Option("policies/default.yaml", help="Path to the policy file."),
        audit_log: str | None = typer.Option(None, help="Append decisions to this JSONL file."),
    ):
        loaded = Policy.from_file(policy)
        RuneGuardMCPServer(loaded, audit_log=audit_log).serve()

    app()


if __name__ == "__main__":
    main()
