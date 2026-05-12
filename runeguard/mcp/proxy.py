"""
RuneGuard MCP Policy Proxy.

Intercepts MCP JSON-RPC tool calls and applies RuneGuard policy before
forwarding to the real upstream MCP server.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from ..decision import DecisionType
from ..logger import log_decision
from ..policy import Policy


class MCPPolicyProxy:
    """Transparent MCP proxy that enforces RuneGuard policy on tool calls."""

    def __init__(
        self,
        policy: Policy,
        upstream_cmd: list[str],
        *,
        audit_log: str | None = None,
        json_logs: bool = False,
    ):
        self.policy = policy
        self.upstream_cmd = upstream_cmd
        self.audit_log = audit_log
        self.json_logs = json_logs

    async def run(self) -> None:
        upstream = await asyncio.create_subprocess_exec(
            *self.upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )

        if upstream.stdin is None or upstream.stdout is None:
            raise RuntimeError("failed to open upstream MCP stdio pipes")

        try:
            await asyncio.gather(
                self._client_to_server(sys.stdin.buffer, upstream.stdin),
                self._server_to_client(upstream.stdout, sys.stdout.buffer),
            )
        finally:
            if upstream.returncode is None:
                upstream.terminate()
                await upstream.wait()

    async def _client_to_server(
        self,
        reader: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        loop = asyncio.get_running_loop()

        while True:
            line = await loop.run_in_executor(None, reader.readline)
            if not line:
                writer.close()
                await writer.wait_closed()
                break

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                writer.write(line)
                await writer.drain()
                continue

            if msg.get("method") == "tools/call":
                blocked_response = self._check_tool_call(msg)
                if blocked_response is not None:
                    encoded = json.dumps(blocked_response).encode("utf-8") + b"\n"
                    await loop.run_in_executor(None, sys.stdout.buffer.write, encoded)
                    await loop.run_in_executor(None, sys.stdout.buffer.flush)
                    continue

            writer.write(line)
            await writer.drain()

    async def _server_to_client(
        self,
        reader: asyncio.StreamReader,
        writer: Any,
    ) -> None:
        loop = asyncio.get_running_loop()

        while True:
            line = await reader.readline()
            if not line:
                break

            await loop.run_in_executor(None, writer.write, line)
            await loop.run_in_executor(None, writer.flush)

    def _check_tool_call(self, msg: dict) -> dict | None:
        """Return a JSON-RPC error dict when blocked, else None."""
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        msg_id = msg.get("id")

        if not isinstance(arguments, dict):
            arguments = {}

        decision = self.policy.decide(tool_name, **arguments)
        log_decision(
            tool_name,
            decision,
            arguments,
            audit_log=self.audit_log,
            json_logs=self.json_logs,
        )

        if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32600,
                    "message": f"RuneGuard blocked: {decision.reason}",
                    "data": {
                        "tool": tool_name,
                        "decision": decision.type.value,
                        "reason": decision.reason,
                    },
                },
            }

        return None


def run_proxy(policy: Policy, upstream_cmd: list[str], **kwargs) -> None:
    proxy = MCPPolicyProxy(policy, upstream_cmd, **kwargs)
    asyncio.run(proxy.run())
