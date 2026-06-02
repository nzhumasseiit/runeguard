"""
RuneGuard MCP Policy Proxy.

Intercepts MCP JSON-RPC tool calls and applies RuneGuard policy before
forwarding to the real upstream MCP server.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import Any
from urllib.parse import urlparse

from ..decision import Decision, DecisionType
from ..logger import log_decision
from ..policy import Policy
from ..redaction import redact_value


class MCPPolicyProxy:
    """Transparent MCP proxy that enforces RuneGuard policy on tool calls."""

    def __init__(
        self,
        policy: Policy,
        upstream_cmd: list[str],
        *,
        audit_log: str | None = None,
        json_logs: bool = False,
        server_name: str = "upstream",
    ):
        self.policy = policy
        self.upstream_cmd = upstream_cmd
        self.audit_log = audit_log
        self.json_logs = json_logs
        self.server_name = server_name

    async def run(self) -> None:
        try:
            upstream = await asyncio.create_subprocess_exec(
                *self.upstream_cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=sys.stderr,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"MCP server executable not found: {self.upstream_cmd[0]}") from exc
        except OSError as exc:
            raise RuntimeError(f"failed to start MCP server {self.upstream_cmd[0]}: {exc}") from exc

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

            checked = self.check_client_message(msg)
            if checked is not None:
                should_forward, blocked_response = checked
                if not should_forward and blocked_response is not None:
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

    def check_client_message(self, msg: dict) -> tuple[bool, dict | None] | None:
        """Return forwarding decision and optional JSON-RPC response."""
        method = msg.get("method")
        if method not in {"tools/list", "tools/call", "resources/list", "resources/read"}:
            return None

        server_decision = self.policy.decide("mcp_server", server_name=self.server_name)
        self._log("mcp_server", server_decision, {"server_name": self.server_name})
        if server_decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, server_decision, "mcp_server")

        if method in {"tools/list", "resources/list"}:
            self._log(method, Decision(DecisionType.ALLOW, "MCP list request allowed"), {"server_name": self.server_name})
            return True, None

        if method == "resources/read":
            decision = self._resource_read_decision(msg)
            self._log("resources/read", decision, self._params(msg))
            if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
                return False, self._error(msg, decision, "resources/read")
            return True, None

        decision = self._tool_call_decision(msg)
        params = self._params(msg)
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        self._log(
            "tools/call",
            decision,
            {"server_name": self.server_name, "tool_name": tool_name, "arguments": arguments},
        )
        if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            return False, self._error(msg, decision, tool_name or "tools/call")
        return True, None

    def _tool_call_decision(self, msg: dict) -> Decision:
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if not isinstance(arguments, dict):
            arguments = {}

        tool_decision = self.policy.decide("mcp_tool", server_name=self.server_name, mcp_tool=tool_name)
        if tool_decision.type != DecisionType.ALLOW:
            return tool_decision

        path = self._argument_path(arguments)
        if self._looks_like_read(tool_name) and path:
            decision = self.policy.decide("read_file", path=path)
            if decision.type != DecisionType.ALLOW:
                return decision

        if self._looks_like_write(tool_name) and path:
            decision = self.policy.decide("write_file", path=path)
            if decision.type != DecisionType.ALLOW:
                return decision
            if self.policy.writable_paths and not self._is_writable(path):
                return Decision(DecisionType.BLOCK, f"write path not allowed by policy: {path}")

        command = self._argument_command(arguments)
        if command:
            decision = self.policy.decide("shell", command=command)
            if decision.type != DecisionType.ALLOW:
                return decision

        for url_or_host in self._urls_or_hosts(arguments):
            decision = self.policy.decide("connect", url=url_or_host if "://" in url_or_host else f"https://{url_or_host}")
            if decision.type != DecisionType.ALLOW:
                return decision

        return Decision(DecisionType.ALLOW, "MCP tool call allowed")

    def _check_tool_call(self, msg: dict) -> dict | None:
        """Compatibility helper for older unit tests."""
        checked = self.check_client_message(msg)
        if checked is None:
            return None
        should_forward, response = checked
        return None if should_forward else response

    def _resource_read_decision(self, msg: dict) -> Decision:
        params = self._params(msg)
        uri = str(params.get("uri") or params.get("path") or "")
        path = uri
        if uri.startswith("file://"):
            path = urlparse(uri).path
        return self.policy.decide("read_file", path=path)

    def _error(self, msg: dict, decision: Decision, tool_name: str) -> dict:
        reason = redact_value(decision.reason)
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": -32001,
                "message": f"RuneGuard blocked: {reason}",
                "data": redact_value({
                    "server": self.server_name,
                    "tool": tool_name,
                    "decision": decision.type.value,
                    "reason": reason,
                }),
            },
        }

    def _log(self, tool_name: str, decision: Decision, kwargs: dict):
        log_decision(
            tool_name,
            decision,
            redact_value(kwargs),
            audit_log=self.audit_log,
            json_logs=self.json_logs,
            quiet=True,
        )

    def _params(self, msg: dict) -> dict:
        params = msg.get("params", {})
        return params if isinstance(params, dict) else {}

    def _argument_path(self, arguments: dict) -> str:
        for key in ("path", "file", "filepath", "file_path", "uri"):
            value = arguments.get(key)
            if isinstance(value, str):
                return value
        return ""

    def _argument_command(self, arguments: dict) -> str:
        for key in ("command", "cmd", "shell"):
            value = arguments.get(key)
            if isinstance(value, str):
                return value
        return ""

    def _looks_like_read(self, tool_name: str) -> bool:
        normalized = tool_name.lower()
        return normalized in {"read_file", "resources/read"} or "read" in normalized or "cat" in normalized

    def _looks_like_write(self, tool_name: str) -> bool:
        normalized = tool_name.lower()
        return normalized in {"write_file"} or any(token in normalized for token in ("write", "create", "append", "edit"))

    def _is_writable(self, path: str) -> bool:
        normalized = path.replace("\\", "/").lstrip("./")
        for writable in self.policy.writable_paths:
            candidate = writable.replace("\\", "/").lstrip("./").rstrip("/")
            if normalized == candidate or normalized.startswith(f"{candidate}/"):
                return True
        return False

    def _urls_or_hosts(self, value: Any, key_hint: str = "") -> list[str]:
        found: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                found.extend(self._urls_or_hosts(item, str(key)))
        elif isinstance(value, list):
            for item in value:
                found.extend(self._urls_or_hosts(item, key_hint))
        elif isinstance(value, str):
            found.extend(re.findall(r"https?://[^\s\"'<>]+", value))
            if key_hint.lower() in {"url", "uri", "host", "hostname", "domain", "endpoint"}:
                for host in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", value):
                    if not any(host in existing for existing in found):
                        found.append(host)
        return found


def run_proxy(policy: Policy, upstream_cmd: list[str], **kwargs) -> None:
    proxy = MCPPolicyProxy(policy, upstream_cmd, **kwargs)
    asyncio.run(proxy.run())
