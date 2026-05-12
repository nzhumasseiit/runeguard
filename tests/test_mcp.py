from runeguard.mcp.proxy import MCPPolicyProxy
from runeguard.mcp.server import RuneGuardMCPServer
from runeguard.policy import Policy


def make_server(policy_dict: dict) -> RuneGuardMCPServer:
    return RuneGuardMCPServer(Policy(policy_dict))


def call_tool(server: RuneGuardMCPServer, tool_name: str, arguments: dict) -> dict:
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    return server._handle_tool_call(msg["id"], msg["params"])


def test_blocked_read_returns_error():
    server = make_server({"protected_paths": [".env"]})
    result = call_tool(server, "read_file", {"path": ".env"})
    assert result["result"]["isError"] is True
    assert "BLOCKED" in result["result"]["content"][0]["text"]


def test_blocked_shell_returns_error():
    server = make_server({"blocked_commands": ["rm -rf"]})
    result = call_tool(server, "shell", {"command": "rm -rf /tmp/test"})
    assert result["result"]["isError"] is True


def test_allowed_shell_runs():
    server = make_server({})
    result = call_tool(server, "shell", {"command": "echo hello"})
    assert result["result"]["isError"] is False
    assert "hello" in result["result"]["content"][0]["text"]


def test_initialize_returns_server_info():
    server = make_server({})
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    result = server._handle(msg)
    assert result["result"]["serverInfo"]["name"] == "runeguard"


def test_tools_list_returns_definitions():
    server = make_server({})
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    result = server._handle(msg)
    tool_names = [tool["name"] for tool in result["result"]["tools"]]
    assert "read_file" in tool_names
    assert "shell" in tool_names


def test_proxy_check_blocks_protected_path():
    policy = Policy({"protected_paths": [".env"]})
    proxy = MCPPolicyProxy(policy, ["echo"])

    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": ".env"}},
    }
    result = proxy._check_tool_call(msg)
    assert result is not None
    assert result["error"]["data"]["decision"] == "BLOCK"


def test_proxy_check_allows_safe_read():
    policy = Policy({"protected_paths": [".env"]})
    proxy = MCPPolicyProxy(policy, ["echo"])

    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "README.md"}},
    }
    result = proxy._check_tool_call(msg)
    assert result is None
