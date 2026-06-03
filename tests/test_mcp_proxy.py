import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runeguard.integrity import unwrap_payload


TEST_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PARENT = TEST_ROOT.parents[0] if (TEST_ROOT / "cli.py").exists() else TEST_ROOT
FAKE_SERVER = Path(__file__).resolve().parent / "fake_mcp_server.py"


def test_mcp_proxy_forwards_allowed_and_blocks_unsafe_calls(tmp_path):
    policy = tmp_path / "policy.yaml"
    audit = tmp_path / "audit.jsonl"
    policy.write_text(
        """
version: 1
files:
  deny:
    - ".env"
    - ".git/**"
    - "**/secrets/**"
sandbox:
  writable_paths:
    - "tmp/"
network:
  default: deny
  allow_domains:
    - "api.github.com"
shell:
  deny_patterns:
    - "rm -rf"
    - "curl * | sh"
    - "cat .env"
    - "printenv"
    - "env"
mcp:
  allow_servers:
    - "fs"
  allow_tools:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "run_command"
""",
        encoding="utf-8",
    )
    process = _start_proxy(policy, audit)
    try:
        _send(process, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        listed = _recv(process)
        assert "tools" in listed["result"]

        _send(process, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        })
        allowed = _recv(process)
        assert "result" in allowed

        _send(process, {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": ".env", "token": "sk-abcdefghijklmnopqrstuvwxyz123456"}},
        })
        blocked = _recv(process)
        assert blocked["jsonrpc"] == "2.0"
        assert blocked["id"] == 3
        assert blocked["error"]["code"] == -32001
        assert "RuneGuard blocked" in blocked["error"]["message"]
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in json.dumps(blocked)

        _send(process, {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "printenv"}},
        })
        shell_blocked = _recv(process)
        assert "error" in shell_blocked

        _send(process, {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "list_directory", "arguments": {"url": "https://evil.example/data"}},
        })
        network_blocked = _recv(process)
        assert "domain not allowlisted" in network_blocked["error"]["message"]
    finally:
        process.stdin.close()
        process.terminate()
        process.wait(timeout=5)

    audit_text = audit.read_text(encoding="utf-8")
    decisions = {
        unwrap_payload(json.loads(line))["decision"]
        for line in audit_text.splitlines()
        if line.strip()
    }
    assert "allow" in decisions
    assert "block" in decisions
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in audit_text


def test_mcp_proxy_blocks_resource_reads(tmp_path):
    policy = tmp_path / "policy.yaml"
    audit = tmp_path / "audit.jsonl"
    policy.write_text(
        """
version: 1
files:
  deny:
    - ".env"
mcp:
  allow_servers:
    - "fs"
""",
        encoding="utf-8",
    )
    process = _start_proxy(policy, audit)
    try:
        _send(process, {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/read",
            "params": {"uri": "file:///.env"},
        })
        blocked = _recv(process)
        assert blocked["error"]["code"] == -32001
    finally:
        process.stdin.close()
        process.terminate()
        process.wait(timeout=5)


def _start_proxy(policy: Path, audit: Path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PACKAGE_PARENT)
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "runeguard.cli",
            "mcp",
            "proxy",
            "--policy",
            str(policy),
            "--server-name",
            "fs",
            "--audit-log",
            str(audit),
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=PACKAGE_PARENT,
    )


def _send(process, message):
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def _recv(process):
    line = process.stdout.readline()
    assert line, process.stderr.read()
    return json.loads(line)


def test_proxy_upstream_not_found(tmp_path):
    """MCPPolicyProxy.run() raises RuntimeError with a clear message when the upstream command doesn't exist."""
    from runeguard.mcp.proxy import MCPPolicyProxy
    from runeguard.policy import Policy

    proxy = MCPPolicyProxy(
        Policy({}),
        ["/nonexistent-binary-runeguard-test"],
        audit_log=str(tmp_path / "audit.jsonl"),
    )

    with pytest.raises(RuntimeError, match="MCP server executable not found"):
        asyncio.run(proxy.run())
