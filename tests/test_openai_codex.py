import json

import pytest

from runeguard.agents.openai_codex import GuardedToolkit, runeguard_tool
from runeguard.integrity import unwrap_payload
from runeguard.policy import Policy


def test_runeguard_tool_blocks_command(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("blocked_commands:\n  - rm -rf\n", encoding="utf-8")

    called = False

    @runeguard_tool(policy)
    def shell(command):
        nonlocal called
        called = True
        return command

    with pytest.raises(PermissionError, match="blocked shell command pattern: rm -rf"):
        shell(command="rm -rf /tmp/project")

    assert called is False


def test_runeguard_tool_allows_call_and_writes_audit_log(tmp_path):
    policy = tmp_path / "policy.yaml"
    audit_log = tmp_path / "audit.jsonl"
    policy.write_text("blocked_commands:\n  - rm -rf\n", encoding="utf-8")

    @runeguard_tool(policy, audit_log=audit_log)
    def shell(command):
        return f"ran: {command}"

    assert shell(command="echo hello") == "ran: echo hello"

    record = unwrap_payload(json.loads(audit_log.read_text(encoding="utf-8")))
    assert record["tool_call"] == "shell"
    assert record["command"] == "echo hello"
    assert record["decision"] == "allow"
    assert record["reason"] == "allowed by policy"


def test_runeguard_tool_blocks_protected_path(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("protected_paths:\n  - .env\n", encoding="utf-8")

    @runeguard_tool(policy)
    def read_file(path):
        return "secret"

    with pytest.raises(PermissionError, match="protected path access"):
        read_file(path="repo/.env")


def test_guarded_toolkit_wraps_tools_for_openai_use(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    policy = Policy({"blocked_commands": ["curl"]})

    def read_file(path):
        return f"read {path}"

    def shell(command):
        return f"ran {command}"

    toolkit = GuardedToolkit([read_file, shell], policy=policy, audit_log=audit_log)

    assert len(toolkit.definitions) == 2
    assert toolkit.definitions[0](path="README.md") == "read README.md"
    with pytest.raises(PermissionError, match="blocked shell command pattern: curl"):
        toolkit.definitions[1](command="curl https://example.com")

    records = [
        unwrap_payload(json.loads(line))
        for line in audit_log.read_text(encoding="utf-8").splitlines()
    ]
    assert [record["decision"] for record in records] == ["allow", "block"]
    assert records[0]["path"] == "README.md"
    assert records[1]["command"] == "curl https://example.com"
