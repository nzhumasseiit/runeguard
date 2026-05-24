import json
import os
from datetime import datetime

from runeguard.audit import audit_record, summarize_audit_log
from runeguard.correlation import agent_turn


EXPECTED_AUDIT_KEYS = {
    "run_id",
    "agent",
    "tool_call",
    "command",
    "path",
    "pid",
    "ppid",
    "decision",
    "rule_matched",
    "reason",
    "timestamp",
}


def test_audit_record_uses_exact_schema(monkeypatch):
    monkeypatch.setenv("RUNEGUARD_AGENT", "pytest-agent")

    with agent_turn(turn_id="run-123"):
        record = audit_record(
            tool_call="read_file",
            command=None,
            path=".env",
            decision="BLOCK",
            rule_matched=".env",
            reason="protected path access: .env",
        )

    assert set(record) == EXPECTED_AUDIT_KEYS
    assert record["run_id"] == "run-123"
    assert record["agent"] == "pytest-agent"
    assert record["tool_call"] == "read_file"
    assert record["command"] is None
    assert record["path"] == ".env"
    assert record["pid"] == os.getpid()
    assert record["ppid"] == os.getppid()
    assert record["decision"] == "block"
    assert record["rule_matched"] == ".env"
    assert record["reason"] == "protected path access: .env"
    datetime.fromisoformat(record["timestamp"])


def test_summarize_audit_log_counts_decisions(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    records = [
        {"tool_call": "read_file", "decision": "allow", "reason": "allowed by policy"},
        {"tool_call": "read_file", "decision": "block", "reason": "protected path access: .env"},
        {"tool_call": "shell", "decision": "block", "reason": "blocked shell command pattern: curl"},
        {"tool_call": "shell", "decision": "block", "reason": "blocked shell command pattern: curl"},
    ]
    audit_log.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    summary = summarize_audit_log(audit_log)

    assert summary["total"] == 4
    assert summary["allowed"] == 1
    assert summary["blocked"] == 3
    assert summary["blocked_actions"]["shell"] == 2
    assert summary["blocked_reasons"]["blocked shell command pattern: curl"] == 2
