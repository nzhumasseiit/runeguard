import json

from runeguard.audit import summarize_audit_log


def test_summarize_audit_log_counts_decisions(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    records = [
        {"tool": "read_file", "decision": "ALLOW", "reason": "allowed by policy"},
        {"tool": "read_file", "decision": "BLOCK", "reason": "protected path access: .env"},
        {"tool": "shell", "decision": "BLOCK", "reason": "blocked shell command pattern: curl"},
        {"tool": "shell", "decision": "BLOCK", "reason": "blocked shell command pattern: curl"},
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
