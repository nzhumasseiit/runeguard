import json

from runeguard.audit import build_report, render_pr_summary_markdown, render_report_json
from runeguard.logger import write_audit_record
from runeguard.redaction import redact_text


def test_redact_text_handles_common_tokens():
    text = "token=ghp_abcdefghijklmnopqrstuvwxyzABCDE and sk-abcdefghijklmnopqrstuvwxyz123456"

    redacted = redact_text(text)

    assert "ghp_abcdefghijklmnopqrstuvwxyzABCDE" not in redacted
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "ghp_...BCDE" in redacted
    assert "sk-...3456" in redacted


def test_audit_reports_redact_secrets(tmp_path):
    audit = tmp_path / "audit.jsonl"
    write_audit_record(
        audit,
        {
            "decision": "block",
            "tool_call": "shell",
            "command": "echo sk-abcdefghijklmnopqrstuvwxyz123456",
            "reason": "blocked shell command pattern: printenv",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    )

    report = build_report(audit)
    rendered_json = render_report_json(report)
    pr_summary = render_pr_summary_markdown(report)

    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in audit.read_text(encoding="utf-8")
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in rendered_json
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in pr_summary
    assert json.loads(rendered_json)["summary"]["blocked_count"] == 1
