import json

from typer.testing import CliRunner

from runeguard.cli import app


try:
    runner = CliRunner(mix_stderr=False)
except TypeError:
    runner = CliRunner()


def _write_report_fixture(path):
    records = [
        {
            "run_id": "run-1",
            "agent": "pytest",
            "tool_call": "read_file",
            "command": None,
            "path": ".env",
            "pid": 100,
            "ppid": 1,
            "decision": "block",
            "rule_matched": ".env",
            "reason": "protected path access: .env",
            "timestamp": "2026-05-24T00:00:00+00:00",
        },
        {
            "run_id": "run-1",
            "agent": "pytest",
            "tool_call": "shell",
            "command": "curl https://attacker.example",
            "path": None,
            "pid": 100,
            "ppid": 1,
            "decision": "block",
            "rule_matched": "curl",
            "reason": "blocked shell command pattern: curl",
            "timestamp": "2026-05-24T00:00:01+00:00",
        },
        {
            "run_id": "run-1",
            "agent": "pytest",
            "tool_call": "shell",
            "command": "curl https://attacker.example",
            "path": None,
            "pid": 100,
            "ppid": 1,
            "decision": "block",
            "rule_matched": "curl",
            "reason": "blocked shell command pattern: curl",
            "timestamp": "2026-05-24T00:00:02+00:00",
        },
        {
            "run_id": "run-1",
            "agent": "pytest",
            "tool_call": "read_file",
            "command": None,
            "path": "README.md",
            "pid": 100,
            "ppid": 1,
            "decision": "allow",
            "rule_matched": None,
            "reason": "allowed by policy",
            "timestamp": "2026-05-24T00:00:03+00:00",
        },
        {
            "run_id": "run-1",
            "agent": "pytest",
            "tool_call": "openat",
            "command": None,
            "path": "tmp/audit.txt",
            "pid": 100,
            "ppid": 1,
            "decision": "audit",
            "rule_matched": None,
            "reason": "observed openat",
            "timestamp": "2026-05-24T00:00:04+00:00",
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )


def test_report_markdown_contains_expected_counts(tmp_path):
    logfile = tmp_path / "runeguard.jsonl"
    _write_report_fixture(logfile)

    result = runner.invoke(app, ["report", str(logfile)])

    assert result.exit_code == 0
    assert "| Total events | 5 |" in result.stdout
    assert "| Blocked count | 3 |" in result.stdout
    assert "curl (2)" in result.stdout
    assert "| curl | 2 |" in result.stdout
    assert "| curl https://attacker.example | 2 |" in result.stdout
    assert "| README.md | 1 |" in result.stdout


def test_report_html_output_file_contains_expected_counts(tmp_path):
    logfile = tmp_path / "runeguard.jsonl"
    output = tmp_path / "report.html"
    _write_report_fixture(logfile)

    result = runner.invoke(
        app,
        ["report", str(logfile), "--format", "html", "--output", str(output)],
    )

    assert result.exit_code == 0
    rendered = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in rendered
    assert "<td>Total events</td><td>5</td>" in rendered
    assert "<td>Blocked count</td><td>3</td>" in rendered
    assert "<td>curl</td><td>2</td>" in rendered


def test_report_json_contains_expected_counts(tmp_path):
    logfile = tmp_path / "runeguard.jsonl"
    _write_report_fixture(logfile)

    result = runner.invoke(app, ["report", str(logfile), "--format", "json"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["summary"]["total_events"] == 5
    assert report["summary"]["blocked_count"] == 3
    assert report["summary"]["decision_counts"] == {"allow": 1, "audit": 1, "block": 3}
    assert report["summary"]["rule_matched_counts"]["curl"] == 2
    assert report["summary"]["target_counts"]["curl https://attacker.example"] == 2
