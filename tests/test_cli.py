from typer.testing import CliRunner

from runeguard.cli import app


runner = CliRunner()


def test_check_command_loads_policy():
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "Policy loaded" in result.stdout


def test_demo_command_runs():
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "RuneGuard demo: poisoned README attack" in result.stdout


def test_run_command_requires_separator_and_command():
    result = runner.invoke(app, ["run"])
    assert result.exit_code != 0
    output = result.stdout + result.stderr
    assert "Pass a command after '--'" in output
    assert "Example: runeguard run -- python examples/fake_agent/agent.py" in output


def test_run_command_allows_safe_subprocess():
    result = runner.invoke(app, ["run", "--", "python3", "-c", "print('guarded')"])
    assert result.exit_code == 0


def test_run_command_blocks_dangerous_subprocess():
    result = runner.invoke(app, ["run", "--", "rm", "-rf", "./project"])
    assert result.exit_code != 0
    assert "blocked shell command pattern: rm -rf" in result.stdout
