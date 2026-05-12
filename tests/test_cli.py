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


def test_run_command_allows_safe_subprocess_with_host_backend():
    result = runner.invoke(app, ["run", "--backend", "host", "--", "python3", "-c", "print('guarded')"])
    assert result.exit_code == 0


def test_run_command_blocks_dangerous_subprocess():
    result = runner.invoke(app, ["run", "--backend", "host", "--", "rm", "-rf", "./project"])
    assert result.exit_code != 0
    assert "blocked shell command pattern: rm -rf" in result.stdout


def test_run_command_uses_docker_backend_by_default(monkeypatch):
    calls = []

    def fake_run(argv, check):
        calls.append((argv, check))
        from subprocess import CompletedProcess

        return CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.core.docker.subprocess.run", fake_run)

    result = runner.invoke(app, ["run", "--", "python", "-c", "print('guarded')"])

    assert result.exit_code == 0
    assert calls
    assert calls[0][0][0:2] == ["docker", "run"]
    assert "--network" in calls[0][0]
    assert calls[0][0][calls[0][0].index("--network") + 1] == "none"
    assert "--read-only" in calls[0][0]
    assert "/tmp:rw,noexec,nosuid,size=64m" in calls[0][0]


def test_run_command_reports_missing_docker(monkeypatch):
    def fake_run(argv, check):
        raise FileNotFoundError

    monkeypatch.setattr("runeguard.core.docker.subprocess.run", fake_run)

    result = runner.invoke(app, ["run", "--", "python", "-c", "print('guarded')"])

    assert result.exit_code == 127
    output = result.stdout + result.stderr
    assert "Docker executable not found" in output


def test_run_command_rejects_preload_with_docker_backend():
    result = runner.invoke(app, ["run", "--preload", "--", "python", "-c", "print('guarded')"])

    assert result.exit_code == 2
    output = result.stdout + result.stderr
    assert "only supported with --backend host" in output


def test_run_command_supports_unsafe_writable_workspace(monkeypatch):
    calls = []

    def fake_run(argv, check):
        calls.append((argv, check))
        from subprocess import CompletedProcess

        return CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.core.docker.subprocess.run", fake_run)

    result = runner.invoke(
        app,
        ["run", "--unsafe-writable-workspace", "--", "python", "-c", "print('guarded')"],
    )

    assert result.exit_code == 0
    assert any("target=/workspace,rw" in arg for arg in calls[0][0])


def test_eval_command_reports_block():
    result = runner.invoke(app, ["eval", "read_file", "--path", "examples/demo_repo/.env"])
    assert result.exit_code == 0
    assert "BLOCK: protected path access" in result.stdout


def test_check_command_can_print_json():
    result = runner.invoke(app, ["check", "--json"])
    assert result.exit_code == 0
    assert '"protected_paths"' in result.stdout


def test_demo_command_can_write_audit_log(tmp_path):
    audit_path = tmp_path / "audit.jsonl"

    result = runner.invoke(app, ["demo", "--audit-log", str(audit_path)])

    assert result.exit_code == 0
    assert audit_path.exists()
    assert '"decision": "BLOCK"' in audit_path.read_text(encoding="utf-8")


def test_daemon_status_reports_missing_socket(tmp_path):
    result = runner.invoke(app, ["daemon", "status", "--socket-path", str(tmp_path / "missing.sock")])

    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_shim_path_command_prints_expected_library():
    result = runner.invoke(app, ["shim", "path"])

    assert result.exit_code == 0
    assert "rg_preload.so" in result.stdout
