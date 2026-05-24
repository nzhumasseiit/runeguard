from typer.testing import CliRunner
import json

from runeguard.cli import app


try:
    runner = CliRunner(mix_stderr=False)
except TypeError:
    runner = CliRunner()


def test_check_command_loads_policy():
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "Python 3.10+" in result.stdout
    assert "Recommended backend:" in result.stdout


def test_check_command_prints_health_table(monkeypatch):
    monkeypatch.setattr("runeguard.cli.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("runeguard.cli._docker_daemon_reachable", lambda: True)
    monkeypatch.setattr("runeguard.cli.platform.system", lambda: "Darwin")

    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0
    assert "✓ Python 3.10+" in result.stdout
    assert "✓ Docker available" in result.stdout
    assert "✗ Linux required for Landlock" in result.stdout
    assert "✗ Linux + root required for eBPF" in result.stdout
    assert "→ Recommended backend: docker" in result.stdout


def test_quickstart_recommends_docker(monkeypatch):
    monkeypatch.setattr("runeguard.cli._docker_available", lambda: True)

    result = runner.invoke(app, ["quickstart"])

    assert result.exit_code == 0
    assert "Docker detected. Recommended: runeguard run --profile ci -- your-command" in result.stdout


def test_quickstart_recommends_landlock_on_linux(monkeypatch):
    monkeypatch.setattr("runeguard.cli._docker_available", lambda: False)
    monkeypatch.setattr("runeguard.cli.platform.system", lambda: "Linux")
    monkeypatch.setattr("runeguard.cli.landlock_available", lambda: True)

    result = runner.invoke(app, ["quickstart"])

    assert result.exit_code == 0
    assert "Linux detected. Recommended: runeguard run --backend landlock -- your-command" in result.stdout


def test_init_creates_policy_and_state_files():
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        from pathlib import Path

        policy = Path("runeguard.yaml")
        assert policy.exists()
        assert Path(".runeguard").is_dir()
        assert Path(".runeguard/audit.jsonl").exists()
        assert Path(".runeguard/README.md").exists()

        content = policy.read_text(encoding="utf-8")
        assert "version: 1" in content
        assert "backend: docker" in content
        assert "network: deny" in content
        assert "readonly_rootfs: true" in content
        assert "readonly_workspace: true" in content
        assert '    - "src/"' in content
        assert '  - ".env"' in content
        assert '    - "~/.ssh/**"' in content


def test_init_refuses_to_overwrite_without_force():
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0

        result = runner.invoke(app, ["init"])
        assert result.exit_code == 1
        output = result.stdout + result.stderr
        assert "already exists" in output


def test_init_force_overwrites_policy():
    with runner.isolated_filesystem():
        from pathlib import Path

        Path("runeguard.yaml").write_text("sandbox_backend: host\n", encoding="utf-8")
        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == 0
        assert "backend: docker" in Path("runeguard.yaml").read_text(encoding="utf-8")


def test_doctor_passes_when_critical_requirements_exist(monkeypatch):
    def fake_run(argv, check, stdout, stderr):
        from subprocess import CompletedProcess

        return CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.cli.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("runeguard.cli.subprocess.run", fake_run)

    result = runner.invoke(app, ["doctor", "--policy", "policies/default.yaml"])

    assert result.exit_code == 0
    assert "Docker executable found" in result.stdout
    assert "Docker: available" in result.stdout
    assert "Default backend:" in result.stdout
    assert "Security mode: fail-closed" in result.stdout


def test_doctor_fails_when_docker_missing(monkeypatch):
    monkeypatch.setattr("runeguard.cli.shutil.which", lambda name: None)

    result = runner.invoke(app, ["doctor", "--policy", "policies/default.yaml"])

    assert result.exit_code == 1
    assert "Docker executable not found" in result.stdout


def test_doctor_fails_when_policy_missing(monkeypatch):
    def fake_run(argv, check, stdout, stderr):
        from subprocess import CompletedProcess

        return CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.cli.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("runeguard.cli.subprocess.run", fake_run)

    result = runner.invoke(app, ["doctor", "--policy", "missing.yaml"])

    assert result.exit_code == 1
    assert "Policy file not found" in result.stdout


def test_audit_summary_command_prints_counts(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    records = [
        {"tool": "read_file", "decision": "ALLOW", "reason": "allowed by policy"},
        {"tool": "read_file", "decision": "BLOCK", "reason": "protected path access: .env"},
        {"tool": "shell", "decision": "BLOCK", "reason": "blocked shell command pattern: curl"},
    ]
    audit_log.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["audit", "summary", str(audit_log)])

    assert result.exit_code == 0
    assert "Total decisions: 3" in result.stdout
    assert "Allowed: 1" in result.stdout
    assert "Blocked: 2" in result.stdout
    assert "read_file: 1" in result.stdout
    assert "shell: 1" in result.stdout
    assert "blocked shell command pattern: curl: 1" in result.stdout


def test_audit_summary_command_reports_missing_file(tmp_path):
    result = runner.invoke(app, ["audit", "summary", str(tmp_path / "missing.jsonl")])

    assert result.exit_code == 1
    output = result.stdout + result.stderr
    assert "Audit log not found" in output


def test_report_command_prints_html(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        json.dumps({"tool": "shell", "decision": "BLOCK", "reason": "blocked"}) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["report", str(audit_log), "--html"])

    assert result.exit_code == 0
    assert "<html" in result.stdout
    assert "RuneGuard Audit Report" in result.stdout


def test_examples_poisoned_readme_runs():
    result = runner.invoke(app, ["examples", "poisoned-readme"])

    assert result.exit_code == 0
    assert "RuneGuard demo: poisoned README attack" in result.stdout


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


def test_run_command_rejects_landlock_backend_without_fallback(monkeypatch):
    monkeypatch.setattr("runeguard.core.landlock.landlock_available", lambda: False)
    monkeypatch.setattr("runeguard.cli.landlock_available", lambda: False)

    result = runner.invoke(app, ["run", "--backend", "landlock", "--", "python", "-c", "print('guarded')"])

    assert result.exit_code == 2
    output = result.stdout + result.stderr
    assert "fail-closed" in output


def test_run_command_allows_landlock_weak_fallback(monkeypatch):
    calls = []

    def fake_run(argv, cwd, env, check):
        calls.append((argv, cwd, env, check))
        from subprocess import CompletedProcess

        return CompletedProcess(argv, 0)

    monkeypatch.setattr("runeguard.core.landlock.landlock_available", lambda: False)
    monkeypatch.setattr("runeguard.cli.landlock_available", lambda: False)
    monkeypatch.setattr("runeguard.core.landlock.subprocess.run", fake_run)

    result = runner.invoke(
        app,
        ["run", "--backend", "landlock", "--allow-weak-fallback", "--", "python", "-c", "print('guarded')"],
    )

    assert result.exit_code == 0
    assert calls


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
    assert '"decision": "block"' in audit_path.read_text(encoding="utf-8")


def test_daemon_status_reports_missing_socket(tmp_path):
    result = runner.invoke(app, ["daemon", "status", "--socket-path", str(tmp_path / "missing.sock")])

    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_shim_path_command_prints_expected_library():
    result = runner.invoke(app, ["shim", "path"])

    assert result.exit_code == 0
    assert "rg_preload.so" in result.stdout
