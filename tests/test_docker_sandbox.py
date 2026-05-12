import subprocess
from pathlib import Path

import pytest

from runeguard.core.docker import DockerSandboxConfig, DockerSandboxRunner
from runeguard.policy import Policy


def test_docker_argv_uses_restricted_defaults(tmp_path):
    runner = DockerSandboxRunner(
        Policy({}),
        DockerSandboxConfig(workspace=tmp_path, user="1000:1000"),
    )

    argv = runner.build_docker_argv(["python", "-c", "print('hi')"])

    assert argv[:3] == ["docker", "run", "--rm"]
    assert "--network" in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert "--user" in argv
    assert argv[argv.index("--user") + 1] == "1000:1000"
    assert "--cap-drop" in argv
    assert "ALL" in argv
    assert "--security-opt" in argv
    assert "no-new-privileges" in argv
    assert f"type=bind,source={tmp_path.resolve()},target=/workspace" in argv
    image_index = argv.index("python:3.12-slim")
    assert argv[image_index + 1 :] == ["python", "-c", "print('hi')"]


def test_docker_runner_invokes_subprocess(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, check):
        calls.append((argv, check))
        return subprocess.CompletedProcess(argv, 7)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = DockerSandboxRunner(
        Policy({}),
        DockerSandboxConfig(workspace=tmp_path, user="1000:1000"),
    )

    exit_code = runner.run(["python", "-c", "print('hi')"])

    assert exit_code == 7
    assert calls
    assert calls[0][0][0:2] == ["docker", "run"]


def test_docker_runner_blocks_policy_denied_command(tmp_path):
    runner = DockerSandboxRunner(
        Policy({"blocked_commands": ["rm -rf"]}),
        DockerSandboxConfig(workspace=tmp_path),
    )

    with pytest.raises(PermissionError):
        runner.run(["rm", "-rf", "/workspace"])
