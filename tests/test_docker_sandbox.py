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
    assert "--read-only" in argv
    assert "--tmpfs" in argv
    assert "/tmp:rw,noexec,nosuid,size=64m" in argv
    assert "/run:rw,noexec,nosuid,size=16m" in argv
    assert f"type=bind,source={tmp_path.resolve()},target=/workspace,readonly" in argv
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


def test_docker_argv_mounts_policy_writable_paths_separately(tmp_path):
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    runner = DockerSandboxRunner(
        Policy({"writable_paths": [".cache", str(output_dir)]}),
        DockerSandboxConfig(workspace=tmp_path, user="1000:1000"),
    )

    argv = runner.build_docker_argv(["python", "-c", "print('hi')"])

    assert f"type=bind,source={tmp_path.resolve()},target=/workspace,readonly" in argv
    assert f"type=bind,source={cache_dir.resolve()},target=/workspace/.cache" in argv
    assert f"type=bind,source={output_dir.resolve()},target=/workspace/out" in argv


def test_filtered_workspace_includes_writable_mount_targets(tmp_path):
    runner = DockerSandboxRunner(
        Policy({"writable_paths": ["tmp/", ".cache/"]}),
        DockerSandboxConfig(workspace=tmp_path),
    )
    destination = tmp_path / "filtered"
    destination.mkdir()

    runner._copy_filtered_workspace(destination)

    assert (destination / "tmp").is_dir()
    assert (destination / ".cache").is_dir()


def test_unsafe_writable_workspace_preserves_old_writable_mount(tmp_path):
    runner = DockerSandboxRunner(
        Policy({"writable_paths": ["out"]}),
        DockerSandboxConfig(
            workspace=tmp_path,
            user="1000:1000",
            unsafe_writable_workspace=True,
        ),
    )

    argv = runner.build_docker_argv(["python", "-c", "print('hi')"])

    assert f"type=bind,source={tmp_path.resolve()},target=/workspace,rw" in argv
    assert not any("target=/workspace/out" in arg for arg in argv)


def test_writable_path_must_stay_inside_workspace(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    runner = DockerSandboxRunner(
        Policy({"writable_paths": [str(outside)]}),
        DockerSandboxConfig(workspace=tmp_path),
    )

    with pytest.raises(ValueError, match="inside workspace"):
        runner.build_docker_argv(["python"])


def test_refuses_dangerous_workspace_mount(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    runner = DockerSandboxRunner(
        Policy({}),
        DockerSandboxConfig(workspace=fake_home),
    )

    with pytest.raises(ValueError, match="dangerous mount source"):
        runner.build_docker_argv(["python"])


def test_refuses_dangerous_writable_mount(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    ssh_dir = fake_home / ".ssh"
    workspace = tmp_path / "workspace"
    ssh_dir.mkdir(parents=True)
    workspace.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    runner = DockerSandboxRunner(
        Policy({"writable_paths": [str(ssh_dir)]}),
        DockerSandboxConfig(workspace=workspace),
    )

    with pytest.raises(ValueError, match="dangerous mount source"):
        runner.build_docker_argv(["python"])
