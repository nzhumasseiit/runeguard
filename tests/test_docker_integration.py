import shutil
import subprocess
from pathlib import Path

import pytest


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False

    result = subprocess.run(
        ["docker", "info"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not docker_available(), reason="Docker is unavailable"),
]


def run_docker(workspace: Path, *command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "python",
            "-m",
            "runeguard.cli",
            "run",
            "--policy",
            "policies/default.yaml",
            "--workspace",
            str(workspace),
            "--image",
            "python:3.12-slim",
            "--",
            *command,
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )


def test_command_runs_in_docker(tmp_path):
    result = run_docker(tmp_path, "python", "-c", "print('hello from docker')")

    assert result.returncode == 0, result.stderr
    assert "hello from docker" in result.stdout


def test_network_none_blocks_outbound_request(tmp_path):
    result = run_docker(
        tmp_path,
        "python",
        "-c",
        "import urllib.request; urllib.request.urlopen('https://example.com', timeout=2)",
    )

    assert result.returncode != 0


def test_user_is_not_root(tmp_path):
    result = run_docker(tmp_path, "python", "-c", "import os; print(os.geteuid())")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] != "0"


def test_readonly_workspace_cannot_be_written(tmp_path):
    result = run_docker(
        tmp_path,
        "python",
        "-c",
        "from pathlib import Path; Path('/workspace/blocked.txt').write_text('nope')",
    )

    assert result.returncode != 0


def test_writable_tmp_dir_can_be_written(tmp_path):
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
sandbox_backend: docker
network: deny_all
readonly_rootfs: true
readonly_workspace: true
protected_paths: []
writable_paths:
  - "./tmp"
allowed_domains: []
blocked_commands: []
require_approval: []
allowed_env_vars: []
max_file_size_mb: 10
""".strip(),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python",
            "-m",
            "runeguard.cli",
            "run",
            "--policy",
            str(policy_path),
            "--workspace",
            str(tmp_path),
            "--image",
            "python:3.12-slim",
            "--",
            "python",
            "-c",
            "from pathlib import Path; Path('/workspace/tmp/ok.txt').write_text('ok'); print('ok')",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
