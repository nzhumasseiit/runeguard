import subprocess

import pytest

from runeguard.core.landlock import LandlockConfig, LandlockSandboxRunner, LandlockUnavailable
from runeguard.policy import Policy


def test_landlock_runner_fails_closed_when_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr("runeguard.core.landlock.landlock_available", lambda: False)
    runner = LandlockSandboxRunner(Policy({}), LandlockConfig(workspace=tmp_path))

    with pytest.raises(LandlockUnavailable):
        runner.run(["python", "-c", "print('hi')"])


def test_landlock_runner_allows_explicit_weak_fallback(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, cwd, env, check):
        calls.append((argv, cwd, env, check))
        return subprocess.CompletedProcess(argv, 3)

    monkeypatch.setattr("runeguard.core.landlock.landlock_available", lambda: False)
    monkeypatch.setattr("runeguard.core.landlock.subprocess.run", fake_run)

    runner = LandlockSandboxRunner(
        Policy({}),
        LandlockConfig(workspace=tmp_path, allow_weak_fallback=True),
    )

    assert runner.run(["python", "-c", "print('hi')"]) == 3
    assert calls[0][1] == tmp_path.resolve()


def test_landlock_runner_blocks_policy_denied_command(monkeypatch, tmp_path):
    monkeypatch.setattr("runeguard.core.landlock.landlock_available", lambda: True)
    runner = LandlockSandboxRunner(
        Policy({"shell": {"deny_patterns": ["rm -rf"]}}),
        LandlockConfig(workspace=tmp_path),
    )

    with pytest.raises(PermissionError):
        runner.run(["rm", "-rf", "/"])


def test_landlock_filtered_workspace_excludes_denied_files(tmp_path):
    (tmp_path / ".env").write_text("secret", encoding="utf-8")
    (tmp_path / "README.md").write_text("ok", encoding="utf-8")
    destination = tmp_path / "filtered"
    destination.mkdir()
    runner = LandlockSandboxRunner(
        Policy({"files": {"deny": [".env"], "allow": ["README.md"]}}),
        LandlockConfig(workspace=tmp_path),
    )

    runner._copy_filtered_workspace(destination)

    assert not (destination / ".env").exists()
    assert (destination / "README.md").exists()
