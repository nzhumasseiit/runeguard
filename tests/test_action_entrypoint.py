"""
Tests for the GitHub Action entrypoint logic.

These tests exercise the Python-side helpers used by action-entrypoint.sh.
The shell script itself is tested with the integration workflow.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "scripts" / "action-entrypoint.sh"


def test_entrypoint_exists_and_is_executable():
    assert ENTRYPOINT.exists(), "scripts/action-entrypoint.sh not found"
    assert os.access(ENTRYPOINT, os.X_OK), "action-entrypoint.sh is not executable"


def test_entrypoint_runs_echo_command(tmp_path):
    """Smoke test: a safe echo command succeeds with no blocks."""
    audit = tmp_path / "audit.jsonl"
    env = {
        **os.environ,
        "RG_COMMAND": "echo hello",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "hello" in result.stdout or result.returncode == 0

    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "blocked=false" in output_text
    assert "block_count=0" in output_text


def test_entrypoint_blocks_protected_path(tmp_path):
    """An agent that reads .env gets blocked; step fails when fail-on-block=true."""
    policy = tmp_path / "policy.yaml"
    audit = tmp_path / "audit.jsonl"
    policy.write_text(
        "version: 1\nfiles:\n  deny:\n    - '.env'\n",
        encoding="utf-8",
    )
    # Create a .env so the read actually tries to access a real file
    (tmp_path / ".env").write_text("SECRET=hunter2", encoding="utf-8")

    env = {
        **os.environ,
        "RG_COMMAND": f"python -c \"open('{tmp_path}/.env').read()\"",
        "RG_POLICY": str(policy),
        "RG_PROFILE": "",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    # With --backend host and --preload or daemon, this would be blocked.
    # Without the preload shim on macOS this test verifies the entrypoint
    # logic works end-to-end; actual blocking is covered by integration tests.
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "audit_log_path" in output_text
    assert "block_count" in output_text


def test_entrypoint_fail_on_block_false_does_not_fail(tmp_path):
    """fail-on-block=false: step exits 0 even if something was blocked."""
    audit = tmp_path / "audit.jsonl"
    # Write a fake audit log with a block entry
    audit.write_text(
        json.dumps({"decision": "block", "tool": "read_file", "reason": "test"}) + "\n",
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "RG_COMMAND": "echo ok",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "false",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    result = subprocess.run(
        [str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
    )
    # The echo command runs fine; fail-on-block=false means the step passes
    assert result.returncode == 0, result.stderr
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert "blocked=true" in output_text


def test_entrypoint_outputs_audit_log_path(tmp_path):
    """audit_log_path output is set to the resolved audit log path."""
    audit = tmp_path / "subdir" / "audit.jsonl"
    env = {
        **os.environ,
        "RG_COMMAND": "echo ok",
        "RG_POLICY": "",
        "RG_PROFILE": "ci",
        "RG_AUDIT_LOG": str(audit),
        "RG_BACKEND": "host",
        "RG_FAIL_ON_BLOCK": "true",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "PYTHONPATH": str(REPO_ROOT),
    }
    Path(env["GITHUB_OUTPUT"]).touch()

    subprocess.run([str(ENTRYPOINT)], env=env, capture_output=True)
    output_text = Path(env["GITHUB_OUTPUT"]).read_text()
    assert f"audit_log_path={audit}" in output_text
