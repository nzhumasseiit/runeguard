import json
import shutil
import subprocess
from pathlib import Path

import pytest

from runeguard.audit import summarize_audit_log
from runeguard.decision import Decision, DecisionType
from runeguard.logger import log_decision
from runeguard.policy import Policy


REPO = Path(__file__).resolve().parents[2]


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


def write_policy(workspace: Path, *, network: str = "deny") -> Path:
    policy = workspace / "runeguard.yaml"
    policy.write_text(
        f"""
version: 1
sandbox:
  backend: docker
  network: {network}
  readonly_rootfs: true
  readonly_workspace: true
  writable_paths:
    - "tmp/"
files:
  deny:
    - ".env"
    - ".env.*"
    - ".git/**"
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.config/gcloud/**"
  allow: []
network:
  default: {network}
  allow_domains:
    - "example.com"
shell:
  deny_patterns:
    - "rm -rf"
    - "curl * | sh"
    - "nc "
    - "scp "
    - "ssh "
""".strip(),
        encoding="utf-8",
    )
    (workspace / "tmp").mkdir(exist_ok=True)
    return policy


def runeguard_run(workspace: Path, command: list[str], *, network: str = "deny"):
    policy = write_policy(workspace, network=network)
    return subprocess.run(
        [
            "python",
            "-m",
            "runeguard.cli",
            "run",
            "--policy",
            str(policy),
            "--workspace",
            str(workspace),
            "--image",
            "python:3.12-slim",
            "--",
            *command,
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


pytestmark = pytest.mark.integration


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_cannot_read_env(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=secret", encoding="utf-8")

    result = runeguard_run(tmp_path, ["python", "-c", "open('/workspace/.env').read()"])

    assert result.returncode != 0
    assert "permission" in result.stderr.lower() or "no such file" in result.stderr.lower()


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_cannot_read_ssh(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_rsa").write_text("secret", encoding="utf-8")

    result = runeguard_run(tmp_path, ["python", "-c", "open('/workspace/.ssh/id_rsa').read()"])

    assert result.returncode != 0


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_cannot_write_outside_writable_paths(tmp_path):
    result = runeguard_run(
        tmp_path,
        ["python", "-c", "from pathlib import Path; Path('/workspace/nope.txt').write_text('x')"],
    )

    assert result.returncode != 0


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_network_denied_by_default(tmp_path):
    result = runeguard_run(
        tmp_path,
        ["python", "-c", "import urllib.request; urllib.request.urlopen('https://example.com', timeout=2)"],
    )

    assert result.returncode != 0


def test_allowed_domain_works_only_when_allowlisted():
    policy = Policy({"network": {"default": "deny", "allow_domains": ["api.openai.com"]}})

    allowed = policy.decide("http_post", url="https://api.openai.com/v1/chat/completions")
    blocked = policy.decide("http_post", url="https://attacker.example/upload")

    assert allowed.type == DecisionType.ALLOW
    assert blocked.type == DecisionType.BLOCK


def test_rm_rf_blocked():
    policy = Policy({"shell": {"deny_patterns": ["rm -rf"]}})
    decision = policy.decide("shell", command="rm -rf /workspace")
    assert decision.type == DecisionType.BLOCK


def test_audit_log_redacts_secret_values(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    log_decision(
        "http_post",
        Decision(DecisionType.BLOCK, "domain not allowlisted"),
        {"url": "https://attacker.example/upload", "payload": "SECRET=abc"},
        audit_log=audit_log,
        quiet=True,
    )

    record = json.loads(audit_log.read_text(encoding="utf-8"))
    assert record["input"]["payload"] == "<redacted>"
    summary = summarize_audit_log(audit_log)
    assert summary["blocked"] == 1


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_container_runs_as_non_root(tmp_path):
    result = runeguard_run(tmp_path, ["python", "-c", "import os; print(os.geteuid())"])

    assert result.returncode == 0
    assert result.stdout.strip().splitlines()[-1] != "0"


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_workspace_is_readonly(tmp_path):
    result = runeguard_run(
        tmp_path,
        ["python", "-c", "from pathlib import Path; Path('/workspace/blocked.txt').write_text('x')"],
    )

    assert result.returncode != 0


@pytest.mark.skipif(not docker_available(), reason="Docker is unavailable")
def test_writable_paths_respected(tmp_path):
    result = runeguard_run(
        tmp_path,
        ["python", "-c", "from pathlib import Path; Path('/workspace/tmp/ok.txt').write_text('ok'); print('ok')"],
    )

    assert result.returncode == 0
    assert "ok" in result.stdout
