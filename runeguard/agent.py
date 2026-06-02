import shutil
from dataclasses import dataclass
from pathlib import Path

from .audit import summarize_audit_log
from .core.docker import DockerSandboxConfig, DockerSandboxRunner, current_user_container_id
from .core.sandbox import filter_child_env
from .policy import Policy


SUPPORTED_AGENTS = {"codex", "claude", "cursor", "generic"}


@dataclass(frozen=True)
class AgentWrapConfig:
    agent: str
    command: list[str]
    workspace: Path
    policy_path: Path = Path("runeguard.yaml")
    audit_log: Path = Path(".runeguard/audit.jsonl")
    image: str = "python:3.12-slim"
    backend: str | None = None


def validate_agent_command(config: AgentWrapConfig):
    if config.agent not in SUPPORTED_AGENTS:
        raise ValueError(f"agent must be one of: {', '.join(sorted(SUPPORTED_AGENTS))}")
    if not config.command:
        raise ValueError("pass the agent command after '--'")
    executable = config.command[0]
    if shutil.which(executable) is None:
        raise FileNotFoundError(f"{executable} is not installed or not on PATH")


def run_agent(config: AgentWrapConfig, policy: Policy | None = None) -> int:
    import subprocess

    validate_agent_command(config)
    policy = policy or Policy.from_file(str(config.policy_path))
    audit_log = str(config.audit_log)
    backend = config.backend or ("docker" if _docker_daemon_reachable() else "host")

    if backend == "docker":
        runner = DockerSandboxRunner(
            policy,
            DockerSandboxConfig(
                image=config.image,
                workspace=config.workspace,
                network="none" if policy.network in {"deny", "deny_all", "none"} else policy.network,
                user=current_user_container_id(),
                readonly_rootfs=policy.readonly_rootfs,
            ),
            audit_log=audit_log,
        )
        return runner.run(config.command)

    if backend != "host":
        raise ValueError("backend must be docker or host")

    decision = policy.decide("shell", command=" ".join(config.command), argv=config.command)
    from .logger import log_decision

    log_decision("shell", decision, {"command": " ".join(config.command), "argv": config.command}, audit_log=audit_log)
    if decision.type.value != "ALLOW":
        raise PermissionError(decision.reason)
    completed = subprocess.run(config.command, cwd=config.workspace, check=False, env=filter_child_env(policy))
    return completed.returncode


def summarize_agent_run(audit_log: Path) -> str:
    try:
        summary = summarize_audit_log(audit_log)
    except FileNotFoundError:
        summary = {"allowed": 0, "blocked": 0}
    return "\n".join(
        [
            "RuneGuard agent run summary:",
            f"Allowed actions: {summary.get('allowed', 0)}",
            f"Blocked actions: {summary.get('blocked', 0)}",
            f"Audit log: {audit_log}",
            f"Report: runeguard report {audit_log}",
        ]
    )


def _docker_daemon_reachable() -> bool:
    import subprocess

    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0
