import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from runeguard.decision import Decision, DecisionType
from runeguard.logger import log_decision
from runeguard.policy import Policy


DEFAULT_IMAGE = "python:3.12-slim"
CONTAINER_WORKDIR = "/workspace"


@dataclass(frozen=True)
class DockerSandboxConfig:
    image: str = DEFAULT_IMAGE
    workspace: Path = Path.cwd()
    network: str = "none"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 256
    user: str = "65532:65532"


class DockerSandboxRunner:
    """Runs commands in a restricted Docker container."""

    def __init__(
        self,
        policy: Policy,
        config: DockerSandboxConfig | None = None,
        *,
        audit_log: str | None = None,
        json_logs: bool = False,
    ):
        self.policy = policy
        self.config = config or DockerSandboxConfig()
        self.audit_log = audit_log
        self.json_logs = json_logs

    def run(self, argv: list[str]) -> int:
        decision = self.policy.decide("shell", command=" ".join(argv), argv=argv)
        self._log_event("sandbox.policy", decision, {"argv": argv, "backend": "docker"})
        if decision.type != DecisionType.ALLOW:
            raise PermissionError(decision.reason)

        docker_argv = self.build_docker_argv(argv)
        self._log_event(
            "sandbox.docker",
            Decision(DecisionType.ALLOW, "starting Docker sandbox"),
            {
                "image": self.config.image,
                "workspace": str(self.workspace),
                "network": self.config.network,
                "memory": self.config.memory,
                "cpus": self.config.cpus,
                "pids_limit": self.config.pids_limit,
                "user": self.config.user,
            },
        )
        completed = subprocess.run(docker_argv, check=False)
        return completed.returncode

    def build_docker_argv(self, command_argv: list[str]) -> list[str]:
        workspace = self.workspace
        return [
            "docker",
            "run",
            "--rm",
            "--workdir",
            CONTAINER_WORKDIR,
            "--mount",
            f"type=bind,source={workspace},target={CONTAINER_WORKDIR}",
            "--user",
            self.config.user,
            "--network",
            self.config.network,
            "--memory",
            self.config.memory,
            "--cpus",
            self.config.cpus,
            "--pids-limit",
            str(self.config.pids_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            self.config.image,
            *command_argv,
        ]

    @property
    def workspace(self) -> Path:
        return Path(self.config.workspace).resolve(strict=True)

    def _log_event(self, tool_name: str, decision: Decision, kwargs: dict):
        log_decision(
            tool_name,
            decision,
            kwargs,
            audit_log=self.audit_log,
            json_logs=self.json_logs,
        )


def current_user_container_id() -> str:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        return "65532:65532"
    return f"{uid}:{gid}"
