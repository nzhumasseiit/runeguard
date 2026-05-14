import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
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
    unsafe_writable_workspace: bool = False
    readonly_rootfs: bool = True
    tmpfs_mounts: tuple[str, ...] = (
        "/tmp:rw,noexec,nosuid,size=64m",
        "/run:rw,noexec,nosuid,size=16m",
    )
    network: str = "none"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 256
    user: str = "65532:65532"
    filtered_workspace: bool = True


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

        with self._workspace_mount_source() as mount_source:
            docker_argv = self.build_docker_argv(argv, workspace_source=mount_source)
            self._log_event(
                "sandbox.docker",
                Decision(DecisionType.ALLOW, "starting Docker sandbox"),
                {
                    "image": self.config.image,
                    "workspace": str(self.workspace),
                    "workspace_mount_source": str(mount_source),
                    "unsafe_writable_workspace": self.config.unsafe_writable_workspace,
                    "readonly_rootfs": self.config.readonly_rootfs,
                    "tmpfs_mounts": list(self.config.tmpfs_mounts),
                    "writable_paths": self.policy.writable_paths,
                    "network": self.config.network,
                    "memory": self.config.memory,
                    "cpus": self.config.cpus,
                    "pids_limit": self.config.pids_limit,
                    "user": self.config.user,
                },
            )
            completed = subprocess.run(docker_argv, check=False)
            return completed.returncode

    def build_docker_argv(
        self,
        command_argv: list[str],
        *,
        workspace_source: Path | None = None,
    ) -> list[str]:
        if not self.policy.readonly_workspace and not self.config.unsafe_writable_workspace:
            raise ValueError(
                "policy readonly_workspace=false requires --unsafe-writable-workspace"
            )

        docker_argv = [
            "docker",
            "run",
            "--rm",
            "--workdir",
            CONTAINER_WORKDIR,
            *self._mount_args(workspace_source=workspace_source),
            "--user",
            self.config.user,
            "--network",
            self._docker_network_mode(),
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
        ]

        if self.config.readonly_rootfs and self.policy.readonly_rootfs:
            docker_argv.append("--read-only")

        for tmpfs_mount in self.config.tmpfs_mounts:
            docker_argv.extend(["--tmpfs", tmpfs_mount])

        docker_argv.extend([self.config.image, *command_argv])
        return docker_argv

    @property
    def workspace(self) -> Path:
        workspace = Path(self.config.workspace).expanduser().resolve(strict=True)
        self._validate_safe_mount_source(workspace, allow_inside_home=True)
        return workspace

    def _mount_args(self, *, workspace_source: Path | None = None) -> list[str]:
        workspace = Path(workspace_source).resolve(strict=True) if workspace_source else self.workspace
        mode = "rw" if self.config.unsafe_writable_workspace else "readonly"
        mounts = [
            "--mount",
            f"type=bind,source={workspace},target={CONTAINER_WORKDIR},{mode}",
        ]

        if self.config.unsafe_writable_workspace:
            return mounts

        for writable_path in self.policy.writable_paths:
            source = self._resolve_writable_path(writable_path)
            target = self._container_target_for(source)
            mounts.extend(
                [
                    "--mount",
                    f"type=bind,source={source},target={target}",
                ]
            )

        return mounts

    def _docker_network_mode(self) -> str:
        if self.config.network == "none":
            return "none"

        if self.policy.network in {"deny", "deny_all", "none"}:
            return "none"

        return self.config.network

    @contextmanager
    def _workspace_mount_source(self):
        if self.config.unsafe_writable_workspace or not self.config.filtered_workspace:
            yield self.workspace
            return

        with tempfile.TemporaryDirectory(prefix="runeguard-workspace-") as tmpdir:
            filtered = Path(tmpdir) / "workspace"
            filtered.mkdir()
            self._copy_filtered_workspace(filtered)
            yield filtered

    def _copy_filtered_workspace(self, destination: Path):
        workspace = self.workspace
        destination = destination.resolve(strict=False)
        for source in workspace.rglob("*"):
            source_resolved = source.resolve(strict=False)
            if source_resolved == destination or self._is_relative_to(source_resolved, destination):
                continue

            relative = source.relative_to(workspace)
            relative_text = str(relative).replace(os.sep, "/")

            if self.policy.is_denied_workspace_path(relative_text):
                continue

            if not self.policy.is_allowed_workspace_path(relative_text):
                continue

            target = destination / relative
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        self._create_writable_mount_targets(destination)

    def _create_writable_mount_targets(self, destination: Path):
        for writable_path in self.policy.writable_paths:
            raw_path = Path(os.path.expanduser(writable_path))
            if raw_path.is_absolute():
                try:
                    relative = raw_path.resolve(strict=False).relative_to(self.workspace)
                except ValueError:
                    continue
            else:
                relative = raw_path

            relative_text = str(relative).replace(os.sep, "/").lstrip("./")
            if not relative_text or relative_text == ".":
                continue

            if self.policy.is_denied_workspace_path(relative_text):
                continue

            (destination / relative).mkdir(parents=True, exist_ok=True)

    def _resolve_writable_path(self, path: str) -> Path:
        raw_path = Path(os.path.expanduser(path))
        source = raw_path if raw_path.is_absolute() else self.workspace / raw_path
        if not source.exists() and not raw_path.is_absolute():
            source.mkdir(parents=True, exist_ok=True)
        source = source.resolve(strict=True)
        self._validate_safe_mount_source(source, allow_inside_home=True)

        try:
            source.relative_to(self.workspace)
        except ValueError as exc:
            raise ValueError(f"writable path must be inside workspace: {path}") from exc

        return source

    def _container_target_for(self, source: Path) -> str:
        relative = source.relative_to(self.workspace)
        if str(relative) == ".":
            return CONTAINER_WORKDIR
        return str(Path(CONTAINER_WORKDIR) / relative)

    def _validate_safe_mount_source(self, source: Path, *, allow_inside_home: bool):
        home = Path.home().resolve()
        exact_dangerous_paths = [home, home.parent]
        dangerous_subtrees = [home / ".ssh", home / ".aws", home / ".config"]

        for dangerous in exact_dangerous_paths:
            if source == dangerous:
                raise ValueError(f"refusing dangerous mount source: {source}")

        for dangerous in dangerous_subtrees:
            if source == dangerous or self._is_relative_to(source, dangerous):
                raise ValueError(f"refusing dangerous mount source: {source}")

        if not allow_inside_home and self._is_relative_to(source, home):
            raise ValueError(f"refusing home directory mount source: {source}")

    def _is_relative_to(self, path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False


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
