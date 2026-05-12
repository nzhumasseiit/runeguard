import os
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .decision import Decision, DecisionType


@dataclass(frozen=True)
class PolicyConfig:
    protected_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    blocked_commands: list[str] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    allowed_env_vars: list[str] = field(default_factory=list)
    max_file_size_mb: int = 10

    @classmethod
    def from_mapping(cls, data: dict):
        allowed_keys = set(cls.__dataclass_fields__)
        unknown_keys = sorted(set(data) - allowed_keys)
        if unknown_keys:
            raise ValueError(f"unknown policy keys: {', '.join(unknown_keys)}")

        return cls(**data)


class Policy:
    def __init__(self, data: dict | PolicyConfig):
        if isinstance(data, PolicyConfig):
            self.config = data
        else:
            if not isinstance(data, dict):
                raise ValueError("policy must be a YAML mapping")

            self.config = PolicyConfig.from_mapping(data)

        self.protected_paths = self.config.protected_paths
        self.writable_paths = self.config.writable_paths
        self.allowed_domains = self.config.allowed_domains
        self.blocked_commands = self.config.blocked_commands
        self.require_approval = self.config.require_approval
        self.allowed_env_vars = self.config.allowed_env_vars
        self.max_file_size_mb = self.config.max_file_size_mb
        self._validate()

    @classmethod
    def from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f) or {})

    def summary(self) -> dict:
        return asdict(self.config)

    def decide(self, tool_name: str, **kwargs) -> Decision:
        if tool_name in self.require_approval:
            return Decision(
                DecisionType.REQUIRE_APPROVAL,
                f"{tool_name} requires human approval",
            )

        if tool_name in {"read_file", "write_file", "open", "openat"}:
            path = kwargs.get("path") or kwargs.get("pathname") or ""
            if self._is_protected_path(path):
                return Decision(
                    DecisionType.BLOCK,
                    f"protected path access: {path}",
                )

        if tool_name in {"shell", "execve"}:
            command = kwargs.get("command", "")
            for blocked in self.blocked_commands:
                if self._matches_command_pattern(blocked, command, kwargs.get("argv")):
                    return Decision(
                        DecisionType.BLOCK,
                        f"blocked shell command pattern: {blocked}",
                    )

        if tool_name in {"http_post", "external_http_post", "connect", "socket"}:
            url = kwargs.get("url", "")
            domain = urlparse(url).hostname or kwargs.get("host", "")
            if not domain:
                return Decision(
                    DecisionType.BLOCK,
                    f"invalid or missing URL: {url}",
                )

            if not self._is_allowed_domain(domain):
                return Decision(
                    DecisionType.BLOCK,
                    f"domain not allowlisted: {domain}",
                )

        return Decision(DecisionType.ALLOW, "allowed by policy")

    def _is_protected_path(self, path: str) -> bool:
        candidate = self._normalize_path(path)
        candidate_parts = candidate.parts

        for protected in self.protected_paths:
            protected_raw = Path(os.path.expanduser(protected))
            protected_path = self._normalize_path(protected)

            if candidate == protected_path:
                return True

            if protected.endswith(os.sep) or protected.endswith("/"):
                if protected_raw.is_absolute():
                    try:
                        candidate.relative_to(protected_path)
                        return True
                    except ValueError:
                        pass
                elif self._path_contains_directory(candidate_parts, protected_raw.name):
                    return True

            if self._is_filename_only(protected_raw) and candidate.name == protected_raw.name:
                return True

            if not protected_raw.is_absolute() and self._ends_with_parts(
                candidate_parts,
                protected_raw.parts,
            ):
                return True

        return False

    def _is_allowed_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")

        for allowed in self.allowed_domains:
            allowed = allowed.lower().rstrip(".")

            if allowed.startswith("*."):
                suffix = allowed[2:]
                if domain == suffix or domain.endswith(f".{suffix}"):
                    return True

            if domain == allowed:
                return True

        return False

    def _matches_command_pattern(
        self,
        blocked: str,
        command: str,
        argv: list[str] | tuple[str, ...] | None,
    ) -> bool:
        blocked_tokens = self._split_command(blocked)
        command_tokens = list(argv) if argv else self._split_command(command)

        if not blocked_tokens:
            return False

        if len(blocked_tokens) == 1:
            return blocked_tokens[0] in command_tokens

        window = len(blocked_tokens)
        return any(
            command_tokens[index : index + window] == blocked_tokens
            for index in range(len(command_tokens) - window + 1)
        )

    def _split_command(self, value: str) -> list[str]:
        try:
            return shlex.split(value)
        except ValueError:
            return value.split()

    def _normalize_path(self, value: str) -> Path:
        return Path(os.path.expanduser(value)).resolve(strict=False)

    def _path_contains_directory(self, parts: tuple[str, ...], directory_name: str) -> bool:
        return directory_name in parts[:-1]

    def _is_filename_only(self, path: Path) -> bool:
        return not path.is_absolute() and len(path.parts) == 1

    def _ends_with_parts(
        self,
        candidate_parts: tuple[str, ...],
        protected_parts: tuple[str, ...],
    ) -> bool:
        if not protected_parts or len(protected_parts) > len(candidate_parts):
            return False

        return candidate_parts[-len(protected_parts) :] == protected_parts

    def _validate(self):
        fields = {
            "protected_paths": self.protected_paths,
            "writable_paths": self.writable_paths,
            "allowed_domains": self.allowed_domains,
            "blocked_commands": self.blocked_commands,
            "require_approval": self.require_approval,
            "allowed_env_vars": self.allowed_env_vars,
        }

        for name, value in fields.items():
            if not isinstance(value, list):
                raise ValueError(f"{name} must be a list")

            if not all(isinstance(item, str) for item in value):
                raise ValueError(f"{name} must contain only strings")

        if not isinstance(self.max_file_size_mb, int) or self.max_file_size_mb < 1:
            raise ValueError("max_file_size_mb must be a positive integer")
