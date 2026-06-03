import os
import shlex
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .decision import Decision, DecisionType


@dataclass(frozen=True)
class PolicyConfig:
    version: int = 1
    policy_backend: str = "yaml"
    sandbox_backend: str = "docker"
    fs_enforcement: str = "none"
    network: str = "deny"
    readonly_rootfs: bool = True
    readonly_workspace: bool = True
    protected_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    writable_paths: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    blocked_commands: list[str] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    allowed_env_vars: list[str] = field(default_factory=list)
    env_var_strip_pattern: list[str] = field(default_factory=list)
    allowed_mcp_servers: list[str] = field(default_factory=list)
    denied_mcp_servers: list[str] = field(default_factory=list)
    allowed_mcp_tools: list[str] = field(default_factory=list)
    denied_mcp_tools: list[str] = field(default_factory=list)
    max_file_size_mb: int = 10
    opa_policy: str = ""
    opa_query: str = "data.runeguard.allow"
    opa_command: str = "opa"

    @classmethod
    def from_mapping(cls, data: dict):
        data = normalize_policy_mapping(data)
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
        self.version = self.config.version
        self.policy_backend = self.config.policy_backend
        self.allowed_paths = self.config.allowed_paths
        self.sandbox_backend = self.config.sandbox_backend
        self.fs_enforcement = self.config.fs_enforcement
        self.network = self.config.network
        self.readonly_rootfs = self.config.readonly_rootfs
        self.readonly_workspace = self.config.readonly_workspace
        self.writable_paths = self.config.writable_paths
        self.allowed_domains = self.config.allowed_domains
        self.blocked_commands = self.config.blocked_commands
        self.require_approval = self.config.require_approval
        self.allowed_env_vars = self.config.allowed_env_vars
        self.env_var_strip_pattern = self.config.env_var_strip_pattern
        self.allowed_mcp_servers = self.config.allowed_mcp_servers
        self.denied_mcp_servers = self.config.denied_mcp_servers
        self.allowed_mcp_tools = self.config.allowed_mcp_tools
        self.denied_mcp_tools = self.config.denied_mcp_tools
        self.max_file_size_mb = self.config.max_file_size_mb
        self.opa_policy = self.config.opa_policy
        self.opa_query = self.config.opa_query
        self.opa_command = self.config.opa_command
        self._validate()

    @classmethod
    def from_file(cls, path: str):
        policy_path = Path(path)
        if policy_path.exists():
            with policy_path.open("r", encoding="utf-8") as f:
                return cls(yaml.safe_load(f) or {})

        if path in {"policies/default.yaml", "default.yaml"}:
            default_policy = files("runeguard").joinpath("default_policy.yaml")
            return cls(yaml.safe_load(default_policy.read_text(encoding="utf-8")) or {})

        with policy_path.open("r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f) or {})

    @classmethod
    def from_profile(cls, name: str):
        profile_name = Path(name).name.removesuffix(".yaml")
        profile_path = files("runeguard").joinpath("profiles", f"{profile_name}.yaml")
        if not profile_path.is_file():
            raise ValueError(f"unknown policy profile: {name}")

        return cls(yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {})

    def summary(self) -> dict:
        return asdict(self.config)

    def decide(self, tool_name: str, **kwargs) -> Decision:
        if self.policy_backend == "opa":
            from .opa import OpaConfig, OpaPolicyBackend

            return OpaPolicyBackend(
                OpaConfig(
                    policy=self.opa_policy,
                    query=self.opa_query,
                    command=self.opa_command,
                )
            ).decide(tool_name, kwargs)

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
            argv = kwargs.get("argv")
            for blocked in self.blocked_commands:
                if fnmatch(command, blocked) or self._matches_command_pattern(blocked, command, argv):
                    return Decision(
                        DecisionType.BLOCK,
                        f"blocked shell command pattern: {blocked}",
                    )

            protected_arg = self._protected_shell_arg(command, argv)
            if protected_arg:
                return Decision(
                    DecisionType.BLOCK,
                    f"protected path access: {protected_arg}",
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

        if tool_name in {"mcp_server", "mcp_tool"}:
            server_name = kwargs.get("server_name") or kwargs.get("server") or ""
            mcp_tool_name = kwargs.get("tool_name") or kwargs.get("mcp_tool") or ""
            if server_name and server_name in self.denied_mcp_servers:
                return Decision(DecisionType.BLOCK, f"denied MCP server: {server_name}")
            if self.allowed_mcp_servers and server_name and server_name not in self.allowed_mcp_servers:
                return Decision(DecisionType.BLOCK, f"MCP server not allowlisted: {server_name}")
            if self.allowed_mcp_tools and mcp_tool_name and mcp_tool_name not in self.allowed_mcp_tools:
                return Decision(DecisionType.BLOCK, f"MCP tool not allowlisted: {mcp_tool_name}")
            if mcp_tool_name and mcp_tool_name in self.denied_mcp_tools:
                return Decision(DecisionType.BLOCK, f"denied MCP tool: {mcp_tool_name}")

        return Decision(DecisionType.ALLOW, "allowed by policy")

    def _is_protected_path(self, path: str) -> bool:
        if self.is_denied_workspace_path(path):
            return True

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

    def is_denied_workspace_path(self, path: str) -> bool:
        normalized = self._strip_current_dir(str(Path(os.path.expanduser(path))).replace(os.sep, "/"))
        candidates = {normalized, Path(normalized).name}

        for pattern in self.protected_paths:
            normalized_pattern = self._strip_current_dir(pattern.replace(os.sep, "/"))
            home_relative = False
            if normalized_pattern.startswith("~/"):
                home_relative = True
                normalized_pattern = normalized_pattern[2:]

            if normalized_pattern.endswith("/"):
                normalized_pattern = f"{normalized_pattern}**"

            if home_relative and self._matches_secret_subtree(normalized, normalized_pattern):
                return True

            for candidate in candidates:
                if fnmatch(candidate, normalized_pattern):
                    return True

                if normalized_pattern.endswith("/**"):
                    prefix = normalized_pattern[:-3].rstrip("/")
                    if candidate == prefix or candidate.startswith(f"{prefix}/"):
                        return True

        return False

    def _matches_secret_subtree(self, candidate: str, pattern: str) -> bool:
        if not pattern.endswith("/**"):
            return False

        prefix = pattern[:-3].rstrip("/")
        return candidate == prefix or candidate.startswith(f"{prefix}/") or f"/{prefix}/" in candidate

    def is_allowed_workspace_path(self, path: str) -> bool:
        if not self.allowed_paths:
            return True

        normalized = self._strip_current_dir(str(Path(path)).replace(os.sep, "/"))
        return any(fnmatch(normalized, self._strip_current_dir(pattern)) for pattern in self.allowed_paths)

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

    def _protected_shell_arg(
        self,
        command: str,
        argv: list[str] | tuple[str, ...] | None,
    ) -> str:
        command_tokens = list(argv) if argv else self._split_command(command)
        for token in command_tokens[1:]:
            if not token or token.startswith("-"):
                continue
            if self._is_protected_path(token):
                return token
        return ""

    def _normalize_path(self, value: str) -> Path:
        return Path(os.path.expanduser(value)).resolve(strict=False)

    def _strip_current_dir(self, value: str) -> str:
        if value == ".":
            return value
        return value[2:] if value.startswith("./") else value

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
            "allowed_paths": self.allowed_paths,
            "writable_paths": self.writable_paths,
            "allowed_domains": self.allowed_domains,
            "blocked_commands": self.blocked_commands,
            "require_approval": self.require_approval,
            "allowed_env_vars": self.allowed_env_vars,
            "env_var_strip_pattern": self.env_var_strip_pattern,
            "allowed_mcp_servers": self.allowed_mcp_servers,
            "denied_mcp_servers": self.denied_mcp_servers,
            "allowed_mcp_tools": self.allowed_mcp_tools,
            "denied_mcp_tools": self.denied_mcp_tools,
        }

        for name, value in fields.items():
            if not isinstance(value, list):
                raise ValueError(f"{name} must be a list")

            if not all(isinstance(item, str) for item in value):
                raise ValueError(f"{name} must contain only strings")

        if not isinstance(self.max_file_size_mb, int) or self.max_file_size_mb < 1:
            raise ValueError("max_file_size_mb must be a positive integer")

        if self.policy_backend not in {"yaml", "opa"}:
            raise ValueError("policy_backend must be one of: yaml, opa")

        if not isinstance(self.opa_policy, str):
            raise ValueError("opa_policy must be a string")

        if not isinstance(self.opa_query, str) or not self.opa_query:
            raise ValueError("opa_query must be a non-empty string")

        if not isinstance(self.opa_command, str) or not self.opa_command:
            raise ValueError("opa_command must be a non-empty string")

        if self.sandbox_backend not in {"docker", "host", "landlock"}:
            raise ValueError("sandbox_backend must be one of: docker, host, landlock")

        if self.fs_enforcement not in {"none", "landlock"}:
            raise ValueError("fs_enforcement must be one of: none, landlock")

        if self.network not in {"deny", "deny_all", "none", "host", "bridge"}:
            raise ValueError("network must be one of: deny, deny_all, none, host, bridge")

        if not isinstance(self.readonly_rootfs, bool):
            raise ValueError("readonly_rootfs must be a boolean")

        if not isinstance(self.readonly_workspace, bool):
            raise ValueError("readonly_workspace must be a boolean")

        if self.version != 1:
            raise ValueError("unsupported policy version; fix by setting version: 1")


def normalize_policy_mapping(data: dict) -> dict:
    if (
        "sandbox" not in data
        and "files" not in data
        and "network" not in data
        and "shell" not in data
        and "policy" not in data
        and "opa" not in data
        and "mcp" not in data
    ):
        return data

    sandbox = _section(data, "sandbox")
    policy_backend = _section(data, "policy")
    files = _section(data, "files")
    network = _section(data, "network")
    shell = _section(data, "shell")
    opa = _section(data, "opa")
    mcp = _section(data, "mcp")

    return {
        "version": data.get("version", 1),
        "policy_backend": policy_backend.get("backend", data.get("policy_backend", "yaml")),
        "sandbox_backend": sandbox.get("backend", data.get("sandbox_backend", "docker")),
        "fs_enforcement": sandbox.get("fs_enforcement", data.get("fs_enforcement", "none")),
        "network": network.get("default", sandbox.get("network", data.get("network", "deny"))),
        "readonly_rootfs": sandbox.get("readonly_rootfs", data.get("readonly_rootfs", True)),
        "readonly_workspace": sandbox.get("readonly_workspace", data.get("readonly_workspace", True)),
        "protected_paths": files.get("deny", data.get("protected_paths", [])),
        "allowed_paths": files.get("allow", data.get("allowed_paths", [])),
        "writable_paths": sandbox.get("writable_paths", data.get("writable_paths", [])),
        "allowed_domains": network.get("allow_domains", data.get("allowed_domains", [])),
        "blocked_commands": shell.get("deny_patterns", data.get("blocked_commands", [])),
        "require_approval": data.get("require_approval", []),
        "allowed_env_vars": data.get("allowed_env_vars", []),
        "env_var_strip_pattern": data.get("env_var_strip_pattern", []),
        "allowed_mcp_servers": mcp.get("allow_servers", data.get("allowed_mcp_servers", [])),
        "denied_mcp_servers": mcp.get("deny_servers", data.get("denied_mcp_servers", [])),
        "allowed_mcp_tools": mcp.get("allow_tools", data.get("allowed_mcp_tools", [])),
        "denied_mcp_tools": mcp.get("deny_tools", data.get("denied_mcp_tools", [])),
        "max_file_size_mb": data.get("max_file_size_mb", 10),
        "opa_policy": opa.get("policy", data.get("opa_policy", "")),
        "opa_query": opa.get("query", data.get("opa_query", "data.runeguard.allow")),
        "opa_command": opa.get("command", data.get("opa_command", "opa")),
    }


def _section(data: dict, key: str) -> dict:
    value = data.get(key, {})
    return value if isinstance(value, dict) else {}
