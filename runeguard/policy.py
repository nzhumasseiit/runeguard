import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .decision import Decision, DecisionType


class Policy:
    def __init__(self, data: dict):
        self.protected_paths = data.get("protected_paths", [])
        self.allowed_domains = data.get("allowed_domains", [])
        self.blocked_commands = data.get("blocked_commands", [])
        self.require_approval = data.get("require_approval", [])

    @classmethod
    def from_file(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f) or {})

    def decide(self, tool_name: str, **kwargs) -> Decision:
        if tool_name in self.require_approval:
            return Decision(
                DecisionType.REQUIRE_APPROVAL,
                f"{tool_name} requires human approval",
            )

        if tool_name in {"read_file", "write_file"}:
            path = kwargs.get("path", "")
            if self._is_protected_path(path):
                return Decision(
                    DecisionType.BLOCK,
                    f"protected path access: {path}",
                )

        if tool_name == "shell":
            command = kwargs.get("command", "")
            for blocked in self.blocked_commands:
                if blocked in command:
                    return Decision(
                        DecisionType.BLOCK,
                        f"blocked shell command pattern: {blocked}",
                    )

        if tool_name in {"http_post", "external_http_post"}:
            url = kwargs.get("url", "")
            domain = urlparse(url).hostname or ""
            if domain not in self.allowed_domains:
                return Decision(
                    DecisionType.BLOCK,
                    f"domain not allowlisted: {domain}",
                )

        return Decision(DecisionType.ALLOW, "allowed by policy")

    def _is_protected_path(self, path: str) -> bool:
        expanded = os.path.expanduser(path)
        normalized = str(Path(expanded))

        for protected in self.protected_paths:
            protected_expanded = os.path.expanduser(protected)
            protected_normalized = str(Path(protected_expanded))

            if normalized == protected_normalized:
                return True

            if normalized.endswith(protected_normalized):
                return True

            if Path(normalized).name == protected:
                return True

        return False
