"""
OpenAI Codex / Responses API integration.

Example:

    from runeguard.agents.openai_codex import GuardedToolkit

    tools = GuardedToolkit([read_file, shell, http_post], policy="ci.yaml")
    client.responses.create(model="codex-mini-latest", tools=tools.definitions, ...)
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

from runeguard.decision import DecisionType
from runeguard.logger import log_decision
from runeguard.policy import Policy


PATH_TOOL_NAMES = {"read_file", "write_file", "open", "openat"}


def runeguard_tool(
    policy_path: str | Path,
    *,
    audit_log: str | Path | None = None,
    policy: Policy | None = None,
):
    """Decorate an OpenAI-style Python tool function with RuneGuard policy checks."""

    loaded_policy = policy or _load_policy(policy_path)

    def decorate(func: Callable[..., Any]):
        @wraps(func)
        def guarded(*args, **kwargs):
            checks = _checks_for_call(func.__name__, kwargs)
            if not checks:
                checks = [(func.__name__, kwargs, {})]

            for tool_name, decision_kwargs, audit_fields in checks:
                decision = loaded_policy.decide(tool_name, **decision_kwargs)
                log_decision(
                    tool_name,
                    decision,
                    decision_kwargs,
                    audit_log=audit_log,
                    quiet=True,
                    tool_call=func.__name__,
                    command=audit_fields.get("command"),
                    path=audit_fields.get("path"),
                )
                if decision.type in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
                    raise PermissionError(decision.reason)

            return func(*args, **kwargs)

        guarded.runeguard_policy = loaded_policy
        guarded.runeguard_original = func
        return guarded

    return decorate


class GuardedToolkit:
    """Wrap a list of Python tool functions for OpenAI Chat Completions or Responses."""

    def __init__(
        self,
        tools: list[Callable[..., Any]],
        *,
        policy: str | Path | Policy = "policies/default.yaml",
        audit_log: str | Path | None = None,
    ):
        self.policy = _load_policy(policy) if not isinstance(policy, Policy) else policy
        self.audit_log = audit_log
        self.definitions = [
            runeguard_tool(
                "policies/default.yaml",
                audit_log=audit_log,
                policy=self.policy,
            )(tool)
            for tool in tools
        ]

    def __iter__(self):
        return iter(self.definitions)


def _load_policy(policy: str | Path) -> Policy:
    policy_text = str(policy)
    if not Path(policy_text).exists() and "/" not in policy_text and "\\" not in policy_text:
        try:
            return Policy.from_profile(policy_text.removesuffix(".yaml"))
        except ValueError:
            pass
    return Policy.from_file(policy_text)


def _checks_for_call(
    function_name: str,
    kwargs: dict[str, Any],
) -> list[tuple[str, dict[str, Any], dict[str, str]]]:
    checks: list[tuple[str, dict[str, Any], dict[str, str]]] = []

    command = kwargs.get("command")
    if command is not None:
        checks.append((
            "shell",
            {"command": str(command), "argv": kwargs.get("argv")},
            {"command": str(command)},
        ))

    path = kwargs.get("path") or kwargs.get("pathname")
    if path is not None:
        key = "pathname" if "pathname" in kwargs else "path"
        tool_name = function_name if function_name in PATH_TOOL_NAMES else "read_file"
        checks.append((
            tool_name,
            {key: str(path)},
            {"path": str(path)},
        ))

    url = kwargs.get("url")
    if url is not None:
        checks.append((
            "http_post",
            {"url": str(url)},
            {},
        ))

    return checks
