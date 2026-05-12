from collections.abc import Callable
from typing import Any

from runeguard.policy import Policy
from runeguard.proxy import RuneGuardProxy


class GuardedAgent:
    """Base helper for routing agent tool calls through RuneGuard."""

    def __init__(
        self,
        policy_path: str = "policies/default.yaml",
        *,
        audit_log: str | None = None,
        json_logs: bool = False,
    ):
        self.policy = Policy.from_file(policy_path)
        self.proxy = RuneGuardProxy(
            self.policy,
            audit_log=audit_log,
            json_logs=json_logs,
        )

    def guarded_call(self, tool_name: str, func: Callable[..., Any], **kwargs):
        return self.proxy.call(tool_name, func, **kwargs)
