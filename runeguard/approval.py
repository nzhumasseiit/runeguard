from dataclasses import dataclass, field

from .decision import Decision, DecisionType


PROTECTED_READ_MARKERS = (".env", ".ssh", ".aws", "PRIVATE KEY", "id_rsa", "service-account")


@dataclass
class ApprovalManager:
    session_allows: set[str] = field(default_factory=set)
    session_denies: set[str] = field(default_factory=set)

    def action_key(self, tool_name: str, kwargs: dict) -> str:
        target = kwargs.get("url") or kwargs.get("host") or kwargs.get("path") or kwargs.get("command") or ""
        return f"{tool_name}:{target}"

    def is_never_approvable(self, tool_name: str, kwargs: dict) -> bool:
        if tool_name not in {"read_file", "open", "openat"}:
            return False
        path = str(kwargs.get("path") or kwargs.get("pathname") or "")
        return any(marker.lower() in path.lower() for marker in PROTECTED_READ_MARKERS)

    def decide(self, tool_name: str, kwargs: dict, base_decision: Decision) -> Decision:
        key = self.action_key(tool_name, kwargs)
        if key in self.session_allows:
            return Decision(DecisionType.ALLOW, "allowed by session approval")
        if key in self.session_denies:
            return Decision(DecisionType.BLOCK, "denied by session approval")
        return base_decision

    def allow_for_session(self, tool_name: str, kwargs: dict):
        self.session_allows.add(self.action_key(tool_name, kwargs))

    def deny_for_session(self, tool_name: str, kwargs: dict):
        self.session_denies.add(self.action_key(tool_name, kwargs))


class ApprovalPolicy:
    def __init__(self, policy, manager: ApprovalManager):
        self._policy = policy
        self._manager = manager

    def decide(self, tool_name: str, **kwargs):
        decision = self._policy.decide(tool_name, **kwargs)
        return self._manager.decide(tool_name, kwargs, decision)

    def __getattr__(self, name):
        return getattr(self._policy, name)
