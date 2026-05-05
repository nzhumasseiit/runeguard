from .decision import DecisionType
from .logger import log_decision


class RuneGuardProxy:
    def __init__(self, policy):
        self.policy = policy

    def call(self, tool_name: str, fn, **kwargs):
        decision = self.policy.decide(tool_name, **kwargs)
        log_decision(tool_name, decision, kwargs)

        if decision.type == DecisionType.BLOCK:
            raise PermissionError(decision.reason)

        if decision.type == DecisionType.REQUIRE_APPROVAL:
            raise PermissionError(decision.reason)

        return fn(**kwargs)
