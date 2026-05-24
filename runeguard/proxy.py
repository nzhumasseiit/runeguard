from .decision import DecisionType
from .logger import log_decision


class RuneGuardProxy:
    def __init__(self, policy, *, audit_log=None, json_logs: bool = False, quiet: bool = False):
        self.policy = policy
        self.audit_log = audit_log
        self.json_logs = json_logs
        self.quiet = quiet

    def call(self, tool_name: str, fn, *, audit_fields: dict | None = None, **kwargs):
        decision = self.policy.decide(tool_name, **kwargs)
        audit_fields = audit_fields or {}
        log_decision(
            tool_name,
            decision,
            kwargs,
            audit_log=self.audit_log,
            json_logs=self.json_logs,
            quiet=self.quiet,
            tool_call=audit_fields.get("tool_call", tool_name),
            command=audit_fields.get("command"),
            path=audit_fields.get("path"),
            rule_matched=audit_fields.get("rule_matched"),
        )

        if decision.type == DecisionType.BLOCK:
            raise PermissionError(decision.reason)

        if decision.type == DecisionType.REQUIRE_APPROVAL:
            raise PermissionError(decision.reason)

        return fn(**kwargs)
