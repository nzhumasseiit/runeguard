import json
from pathlib import Path

from .audit import audit_record
from .decision import DecisionType
from .redaction import redact_value

try:
    from rich.console import Console

    console = Console()
except Exception:
    console = None


def log_decision(
    tool_name: str,
    decision,
    kwargs: dict,
    *,
    audit_log: str | Path | None = None,
    json_logs: bool = False,
    quiet: bool = False,
    tool_call: str | None = None,
    command: str | None = None,
    path: str | None = None,
    rule_matched: str | None = None,
):
    record = decision_record(
        tool_name,
        decision,
        kwargs,
        tool_call=tool_call,
        command=command,
        path=path,
        rule_matched=rule_matched,
    )

    if audit_log:
        write_audit_record(audit_log, record)

    if quiet:
        return

    if json_logs:
        print(json.dumps(redact_value(record), sort_keys=True))
        return

    msg = f"[{decision.type.value}] {tool_name}({redact_value(kwargs)}) - {redact_value(decision.reason)}"

    if console:
        if decision.type == DecisionType.ALLOW:
            console.print(msg, style="green")
        elif decision.type == DecisionType.BLOCK:
            console.print(msg, style="bold red")
        else:
            console.print(msg, style="yellow")
    else:
        print(msg)


def decision_record(
    tool_name: str,
    decision,
    kwargs: dict,
    *,
    tool_call: str | None = None,
    command: str | None = None,
    path: str | None = None,
    rule_matched: str | None = None,
) -> dict:
    return audit_record(
        tool_call=tool_call or tool_name,
        command=command if command is not None else _command_from_kwargs(kwargs),
        path=path if path is not None else _path_from_kwargs(kwargs),
        decision=decision.type.value,
        rule_matched=rule_matched if rule_matched is not None else _rule_from_reason(decision.reason),
        reason=decision.reason,
    )


def write_audit_record(path: str | Path, record: dict):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("a", encoding="utf-8") as f:
        f.write(json.dumps(redact_value(record), sort_keys=True))
        f.write("\n")


def _command_from_kwargs(kwargs: dict) -> str | None:
    command = kwargs.get("command")
    if command is not None:
        return str(command)

    argv = kwargs.get("argv")
    if isinstance(argv, (list, tuple)):
        return " ".join(str(part) for part in argv)

    return None


def _path_from_kwargs(kwargs: dict) -> str | None:
    path = kwargs.get("path") or kwargs.get("pathname")
    return str(path) if path is not None else None


def _rule_from_reason(reason: str) -> str | None:
    if ": " not in reason:
        return None

    prefix, matched = reason.split(": ", 1)
    if prefix in {
        "protected path access",
        "blocked shell command pattern",
        "domain not allowlisted",
    }:
        return matched

    return None

