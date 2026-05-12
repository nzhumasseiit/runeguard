import json
from datetime import datetime, timezone
from pathlib import Path

from .decision import DecisionType

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
):
    record = decision_record(tool_name, decision, kwargs)

    if audit_log:
        write_audit_record(audit_log, record)

    if quiet:
        return

    if json_logs:
        print(json.dumps(record, sort_keys=True))
        return

    msg = f"[{decision.type.value}] {tool_name}({kwargs}) - {decision.reason}"

    if console:
        if decision.type == DecisionType.ALLOW:
            console.print(msg, style="green")
        elif decision.type == DecisionType.BLOCK:
            console.print(msg, style="bold red")
        else:
            console.print(msg, style="yellow")
    else:
        print(msg)


def decision_record(tool_name: str, decision, kwargs: dict) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "decision": decision.type.value,
        "reason": decision.reason,
        "input": _redact(kwargs),
    }


def write_audit_record(path: str | Path, record: dict):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True))
        f.write("\n")


def _redact(value):
    if isinstance(value, dict):
        redacted = {}

        for key, item in value.items():
            key_text = str(key).lower()
            if key_text in {"data", "body", "payload", "secret", "token", "password"}:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _redact(item)

        return redacted

    if isinstance(value, list):
        return [_redact(item) for item in value]

    if isinstance(value, tuple):
        return [_redact(item) for item in value]

    return value
