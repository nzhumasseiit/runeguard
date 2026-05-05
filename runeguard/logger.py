from .decision import DecisionType

try:
    from rich.console import Console

    console = Console()
except Exception:
    console = None


def log_decision(tool_name: str, decision, kwargs: dict):
    msg = f"[{decision.type}] {tool_name}({kwargs}) - {decision.reason}"

    if console:
        if decision.type == DecisionType.ALLOW:
            console.print(msg, style="green")
        elif decision.type == DecisionType.BLOCK:
            console.print(msg, style="bold red")
        else:
            console.print(msg, style="yellow")
    else:
        print(msg)
