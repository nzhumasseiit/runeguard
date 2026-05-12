import json
from collections import Counter
from html import escape
from pathlib import Path


def summarize_audit_log(path: str | Path) -> dict:
    total = 0
    allowed = 0
    blocked = 0
    blocked_actions: Counter[str] = Counter()
    blocked_reasons: Counter[str] = Counter()

    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            record = json.loads(line)
            total += 1
            decision = record.get("decision")

            if decision == "ALLOW":
                allowed += 1
            elif decision == "BLOCK":
                blocked += 1
                blocked_actions[record.get("tool", "<unknown>")] += 1
                blocked_reasons[record.get("reason", "<unknown>")] += 1

    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "blocked_actions": blocked_actions,
        "blocked_reasons": blocked_reasons,
    }


def render_summary_text(summary: dict) -> str:
    lines = [
        f"Total decisions: {summary['total']}",
        f"Allowed: {summary['allowed']}",
        f"Blocked: {summary['blocked']}",
        "Blocked actions by tool:",
    ]

    if summary["blocked_actions"]:
        lines.extend(f"  {tool}: {count}" for tool, count in summary["blocked_actions"].most_common())
    else:
        lines.append("  none")

    lines.append("Top blocked reasons:")
    if summary["blocked_reasons"]:
        lines.extend(
            f"  {reason}: {count}" for reason, count in summary["blocked_reasons"].most_common(5)
        )
    else:
        lines.append("  none")

    return "\n".join(lines)


def render_summary_html(summary: dict) -> str:
    blocked_actions = summary["blocked_actions"].most_common()
    blocked_reasons = summary["blocked_reasons"].most_common(5)

    action_rows = "\n".join(
        f"<tr><td>{escape(tool)}</td><td>{count}</td></tr>" for tool, count in blocked_actions
    ) or "<tr><td colspan=\"2\">none</td></tr>"
    reason_rows = "\n".join(
        f"<tr><td>{escape(reason)}</td><td>{count}</td></tr>" for reason, count in blocked_reasons
    ) or "<tr><td colspan=\"2\">none</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RuneGuard Audit Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }}
    table {{ border-collapse: collapse; margin: 1rem 0 2rem; min-width: 24rem; }}
    td, th {{ border: 1px solid #ccc; padding: 0.45rem 0.65rem; text-align: left; }}
    th {{ background: #f4f4f4; }}
  </style>
</head>
<body>
  <h1>RuneGuard Audit Report</h1>
  <p>Total decisions: <strong>{summary['total']}</strong></p>
  <p>Allowed: <strong>{summary['allowed']}</strong></p>
  <p>Blocked: <strong>{summary['blocked']}</strong></p>
  <h2>Blocked actions by tool</h2>
  <table><thead><tr><th>Tool</th><th>Count</th></tr></thead><tbody>{action_rows}</tbody></table>
  <h2>Top blocked reasons</h2>
  <table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>{reason_rows}</tbody></table>
</body>
</html>
"""
