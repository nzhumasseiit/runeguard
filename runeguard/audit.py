import json
import os
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from .correlation import current_turn
from .redaction import redact_value


def audit_record(
    *,
    tool_call: str,
    decision: str,
    reason: str,
    command: str | None = None,
    path: str | None = None,
    rule_matched: str | None = None,
) -> dict:
    context = current_turn()

    return {
        "run_id": context.turn_id if context else "unknown",
        "agent": os.environ.get("RUNEGUARD_AGENT") or (context.agent if context else "unknown"),
        "tool_call": tool_call,
        "command": command,
        "path": path,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "decision": _normalize_decision(decision),
        "rule_matched": rule_matched,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


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

            record = redact_value(json.loads(line))
            total += 1
            decision = str(record.get("decision", "")).lower()

            if decision == "allow":
                allowed += 1
            elif decision == "block":
                blocked += 1
                blocked_actions[record.get("tool_call") or record.get("tool", "<unknown>")] += 1
                blocked_reasons[record.get("reason", "<unknown>")] += 1

    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "blocked_actions": blocked_actions,
        "blocked_reasons": blocked_reasons,
    }


def build_report(path: str | Path) -> dict:
    events = _read_jsonl(path)
    decision_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    target_counts: Counter[str] = Counter()

    for event in events:
        decision = _normalize_decision(str(event.get("decision", "audit")))
        event["decision"] = decision
        decision_counts[decision] += 1

        rule = event.get("rule_matched")
        if rule:
            rule_counts[str(rule)] += 1

        target = event.get("path") or event.get("command")
        if target:
            target_counts[str(target)] += 1

    return {
        "summary": {
            "total_events": len(events),
            "blocked_count": decision_counts["block"],
            "decision_counts": {
                "allow": decision_counts["allow"],
                "block": decision_counts["block"],
                "audit": decision_counts["audit"],
            },
            "rule_matched_counts": dict(rule_counts.most_common()),
            "target_counts": dict(target_counts.most_common()),
            "top_blocked_rules": _top_blocked_rules(events),
        },
        "events": events,
    }


def render_report_markdown(report: dict) -> str:
    summary = report["summary"]
    top_rules = summary["top_blocked_rules"]
    top_rules_text = ", ".join(f"{rule} ({count})" for rule, count in top_rules) or "none"

    lines = [
        "# RuneGuard Report",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total events | {summary['total_events']} |",
        f"| Blocked count | {summary['blocked_count']} |",
        f"| Allowed count | {summary['decision_counts']['allow']} |",
        f"| Audit count | {summary['decision_counts']['audit']} |",
        f"| Top 5 blocked rules | {_md(top_rules_text)} |",
        "",
        "## Rule Counts",
        "",
        "| Rule matched | Count |",
        "| --- | ---: |",
    ]

    if summary["rule_matched_counts"]:
        lines.extend(
            f"| {_md(rule)} | {count} |"
            for rule, count in summary["rule_matched_counts"].items()
        )
    else:
        lines.append("| none | 0 |")

    lines.extend([
        "",
        "## Path And Command Counts",
        "",
        "| Path or command | Count |",
        "| --- | ---: |",
    ])

    if summary["target_counts"]:
        lines.extend(
            f"| {_md(target)} | {count} |"
            for target, count in summary["target_counts"].items()
        )
    else:
        lines.append("| none | 0 |")

    lines.extend([
        "",
        "## Events",
        "",
        "| Timestamp | Decision | Tool | Rule matched | Path | Command | Reason |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])

    for event in report["events"]:
        lines.append(
            "| "
            + " | ".join(
                _md(str(event.get(key) or ""))
                for key in ("timestamp", "decision", "tool_call", "rule_matched", "path", "command", "reason")
            )
            + " |"
        )

    return "\n".join(lines)


def render_report_html(report: dict) -> str:
    summary = report["summary"]
    top_rules = ", ".join(
        f"{escape(rule)} ({count})" for rule, count in summary["top_blocked_rules"]
    ) or "none"
    rule_rows = "\n".join(
        f"<tr><td>{escape(rule)}</td><td>{count}</td></tr>"
        for rule, count in summary["rule_matched_counts"].items()
    ) or "<tr><td>none</td><td>0</td></tr>"
    target_rows = "\n".join(
        f"<tr><td>{escape(target)}</td><td>{count}</td></tr>"
        for target, count in summary["target_counts"].items()
    ) or "<tr><td>none</td><td>0</td></tr>"
    event_rows = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(str(event.get(key) or ''))}</td>"
            for key in ("timestamp", "decision", "tool_call", "rule_matched", "path", "command", "reason")
        )
        + "</tr>"
        for event in report["events"]
    ) or "<tr><td colspan=\"7\">No events</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RuneGuard Audit Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #172033; }}
    h1, h2 {{ margin: 0 0 1rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 0 0 2rem; font-size: 0.92rem; }}
    th, td {{ border: 1px solid #d3d8e0; padding: 0.5rem 0.65rem; text-align: left; vertical-align: top; }}
    th {{ background: #f4f6f8; }}
    code {{ background: #f4f6f8; padding: 0.1rem 0.25rem; border-radius: 0.2rem; }}
  </style>
</head>
<body>
  <h1>RuneGuard Audit Report</h1>
  <h2>Summary</h2>
  <table>
    <thead><tr><th>Metric</th><th>Value</th></tr></thead>
    <tbody>
      <tr><td>Total events</td><td>{summary['total_events']}</td></tr>
      <tr><td>Blocked count</td><td>{summary['blocked_count']}</td></tr>
      <tr><td>Allowed count</td><td>{summary['decision_counts']['allow']}</td></tr>
      <tr><td>Audit count</td><td>{summary['decision_counts']['audit']}</td></tr>
      <tr><td>Top 5 blocked rules</td><td>{top_rules}</td></tr>
    </tbody>
  </table>
  <h2>Rule Counts</h2>
  <table>
    <thead><tr><th>Rule matched</th><th>Count</th></tr></thead>
    <tbody>{rule_rows}</tbody>
  </table>
  <h2>Path And Command Counts</h2>
  <table>
    <thead><tr><th>Path or command</th><th>Count</th></tr></thead>
    <tbody>{target_rows}</tbody>
  </table>
  <h2>Events</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Decision</th><th>Tool</th><th>Rule matched</th><th>Path</th><th>Command</th><th>Reason</th></tr></thead>
    <tbody>{event_rows}</tbody>
  </table>
</body>
</html>
"""


def render_report_json(report: dict) -> str:
    return json.dumps(redact_value(report), indent=2, sort_keys=True)


def render_pr_summary_markdown(report: dict) -> str:
    summary = report["summary"]
    blocked = [
        event for event in report["events"]
        if _normalize_decision(str(event.get("decision", "audit"))) == "block"
    ]
    domains = sorted({
        str(event.get("reason", "")).split(": ", 1)[1]
        for event in blocked
        if str(event.get("reason", "")).startswith("domain not allowlisted: ")
    })
    written = sorted({
        str(event.get("path"))
        for event in report["events"]
        if event.get("tool_call") in {"write_file", "write", "openat"} and event.get("path")
    })
    commands = sorted({
        str(event.get("command"))
        for event in report["events"]
        if event.get("command")
    })

    lines = [
        "## RuneGuard PR Summary",
        "",
        f"- Total events: {summary['total_events']}",
        f"- Blocked actions: {summary['blocked_count']}",
        f"- Allowed actions: {summary['decision_counts']['allow']}",
        f"- Domains blocked/contacted: {', '.join(domains) if domains else 'none recorded'}",
        f"- Files written: {', '.join(written) if written else 'none recorded'}",
        "",
        "### Commands",
    ]
    lines.extend(f"- `{_md(command)}`" for command in commands) if commands else lines.append("- none recorded")
    lines.append("")
    lines.append("### Review Before Merging")
    if blocked:
        lines.extend(f"- Blocked `{event.get('tool_call')}`: {_md(str(event.get('reason') or 'unknown'))}" for event in blocked[:10])
    else:
        lines.append("- No blocked actions recorded.")
    return "\n".join(redact_value(lines))


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


def _normalize_decision(decision: str) -> str:
    normalized = decision.lower()
    if normalized == "require_approval":
        return "block"
    if normalized in {"allow", "block", "audit"}:
        return normalized
    return "audit"


def _read_jsonl(path: str | Path) -> list[dict]:
    events = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(redact_value(json.loads(line)))
    return events


def _top_blocked_rules(events: list[dict]) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for event in events:
        if _normalize_decision(str(event.get("decision", "audit"))) != "block":
            continue
        rule = event.get("rule_matched") or "<none>"
        counter[str(rule)] += 1
    return counter.most_common(5)


def _md(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")
