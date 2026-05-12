import json
from collections import Counter
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
