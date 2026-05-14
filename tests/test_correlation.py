import json

from runeguard.correlation import agent_turn
from runeguard.decision import Decision, DecisionType
from runeguard.logger import decision_record, write_audit_record


def test_decision_record_includes_agent_turn_correlation():
    with agent_turn(agent="fake-agent", turn_id="turn-1"):
        record = decision_record(
            "shell",
            Decision(DecisionType.ALLOW, "allowed"),
            {"command": "echo hello", "argv": ["echo", "hello"]},
        )

    correlation = record["correlation"]
    assert correlation["turn_id"] == "turn-1"
    assert correlation["agent"] == "fake-agent"
    assert correlation["spawned_by_turn"] == "turn-1"
    assert correlation["event_id"].startswith("cmd_")
    assert correlation["causal_chain"] == ["turn-1"]


def test_audit_log_preserves_correlation(tmp_path):
    audit_log = tmp_path / "audit.jsonl"

    with agent_turn(agent="fake-agent", turn_id="turn-2", parent_turn_id="turn-1"):
        write_audit_record(
            audit_log,
            decision_record("read_file", Decision(DecisionType.BLOCK, "blocked"), {"path": ".env"}),
        )

    record = json.loads(audit_log.read_text(encoding="utf-8"))
    assert record["correlation"]["causal_chain"] == ["turn-1", "turn-2"]
