import json

from runeguard.correlation import agent_turn
from runeguard.decision import Decision, DecisionType
from runeguard.integrity import unwrap_payload
from runeguard.logger import decision_record, write_audit_record


def test_decision_record_includes_agent_turn_correlation():
    with agent_turn(agent="fake-agent", turn_id="turn-1"):
        record = decision_record(
            "shell",
            Decision(DecisionType.ALLOW, "allowed"),
            {"command": "echo hello", "argv": ["echo", "hello"]},
        )

    assert record["run_id"] == "turn-1"
    assert record["agent"] == "fake-agent"
    assert record["tool_call"] == "shell"
    assert record["command"] == "echo hello"
    assert "correlation" not in record


def test_audit_log_preserves_run_id(tmp_path):
    audit_log = tmp_path / "audit.jsonl"

    with agent_turn(agent="fake-agent", turn_id="turn-2", parent_turn_id="turn-1"):
        write_audit_record(
            audit_log,
            decision_record("read_file", Decision(DecisionType.BLOCK, "blocked"), {"path": ".env"}),
        )

    record = unwrap_payload(json.loads(audit_log.read_text(encoding="utf-8")))
    assert record["run_id"] == "turn-2"
    assert record["agent"] == "fake-agent"
    assert "correlation" not in record
