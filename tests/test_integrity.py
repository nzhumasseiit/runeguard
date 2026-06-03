import json

from typer.testing import CliRunner

from runeguard.audit import build_report, summarize_audit_log
from runeguard.cli import app
from runeguard.integrity import TamperEvidentLog, verify_log
from runeguard.logger import write_audit_record


runner = CliRunner()


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_log(path, *, key=None, count=4):
    log = TamperEvidentLog(path, key=key)
    for seq in range(count):
        log.append(
            {
                "decision": "allow" if seq % 2 else "block",
                "tool_call": "shell",
                "command": f"echo {seq}",
                "reason": f"reason {seq}",
                "timestamp": f"2026-01-01T00:00:0{seq}Z",
            }
        )


def _save(path, records):
    path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")


def test_write_audit_record_writes_envelope_and_reports_unwrap_payload(tmp_path):
    audit = tmp_path / "audit.jsonl"

    write_audit_record(
        audit,
        {
            "decision": "block",
            "tool_call": "shell",
            "command": "printenv",
            "reason": "blocked shell command pattern: printenv",
            "timestamp": "2026-01-01T00:00:00Z",
        },
    )

    persisted = _records(audit)[0]
    assert persisted["seq"] == 0
    assert persisted["payload"]["decision"] == "block"
    assert verify_log(audit).ok
    assert summarize_audit_log(audit)["blocked"] == 1
    assert build_report(audit)["events"][0]["command"] == "printenv"


def test_legacy_plain_jsonl_still_parses_for_reports(tmp_path):
    audit = tmp_path / "legacy.jsonl"
    audit.write_text(
        json.dumps({"decision": "allow", "tool_call": "shell", "reason": "ok", "timestamp": "2026-01-01T00:00:00Z"})
        + "\n",
        encoding="utf-8",
    )

    assert summarize_audit_log(audit)["allowed"] == 1
    assert build_report(audit)["summary"]["total_events"] == 1
    result = verify_log(audit)
    assert not result.ok
    assert "not an integrity envelope" in result.error


def test_verify_accepts_untampered_chain(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)

    result = verify_log(audit)

    assert result.ok
    assert result.count == 4
    assert result.head_hash == _records(audit)[-1]["hash"]


def test_verify_catches_payload_edit(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    records = _records(audit)
    records[1]["payload"]["reason"] = "edited"
    _save(audit, records)

    result = verify_log(audit)

    assert not result.ok
    assert result.break_seq == 1
    assert "hash mismatch" in result.error


def test_verify_catches_middle_deletion(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    records = _records(audit)
    del records[1]
    _save(audit, records)

    result = verify_log(audit)

    assert not result.ok
    assert result.break_seq == 1
    assert "sequence break" in result.error


def test_verify_catches_reorder(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    records = _records(audit)
    records[1], records[2] = records[2], records[1]
    _save(audit, records)

    result = verify_log(audit)

    assert not result.ok
    assert result.break_seq == 1
    assert "sequence break" in result.error


def test_tail_truncation_requires_expected_head_anchor(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    original_head = _records(audit)[-1]["hash"]
    _save(audit, _records(audit)[:-1])

    without_anchor = verify_log(audit)
    with_anchor = verify_log(audit, expected_head=original_head)

    assert without_anchor.ok
    assert not with_anchor.ok
    assert "truncated" in with_anchor.error


def test_verify_catches_invalid_json(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    audit.write_text(audit.read_text(encoding="utf-8") + "{broken\n", encoding="utf-8")

    result = verify_log(audit)

    assert not result.ok
    assert "not valid JSON" in result.error


def test_verify_catches_prev_hash_relink_without_digest_update(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)
    records = _records(audit)
    records[2]["prev_hash"] = "f" * 64
    _save(audit, records)

    result = verify_log(audit)

    assert not result.ok
    assert result.break_seq == 2
    assert "prev_hash" in result.error


def test_sealed_log_catches_no_key_forward_rewrite(tmp_path):
    audit = tmp_path / "audit.jsonl"
    key = b"test-sealing-key"
    _write_log(audit, key=key)
    records = _records(audit)
    attacker = TamperEvidentLog(tmp_path / "attacker.jsonl")
    _save(attacker.path, [records[0]])
    forged = [records[0]]
    for index, record in enumerate(records[1:], start=1):
        payload = dict(record["payload"])
        if index == 1:
            payload["reason"] = "edited"
        forged.append(attacker.append(payload))
    _save(audit, forged)

    result = verify_log(audit, key=key)

    assert not result.ok
    assert result.break_seq == 1
    assert "hash mismatch" in result.error


def test_audit_verify_cli_reports_success_and_failure(tmp_path):
    audit = tmp_path / "audit.jsonl"
    _write_log(audit)

    ok = runner.invoke(app, ["audit", "verify", str(audit)])
    assert ok.exit_code == 0
    assert "OK: 4 records" in ok.stdout

    records = _records(audit)
    records[0]["payload"]["reason"] = "edited"
    _save(audit, records)
    failed = runner.invoke(app, ["audit", "verify", str(audit)])
    assert failed.exit_code == 1
    assert "TAMPER DETECTED" in failed.stderr
