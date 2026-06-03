import json

from typer.testing import CliRunner

from runeguard.audit import build_report, summarize_audit_log
from runeguard.audit_compliance import (
    AuditRetentionConfig,
    ComplianceAuditLog,
    LocalWORMExporter,
    manifest_summary,
    verify_retention,
)
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
    assert persisted["ts"]
    assert persisted["mode"] == "chain"
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


def test_retention_manifest_defaults_to_at_least_180_days(tmp_path):
    audit = tmp_path / "audit.jsonl"

    write_audit_record(audit, {"decision": "allow", "tool_call": "shell", "reason": "ok"})

    manifest = manifest_summary(tmp_path)
    segment = manifest["segments"][0]
    assert segment["record_count"] == 1
    assert segment["first_seq"] == 0
    assert segment["last_seq"] == 0
    assert segment["retention_until"] >= segment["created_at"]
    assert verify_retention(tmp_path).ok


def test_retention_below_180_days_is_rejected_unless_dev_override(tmp_path):
    bad = AuditRetentionConfig(retention_days=30)
    try:
        bad.validate()
    except ValueError as exc:
        assert "at least 180" in str(exc)
    else:
        raise AssertionError("expected short retention to be rejected")

    AuditRetentionConfig(retention_days=30, allow_short_retention_for_dev=True).validate()


def test_rotation_creates_valid_linked_segments(tmp_path):
    audit = tmp_path / "audit.jsonl"
    config = AuditRetentionConfig(retention_days=180, rotation_max_bytes=1)
    log = ComplianceAuditLog(audit, config=config)

    log.append({"decision": "allow", "tool_call": "shell", "reason": "one"})
    log.append({"decision": "block", "tool_call": "shell", "reason": "two"})

    manifest = manifest_summary(tmp_path)
    segments = manifest["segments"]
    assert len(segments) == 2
    assert segments[0]["status"] == "closed"
    assert segments[1]["status"] == "open"
    assert segments[1]["prev_segment_head"] == segments[0]["head_hash"]
    assert verify_retention(tmp_path).ok


def test_deleting_retained_segment_fails_verify_retention(tmp_path):
    audit = tmp_path / "audit.jsonl"
    log = ComplianceAuditLog(audit)
    log.append({"decision": "allow", "tool_call": "shell", "reason": "one"})
    closed = log.rotate()
    assert closed is not None

    (tmp_path / closed["path"]).unlink()

    result = verify_retention(tmp_path)
    assert not result.ok
    assert "missing" in "\n".join(result.errors)
    assert manifest_summary(tmp_path)["segments"][0]["deletion_status"] == "missing"


def test_tail_truncation_is_detected_with_manifest_head(tmp_path):
    audit = tmp_path / "audit.jsonl"
    log = ComplianceAuditLog(audit)
    for index in range(3):
        log.append({"decision": "allow", "tool_call": "shell", "reason": str(index)})
    records = _records(audit)
    _save(audit, records[:-1])

    result = verify_retention(tmp_path)

    assert not result.ok
    assert "mismatch" in "\n".join(result.errors)


def test_local_worm_export_writes_receipts_and_refuses_overwrite(tmp_path):
    audit = tmp_path / "audit.jsonl"
    export_dir = tmp_path / "worm"
    log = ComplianceAuditLog(audit)
    log.append({"decision": "allow", "tool_call": "shell", "reason": "one"})
    log.rotate()

    receipts = LocalWORMExporter().export(tmp_path, export_dir)

    assert receipts
    assert list((export_dir / "receipts").glob("*.receipt.json"))
    try:
        LocalWORMExporter().export(tmp_path, export_dir)
    except FileExistsError:
        pass
    else:
        raise AssertionError("expected exporter to refuse overwriting receipts")


def test_audit_retention_cli_reports_missing_segment(tmp_path):
    audit = tmp_path / "audit.jsonl"
    log = ComplianceAuditLog(audit)
    log.append({"decision": "allow", "tool_call": "shell", "reason": "one"})
    closed = log.rotate()
    (tmp_path / closed["path"]).unlink()

    result = runner.invoke(app, ["audit", "verify-retention", "--audit-dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "RETENTION VIOLATION" in result.stderr


def test_audit_manifest_and_export_cli(tmp_path):
    audit = tmp_path / "audit.jsonl"
    export_dir = tmp_path / "export"
    log = ComplianceAuditLog(audit)
    log.append({"decision": "allow", "tool_call": "shell", "reason": "one"})
    log.rotate()

    manifest = runner.invoke(app, ["audit", "manifest", "--audit-dir", str(tmp_path)])
    exported = runner.invoke(app, ["audit", "export", "--audit-dir", str(tmp_path), "--destination", str(export_dir)])

    assert manifest.exit_code == 0
    assert '"segments"' in manifest.stdout
    assert exported.exit_code == 0
    assert "Exported" in exported.stdout
