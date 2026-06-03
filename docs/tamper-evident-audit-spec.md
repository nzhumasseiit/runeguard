# RuneGuard Tamper-Evident Audit Store

**Status:** implemented repo-local compliance path  
**Goal:** turn the existing plain JSONL audit log into verifiable audit evidence with hash-chained records, retention manifests, safe rotation, deletion detection, and local WORM-style export.

## Why this first

The current `.runeguard/audit.jsonl` payload can be edited, reordered, deleted, or truncated by anyone with file access. Compliance buyers need evidence that records have not silently changed after write time.

The implementation is additive: existing audit payloads are preserved, and the new format wraps them in an integrity envelope.

## Threat Model

Defends against offline tampering:

- editing a past record payload
- deleting a record from the middle
- reordering records
- tail truncation when verification receives an externally stored expected head hash

Does not defend against:

- an attacker who has both the sealing key and live write access at logging time
- destruction of the entire file

This makes tampering detectable, not impossible.

## Record Format

Each line remains one JSON object:

```json
{"seq":2,"ts":"2026-06-03T00:00:00+00:00","prev_hash":"<hash of seq 1>","payload":{ "...existing audit_record": "..." },"hash":"<digest>","mode":"chain"}
```

- `seq`: monotonic integer from 0.
- `ts`: UTC write timestamp for the envelope.
- `prev_hash`: the previous envelope hash, or `0` repeated 64 times for the first record.
- `payload`: the existing redacted `audit_record` dictionary.
- `mode`: `chain` for SHA-256, or `sealed` for HMAC-SHA-256 when a real key is supplied.
- `hash`: `H(domain || seq || prev_hash || canonical(payload))`.

Canonical payload serialization is `json.dumps(payload, sort_keys=True, separators=(",", ":"))`.

## Integrity Modes

| Mode | Digest | Verifier needs | Boundary |
| --- | --- | --- | --- |
| `chain` | SHA-256 | nothing | OSS |
| `sealed` | HMAC-SHA-256 | off-host key | paid |
| `anchored` | sealed plus off-host head receipt | key and expected head | paid/SaaS |

`chain` mode is useful for detecting naive edits and protecting copies that have left the host, but an attacker can recompute the chain if no secret is involved. `sealed` mode uses `RUNEGUARD_AUDIT_KEY` or `RUNEGUARD_AUDIT_KEYFILE` so an attacker without the key cannot forge a valid continuation.

## Tail Truncation And Anchoring

Dropping records from the tail leaves a shorter chain that is internally valid. Verification catches that only when passed `expected_head`, which should come from storage the logging host cannot rewrite, such as WORM storage, a signed commit, or a hosted receipt endpoint.

That external proof boundary is the natural paid line: "prove it to a third party."

## Retention Manifest

RuneGuard writes `.runeguard/audit-manifest.json` beside the audit segments. The default retention period is 180 days. Values below 180 days are rejected unless `RUNEGUARD_AUDIT_ALLOW_SHORT_RETENTION=true` is set for dev/test.

Each segment entry records:

- log file name
- creation time and close/rotation time
- first and last sequence number
- previous segment head hash
- current head hash
- record count
- file SHA-256
- `retention_until`
- export status
- deletion status

The manifest includes a `manifest_hash` over its contents. This is local integrity metadata, not a substitute for external anchoring.

## Rotation

Rotation closes the current `audit.jsonl`, renames it to a segment file such as `audit-000000000000-000000000123-<head>.jsonl`, records the final head hash in the manifest, and starts the next segment with `prev_hash` set to the previous segment head. Closed segments are marked read-only as a local best effort, but deletion prevention is not guaranteed on a writable filesystem.

`runeguard audit verify-retention` verifies each segment and then verifies segment continuity through the manifest.

## Local WORM-Style Export

`runeguard audit export --audit-dir .runeguard --destination <dir>` copies closed segments and manifest snapshots into an export directory and writes receipt files containing exported object path, SHA-256, timestamp, segment id, and `retention_until`.

Receipt files are never overwritten. This is WORM-style local evidence packaging, not real cloud WORM/Object Lock. Real S3 Object Lock or hosted receipt endpoints should sit behind the exporter interface when implemented.

## Integration Points

- `runeguard.integrity`: hash-chain append and verification.
- `runeguard.audit_compliance`: retention config, manifest, rotation, local WORM-style export, and retention verification.
- `logger.write_audit_record`: redacts first, then appends a chained envelope through the compliance writer.
- `audit` readers: unwrap `payload` when present and fall back to legacy plain records.
- `runeguard audit verify`: CI-friendly cryptographic verification command.
- `runeguard audit verify-retention`: manifest, segment, continuity, and retention verification.

## CLI

```bash
runeguard audit verify .runeguard/audit.jsonl
runeguard audit verify .runeguard/audit.jsonl --expected-head <hash>
runeguard audit verify-retention --audit-dir .runeguard
runeguard audit manifest --audit-dir .runeguard
runeguard audit export --audit-dir .runeguard --destination ./worm-export
RUNEGUARD_AUDIT_KEY=<hex> runeguard audit verify .runeguard/audit.jsonl
RUNEGUARD_AUDIT_KEYFILE=/path/to/key runeguard audit verify .runeguard/audit.jsonl
```

Success exits `0` and prints the record count plus current head. Failure exits `1` and prints the first break location.

## Free/Paid Boundary

- OSS: `chain` mode, `audit verify`, retention manifest, local rotation, deletion detection, and local WORM-style export.
- Paid/cloud: sealed key management, external anchoring/receipts, managed retention, real WORM export, and an auditor-facing evidence pack.

Compliance claim caveat: describe this as producing a tamper-evident audit trail to help with record-keeping obligations, not as making a customer compliant.

Local deletion caveat: local files cannot fully prevent deletion while the host can rewrite the filesystem. RuneGuard now detects missing retained segments through the manifest; legally stronger retention still requires external anchoring or true WORM storage.
