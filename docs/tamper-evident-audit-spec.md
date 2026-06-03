# RuneGuard Tamper-Evident Audit Store

**Status:** implemented reference path  
**Goal:** turn the existing plain JSONL audit log into a verifiable, tamper-evident audit trail.

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
{"seq":2,"prev_hash":"<hash of seq 1>","payload":{ "...existing audit_record": "..." },"hash":"<digest>"}
```

- `seq`: monotonic integer from 0.
- `prev_hash`: the previous envelope hash, or `0` repeated 64 times for the first record.
- `payload`: the existing redacted `audit_record` dictionary.
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

## Integration Points

- `runeguard.integrity`: hash-chain append and verification.
- `logger.write_audit_record`: redacts first, then appends a chained envelope.
- `audit` readers: unwrap `payload` when present and fall back to legacy plain records.
- `runeguard audit verify`: CI-friendly verification command.

## CLI

```bash
runeguard audit verify .runeguard/audit.jsonl
runeguard audit verify .runeguard/audit.jsonl --expected-head <hash>
RUNEGUARD_AUDIT_KEY=<hex> runeguard audit verify .runeguard/audit.jsonl
RUNEGUARD_AUDIT_KEYFILE=/path/to/key runeguard audit verify .runeguard/audit.jsonl
```

Success exits `0` and prints the record count plus current head. Failure exits `1` and prints the first break location.

## Free/Paid Boundary

- OSS: `chain` mode, `audit verify`, and the envelope format.
- Paid: sealed key management, external anchoring/receipts, retention enforcement, WORM export, and an auditor-facing evidence pack.

Compliance claim caveat: describe this as producing a tamper-evident audit trail to help with record-keeping obligations, not as making a customer compliant.
