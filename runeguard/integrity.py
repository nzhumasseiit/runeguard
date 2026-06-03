"""Tamper-evident audit log support for RuneGuard.

Each audit record is wrapped in a hash-chained envelope so payload edits,
middle deletions, and reorders are detectable during verification. Tail
truncation is detectable only when verification is given an externally
stored expected head hash.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


GENESIS_PREV = "0" * 64
_DOMAIN = b"runeguard.audit.v1"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(
    seq: int,
    prev_hash: str,
    payload: dict,
    *,
    key: bytes | None,
    ts: str | None = None,
    mode: str | None = None,
) -> str:
    material = b"\x00".join(
        [
            _DOMAIN,
            str(seq).encode("ascii"),
            prev_hash.encode("ascii"),
            (ts or "").encode("utf-8"),
            (mode or "").encode("ascii"),
            _canonical(payload),
        ]
    )
    if key is None:
        return hashlib.sha256(material).hexdigest()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def _legacy_digest(seq: int, prev_hash: str, payload: dict, *, key: bytes | None) -> str:
    material = b"\x00".join(
        [_DOMAIN, str(seq).encode("ascii"), prev_hash.encode("ascii"), _canonical(payload)]
    )
    if key is None:
        return hashlib.sha256(material).hexdigest()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def is_integrity_envelope(record: object) -> bool:
    return (
        isinstance(record, dict)
        and isinstance(record.get("seq"), int)
        and isinstance(record.get("prev_hash"), str)
        and isinstance(record.get("payload"), dict)
        and isinstance(record.get("hash"), str)
    )


def unwrap_payload(record: dict) -> dict:
    if is_integrity_envelope(record):
        return record["payload"]
    return record


@dataclass(frozen=True)
class ChainHead:
    seq: int
    hash: str

    @classmethod
    def genesis(cls) -> "ChainHead":
        return cls(seq=-1, hash=GENESIS_PREV)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    head_hash: str | None
    error: str | None = None
    break_seq: int | None = None


class TamperEvidentLog:
    """Append-only, hash-chained JSONL audit log."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes | None = None,
        initial_seq: int = 0,
        initial_prev_hash: str = GENESIS_PREV,
    ) -> None:
        self.path = Path(path)
        self.key = key
        self.initial_seq = initial_seq
        self.initial_prev_hash = initial_prev_hash

    def _tail_head(self) -> ChainHead:
        last = None
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = line

        if last is None:
            return ChainHead(seq=self.initial_seq - 1, hash=self.initial_prev_hash)

        env = json.loads(last)
        if not is_integrity_envelope(env):
            raise ValueError(
                f"{self.path} contains legacy audit records; start a new log before enabling integrity"
            )
        return ChainHead(seq=env["seq"], hash=env["hash"])

    def append(self, payload: dict) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                head = self._tail_head()
                seq = head.seq + 1
                mode = "sealed" if self.key is not None else "chain"
                ts = datetime.now(timezone.utc).isoformat()
                digest = _digest(seq, head.hash, payload, key=self.key, ts=ts, mode=mode)
                envelope = {
                    "seq": seq,
                    "ts": ts,
                    "prev_hash": head.hash,
                    "payload": payload,
                    "hash": digest,
                    "mode": mode,
                }
                f.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
                return envelope
            finally:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _iter_lines(path: str | Path) -> Iterator[str]:
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def verify_log(
    path: str | Path,
    *,
    key: bytes | None = None,
    expected_head: str | None = None,
    expected_start_seq: int = 0,
    expected_prev_hash: str = GENESIS_PREV,
) -> VerifyResult:
    prev_hash = expected_prev_hash
    expected_seq = expected_start_seq
    count = 0
    head: str | None = None

    for lineno, raw in enumerate(_iter_lines(path), start=1):
        try:
            env = json.loads(raw)
        except json.JSONDecodeError:
            return VerifyResult(False, count, head, f"line {lineno}: not valid JSON")

        if not is_integrity_envelope(env):
            return VerifyResult(False, count, head, f"line {lineno}: not an integrity envelope")

        seq = env["seq"]
        if seq != expected_seq:
            return VerifyResult(
                False,
                count,
                head,
                f"sequence break: expected {expected_seq}, got {seq} (record deleted or reordered)",
                break_seq=expected_seq,
            )
        if env["prev_hash"] != prev_hash:
            return VerifyResult(
                False,
                count,
                head,
                f"seq {seq}: prev_hash does not link to previous record",
                break_seq=seq,
            )

        recomputed = _digest(
            seq,
            prev_hash,
            env["payload"],
            key=key,
            ts=env.get("ts"),
            mode=env.get("mode"),
        )
        legacy_recomputed = _legacy_digest(seq, prev_hash, env["payload"], key=key)
        if not hmac.compare_digest(recomputed, env["hash"]):
            if env.get("ts") is not None or env.get("mode") is not None or not hmac.compare_digest(legacy_recomputed, env["hash"]):
                return VerifyResult(
                    False,
                    count,
                    head,
                    f"seq {seq}: hash mismatch (payload altered)",
                    break_seq=seq,
                )

        prev_hash = env["hash"]
        head = env["hash"]
        expected_seq += 1
        count += 1

    if expected_head is not None and head != expected_head:
        return VerifyResult(
            False,
            count,
            head,
            f"head {head} != expected {expected_head} (records may have been truncated from the tail)",
        )

    return VerifyResult(True, count, head)


def load_key() -> bytes | None:
    hex_key = os.environ.get("RUNEGUARD_AUDIT_KEY")
    if hex_key:
        return bytes.fromhex(hex_key)

    keyfile = os.environ.get("RUNEGUARD_AUDIT_KEYFILE")
    if keyfile:
        return Path(keyfile).read_bytes().strip()

    return None
