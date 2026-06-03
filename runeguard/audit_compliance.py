"""Audit retention, rotation, and WORM-style export support."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .integrity import GENESIS_PREV, TamperEvidentLog, is_integrity_envelope, load_key, verify_log


MIN_RETENTION_DAYS = 180
MANIFEST_NAME = "audit-manifest.json"
EXPORT_RECEIPTS_DIR = "receipts"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass(frozen=True)
class AuditRetentionConfig:
    retention_days: int = MIN_RETENTION_DAYS
    rotation_max_bytes: int | None = None
    rotation_max_age_days: int | None = None
    export_enabled: bool = False
    export_destination: str | None = None
    allow_short_retention_for_dev: bool = False

    @classmethod
    def from_env(cls) -> "AuditRetentionConfig":
        return cls(
            retention_days=_env_int("RUNEGUARD_AUDIT_RETENTION_DAYS", MIN_RETENTION_DAYS),
            rotation_max_bytes=_env_int("RUNEGUARD_AUDIT_ROTATION_MAX_BYTES", None),
            rotation_max_age_days=_env_int("RUNEGUARD_AUDIT_ROTATION_MAX_AGE_DAYS", None),
            export_enabled=os.environ.get("RUNEGUARD_AUDIT_EXPORT_ENABLED", "").lower() in {"1", "true", "yes"},
            export_destination=os.environ.get("RUNEGUARD_AUDIT_EXPORT_DESTINATION"),
            allow_short_retention_for_dev=os.environ.get("RUNEGUARD_AUDIT_ALLOW_SHORT_RETENTION", "").lower()
            in {"1", "true", "yes"},
        )

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "AuditRetentionConfig":
        audit = values.get("audit", values)
        rotation = audit.get("rotation", {}) or {}
        export = audit.get("export", {}) or {}
        return cls(
            retention_days=int(audit.get("retention_days", MIN_RETENTION_DAYS)),
            rotation_max_bytes=rotation.get("max_bytes"),
            rotation_max_age_days=rotation.get("max_age_days"),
            export_enabled=bool(export.get("enabled", False)),
            export_destination=export.get("destination"),
            allow_short_retention_for_dev=bool(audit.get("allow_short_retention_for_dev", False)),
        )

    def validate(self) -> None:
        if self.retention_days < MIN_RETENTION_DAYS and not self.allow_short_retention_for_dev:
            raise ValueError(
                f"audit.retention_days must be at least {MIN_RETENTION_DAYS}; "
                "set RUNEGUARD_AUDIT_ALLOW_SHORT_RETENTION=true only for dev/test"
            )
        if self.rotation_max_bytes is not None and int(self.rotation_max_bytes) <= 0:
            raise ValueError("audit.rotation.max_bytes must be positive")
        if self.rotation_max_age_days is not None and int(self.rotation_max_age_days) <= 0:
            raise ValueError("audit.rotation.max_age_days must be positive")


@dataclass(frozen=True)
class RetentionVerifyResult:
    ok: bool
    errors: list[str]
    checked_segments: int


class RetentionManifest:
    def __init__(self, audit_dir: str | Path) -> None:
        self.audit_dir = Path(audit_dir)
        self.path = self.audit_dir / MANIFEST_NAME

    def load(self) -> dict:
        if not self.path.exists():
            return {
                "version": 1,
                "created_at": iso(utc_now()),
                "updated_at": iso(utc_now()),
                "segments": [],
                "manifest_hash": None,
            }
        return json.loads(self.path.read_text(encoding="utf-8"))

    def write(self, manifest: dict) -> None:
        manifest = dict(manifest)
        manifest["updated_at"] = iso(utc_now())
        manifest["manifest_hash"] = _manifest_hash(manifest)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        _fsync_parent(self.path)

    def upsert_segment(self, segment: dict) -> None:
        manifest = self.load()
        segments = manifest.setdefault("segments", [])
        for index, existing in enumerate(segments):
            if existing["id"] == segment["id"] or (
                existing.get("status") == "open"
                and segment.get("status") == "open"
                and existing.get("path") == segment.get("path")
            ):
                segments[index] = segment
                break
        else:
            segments.append(segment)
        segments.sort(key=lambda item: item["first_seq"])
        self.write(manifest)


class ComplianceAuditLog:
    def __init__(
        self,
        path: str | Path,
        *,
        config: AuditRetentionConfig | None = None,
        key: bytes | None = None,
    ) -> None:
        self.path = Path(path)
        self.audit_dir = self.path.parent
        self.config = config or AuditRetentionConfig.from_env()
        self.config.validate()
        self.key = load_key() if key is None else key
        self.manifest = RetentionManifest(self.audit_dir)

    def append(self, payload: dict) -> dict:
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._rotate_if_needed()
        initial_seq, initial_prev_hash = self._next_chain_start()
        envelope = TamperEvidentLog(
            self.path,
            key=self.key,
            initial_seq=initial_seq,
            initial_prev_hash=initial_prev_hash,
        ).append(payload)
        self._record_open_segment(envelope)
        return envelope

    def rotate(self) -> dict | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        current = self._segment_from_file(self.path, status="closed")
        closed_name = _segment_name(current["first_seq"], current["last_seq"], current["head_hash"])
        closed_path = self.audit_dir / closed_name
        if closed_path.exists():
            raise FileExistsError(f"closed audit segment already exists: {closed_path}")
        os.replace(self.path, closed_path)
        _fsync_parent(closed_path)
        current["path"] = closed_name
        current["closed_at"] = iso(utc_now())
        current["retention_until"] = iso(utc_now() + timedelta(days=self.config.retention_days))
        current["export_status"] = "pending"
        self.manifest.upsert_segment(current)
        try:
            closed_path.chmod(0o444)
        except OSError:
            pass
        return current

    def _rotate_if_needed(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        if self.config.rotation_max_bytes is not None and self.path.stat().st_size >= self.config.rotation_max_bytes:
            self.rotate()
            return
        if self.config.rotation_max_age_days is not None:
            created_at = parse_iso(self._segment_from_file(self.path, status="open")["created_at"])
            if utc_now() - created_at >= timedelta(days=self.config.rotation_max_age_days):
                self.rotate()

    def _next_chain_start(self) -> tuple[int, str]:
        if self.path.exists() and self.path.stat().st_size > 0:
            tail = _read_envelopes(self.path)[-1]
            return int(tail["seq"]) + 1, str(tail["hash"])
        segments = self.manifest.load().get("segments", [])
        if not segments:
            return 0, GENESIS_PREV
        last = sorted(segments, key=lambda item: item["last_seq"])[-1]
        return int(last["last_seq"]) + 1, str(last["head_hash"])

    def _record_open_segment(self, envelope: dict) -> None:
        segment = self._segment_from_file(self.path, status="open")
        existing = _find_segment(self.manifest.load(), segment["id"])
        if existing:
            segment["created_at"] = existing.get("created_at", segment["created_at"])
            segment["retention_until"] = existing.get("retention_until", segment["retention_until"])
        self.manifest.upsert_segment(segment)

    def _segment_from_file(self, path: Path, *, status: str) -> dict:
        envelopes = _read_envelopes(path)
        if not envelopes:
            raise ValueError(f"empty audit segment: {path}")
        first = envelopes[0]
        last = envelopes[-1]
        file_hash = file_sha256(path)
        created_at = first.get("ts") or first["payload"].get("timestamp") or iso(utc_now())
        return {
            "id": _segment_id(int(first["seq"]), int(last["seq"]), str(last["hash"])),
            "path": path.name,
            "status": status,
            "created_at": created_at,
            "closed_at": None if status == "open" else iso(utc_now()),
            "first_seq": int(first["seq"]),
            "last_seq": int(last["seq"]),
            "prev_segment_head": first["prev_hash"],
            "head_hash": last["hash"],
            "record_count": len(envelopes),
            "file_sha256": file_hash,
            "retention_until": iso(parse_iso(created_at) + timedelta(days=self.config.retention_days)),
            "export_status": "not_required" if not self.config.export_enabled else "pending",
            "deletion_status": "present",
        }


class AuditExporter:
    def export(self, audit_dir: str | Path, destination: str | Path) -> list[dict]:
        raise NotImplementedError


class LocalWORMExporter(AuditExporter):
    """Local append-only-style export.

    This is not real WORM storage. It avoids overwriting receipts and gives
    auditors a durable receipt trail that can be copied to external storage.
    """

    def export(self, audit_dir: str | Path, destination: str | Path) -> list[dict]:
        audit_dir = Path(audit_dir)
        destination = Path(destination)
        manifest = RetentionManifest(audit_dir).load()
        receipts_dir = destination / EXPORT_RECEIPTS_DIR
        objects_dir = destination / "objects"
        receipts_dir.mkdir(parents=True, exist_ok=True)
        objects_dir.mkdir(parents=True, exist_ok=True)
        receipts: list[dict] = []

        candidates = [segment["path"] for segment in manifest.get("segments", []) if segment.get("status") == "closed"]
        candidates.append(MANIFEST_NAME)
        for relative in candidates:
            source = audit_dir / relative
            if not source.exists():
                continue
            digest = file_sha256(source)
            object_name = f"{source.name}.{digest}"
            object_path = objects_dir / object_name
            receipt_path = receipts_dir / f"{object_name}.receipt.json"
            if receipt_path.exists():
                raise FileExistsError(f"export receipt already exists: {receipt_path}")
            if object_path.exists():
                raise FileExistsError(f"export object already exists: {object_path}")
            shutil.copy2(source, object_path)
            receipt = {
                "exported_at": iso(utc_now()),
                "source": source.name,
                "object_path": str(object_path),
                "sha256": digest,
                "segment_id": _segment_id_for_path(manifest, source.name),
                "retention_until": _retention_for_path(manifest, source.name),
            }
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            receipts.append(receipt)
        return receipts


def verify_retention(audit_dir: str | Path, *, key: bytes | None = None) -> RetentionVerifyResult:
    audit_dir = Path(audit_dir)
    manifest_path = audit_dir / MANIFEST_NAME
    if not manifest_path.exists():
        return RetentionVerifyResult(False, [f"manifest not found: {manifest_path}"], 0)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if manifest.get("manifest_hash") != _manifest_hash(manifest):
        errors.append("manifest_hash mismatch")

    previous_head = GENESIS_PREV
    expected_seq = 0
    now = utc_now()
    changed = False
    segments = sorted(manifest.get("segments", []), key=lambda item: item.get("first_seq", -1))
    for segment in segments:
        segment_path = audit_dir / segment["path"]
        retention_until = parse_iso(segment["retention_until"])
        if not segment_path.exists():
            if segment.get("deletion_status") != "missing":
                segment["deletion_status"] = "missing"
                changed = True
            if now < retention_until:
                errors.append(f"retained segment missing before retention_until: {segment['path']}")
            else:
                errors.append(f"segment missing: {segment['path']}")
            continue
        if segment.get("deletion_status") != "present":
            segment["deletion_status"] = "present"
            changed = True
        if file_sha256(segment_path) != segment.get("file_sha256"):
            errors.append(f"segment file hash mismatch: {segment['path']}")

        if segment.get("first_seq") != expected_seq:
            errors.append(f"segment sequence continuity broken at {segment['path']}")
        if segment.get("prev_segment_head") != previous_head:
            errors.append(f"segment head continuity broken at {segment['path']}")

        result = verify_log(
            segment_path,
            key=key,
            expected_head=segment.get("head_hash"),
            expected_start_seq=int(segment["first_seq"]),
            expected_prev_hash=str(segment["prev_segment_head"]),
        )
        if not result.ok:
            errors.append(f"{segment['path']}: {result.error}")

        expected_seq = int(segment["last_seq"]) + 1
        previous_head = str(segment["head_hash"])

    if changed:
        RetentionManifest(audit_dir).write(manifest)

    return RetentionVerifyResult(not errors, errors, len(segments))


def manifest_summary(audit_dir: str | Path) -> dict:
    return RetentionManifest(audit_dir).load()


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_envelopes(path: Path) -> list[dict]:
    envelopes = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if not is_integrity_envelope(record):
                raise ValueError(f"{path} contains legacy audit records; start a new log before enabling compliance retention")
            envelopes.append(record)
    return envelopes


def _manifest_hash(manifest: dict) -> str:
    material = dict(manifest)
    material.pop("manifest_hash", None)
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _env_int(name: str, default: int | None) -> int | None:
    value = os.environ.get(name)
    if value in {None, ""}:
        return default
    return int(value)


def _segment_name(first_seq: int, last_seq: int, head_hash: str) -> str:
    return f"audit-{first_seq:012d}-{last_seq:012d}-{head_hash[:12]}.jsonl"


def _segment_id(first_seq: int, last_seq: int, head_hash: str) -> str:
    return f"{first_seq}-{last_seq}-{head_hash[:16]}"


def _find_segment(manifest: dict, segment_id: str) -> dict | None:
    for segment in manifest.get("segments", []):
        if segment.get("id") == segment_id:
            return segment
    return None


def _segment_id_for_path(manifest: dict, path: str) -> str | None:
    for segment in manifest.get("segments", []):
        if segment.get("path") == path:
            return segment.get("id")
    return "manifest"


def _retention_for_path(manifest: dict, path: str) -> str | None:
    for segment in manifest.get("segments", []):
        if segment.get("path") == path:
            return segment.get("retention_until")
    return None


def _fsync_parent(path: Path) -> None:
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
