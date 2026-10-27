"""Content-addressed immutable evidence with signed manifests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import mimetypes
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

from .store import CanonicalStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    engagement_id: str
    sha256: str
    size: int
    media_type: str
    captured_at: str
    source_execution_id: str | None
    operator: str
    original_name: str
    blob_ref: str
    derived_from: str | None = None
    redacted: bool = False
    annotations: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class EvidenceStore:
    def __init__(self, root: str | Path, store: CanonicalStore, secret_provider=None):
        self.root = Path(root)
        self.blobs = self.root / "blobs" / "sha256"
        self.blobs.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.store = store
        self.secret_provider = secret_provider
        self._manifest_key_ref = None
        if secret_provider is not None:
            existing = next(
                (
                    item
                    for item in secret_provider.list()
                    if item.get("label") == "evidence-manifest-hmac"
                ),
                None,
            )
            if existing:
                self._manifest_key_ref = existing["reference"]
            else:
                self._manifest_key_ref = secret_provider.set(
                    os.urandom(32).hex(), label="evidence-manifest-hmac"
                ).uri

    def _blob(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest[2:]

    def add_bytes(
        self,
        engagement_id: str,
        content: bytes,
        *,
        name: str,
        media_type: str | None = None,
        source_execution_id: str | None = None,
        operator: str = "system",
        annotations: dict[str, Any] | None = None,
        derived_from: str | None = None,
        redacted: bool = False,
        evidence_id: str | None = None,
    ) -> EvidenceRecord:
        if not isinstance(content, bytes):
            raise TypeError("Evidence content must be bytes")
        if derived_from is not None:
            self.get(derived_from)
        digest = hashlib.sha256(content).hexdigest()
        target = self._blob(digest)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Existing evidence blob failed integrity verification")
        else:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=target.parent, prefix=".evidence-", delete=False
                ) as stream:
                    temporary = Path(stream.name)
                    os.chmod(temporary, 0o600)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
                target.chmod(0o600)
            finally:
                if temporary is not None and temporary.exists():
                    temporary.unlink()
        record = EvidenceRecord(
            id=evidence_id or str(uuid4()),
            engagement_id=engagement_id,
            sha256=digest,
            size=len(content),
            media_type=media_type or mimetypes.guess_type(name)[0] or "application/octet-stream",
            captured_at=_now(),
            source_execution_id=source_execution_id,
            operator=operator,
            original_name=Path(name).name,
            blob_ref=str(target.relative_to(self.root)),
            derived_from=derived_from,
            redacted=redacted,
            annotations=annotations or {},
        )
        self.store.put_record(
            "evidence", record.id, engagement_id, record.to_dict(), actor=operator
        )
        return record

    def add_file(self, engagement_id: str, path: str | Path, **values) -> EvidenceRecord:
        path = Path(path)
        return self.add_bytes(
            engagement_id, path.read_bytes(), name=values.pop("name", path.name), **values
        )

    def get(self, evidence_id: str) -> EvidenceRecord:
        return EvidenceRecord(**self.store.get_record("evidence", evidence_id).payload)

    def read(self, evidence_id: str) -> bytes:
        record = self.get(evidence_id)
        blob = self.root / record.blob_ref
        content = blob.read_bytes()
        if len(content) != record.size or hashlib.sha256(content).hexdigest() != record.sha256:
            raise RuntimeError(f"Evidence integrity failure: {evidence_id}")
        return content

    def add_redaction(
        self, evidence_id: str, content: bytes, *, operator: str, name: str | None = None
    ) -> EvidenceRecord:
        original = self.get(evidence_id)
        return self.add_bytes(
            original.engagement_id,
            content,
            name=name or f"redacted-{original.original_name}",
            media_type=original.media_type,
            source_execution_id=original.source_execution_id,
            operator=operator,
            derived_from=evidence_id,
            redacted=True,
        )

    def verify(self, engagement_id: str | None = None) -> dict[str, Any]:
        failures = []
        records = self.store.list_records("evidence", engagement_id)
        for item in records:
            try:
                self.read(item.record_id)
            except (OSError, RuntimeError, ValueError) as exc:
                failures.append({"id": item.record_id, "error": str(exc)})
        return {"valid": not failures, "count": len(records), "failures": failures}

    def manifest(self, engagement_id: str) -> dict[str, Any]:
        records = [item.payload for item in self.store.list_records("evidence", engagement_id)]
        payload = {
            "schema_version": 1,
            "engagement_id": engagement_id,
            "generated_at": _now(),
            "evidence": sorted(records, key=lambda item: item["id"]),
        }
        if self.secret_provider is None:
            payload["signature"] = None
            payload["signature_algorithm"] = None
        else:
            key = bytes.fromhex(self.secret_provider.get(self._manifest_key_ref))
            payload["signature"] = hmac.new(key, _json(payload), hashlib.sha256).hexdigest()
            payload["signature_algorithm"] = "HMAC-SHA256"
            payload["key_reference"] = self._manifest_key_ref
        return payload

    def verify_manifest(self, manifest: dict[str, Any]) -> bool:
        signature = manifest.get("signature")
        if not signature or self.secret_provider is None:
            return False
        unsigned = dict(manifest)
        unsigned.pop("signature")
        unsigned.pop("signature_algorithm", None)
        unsigned.pop("key_reference", None)
        key = bytes.fromhex(self.secret_provider.get(manifest["key_reference"]))
        expected = hmac.new(key, _json(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        return all(self.read(item["id"]) is not None for item in manifest["evidence"])

    def delete(self, evidence_id: str, *, actor: str, purge_blob: bool = False) -> bool:
        record = self.get(evidence_id)
        if not self.store.delete_record("evidence", evidence_id, actor=actor):
            return False
        if purge_blob:
            remaining = [
                item
                for item in self.store.list_records("evidence")
                if item.payload.get("sha256") == record.sha256
            ]
            if not remaining:
                (self.root / record.blob_ref).unlink(missing_ok=True)
        return True
