"""Transactional canonical persistence and legacy reconciliation.

The application service layer uses this store as its only writable system of
record.  Legacy JSON and SQLite files are explicit import sources; they are
never dual-written.  Every child record belongs to one engagement and every
mutation is represented in a tamper-evident audit chain.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from threading import RLock
from typing import Any, Iterator
from uuid import uuid4


SCHEMA_VERSION = 2
RECORD_TYPES = frozenset(
    {
        "asset",
        "identity",
        "service",
        "execution",
        "observation",
        "finding",
        "evidence",
        "remediation",
        "retest",
        "workflow",
        "integration",
        "audit",
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class StoreRecord:
    record_type: str
    record_id: str
    engagement_id: str
    payload: dict[str, Any]
    revision: int
    checksum: str
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "record_id": self.record_id,
            "engagement_id": self.engagement_id,
            "payload": deepcopy(self.payload),
            "revision": self.revision,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CanonicalStore:
    """Single-writer SQLite authority with versioned, checksummed documents."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(self.path), timeout=30, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        self.path.chmod(0o600)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize writers and make rollback the only partial-failure state."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _migrate(self) -> None:
        with self.transaction() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                )"""
            )
            current = connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Canonical store schema {current} is newer than supported {SCHEMA_VERSION}"
                )
            if current < 1:
                connection.executescript(
                    """
                    CREATE TABLE engagements (
                        engagement_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        checksum TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE records (
                        record_type TEXT NOT NULL,
                        record_id TEXT NOT NULL,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id) ON DELETE CASCADE,
                        payload_json TEXT NOT NULL,
                        checksum TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (record_type, record_id)
                    );
                    CREATE INDEX records_engagement_type
                        ON records(engagement_id, record_type, updated_at);
                    CREATE TABLE audit_events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        engagement_id TEXT,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        subject_type TEXT NOT NULL,
                        subject_id TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL UNIQUE
                    );
                    CREATE TABLE import_ledger (
                        source_id TEXT PRIMARY KEY,
                        source_path TEXT NOT NULL,
                        source_checksum TEXT NOT NULL,
                        imported_at TEXT NOT NULL,
                        summary_json TEXT NOT NULL
                    );
                    """
                )
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                    (1, _now(), "canonical engagement, record, audit, and import authority"),
                )
                current = 1
            if current < 2:
                connection.executescript(
                    """
                    CREATE TABLE spray_reservations (
                        reservation_id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id) ON DELETE CASCADE,
                        domain_name TEXT NOT NULL,
                        principal TEXT NOT NULL,
                        target TEXT NOT NULL,
                        reserved_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        outcome TEXT,
                        UNIQUE(engagement_id, domain_name, principal, target, reservation_id)
                    );
                    CREATE INDEX spray_budget_window
                        ON spray_reservations(engagement_id, domain_name, principal, reserved_at);
                    """
                )
                connection.execute(
                    "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                    (2, _now(), "cross-run credential spray reservation ledger"),
                )

    @property
    def schema_version(self) -> int:
        return int(
            self._connection.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        engagement_id: str | None,
        actor: str,
        action: str,
        subject_type: str,
        subject_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        previous = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        event = {
            "event_id": str(uuid4()),
            "engagement_id": engagement_id,
            "actor": actor,
            "action": action,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "details": details or {},
            "occurred_at": _now(),
            "previous_hash": previous_hash,
        }
        event_hash = _digest(previous_hash + _canonical(event))
        connection.execute(
            """INSERT INTO audit_events
               (event_id, engagement_id, actor, action, subject_type, subject_id,
                details_json, occurred_at, previous_hash, event_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["event_id"],
                engagement_id,
                actor,
                action,
                subject_type,
                subject_id,
                _canonical(event["details"]),
                event["occurred_at"],
                previous_hash,
                event_hash,
            ),
        )

    def put_engagement(
        self,
        engagement_id: str,
        payload: dict[str, Any],
        *,
        actor: str = "system",
        create_only: bool = False,
    ) -> dict[str, Any]:
        if not engagement_id or payload.get("id") != engagement_id:
            raise ValueError("Engagement payload id must match engagement_id")
        encoded = _canonical(payload)
        checksum = _digest(encoded)
        timestamp = _now()
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT revision, created_at FROM engagements WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            if current and create_only:
                raise ValueError(f"Engagement already exists: {engagement_id}")
            revision = (current["revision"] + 1) if current else 1
            created_at = current["created_at"] if current else timestamp
            connection.execute(
                """INSERT INTO engagements
                   (engagement_id, payload_json, checksum, revision, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(engagement_id) DO UPDATE SET
                       payload_json=excluded.payload_json,
                       checksum=excluded.checksum,
                       revision=excluded.revision,
                       updated_at=excluded.updated_at""",
                (engagement_id, encoded, checksum, revision, created_at, timestamp),
            )
            self._audit(
                connection,
                engagement_id=engagement_id,
                actor=actor,
                action="create" if current is None else "update",
                subject_type="engagement",
                subject_id=engagement_id,
                details={"revision": revision, "checksum": checksum},
            )
        return deepcopy(payload)

    def get_engagement(self, engagement_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT payload_json, checksum FROM engagements WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()
        if row is None:
            raise FileNotFoundError(engagement_id)
        if _digest(row["payload_json"]) != row["checksum"]:
            raise RuntimeError(f"Engagement checksum mismatch: {engagement_id}")
        return json.loads(row["payload_json"])

    def list_engagements(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT engagement_id FROM engagements ORDER BY created_at, engagement_id"
        ).fetchall()
        return [self.get_engagement(row[0]) for row in rows]

    def put_record(
        self,
        record_type: str,
        record_id: str,
        engagement_id: str,
        payload: dict[str, Any],
        *,
        actor: str = "system",
    ) -> StoreRecord:
        if record_type not in RECORD_TYPES:
            raise ValueError(f"Unsupported canonical record type: {record_type}")
        if not record_id or not engagement_id:
            raise ValueError("Canonical records require record_id and engagement_id")
        encoded = _canonical(payload)
        checksum = _digest(encoded)
        timestamp = _now()
        with self.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM engagements WHERE engagement_id = ?", (engagement_id,)
                ).fetchone()
                is None
            ):
                raise ValueError(f"Unknown engagement: {engagement_id}")
            current = connection.execute(
                """SELECT revision, created_at, engagement_id FROM records
                   WHERE record_type = ? AND record_id = ?""",
                (record_type, record_id),
            ).fetchone()
            if current and current["engagement_id"] != engagement_id:
                raise ValueError("A record cannot move between engagements")
            revision = (current["revision"] + 1) if current else 1
            created_at = current["created_at"] if current else timestamp
            connection.execute(
                """INSERT INTO records
                   (record_type, record_id, engagement_id, payload_json, checksum,
                    revision, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(record_type, record_id) DO UPDATE SET
                       payload_json=excluded.payload_json,
                       checksum=excluded.checksum,
                       revision=excluded.revision,
                       updated_at=excluded.updated_at""",
                (
                    record_type,
                    record_id,
                    engagement_id,
                    encoded,
                    checksum,
                    revision,
                    created_at,
                    timestamp,
                ),
            )
            self._audit(
                connection,
                engagement_id=engagement_id,
                actor=actor,
                action="create" if current is None else "update",
                subject_type=record_type,
                subject_id=record_id,
                details={"revision": revision, "checksum": checksum},
            )
        return StoreRecord(
            record_type,
            record_id,
            engagement_id,
            deepcopy(payload),
            revision,
            checksum,
            created_at,
            timestamp,
        )

    def get_record(self, record_type: str, record_id: str) -> StoreRecord:
        row = self._connection.execute(
            """SELECT * FROM records WHERE record_type = ? AND record_id = ?""",
            (record_type, record_id),
        ).fetchone()
        if row is None:
            raise KeyError(record_id)
        if _digest(row["payload_json"]) != row["checksum"]:
            raise RuntimeError(f"Record checksum mismatch: {record_type}/{record_id}")
        return StoreRecord(
            row["record_type"],
            row["record_id"],
            row["engagement_id"],
            json.loads(row["payload_json"]),
            row["revision"],
            row["checksum"],
            row["created_at"],
            row["updated_at"],
        )

    def list_records(
        self, record_type: str | None = None, engagement_id: str | None = None
    ) -> list[StoreRecord]:
        clauses, parameters = [], []
        if record_type is not None:
            clauses.append("record_type = ?")
            parameters.append(record_type)
        if engagement_id is not None:
            clauses.append("engagement_id = ?")
            parameters.append(engagement_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._connection.execute(
            "SELECT record_type, record_id FROM records"
            + where
            + " ORDER BY record_type, record_id",
            parameters,
        ).fetchall()
        return [self.get_record(row[0], row[1]) for row in rows]

    def delete_record(self, record_type: str, record_id: str, *, actor: str = "system") -> bool:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT engagement_id, checksum FROM records WHERE record_type = ? AND record_id = ?",
                (record_type, record_id),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "DELETE FROM records WHERE record_type = ? AND record_id = ?",
                (record_type, record_id),
            )
            self._audit(
                connection,
                engagement_id=row["engagement_id"],
                actor=actor,
                action="delete",
                subject_type=record_type,
                subject_id=record_id,
                details={"previous_checksum": row["checksum"]},
            )
        return True

    def audit_events(self, engagement_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_events"
        parameters: tuple[Any, ...] = ()
        if engagement_id is not None:
            query += " WHERE engagement_id = ?"
            parameters = (engagement_id,)
        query += " ORDER BY sequence"
        return [
            {
                **dict(row),
                "details": json.loads(row["details_json"]),
            }
            for row in self._connection.execute(query, parameters).fetchall()
        ]

    def verify(self) -> dict[str, Any]:
        integrity = self._connection.execute("PRAGMA integrity_check").fetchone()[0]
        mismatches = []
        for table, identity in (("engagements", "engagement_id"), ("records", "record_id")):
            for row in self._connection.execute(
                f"SELECT {identity}, payload_json, checksum FROM {table}"  # nosec B608 - constants only
            ).fetchall():
                if _digest(row["payload_json"]) != row["checksum"]:
                    mismatches.append(f"{table}:{row[identity]}")
        previous = "0" * 64
        audit_valid = True
        for row in self._connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ).fetchall():
            event = {
                "event_id": row["event_id"],
                "engagement_id": row["engagement_id"],
                "actor": row["actor"],
                "action": row["action"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "details": json.loads(row["details_json"]),
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected = _digest(previous + _canonical(event))
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                audit_valid = False
                break
            previous = row["event_hash"]
        return {
            "valid": integrity == "ok" and not mismatches and audit_valid,
            "sqlite_integrity": integrity,
            "checksum_mismatches": mismatches,
            "audit_chain_valid": audit_valid,
            "schema_version": self.schema_version,
        }

    def backup(self, destination: str | Path) -> dict[str, Any]:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        with self._lock:
            output = sqlite3.connect(str(temporary))
            try:
                self._connection.backup(output)
            finally:
                output.close()
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        checksum = _digest(destination.read_bytes())
        manifest = {
            "schema_version": self.schema_version,
            "created_at": _now(),
            "database": destination.name,
            "sha256": checksum,
            "size": destination.stat().st_size,
        }
        manifest_path = destination.with_suffix(destination.suffix + ".manifest.json")
        manifest_path.write_text(_canonical(manifest) + "\n", encoding="utf-8")
        manifest_path.chmod(0o600)
        return {**manifest, "path": str(destination), "manifest": str(manifest_path)}

    @classmethod
    def restore(
        cls,
        backup: str | Path,
        destination: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> "CanonicalStore":
        backup, destination = Path(backup), Path(destination)
        checksum = _digest(backup.read_bytes())
        if expected_sha256 and checksum != expected_sha256:
            raise ValueError("Backup checksum mismatch")
        probe = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
        try:
            if probe.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Backup failed SQLite integrity check")
            version = probe.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            if version > SCHEMA_VERSION:
                raise ValueError("Backup schema is newer than this application")
        finally:
            probe.close()
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.restore")
        shutil.copyfile(backup, temporary)
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        restored = cls(destination)
        verification = restored.verify()
        if not verification["valid"]:
            restored.close()
            raise ValueError(f"Restored database verification failed: {verification}")
        return restored

    def import_legacy(
        self,
        *,
        assessment_dir: str | Path | None = None,
        findings_file: str | Path | None = None,
        sqlite_file: str | Path | None = None,
        default_engagement_id: str = "legacy-import",
    ) -> dict[str, Any]:
        """Import legacy sources once, with source checksums and reconciliation."""
        summary = {"engagements": 0, "findings": 0, "assets": 0, "services": 0}
        sources = [
            Path(value)
            for value in (assessment_dir, findings_file, sqlite_file)
            if value is not None and Path(value).exists()
        ]
        if not sources:
            return summary
        if not any(item.get("id") == default_engagement_id for item in self.list_engagements()):
            self.put_engagement(
                default_engagement_id,
                {
                    "id": default_engagement_id,
                    "name": "Reconciled legacy import",
                    "created_at": _now(),
                    "targets": [],
                    "phases": ["migration"],
                    "metadata": {"legacy_import": True},
                    "plans": [],
                    "evidence": [],
                    "manual_entries": [],
                    "hypotheses": [],
                    "reviews": [],
                    "findings": [],
                    "remediations": [],
                    "retests": [],
                    "checks": [],
                    "executions": [],
                    "profiles": [],
                    "baselines": {},
                    "schema_version": 1,
                },
                actor="migration",
                create_only=True,
            )
        for source in sources:
            checksum = self._source_checksum(source)
            source_id = _digest(str(source.resolve()) + checksum)
            if self._connection.execute(
                "SELECT 1 FROM import_ledger WHERE source_id = ?", (source_id,)
            ).fetchone():
                continue
            before = dict(summary)
            if source.is_dir():
                for path in sorted(source.glob("*.json")):
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    engagement_id = payload.get("id")
                    if not engagement_id:
                        raise ValueError(f"Legacy engagement has no id: {path}")
                    self.put_engagement(engagement_id, payload, actor="migration", create_only=True)
                    summary["engagements"] += 1
            elif source.suffix.lower() == ".json":
                values = json.loads(source.read_text(encoding="utf-8"))
                if not isinstance(values, list):
                    raise ValueError("Legacy findings file must contain a list")
                for value in values:
                    record_id = str(value.get("id") or uuid4())
                    engagement_id = value.get("metadata", {}).get(
                        "engagement_id", default_engagement_id
                    )
                    self.put_record("finding", record_id, engagement_id, value, actor="migration")
                    summary["findings"] += 1
            else:
                source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
                source_connection.row_factory = sqlite3.Row
                try:
                    tables = {
                        row[0]
                        for row in source_connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        )
                    }
                    for table, record_type, identity in (
                        ("targets", "asset", "identifier"),
                        ("services", "service", "id"),
                    ):
                        if table not in tables:
                            continue
                        for row in source_connection.execute(f"SELECT * FROM {table}"):  # nosec B608 - allowlisted
                            value = dict(row)
                            record_id = f"legacy:{table}:{value.get(identity)}"
                            self.put_record(
                                record_type,
                                record_id,
                                default_engagement_id,
                                value,
                                actor="migration",
                            )
                            summary["assets" if record_type == "asset" else "services"] += 1
                finally:
                    source_connection.close()
            delta = {key: summary[key] - before[key] for key in summary}
            with self.transaction() as connection:
                connection.execute(
                    "INSERT INTO import_ledger VALUES (?, ?, ?, ?, ?)",
                    (
                        source_id,
                        str(source.resolve()),
                        checksum,
                        _now(),
                        _canonical(delta),
                    ),
                )
        return summary

    @staticmethod
    def _source_checksum(path: Path) -> str:
        if path.is_file():
            return _digest(path.read_bytes())
        content = hashlib.sha256()
        for item in sorted(path.rglob("*")):
            if item.is_file():
                content.update(str(item.relative_to(path)).encode())
                content.update(item.read_bytes())
        return content.hexdigest()

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class CanonicalAssessmentRepository:
    """Assessment repository adapter backed only by :class:`CanonicalStore`."""

    def __init__(self, store: CanonicalStore):
        self.store = store

    def create(self, engagement):
        engagement.validate()
        self.store.put_engagement(
            engagement.id, engagement.to_dict(), create_only=True, actor="assessment"
        )
        return type(engagement).from_dict(engagement.to_dict())

    def save(self, engagement):
        engagement.validate()
        self.store.put_engagement(engagement.id, engagement.to_dict(), actor="assessment")
        return type(engagement).from_dict(engagement.to_dict())

    update = save

    def load(self, engagement_id):
        from .assessment import Engagement

        return Engagement.from_dict(self.store.get_engagement(engagement_id))

    def list(self):
        from .assessment import Engagement

        return [Engagement.from_dict(value) for value in self.store.list_engagements()]


class CanonicalFindingsManager:
    """Canonical Finding lifecycle with no JSON mirror or best-effort writes."""

    def __init__(
        self, store: CanonicalStore, framework=None, default_engagement_id="local-default"
    ):
        from .findings import Finding

        self.framework = framework
        self.store = store
        self.default_engagement_id = default_engagement_id
        self.storage_path = store.path.parent
        self.findings = {
            record.record_id: Finding.from_dict(record.payload)
            for record in store.list_records("finding")
        }

    def _save_findings(self):
        existing = {record.record_id for record in self.store.list_records("finding")}
        current = set(self.findings)
        for finding in self.findings.values():
            payload = finding.to_dict()
            engagement_id = payload.get("metadata", {}).get(
                "engagement_id", self.default_engagement_id
            )
            self.store.put_record("finding", finding.id, engagement_id, payload, actor="findings")
        for record_id in existing - current:
            self.store.delete_record("finding", record_id, actor="findings")

    # Reuse the canonical lifecycle implementation without its JSON persistence.
    from .findings import FindingsManager as _Lifecycle

    create = _Lifecycle.create
    get = _Lifecycle.get
    update = _Lifecycle.update
    delete = _Lifecycle.delete
    list_findings = _Lifecycle.list_findings
    get_statistics = _Lifecycle.get_statistics
    add_evidence = _Lifecycle.add_evidence
    transition_status = _Lifecycle.transition_status
    _find_duplicate = _Lifecycle._find_duplicate
    _similar_titles = _Lifecycle._similar_titles
    export_json = _Lifecycle.export_json
    import_json = _Lifecycle.import_json
    to_report_generator = _Lifecycle.to_report_generator
