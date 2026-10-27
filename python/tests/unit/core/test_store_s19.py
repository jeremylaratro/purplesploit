import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from purplesploit.core.assessment import AssessmentService
from purplesploit.core.findings import Severity
from purplesploit.core.store import (
    CanonicalAssessmentRepository,
    CanonicalFindingsManager,
    CanonicalStore,
)


def engagement(ident="eng-1"):
    return {
        "id": ident,
        "name": "Canonical fixture",
        "created_at": "2026-10-26T00:00:00+00:00",
        "targets": [],
        "phases": ["testing"],
        "metadata": {},
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
    }


def test_engagement_children_revisions_and_audit_chain(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    store.put_engagement("eng-1", engagement(), create_only=True, actor="fixture")
    with pytest.raises(ValueError, match="Unknown engagement"):
        store.put_record("asset", "a-0", "absent", {"id": "a-0"})
    first = store.put_record("asset", "a-1", "eng-1", {"id": "a-1", "address": "192.0.2.1"})
    second = store.put_record("asset", "a-1", "eng-1", {"id": "a-1", "address": "192.0.2.2"})
    assert first.revision == 1 and second.revision == 2
    assert store.get_record("asset", "a-1").payload["address"] == "192.0.2.2"
    assert store.verify() == {
        "valid": True,
        "sqlite_integrity": "ok",
        "checksum_mismatches": [],
        "audit_chain_valid": True,
        "schema_version": 2,
    }
    events = store.audit_events("eng-1")
    assert [item["action"] for item in events] == ["create", "create", "update"]
    assert events[1]["previous_hash"] == events[0]["event_hash"]


def test_assessments_and_findings_share_one_authority(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    assessments = AssessmentService(CanonicalAssessmentRepository(store))
    created = assessments.create_engagement("One authority", engagement_id="eng-1")
    findings = CanonicalFindingsManager(store, default_engagement_id=created.id)
    finding = findings.create(
        title="Fixture",
        severity=Severity.MEDIUM,
        description="Stored in the canonical authority",
        target="192.0.2.1",
        metadata={"engagement_id": created.id},
    )
    assert store.get_record("finding", finding.id).engagement_id == created.id
    restarted = CanonicalFindingsManager(store, default_engagement_id=created.id)
    assert restarted.get(finding.id).to_dict() == finding.to_dict()
    assert assessments.get_engagement(created.id).to_dict() == created.to_dict()


def test_single_writer_and_transaction_rollback(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    store.put_engagement("eng-1", engagement())

    def write(index):
        return store.put_record(
            "observation", f"o-{index}", "eng-1", {"id": f"o-{index}"}
        ).record_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert len(set(executor.map(write, range(40)))) == 40
    with pytest.raises(RuntimeError):
        with store.transaction() as connection:
            connection.execute(
                "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("asset", "rollback", "eng-1", "{}", "bad", 1, "now", "now"),
            )
            raise RuntimeError("rollback")
    with pytest.raises(KeyError):
        store.get_record("asset", "rollback")
    assert store.verify()["valid"]


def test_backup_restore_and_tamper_detection(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    store.put_engagement("eng-1", engagement())
    store.put_record("service", "s-1", "eng-1", {"id": "s-1", "port": 443})
    backup = store.backup(tmp_path / "backup" / "canonical.db")
    restored = CanonicalStore.restore(
        backup["path"], tmp_path / "restored.db", expected_sha256=backup["sha256"]
    )
    assert restored.get_record("service", "s-1").payload["port"] == 443
    assert restored.verify()["valid"]
    with pytest.raises(ValueError, match="checksum"):
        CanonicalStore.restore(
            backup["path"], tmp_path / "rejected.db", expected_sha256="0" * 64
        )


def test_explicit_legacy_reconciliation_is_idempotent(tmp_path):
    legacy_assessments = tmp_path / "assessments"
    legacy_assessments.mkdir()
    (legacy_assessments / "eng-old.json").write_text(json.dumps(engagement("eng-old")))
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{
        "id": "F-1",
        "title": "Legacy",
        "severity": "low",
        "metadata": {"engagement_id": "eng-old"},
    }]))
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE targets (identifier TEXT, type TEXT)")
    connection.execute("INSERT INTO targets VALUES ('192.0.2.8', 'network')")
    connection.execute("CREATE TABLE services (id INTEGER, target TEXT, service TEXT, port INTEGER)")
    connection.execute("INSERT INTO services VALUES (1, '192.0.2.8', 'https', 443)")
    connection.commit()
    connection.close()

    store = CanonicalStore(tmp_path / "canonical.db")
    result = store.import_legacy(
        assessment_dir=legacy_assessments,
        findings_file=findings,
        sqlite_file=database,
    )
    assert result == {"engagements": 1, "findings": 1, "assets": 1, "services": 1}
    assert store.import_legacy(
        assessment_dir=legacy_assessments,
        findings_file=findings,
        sqlite_file=database,
    ) == {"engagements": 0, "findings": 0, "assets": 0, "services": 0}
    assert {item["id"] for item in store.list_engagements()} == {"legacy-import", "eng-old"}
    assert store.verify()["valid"]
