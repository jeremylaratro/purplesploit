import json

import pytest

from purplesploit.core.evidence import EvidenceStore
from purplesploit.core.recovery import RecoveryManager
from purplesploit.core.secrets import (
    EncryptedFileSecretProvider,
    SecretRedactor,
    SecretReference,
    externalize_secrets,
    resolve_secrets,
)
from purplesploit.core.store import CanonicalStore

from .test_store_s19 import engagement


def stack(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    store.put_engagement("eng-1", engagement())
    secrets = EncryptedFileSecretProvider(tmp_path / "secrets.vault")
    evidence = EvidenceStore(tmp_path / "evidence", store, secrets)
    return store, secrets, evidence


def test_encrypted_secret_references_and_redaction(tmp_path):
    provider = EncryptedFileSecretProvider(tmp_path / "secrets.vault")
    reference = provider.set("correct horse battery staple", label="fixture")
    assert reference.uri.startswith("secret://local/")
    assert SecretReference.parse(reference.uri).id == reference.id
    assert provider.get(reference) == "correct horse battery staple"
    ciphertext = provider.path.read_bytes()
    assert b"correct horse" not in ciphertext
    assert provider.path.stat().st_mode & 0o777 == 0o600
    assert provider.key_path.stat().st_mode & 0o777 == 0o600

    redactor = SecretRedactor(provider)
    value = redactor.redact({
        "password": "correct horse battery staple",
        "message": "Authorization=correct horse battery staple",
        "reference": reference.uri,
    })
    assert json.dumps(value).count("correct horse") == 0
    assert value["password"] == "[REDACTED]"
    assert value["reference"] == "[REDACTED]"


def test_externalization_persists_references_only_and_round_trips(tmp_path):
    provider = EncryptedFileSecretProvider(tmp_path / "secrets.vault")
    config = {
        "server_url": "https://example.invalid",
        "api_key": "fixture-api-key",
        "nested": {"client_secret": "fixture-client-secret", "enabled": True},
    }
    persisted = externalize_secrets(config, provider, namespace="integration/lab")
    assert persisted["api_key"].startswith("secret://")
    assert persisted["nested"]["client_secret"].startswith("secret://")
    assert "fixture-api-key" not in json.dumps(persisted)
    assert resolve_secrets(persisted, provider) == config
    # Stable field references rotate a value without leaving duplicate secrets.
    changed = externalize_secrets(
        {**config, "api_key": "rotated-api-key"}, provider, namespace="integration/lab"
    )
    assert changed["api_key"] == persisted["api_key"]
    assert provider.get(changed["api_key"]) == "rotated-api-key"


def test_immutable_evidence_redactions_and_signed_manifest(tmp_path):
    store, secrets, evidence = stack(tmp_path)
    original = evidence.add_bytes(
        "eng-1",
        b"original evidence\nsecret=value\n",
        name="tool.txt",
        media_type="text/plain",
        source_execution_id="exec-1",
        operator="analyst@example.test",
    )
    assert evidence.read(original.id).startswith(b"original evidence")
    redacted = evidence.add_redaction(
        original.id, b"original evidence\nsecret=[REDACTED]\n", operator="reviewer"
    )
    assert redacted.derived_from == original.id and redacted.redacted
    assert evidence.read(original.id) != evidence.read(redacted.id)
    manifest = evidence.manifest("eng-1")
    assert manifest["signature_algorithm"] == "HMAC-SHA256"
    assert evidence.verify_manifest(manifest)
    manifest["evidence"][0]["size"] += 1
    assert not evidence.verify_manifest(manifest)
    assert evidence.verify("eng-1")["valid"]


def test_evidence_tampering_and_retention_deletion_are_observable(tmp_path):
    store, _, evidence = stack(tmp_path)
    item = evidence.add_bytes("eng-1", b"immutable", name="proof.bin")
    blob = evidence.root / item.blob_ref
    blob.write_bytes(b"tampered")
    assert not evidence.verify()["valid"]
    with pytest.raises(RuntimeError, match="integrity"):
        evidence.read(item.id)
    assert evidence.delete(item.id, actor="retention-policy", purge_blob=True)
    assert not blob.exists()
    assert store.audit_events("eng-1")[-1]["action"] == "delete"


def test_coordinated_backup_verification_and_restore(tmp_path):
    store, secrets, evidence = stack(tmp_path / "active")
    reference = secrets.set("recover-me", label="recovery-fixture")
    proof = evidence.add_bytes("eng-1", b"recover-evidence", name="proof.bin")
    manager = RecoveryManager(store, secrets, evidence)
    recovery = manager.backup(tmp_path / "recovery-set")
    assert RecoveryManager.verify_backup(recovery["path"])["valid"]
    restored_path = tmp_path / "restored"
    assert RecoveryManager.restore(recovery["path"], restored_path)["success"]

    restored_store = CanonicalStore(restored_path / "canonical.db")
    restored_secrets = EncryptedFileSecretProvider(
        restored_path / "secrets" / "secrets.vault",
        key_path=restored_path / "secrets" / "secrets.key",
    )
    restored_evidence = EvidenceStore(restored_path / "evidence", restored_store, restored_secrets)
    assert restored_secrets.get(reference) == "recover-me"
    assert restored_evidence.read(proof.id) == b"recover-evidence"
    assert restored_store.verify()["valid"]
