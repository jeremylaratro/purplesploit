#!/usr/bin/env python3
"""Synthetic backup/restore rehearsal used by operators and release certification."""

import json
from pathlib import Path
import tempfile

from purplesploit.core.evidence import EvidenceStore
from purplesploit.core.recovery import RecoveryManager
from purplesploit.core.secrets import EncryptedFileSecretProvider
from purplesploit.core.store import CanonicalStore


def main():
    with tempfile.TemporaryDirectory(prefix="purplesploit-recovery-") as directory:
        root = Path(directory)
        store = CanonicalStore(root / "source/canonical.db")
        secrets = EncryptedFileSecretProvider(root / "source/secrets.vault")
        evidence = EvidenceStore(root / "source/evidence", store, secrets)
        store.put_engagement(
            "rehearsal", {"id": "rehearsal", "name": "Synthetic recovery rehearsal"}
        )
        reference = secrets.set("synthetic-secret", label="rehearsal")
        evidence.add_bytes("rehearsal", b"synthetic evidence", name="evidence.txt")
        manager = RecoveryManager(store, secrets, evidence)
        backup = manager.backup(root / "backup")
        verification = manager.verify_backup(backup["path"])
        restored = manager.restore(backup["path"], root / "restored")
        restored_store = CanonicalStore(root / "restored/canonical.db")
        result = {
            "backup_valid": verification["valid"],
            "restored": restored["success"],
            "store_valid": restored_store.verify()["valid"],
            "engagement_present": restored_store.get_engagement("rehearsal")["id"] == "rehearsal",
            "secret_reference": reference.uri,
        }
        restored_store.close()
        store.close()
        if not all(result[key] for key in ("backup_valid", "restored", "store_valid", "engagement_present")):
            raise SystemExit(json.dumps(result))
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
