# Backup and recovery

Use `RecoveryManager` to create one coordinated recovery set containing the canonical
database, encrypted vault and key, evidence blobs, checksums, and a manifest. Store the
set with the same protection as live assessment evidence. A database-only copy is not a
complete backup.

Before restoration, run `RecoveryManager.verify_backup`. Restore only into an empty
directory, start the service against the restored directory, check `/readyz`, verify
evidence manifests, and perform a read-only assessment query. Never overwrite a live
data directory in place.

Run the synthetic rehearsal after upgrades:

```bash
cd python
python scripts/recovery_rehearsal.py
```

The script creates temporary synthetic data, backs it up, restores it, verifies the
SQLite and audit chain, and removes the temporary workspace. Production recovery still
requires an operator-approved runbook, storage snapshots, and retention policy.
