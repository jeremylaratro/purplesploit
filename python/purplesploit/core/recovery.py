"""Coordinated backup and restore for canonical state, secrets, and evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

from .store import CanonicalStore


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RecoveryManager:
    def __init__(self, store, secrets, evidence):
        self.store = store
        self.secrets = secrets
        self.evidence = evidence

    def backup(self, destination: str | Path) -> dict:
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        destination.chmod(0o700)
        database = self.store.backup(destination / "canonical.db")
        secrets = self.secrets.backup(destination / "secrets")
        evidence_destination = destination / "evidence"
        shutil.copytree(self.evidence.root, evidence_destination)
        for path in evidence_destination.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        files = {}
        for path in sorted(destination.rglob("*")):
            if path.is_file() and path.name != "recovery-manifest.json":
                files[str(path.relative_to(destination))] = {
                    "sha256": _sha(path),
                    "size": path.stat().st_size,
                }
        manifest = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database": database,
            "secrets": secrets,
            "evidence": self.evidence.verify(),
            "files": files,
        }
        manifest_path = destination / "recovery-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest_path.chmod(0o600)
        return {**manifest, "path": str(destination)}

    @staticmethod
    def verify_backup(source: str | Path) -> dict:
        source = Path(source)
        manifest = json.loads((source / "recovery-manifest.json").read_text())
        failures = []
        for relative, expected in manifest["files"].items():
            path = source / relative
            if (
                not path.is_file()
                or path.stat().st_size != expected["size"]
                or _sha(path) != expected["sha256"]
            ):
                failures.append(relative)
        return {"valid": not failures, "failures": failures, "manifest": manifest}

    @classmethod
    def restore(cls, source: str | Path, destination: str | Path):
        source, destination = Path(source), Path(destination)
        verification = cls.verify_backup(source)
        if not verification["valid"]:
            raise ValueError(f"Recovery set failed verification: {verification['failures']}")
        if destination.exists() and any(destination.iterdir()):
            raise ValueError("Recovery destination must be empty")
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = destination / f".restore-{uuid4().hex}"
        stage.mkdir(mode=0o700)
        try:
            database = CanonicalStore.restore(
                source / "canonical.db",
                stage / "canonical.db",
                expected_sha256=verification["manifest"]["files"]["canonical.db"]["sha256"],
            )
            database.close()
            shutil.copytree(source / "secrets", stage / "secrets")
            shutil.copytree(source / "evidence", stage / "evidence")
            for child in stage.iterdir():
                os.replace(child, destination / child.name)
        finally:
            stage.rmdir()
        return {"success": True, "path": str(destination)}
