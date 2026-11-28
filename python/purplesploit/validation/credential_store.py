"""Operator-only credential persistence, separate from receipts and reports."""
from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .executors.base import Capability, Credential, CAP_CCACHE, CAP_PFX


_METADATA = ("principal", "domain", "secret_type", "source_technique", "first_seen")


class CredentialStore:
    """A private engagement JSON file. File credentials store base64 material.

    Each write mirrors the loot store's exclusive 0600 creation. Updates are
    written to an exclusive sibling before replacement so a failed write leaves
    the previous store intact and never opens a permissive file for secrets.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    @classmethod
    def from_config(cls, cfg) -> "CredentialStore":
        directory = Path(cfg.cred_store_dir or (Path(cfg.output_dir) / "cred-store"))
        return cls(Path(cfg.cred_store_file) if cfg.cred_store_file else directory / "creds.json")

    def load(self) -> list[dict]:
        """Read secret-bearing entries for operator use only."""
        try:
            with self.path.open(encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return []

    def _save(self, entries: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        pending = self.path.with_name(f".{self.path.name}-{secrets.token_hex(6)}")
        fd = os.open(str(pending), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(entries, fh, indent=2)
            os.replace(pending, self.path)
        finally:
            pending.unlink(missing_ok=True)

    def upsert(self, capabilities: Iterable[Capability]) -> None:
        """Collect only standardized secret Credentials; retain first_seen."""
        credentials = [cap for cap in capabilities if isinstance(cap, Credential) and cap.secret]
        if not credentials:
            return
        entries = self.load()
        keyed = {(e["principal"], e["domain"], e["secret_type"]): e for e in entries}
        for cap in credentials:
            value = cap.value
            if cap.channel in (CAP_CCACHE, CAP_PFX):
                # Phase 1 snapshot paths expire with their runtime owner. Persist
                # the actual bearer material before those snapshots disappear.
                value = base64.b64encode(Path(value).read_bytes()).decode("ascii")
            key = (cap.principal, cap.domain, cap.secret_type)
            previous = keyed.get(key)
            keyed[key] = {
                "principal": cap.principal,
                "domain": cap.domain,
                "is_machine": cap.is_machine,
                "secret_type": cap.secret_type,
                "source_technique": cap.source_technique,
                "value": value,
                "first_seen": (previous["first_seen"] if previous else
                               datetime.now(timezone.utc).isoformat()),
            }
        self._save(list(keyed.values()))

    def list(self) -> list[dict]:
        """Return only the explicit public metadata allowlist."""
        return [{key: entry[key] for key in _METADATA} for entry in self.load()]

    def clear(self) -> None:
        self._save([])
