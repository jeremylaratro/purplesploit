"""Adapt recovery-time reveal captures to runtime-only credentials."""
from __future__ import annotations

import base64
from pathlib import Path
from tempfile import TemporaryDirectory

from .. import states
from .base import (Credential, CAP_PASSWORD, CAP_NT_HASH, CAP_AES_KEY, CAP_CCACHE,
                   CAP_PFX)


_KINDS = {
    "password": ("password", CAP_PASSWORD),
    "nt_hash": ("nthash", CAP_NT_HASH),
    "aes_key": ("aeskey", CAP_AES_KEY),
    "ccache_base64": ("ccache", CAP_CCACHE),
    "pfx_base64": ("pfx", CAP_PFX),
}


class _SnapshotPath(str):
    """A tool-compatible path owning its private, temporary bearer material.

    Keeping the owner on the value also preserves it when the engine copies a
    capability or threads just its value into an edge's context. No snapshot is
    written to the receipt directory or retained after the last runtime owner.
    """

    def __new__(cls, data: bytes, suffix: str):
        owner = TemporaryDirectory(prefix="purplesploit-credential-")
        path = Path(owner.name) / ("credential." + suffix)
        try:
            path.touch(mode=0o600)
            path.write_bytes(data)
        except BaseException:
            owner.cleanup()
            raise
        value = super().__new__(cls, str(path))
        value._owner = owner
        return value


def credentials_from_reveals(ctx, artifact: dict, *, finding, params) -> list[Credential]:
    """Use the SAME captures as reveal, never parse output or re-read old files.

    Preserve qualified principals exactly. Their explicit realm overrides the
    configured domain; bare domain accounts use the configured realm. A bare SAM
    account belongs to the relay target's local realm. LAPS captures a host-qualified
    local account, and location-only loot keeps that location as its identity until
    a later phase can resolve the account.
    """
    # Private cache makes repeated produced() reads stable and avoids creating
    # duplicate file snapshots. Incremental captures can still add credentials.
    cache = artifact.setdefault("_credential_cache", {})
    credentials = []
    for reveal in artifact.get("_reveal", []):
        if reveal.kind not in _KINDS or not reveal.value:
            continue
        if reveal not in cache:
            secret_type, channel = _KINDS[reveal.kind]
            principal = reveal.principal
            domain = ctx.config.domain
            account = principal
            if "\\" in principal:
                domain, account = principal.rsplit("\\", 1)
            elif "@" in principal and "/" not in principal:
                account, domain = principal.rsplit("@", 1)
            elif reveal.technique == "NTLM-RELAY":
                target = params.get("relay_target")
                domain = (target.value if target else "") or finding.host or ""
            value = reveal.value
            if reveal.kind.endswith("_base64"):
                data = base64.b64decode(value, validate=True)
                if not data:
                    continue
                value = _SnapshotPath(data, secret_type)
            cache[reveal] = Credential(
                state=states.cred_for(principal), channel=channel, value=value,
                principal=principal, domain=domain, is_machine=account.endswith("$"),
                secret_type=secret_type, source_technique=reveal.technique,
            )
        credential = cache[reveal]
        if credential not in credentials:
            credentials.append(credential)
    return credentials
