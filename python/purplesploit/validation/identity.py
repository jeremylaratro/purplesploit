"""Resolve public credential selectors and scope authentication to one command."""
from __future__ import annotations

import base64
import os
import tempfile
from contextlib import contextmanager, ExitStack
from dataclasses import replace
from pathlib import Path

from .config import ValidationConfig
from .credential_store import CredentialStore


class CredentialScopeError(ValueError):
    """A fixed, public error; never includes store values or parser exceptions."""


def resolve_credential(store: CredentialStore, selector: str) -> dict:
    """Match an AD name (case-insensitive) or a zero-based store index.

    Store upserts retain entry order. A name shared by multiple auth credentials
    requires an index; qualifying the domain resolves cross-domain collisions.
    PFX entries are excluded from name matching because this path cannot use them.
    """
    try:
        entries = store.load()
        if selector.isascii() and selector.isdecimal():
            index = int(selector)
            matches = entries[index:index + 1]
        else:
            name = selector.casefold()
            matches = [entry for entry in entries
                       if name in (entry["principal"].casefold(),
                                   f'{entry["principal"]}@{entry["domain"]}'.casefold())]
            auth = [entry for entry in matches if entry["secret_type"] != "pfx"]
            if auth:
                matches = auth
        if not matches:
            raise CredentialScopeError("as_cred_not_found")
        if len(matches) != 1:
            raise CredentialScopeError("as_cred_ambiguous: use principal@domain or a store index")
        credential = matches[0]
        if not all(isinstance(credential.get(key), str) for key in
                   ("principal", "domain", "source_technique", "secret_type", "value")):
            raise CredentialScopeError("as_cred_invalid_entry")
        if credential["secret_type"] not in ("password", "nthash", "aeskey", "ccache"):
            raise CredentialScopeError("as_cred_unsupported_secret_type")
        if not credential["principal"] or not credential["value"]:
            raise CredentialScopeError("as_cred_invalid_entry")
        return credential
    except CredentialScopeError:
        raise
    except Exception:
        raise CredentialScopeError("credential_store_error") from None


def derive_config(base: ValidationConfig, credential: dict) -> ValidationConfig:
    """Keep scope and execution settings, replacing only the auth identity."""
    fields = {"password": None, "nt_hash": None, "aes_key": None}
    kind = credential["secret_type"]
    field = {"password": "password", "nthash": "nt_hash", "aeskey": "aes_key"}.get(kind)
    if field:
        fields[field] = credential["value"]
    elif kind != "ccache":
        raise CredentialScopeError("as_cred_unsupported_secret_type")
    return replace(base, username=credential["principal"],
                   domain=credential["domain"] or base.domain, **fields)


@contextmanager
def credential_scope(base: ValidationConfig, selector: str):
    """Yield a derived config with a command-local cache environment.

    File credentials in the store contain base64 bytes, not reusable paths.
    Materialize a cache privately for the command, then remove it and restore
    the caller's environment even when dispatch fails. Other credential types
    unset an inherited cache so the operator's ticket cannot authenticate.
    """
    credential = resolve_credential(CredentialStore.from_config(base), selector)
    config = derive_config(base, credential)
    with ExitStack() as stack:
        cache = None
        if credential["secret_type"] == "ccache":
            try:
                material = base64.b64decode(credential["value"], validate=True)
                if not material:
                    raise ValueError
                config.output_dir.mkdir(parents=True, exist_ok=True)
                directory = stack.enter_context(tempfile.TemporaryDirectory(
                    prefix=".as-cred-", dir=config.output_dir))
                cache = str((Path(directory) / "auth.ccache").resolve())
                with open(os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh:
                    fh.write(material)
            except Exception:
                raise CredentialScopeError("as_cred_cache_error") from None
        previous = os.environ.get("KRB5CCNAME")
        try:
            if cache is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = cache
            yield config, credential
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous
