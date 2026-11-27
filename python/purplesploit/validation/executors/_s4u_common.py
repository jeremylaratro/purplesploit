"""Shared S4U/getST helpers for the T6 delegation executors.

Both Bronze Bit (CVE-2020-17049) and S4U2self-abuse drive impacket ``getST`` as a
compromised service/machine account, then prove the ticket with ``nxc ... -k
--use-kcache``. This module centralises the key formatting (the review fix: prefer
AES, normalise a bare NT hash) and the KDC-failure classification (so ``exit 0 is
never proof`` -- a classified Kerberos error, not the return code, decides).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# getST ticket-save marker (same tooling as constrained_deleg/rbcd, #66146).
TICKET_RE = re.compile(r"(?:Saving|Updating) ticket in\s+(\S+)", re.I)
PWNED_RE = re.compile(r"\(Pwn3d!\)", re.I)          # nxc: LOCAL ADMIN
AUTH_RE = re.compile(r"\bSMB\b.*\[\+\]", re.I)      # nxc: authenticated (NOT necessarily admin)

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def getst_key_flags(cfg) -> list[str]:
    """getST key flags for the account whose key the operator holds. Prefer ``-aesKey``
    (an NT hash cannot decrypt an AES S4U ticket -- review HIGH), and normalise a bare
    NT hash to ``LM:NT`` (impacket requires the colon form). Password -> no flags (it
    rides in the auth target). The value is a SECRET -- masked by ``redact_argv``."""
    if getattr(cfg, "aes_key", None):
        return ["-aesKey", cfg.aes_key]
    if getattr(cfg, "nt_hash", None):
        nt = cfg.nt_hash
        if ":" not in nt:                            # bare NT -> empty-LM : NT
            nt = f"{_EMPTY_LM}:{nt}"
        return ["-hashes", nt]
    return []


def op_auth_target(cfg, principal: str) -> str:
    """impacket auth target ``domain/principal[:password]`` -- password appended ONLY
    when no key flag carries the secret (see :func:`getst_key_flags`)."""
    target = f"{cfg.domain}/{principal}"
    if not getattr(cfg, "aes_key", None) and not getattr(cfg, "nt_hash", None) \
            and getattr(cfg, "password", None) is not None:
        target += f":{cfg.password}"
    return target


def parse_ticket(stdout: str, out_dir: Path) -> Optional[str]:
    """The saved ccache path, resolved ABSOLUTE. getST writes a bare filename to its
    cwd (``out_dir``); the proof step then runs with ``cwd=out_dir`` too, so a RELATIVE
    path (e.g. the CLI default ``./validation-run``) would double-nest under
    ``KRB5CCNAME`` and the ticket would not be found. Always return an absolute path."""
    m = TICKET_RE.search(stdout or "")
    if not m:
        return None
    p = Path(m.group(1).strip())
    return str(p if p.is_absolute() else (Path(out_dir) / p).resolve())


def classify_kerberos_failure(text: str) -> Optional[str]:
    """Classify a getST failure from the tool output (the carrier, not exit code).

    ``kdc_patched`` is the determined-negative that matters for Bronze Bit: a KDC
    enforcing CVE-2020-17049 rejects the forged forwardable ticket with
    ``KRB_AP_ERR_MODIFIED``. ``not_delegatable`` (``KDC_ERR_BADOPTION``) means the SPN
    is not allowed or the S4U2self ticket was not forwardable."""
    t = text or ""
    if re.search(r"KRB_AP_ERR_MODIFIED", t, re.I):
        return "kdc_patched"
    if re.search(r"KDC_ERR_BADOPTION", t, re.I):
        return "not_delegatable"
    if re.search(r"KDC_ERR_S_PRINCIPAL_UNKNOWN", t, re.I):
        return "spn_unknown"
    if re.search(r"KDC_ERR_C_PRINCIPAL_UNKNOWN|PRINCIPAL_UNKNOWN", t, re.I):
        return "principal_unknown"
    if re.search(r"KDC_ERR_PREAUTH_FAILED|KRB_AP_ERR_SKEW|wrong key", t, re.I):
        return "bad_key_or_skew"
    return None
