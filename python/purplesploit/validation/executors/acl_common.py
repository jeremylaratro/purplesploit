"""Shared ACL/owner read-write infrastructure for the T3 executors.

Plain functions + regex constants only -- NO executor classes, precedented by
``process_manager.py`` being shared infra, and by ``certifried.py`` importing
plain helpers (``machine_account``/``_short_name``) from ``coercion.py``. Every
T3 executor's own "confirm precondition" step calls :func:`confirm_ace`, and
every ACE/owner read or write goes through one of the ``*_argv`` builders here,
so parsing rules can't drift across the 7 files that need them.

UNVERIFIED (pin in-lab): the exact human-readable rights wording impacket's
``impacket-dacledit``/``impacket-owneredit`` print. If the real wording differs, a T3
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
_RE_DACL_READ_OK = re.compile(r"(ACCESS[-_ ]ALLOWED|ace type|ObjectType|Rights\s*:)", re.I)
_RE_OWNER_READ_OK = re.compile(r"(current owner|owner\s*:|ownersid)", re.I)
# Captures the owner identity. Matches BOTH the legacy single-line form
# ("current owner: DOMAIN\\name") AND impacket-owneredit 0.13.x's multi-line
# block, where the identity is on its own "- sAMAccountName: <name>" line under
# a "[*] Current owner information below" header (the value never follows
# "owner" on that header line, so the sAMAccountName branch is what fires live).
_RE_OWNER_VALUE = re.compile(
    r"(?:current owner|owner|sAMAccountName)\s*[:=]\s*(\S.*)", re.I)

# ---- ACE-block delimiters (impacket-dacledit 0.13.x prints each ACE as a
# multi-line block; the Access-mask/rights line and the Trustee line are on
# SEPARATE lines, so confirm_ace must group by block, not by single line) ------
_RE_ACE_INDEX = re.compile(r"ACE\[\d+\]")
_RE_ACE_HEADER = re.compile(r"ACCESS[-_ ](?:ALLOWED|DENIED)", re.I)
# confirm_ace parses a block by its STRUCTURED FIELDS, never by scanning the
# whole block text: the ACE-type (allow/deny), the trustee principal, and the
# rights each come from their own field, so a trustee name, a ``(SID)`` label, an
# apostrophe in an account name, or an account literally named ``ACCESS_DENIED``
# can never be confused for an ACE-type or for another principal.
#
# ACE-type token: ``ACCESS_ALLOWED...ACE`` / ``ACCESS_DENIED...ACE`` (impacket's
# ``ACE Type`` line, or the fixtures' ``ACCESS ALLOWED ACE`` header). A trailing
# ``ACE`` is required (so a trustee named ``ACCESS_DENIED$`` -- no ``ACE`` suffix
# -- is NOT read as an ACE-type). No LEADING word boundary: ``ACCESS_ALLOWED_ACE``
# joins ``ACE`` with an underscore (a \w char), which has no \b before it. The
# ACE-type field precedes the Trustee line in every format, so the leftmost match
# is always the real ACE-type, never a trustee name.
_RE_ACE_TYPE_TOKEN = re.compile(r"ACCESS[-_ ](ALLOWED|DENIED)[A-Z0-9_ -]*ACE\b", re.I)
# Trustee field value: everything after ``Trustee [(SID)] :``. The ``(SID)`` label
# is consumed by the optional group, not captured.
_RE_TRUSTEE_VALUE = re.compile(r"Trustee(?:\s*\(SID\))?\s*[:=]\s*(\S[^\n]*)", re.I)
# Trailing ``(S-1-5-...)`` SID that impacket appends after the principal name.
_RE_SID_SUFFIX = re.compile(r"\s*\(S-[0-9-]+\)\s*$", re.I)
# In the single-line fixture the trustee value is followed by ``Rights: ...`` (or a
# 2+ space gap); cut it off so the principal is just the name.
_RE_TRUSTEE_TAIL = re.compile(r"\s{2,}|\bRights\b\s*[:=]", re.I)

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


def _impacket_auth(cfg) -> tuple[str, list[str]]:
    """impacket 0.13.x auth: a POSITIONAL connection string ``domain/user[:pw]``
    (NOT ``-u``/``-p`` -- dacledit/owneredit have no such flags; ``-p`` is even
    ambiguous with ``-principal``), plus ``-hashes``/``-aesKey`` when used.

    Returns ``(identity, extra_flags)``; callers place ``identity`` LAST (it is
    the sole positional) and splice ``extra_flags`` before it. ``redact_argv``
    masks the ``:password`` tail of the connstr, so it is receipt-safe.
    """
    identity = f"{cfg.domain}/{cfg.username or ''}"
    extra: list[str] = []
    if cfg.nt_hash:
        extra = ["-hashes", cfg.nt_hash if ":" in cfg.nt_hash else f":{cfg.nt_hash}"]
    elif cfg.aes_key:
        extra = ["-aesKey", cfg.aes_key]
    elif cfg.password is not None:
        identity = f"{identity}:{cfg.password}"
    return identity, extra


# ---------------------------------------------------------------- dacledit argv
def dacledit_read_argv(cfg, target: str, dc: str) -> list[str]:
    identity, extra = _impacket_auth(cfg)
    return ["impacket-dacledit", "-action", "read", "-target", target, "-dc-ip", dc,
            *extra, identity]


def dacledit_write_argv(cfg, target: str, dc: str, trustee: str,
                        rights: str = "FullControl") -> list[str]:
    identity, extra = _impacket_auth(cfg)
    return ["impacket-dacledit", "-action", "write", "-ace-type", "allowed",
            "-rights", rights, "-principal", trustee, "-target", target,
            "-dc-ip", dc, *extra, identity]


def dacledit_remove_argv(cfg, target: str, dc: str, trustee: str,
                         rights: str = "FullControl") -> list[str]:
    identity, extra = _impacket_auth(cfg)
    return ["impacket-dacledit", "-action", "remove", "-ace-type", "allowed",
            "-rights", rights, "-principal", trustee, "-target", target,
            "-dc-ip", dc, *extra, identity]


# ---------------------------------------------------------------- owneredit argv
def owneredit_read_argv(cfg, target: str, dc: str) -> list[str]:
    identity, extra = _impacket_auth(cfg)
    return ["impacket-owneredit", "-action", "read", "-target", target, "-dc-ip", dc,
            *extra, identity]


def owneredit_write_argv(cfg, target: str, dc: str, new_owner: str) -> list[str]:
    identity, extra = _impacket_auth(cfg)
    return ["impacket-owneredit", "-action", "write", "-new-owner", new_owner,
            "-target", target, "-dc-ip", dc, *extra, identity]


# ---------------------------------------------------------------- confirm_ace
def _ace_blocks(text: str) -> list[str]:
    """Split a dacledit read into per-ACE blocks.

    impacket-dacledit 0.13.x emits each ACE as a multi-line block headed by
    ``ACE[N] info``, with the rights (``Access mask``) and the ``Trustee (SID)``
    on DISTINCT lines -- so grouping by the single line that mentions the
    trustee (the pre-0.13 assumption) would never see the rights. When the
    ``ACE[N]`` index markers are present we split on them; otherwise we fall
    back to splitting on ``ACCESS ALLOWED/DENIED`` headers (the shape the unit
    fixtures and other tools use, where trustee+rights may share one line).
    Lines before the first header are preamble and dropped.
    """
    lines = (text or "").splitlines()
    starts = _RE_ACE_INDEX if any(_RE_ACE_INDEX.search(ln) for ln in lines) else _RE_ACE_HEADER
    blocks: list[list[str]] = []
    cur: Optional[list[str]] = None
    for ln in lines:
        if starts.search(ln):
            if cur is not None:
                blocks.append(cur)
            cur = [ln]
        elif cur is not None:
            cur.append(ln)
    if cur is not None:
        blocks.append(cur)
    return ["\n".join(b) for b in blocks]


def confirm_ace(read_res: RunResult, read_text: str, trustee: str,
               right_res: tuple[re.Pattern, ...]) -> Optional[bool]:
    """Tri-state, fail-safe like every probe in this codebase:

    ``True``  -- the read POSITIVELY shows ``trustee`` holding >=1 of
    ``right_res`` (sufficient).
    ``False`` -- the read POSITIVELY shows ``trustee``'s own ACE block, but none
    of ``right_res`` match it (positively INSUFFICIENT -- the only state that
    should abort a mutation before it fires).
    ``None``  -- unreadable / ``trustee``'s ACE block not located (unknown --
    NEVER a false negative; callers proceed anyway with an
    ``advisory:*_unconfirmed`` note, mirroring ``RbcdProbe``/``ShadowCredsProbe``'s
    existing fail-open philosophy).

    Grouping is by ACE BLOCK (see :func:`_ace_blocks`), so the rights line and
    the trustee line of the same ACE are evaluated together even when impacket
    prints them separately. This 3-way branch (not a 2-way "block unless
    confirmed") is deliberate: it keeps T3 consistent with every existing
    probe's "unknown never skips, only a positive negative does" contract.
    """
    if _tool_errored(read_res) or not _RE_DACL_READ_OK.search(read_text or ""):
        return None
    tl = (trustee or "").strip().lower()
    if not tl:
        return None
    trustee_seen = False
    grant_blocks: list[str] = []
    for block in _ace_blocks(read_text):
        is_allow, principals = _ace_block_fields(block)
        if not _principal_matches(principals, tl):
            continue
        trustee_seen = True
        if is_allow:                       # only an ALLOW ace can grant a right
            grant_blocks.append(block)
    if not trustee_seen:
        return None                        # trustee's own ACE not located -> unknown
    if not grant_blocks:
        return False                       # present only via DENY (or non-allow) aces
    return any(r.search(b) for b in grant_blocks for r in right_res)


def _ace_block_fields(block: str) -> tuple[bool, list[str]]:
    """Extract an ACE block's (is_allow, [trustee principals]) from its FIELDS.

    is_allow comes from the ACE-TYPE token only (never a trustee name); each
    principal is the value of a ``Trustee`` field with the ``(SID)`` suffix and
    the fixtures' trailing ``Rights:`` stripped. Field-based so a ``(SID)`` label,
    an account named ``ACCESS_DENIED$``, or an apostrophe in a name cannot be
    mistaken for an ACE-type or split a principal.
    """
    m = _RE_ACE_TYPE_TOKEN.search(block)
    is_allow = bool(m) and m.group(1).upper() == "ALLOWED"
    principals: list[str] = []
    for tm in _RE_TRUSTEE_VALUE.finditer(block):
        val = _RE_TRUSTEE_TAIL.split(tm.group(1), 1)[0]      # drop fixture's Rights: tail
        val = _RE_SID_SUFFIX.sub("", val).strip()            # drop impacket's (S-...) suffix
        if val:
            principals.append(val)
    return is_allow, principals


def _principal_matches(principals: list[str], trustee_lower: str) -> bool:
    """True iff some principal equals the trustee exactly (case-insensitive), or
    its ``DOMAIN\\name`` component does. Exact match -- never a substring -- so
    "jon.snow" does not pick up "jon.snow.backup" (or "jon.snow'backup")."""
    for p in principals:
        pl = p.lower()
        if pl == trustee_lower or pl.rsplit("\\", 1)[-1] == trustee_lower:
            return True
    return False


__all__ = [
    "_RE_DACL_READ_OK", "_RE_OWNER_READ_OK", "_RE_OWNER_VALUE",
    "_RE_ACE_GENERIC_ALL", "_RE_ACE_GENERIC_WRITE", "_RE_ACE_WRITE_DACL",
    "_RE_ACE_WRITE_OWNER", "_RE_ACE_SELF_MEMBERSHIP", "_RE_FORCE_CHANGE_PW_RIGHT",
    "_RE_DACL_WRITE_OK", "_RE_DACL_REMOVE_OK", "_RE_OWNER_WRITE_OK",
    "dacledit_read_argv", "dacledit_write_argv", "dacledit_remove_argv",
    "owneredit_read_argv", "owneredit_write_argv", "confirm_ace",
    "dacl_read_bind_ok", "owner_read_bind_ok",
]
