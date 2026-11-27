"""Precondition-probe layer -- ADR-002 D1 ("detect before you fire").

Per technique, a **non-destructive** CHECK that reads AD / SMB / ADCS state and
predicts whether the technique can plausibly succeed, so the orchestrator only
fires what will work and can *explain every skip* (ADR-002 D1, research
catalog 24NOV2026 section 0.2). A probe returns a :class:`ProbeResult`:

* ``viable=True``  -- a positive determination the technique can plausibly work
  (it proceeds; the reason may still carry caveats).
* ``viable=False`` -- a positive determination it will NOT work (e.g. AS-REP with
  pre-auth required). **Only this skips the technique.**
* ``unknown=True`` -- the probe COULD NOT determine (tool error, data
  unavailable, or a genuinely-required fact that is not readable
  non-destructively, such as an RBCD/shadow-cred write-ACL that needs
  BloodHound). **Unknown NEVER skips** -- the technique is attempted anyway with
  the uncertainty flagged, so a real finding is never wrongly dropped.

Probes **fail safe**: a tool error or unparseable output yields ``unknown=True``,
never a false ``viable=False``. They are **non-destructive reads only**
(LDAP/SMB/certipy-find style queries) and run through the injected
``ctx.runner`` exactly like the executors, so they are unit-testable with a
scripted fake runner and never touch a live lab.

UNVERIFIED ASSUMPTIONS (pin against the real tooling during the lab run,
mirroring the executors' UNVERIFIED output markers -- these probes are a
FRAMEWORK build and have not been lab-pinned):

* **LDAP attribute reads** use NetExec::

      nxc ldap <dc> -u <user> (-p <pass> | -H <hash>) --query "<filter>" "<attrs>"

  and parse each attribute from a ``name: value`` / ``name = value`` line; a
  successful account read is anchored on the echoed ``sAMAccountName`` line (its
  absence -> the object was not read -> ``unknown``). Attributes read:
  ``msDS-SupportedEncryptionTypes`` (KERBEROAST), ``userAccountControl``
  (ASREP / CONSTRAINED-DELEG-PT), ``msDS-AllowedToDelegateTo``
  (CONSTRAINED-DELEG-PT), ``ms-DS-MachineAccountQuota`` + ``msDS-Behavior-Version``
  (RBCD, domain NC), ``ms-Mcs-AdmPwd`` / ``msLAPS-Password`` (LAPS).
* **SMB share-permissions read** uses ``nxc smb <host> <auth> --shares`` and reads
  the share row's READ/WRITE column -- it NEVER writes a test file.
* **ADCS reads** use ``certipy-ad find -dc-ip <dc> -stdout [-vulnerable]`` and
  parse the CA-present / ESC1 / no-vulnerable markers.

If the real wording differs, a probe gets no positive determination and returns
``unknown=True`` (attempt anyway) -- it never fabricates a ``viable=False`` that
would wrongly skip a finding.

Stdlib only; no LLM.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional

from . import netresolve
from .predicates import strip_ansi
from .executors.base import ExecutorContext, RunResult
# Safe despite living in the `executors` package: by the time THIS top-level
# import line runs, `from .executors.base import ...` above has already forced
# `executors/__init__.py` to run to completion (importing every T3 executor,
# including `write_dacl.py` -> `acl_common.py`), so `acl_common` is already a
# fully-initialized module in `sys.modules` -- no cycle, in either import order
# (acl_common.py itself never imports FROM probes.py; see its _tool_errored
# docstring for why that direction specifically is import-order-fragile).
from .executors.acl_common import (dacledit_read_argv, confirm_ace,
                                   _RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_DACL,
                                   _RE_ACE_WRITE_OWNER, _RE_ACE_GENERIC_WRITE,
                                   _RE_ACE_SELF_MEMBERSHIP, _RE_FORCE_CHANGE_PW_RIGHT)


# ---------------------------------------------------------------- bit constants
# userAccountControl flags (MS-ADTS 2.2.16).
UAC_DONT_REQ_PREAUTH = 0x400000             # AS-REP roastable
UAC_TRUSTED_FOR_DELEGATION = 0x80000        # UNCONSTRAINED delegation (not 0x1000000)
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000   # constrained-deleg protocol transition
UAC_NOT_DELEGATED = 0x100000                # "account is sensitive and cannot be delegated"
# msDS-SupportedEncryptionTypes bits (MS-KILE 2.2.7).
ENC_RC4 = 0x4
ENC_AES128 = 0x8
ENC_AES256 = 0x10
# msDS-Behavior-Version: 5 == domain functional level 2012 (RBCD minimum).
DFL_2012 = 5


# ---------------------------------------------------------------- probe result
@dataclass
class ProbeResult:
    """A non-destructive precondition CHECK's verdict for one finding.

    ``viable`` -- can this technique plausibly succeed on this finding?
    ``reason`` -- human-readable: why viable, or why it will be skipped.
    ``evidence`` -- the non-secret facts read (e.g. ``{"maq": 10, "enc": "rc4"}``).
    ``unknown`` -- True if the probe COULD NOT determine (tool error / data
    unavailable). ``unknown`` NEVER skips -- only ``viable=False`` skips.
    """
    viable: bool
    reason: str
    evidence: dict = field(default_factory=dict)
    unknown: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"viable": self.viable, "unknown": self.unknown,
                "reason": self.reason, "evidence": self.evidence}


# ---------------------------------------------------------------- probe ABC
class PreconditionProbe(ABC):
    """Base class: read non-destructive state, predict success for one technique."""
    technique: str = ""

    @abstractmethod
    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        """Read preconditions for ``finding`` and return a :class:`ProbeResult`."""


# ---------------------------------------------------------------- read helpers
# A successful NetExec LDAP object read echoes the sAMAccountName anchor; its
# absence means we did not actually read the object -> unknown (fail safe).
# A per-account LDAP read succeeded. Real `nxc ldap --query` prints a
# "[+] Response for object: CN=..." marker and then whitespace-separated attributes
# (NOT colon-delimited), so anchor on that marker OR the echoed sAMAccountName (any
# separator) -- the old colon-only anchor never matched real nxc output.
_RE_ANCHOR = re.compile(r"(Response for object\b|\bsAMAccountName\b)", re.I)


def _tool_errored(res: RunResult) -> bool:
    """A hard runner failure (OSError / timeout / no return code) -> unreadable."""
    return bool(res.error) or res.timed_out or res.returncode is None


def _text(res: RunResult) -> str:
    """ANSI-stripped stdout+stderr (strip_ansi is also applied at the live runner
    boundary; applying it here is harmless and keeps fake-driven parsing robust)."""
    return strip_ansi((res.stdout or "") + "\n" + (res.stderr or ""))


def _extract_attr(text: str, attr: str) -> Optional[str]:
    """The value on a ``<attr>: value`` / ``<attr> = value`` / ``<attr>   value`` line
    (first match), read ONLY from result rows.

    Tolerates a leading tool prefix (NetExec prints ``LDAP <ip> <port> <host>
    attr<sep>value``) and the real ``nxc ldap --query`` format, which separates the
    attribute from its value with WHITESPACE (``attr    value``), not a colon/equals --
    so the separator is a colon/equals (with optional spaces) OR one-or-more spaces.

    SECURITY: a line with an nxc status marker (``[+]``/``[-]``/``[*]``) -- e.g. the
    ``[+] domain\\user:PASSWORD`` auth banner -- is EXCLUDED, so a password/argv that
    happens to contain an attribute-name substring can never be captured as a value
    (the leading ``(?!.*\\[[-+*]\\])`` negative lookahead)."""
    pat = re.compile(
        rf"(?mi)^(?!.*\[[-+*]\]).*?{re.escape(attr)}(?:[ \t]*[:=][ \t]*|[ \t]+)(\S.*?)[ \t]*$")
    m = pat.search(text or "")
    return m.group(1).strip() if m else None


def _parse_int(token: Optional[str]) -> Optional[int]:
    """Parse a decimal (default) or ``0x``-prefixed integer from a token; None if
    unparseable. AD tools print these attributes in decimal, so decimal wins."""
    if not token:
        return None
    t = token.strip().split()[0]
    for base in (0, 10, 16):
        try:
            return int(t, base)
        except (ValueError, TypeError):
            continue
    return None


def _nxc_auth(cfg) -> list[str]:
    """NetExec auth flags from the operator config -- delegates to the canonical
    :func:`netresolve.nxc_auth_flags` (adds Kerberos discovery flags when the mode
    is ``--aesKey``, so probe KDC discovery works without a carrier ``/etc/hosts``)."""
    return netresolve.nxc_auth_flags(cfg)


def _ldap_query(ctx: ExecutorContext, ldap_filter: str, attributes: list[str]) -> RunResult:
    """Run a non-destructive ``nxc ldap --query`` read (UNVERIFIED invocation)."""
    cfg = ctx.config
    argv = ["nxc", "ldap", cfg.dc_ip, *_nxc_auth(cfg),
            "--query", ldap_filter, " ".join(attributes)]
    return ctx.runner.run(argv, timeout=cfg.tool_timeout_s)


def _account_read_ok(res: RunResult, text: str) -> bool:
    """A per-account LDAP read succeeded (not errored and the object was echoed)."""
    if _tool_errored(res) or not text.strip():
        return False
    return bool(_RE_ANCHOR.search(text))


def _certipy_find(ctx: ExecutorContext, *, vulnerable: bool = False) -> RunResult:
    """Run a non-destructive ``certipy-ad find`` ADCS read (UNVERIFIED invocation)."""
    cfg = ctx.config
    argv = ["certipy-ad", "find", "-dc-ip", cfg.dc_ip, "-stdout",
            "-u", f"{cfg.username or ''}@{cfg.domain}"]
    if cfg.nt_hash:
        argv += ["-hashes", cfg.nt_hash]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    if vulnerable:
        argv += ["-vulnerable"]
    return ctx.runner.run(argv, timeout=cfg.tool_timeout_s)


# ---- output markers (UNVERIFIED -- see module docstring) ----------------------
_RE_LAPS_ATTR = re.compile(r"(ms-?Mcs-?AdmPwd|msLAPS-Password)\s*[:=]\s*\S", re.I)
_RE_LAPS_ABSENT = re.compile(
    r"(attribute not found|not set|no laps|laps not (configured|present)|"
    r"0 results|no results|does not have)", re.I)
_RE_SHARES_TABLE = re.compile(r"(Permissions|\bREAD\b|\bWRITE\b)", re.I)
_RE_CERTIPY_RAN = re.compile(
    r"(Certificate Authorities|Certificate Templates|Certipy|Found \d+|Enrollment)", re.I)
_RE_CA_PRESENT = re.compile(r"(Certificate Authorities|CA Name|DNS Name|Web Enrollment)", re.I)
_RE_CA_NONE = re.compile(
    r"(Could not find any (certificate authorities|CAs)|"
    r"Found 0 certificate authorities|No certificate authorities|"
    r"0 enabled certificate authorities)", re.I)
_RE_ESC1 = re.compile(r"\bESC1\b", re.I)
_RE_NO_VULN = re.compile(
    r"(Found 0 vulnerable|no vulnerable (certificate )?templates|0 vulnerable)", re.I)
# ESC8: certipy find reports the CA's Web Enrollment endpoint enabled / an ESC8
# vulnerability marker.
_RE_ESC8 = re.compile(r"(\bESC8\b|Web Enrollment[^\n]*Enabled)", re.I)
# ESC11: the ICPR/RPC enrollment interface does NOT enforce request encryption.
_RE_ESC11 = re.compile(r"(\bESC11\b|Enforce Encryption[^\n]*Disabled)", re.I)
# Certifried SID-ext oracle: the szOID_NTDS_CA_SECURITY_EXT (Certificate object
# SID) security extension. PRESENT -> patched (post May-2022); ABSENT -> unpatched.
_RE_SID_EXT = re.compile(
    r"(Certificate object SID|szOID_NTDS_CA_SECURITY_EXT|1\.3\.6\.1\.4\.1\.311\.25\.2|"
    r"SID security extension)", re.I)
# SMB signing enforcement in an nxc smb banner: "signing:True" = required (relay
# to SMB blocked); "signing:False" = not required (relayable). UNVERIFIED wording.
_RE_SMB_SIGNING_OFF = re.compile(r"signing\s*[:=]\s*False", re.I)
_RE_SMB_SIGNING_ON = re.compile(r"signing\s*[:=]\s*True", re.I)
# LDAP relay surface: channel binding / signing NOT enforced on the DC. nxc ldap
# reports an LDAP-signing / channel-binding state; "None"/"not enforced" = relayable.
_RE_LDAP_RELAYABLE = re.compile(
    r"(channel\s*binding[^\n]*(no|none|not|disabled)|"
    r"ldap\s*signing[^\n]*(none|not|disabled|no)|signing\s*[:=]\s*None)", re.I)
# Coercer scan: a coercion method is reachable / the pipe is exposed on the victim.
_RE_COERCE_METHOD = re.compile(
    r"(\[\+\][^\n]*(MS-RPRN|MS-EFSR|MS-DFSNM|MS-FSRVP|EfsRpc|RpcRemoteFindFirstPrinterChangeNotification)|"
    r"\bVULNERABLE\b|pipe[^\n]*(accessible|reachable|exists))", re.I)


def _target_protected(impersonate: Optional[str]) -> Optional[bool]:
    """Best-effort: is the impersonation target protected from delegation?

    RID-500 Administrator is delegatable even inside Protected Users (research
    catalog section 3.1), so it returns ``False``. For any other target this is
    ``None`` (not determinable without a Protected-Users membership read) and is
    therefore NEVER treated as a skip -- only surfaced as a caveat.
    """
    if impersonate and impersonate.strip().lower() in ("administrator", "administrateur"):
        return False
    return None


def _share_writable(text: str, share: str) -> Optional[bool]:
    """True/False iff the named share's row shows WRITE / READ-only; None if absent."""
    if not share:
        return None
    for line in text.splitlines():
        if re.search(rf"(?<![\w$]){re.escape(share)}(?![\w$])", line, re.I):
            perms = line.upper()
            if "WRITE" in perms:
                return True
            if "READ" in perms:
                return False
    return None


# ================================================================= the 8 probes
class KerberoastProbe(PreconditionProbe):
    """KERBEROAST: the principal must be a user (not computer/MSA -- those carry a
    120-char machine password and are uncrackable), and its
    ``msDS-SupportedEncryptionTypes`` predicts crackability (RC4/unset = fast mode
    13100; AES-only = slow, weak-password-only). The technique is attemptable for
    any user, so only a computer/MSA principal is a positive ``viable=False``."""
    technique = "KERBEROAST"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        principal = (finding.entity or {}).get("principal") or ""
        is_user = bool(principal) and not principal.rstrip().endswith("$")
        if principal and not is_user:
            return ProbeResult(
                viable=False,
                reason=(f"{principal} is a computer/MSA account (trailing '$'): "
                        "120-char machine password, not crackable -> skip"),
                evidence={"is_user": False, "enc_types": None})
        res = _ldap_query(ctx, f"(sAMAccountName={principal})",
                          ["sAMAccountName", "msDS-SupportedEncryptionTypes"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read msDS-SupportedEncryptionTypes for "
                        f"{principal or '(principal)'}; attempting anyway "
                        "(crackability unknown)"),
                evidence={"is_user": is_user, "enc_types": None})
        enc = _parse_int(_extract_attr(text, "msDS-SupportedEncryptionTypes"))
        if enc is None or enc == 0:
            return ProbeResult(
                viable=True,
                reason=("msDS-SupportedEncryptionTypes unset/0 -> RC4 default: fast "
                        "crack (hashcat -m 13100)"),
                evidence={"is_user": is_user, "enc_types": enc, "rc4": True})
        if enc & ENC_RC4:
            return ProbeResult(
                viable=True,
                reason=(f"RC4 enabled (enc=0x{enc:x}): fast crack (hashcat -m 13100)"),
                evidence={"is_user": is_user, "enc_types": enc, "rc4": True})
        return ProbeResult(
            viable=True,
            reason=(f"AES-only (enc=0x{enc:x}, no RC4 bit): hash obtainable but slow, "
                    "weak-password-only crack (hashcat -m 19600/19700)"),
            evidence={"is_user": is_user, "enc_types": enc, "rc4": False, "aes_only": True})


class ASREPProbe(PreconditionProbe):
    """ASREP: viable iff the principal's ``userAccountControl`` has
    DONT_REQ_PREAUTH (0x400000). Pre-auth-required -> positive ``viable=False``."""
    technique = "ASREP"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        principal = (finding.entity or {}).get("principal") or ""
        res = _ldap_query(ctx, f"(sAMAccountName={principal})",
                          ["sAMAccountName", "userAccountControl"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=(f"could not read userAccountControl for {principal or '(principal)'}; "
                        "attempting AS-REP roast anyway (pre-auth state unknown)"),
                evidence={"uac_dont_req_preauth": None})
        uac = _parse_int(_extract_attr(text, "userAccountControl"))
        if uac is None:
            return ProbeResult(
                viable=True, unknown=True,
                reason="read ok but userAccountControl unparsed; attempting anyway",
                evidence={"uac_dont_req_preauth": None})
        if uac & UAC_DONT_REQ_PREAUTH:
            return ProbeResult(
                viable=True,
                reason=f"DONT_REQ_PREAUTH set (uac=0x{uac:x}): AS-REP roastable",
                evidence={"uac_dont_req_preauth": True, "uac": uac})
        return ProbeResult(
            viable=False,
            reason=(f"DONT_REQ_PREAUTH not set (uac=0x{uac:x}): pre-auth required, "
                    "not AS-REP roastable -> skip"),
            evidence={"uac_dont_req_preauth": False, "uac": uac})


class LapsProbe(PreconditionProbe):
    """LAPS: re-confirm a readable ms-Mcs-AdmPwd / msLAPS-Password on the host; an
    explicit "no LAPS attribute" is a positive ``viable=False``. aranum already
    flagged the finding, so an inconclusive / failed re-confirm passes that marker
    through as ``unknown`` (attempt anyway), never a false skip."""
    technique = "LAPS"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        host = finding.host or (finding.entity or {}).get("host") or ""
        short = host.split(".", 1)[0]
        res = _ldap_query(ctx, f"(sAMAccountName={short}$)",
                          ["sAMAccountName", "ms-Mcs-AdmPwd", "msLAPS-Password",
                           "msLAPS-EncryptedPassword"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not re-confirm LAPS readability on "
                        f"{host or '(host)'}; aranum LAPS marker passed through "
                        "-> attempting"),
                evidence={"laps_readable": None})
        if _RE_LAPS_ATTR.search(text):
            return ProbeResult(
                viable=True,
                reason=f"LAPS attribute present and readable on {host} (re-confirmed)",
                evidence={"laps_readable": True})
        if _RE_LAPS_ABSENT.search(text):
            return ProbeResult(
                viable=False,
                reason=("no readable LAPS attribute (ms-Mcs-AdmPwd/msLAPS-Password) on "
                        f"{host}: nothing to recover -> skip"),
                evidence={"laps_readable": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("LAPS re-confirm inconclusive on "
                    f"{host or '(host)'}; aranum marker passed through -> attempting"),
            evidence={"laps_readable": None})


class ConstrainedDelegProbe(PreconditionProbe):
    """CONSTRAINED-DELEG-PT: the delegation principal (the operator account, per
    the executor default) must have a non-empty ``msDS-AllowedToDelegateTo``;
    TRUSTED_TO_AUTH_FOR_DELEGATION set -> full S4U, absent -> viable-with-caveat
    (needs an RBCD/coercion pivot). An empty msDS-AllowedToDelegateTo on an
    otherwise-read object is a positive ``viable=False``."""
    technique = "CONSTRAINED-DELEG-PT"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        principal = ctx.config.username or ""
        impersonate = "Administrator"  # the executor's recommended default
        res = _ldap_query(ctx, f"(sAMAccountName={principal})",
                          ["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read msDS-AllowedToDelegateTo/userAccountControl "
                        f"for {principal or '(principal)'}; attempting anyway"),
                evidence={"allowed_to_delegate_to": None, "protocol_transition": None,
                          "target_protected": None})
        a2d = _extract_attr(text, "msDS-AllowedToDelegateTo")
        uac = _parse_int(_extract_attr(text, "userAccountControl"))
        has_a2d = bool(a2d) and a2d.strip().lower() not in (
            "", "(not set)", "<not set>", "none", "-", "n/a")
        tp = _target_protected(impersonate)
        if not has_a2d:
            return ProbeResult(
                viable=False,
                reason=(f"msDS-AllowedToDelegateTo empty on {principal}: no constrained "
                        "delegation configured -> skip"),
                evidence={"allowed_to_delegate_to": None, "protocol_transition": None,
                          "target_protected": tp})
        pt = bool(uac is not None and (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION))
        if pt:
            reason = (f"msDS-AllowedToDelegateTo set ({a2d}) and protocol transition "
                      f"(TRUSTED_TO_AUTH_FOR_DELEGATION, uac=0x{uac:x}): full S4U viable")
        else:
            reason = (f"msDS-AllowedToDelegateTo set ({a2d}) but no protocol transition "
                      "(TRUSTED_TO_AUTH_FOR_DELEGATION absent): viable-with-caveat, "
                      "needs an RBCD/coercion pivot for the initial ticket")
        if tp is None:
            reason += "; verify the impersonation target is not Protected Users/sensitive"
        return ProbeResult(
            viable=True, reason=reason,
            evidence={"allowed_to_delegate_to": a2d, "protocol_transition": pt,
                      "target_protected": tp})


class RbcdProbe(PreconditionProbe):
    """RBCD: the source must be creatable -- read ``ms-DS-MachineAccountQuota``
    (0 -> positive ``viable=False`` for this executor's addcomputer path) and the
    domain functional level (< 2012 -> ``viable=False``). The required write-ACL
    over the target (GenericWrite/WriteDacl/WriteOwner/WriteAccountRestrictions)
    and the "Add workstations" right are NOT readable without BloodHound, so the
    viable path is flagged ``unknown`` rather than ever falsely skipped."""
    technique = "RBCD"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        res = _ldap_query(ctx, "(objectClass=domain)",
                          ["ms-DS-MachineAccountQuota", "msDS-Behavior-Version"])
        text = _text(res)
        maq = _parse_int(_extract_attr(text, "ms-DS-MachineAccountQuota"))
        dfl = _parse_int(_extract_attr(text, "msDS-Behavior-Version"))
        if _tool_errored(res) or (maq is None and dfl is None):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read ms-DS-MachineAccountQuota/msDS-Behavior-Version; "
                        "the RBCD write-ACL is also not readable here -> attempting anyway"),
                evidence={"maq": maq, "dfl": dfl})
        if maq is not None and maq <= 0:
            return ProbeResult(
                viable=False,
                reason=("ms-DS-MachineAccountQuota=0: cannot add a computer account for "
                        "the RBCD source (this executor's addcomputer path) -> skip "
                        "(owned-computer / SPN-less-U2U workarounds are not auto-validated)"),
                evidence={"maq": maq, "dfl": dfl})
        if dfl is not None and dfl < DFL_2012:
            return ProbeResult(
                viable=False,
                reason=(f"domain functional level < 2012 (msDS-Behavior-Version={dfl}): "
                        "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) unsupported -> skip"),
                evidence={"maq": maq, "dfl": dfl})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"ms-DS-MachineAccountQuota={maq} (>0) and DFL>=2012: the source is "
                    "creatable, BUT the write-ACL over the target "
                    "(GenericWrite/WriteDacl/WriteOwner/WriteAccountRestrictions) and the "
                    "'Add workstations to domain' right are NOT readable without "
                    "BloodHound -> ASSUMED; attempting with that uncertainty flagged"),
            evidence={"maq": maq, "dfl": dfl})


class OpenSharesProbe(PreconditionProbe):
    """OPENSHARES-WRITE: confirm the share is writable via a non-destructive
    ``nxc smb --shares`` read (NO test file is written) -- a READ-only share is a
    positive ``viable=False``. A failed read or an unlisted share passes the
    aranum RW-share marker through as ``unknown`` (attempt anyway)."""
    technique = "OPENSHARES-WRITE"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        host = finding.host or ""
        share = (finding.entity or {}).get("share") or ""
        argv = ["nxc", "smb", host, *_nxc_auth(cfg), "--shares"]
        res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s)
        text = _text(res)
        if _tool_errored(res) or not _RE_SHARES_TABLE.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=(f"could not read share permissions on {host or '(host)'}; "
                        "aranum RW-share marker passed through -> attempting"),
                evidence={"share_rw": None})
        writable = _share_writable(text, share)
        if writable is True:
            return ProbeResult(
                viable=True,
                reason=(f"share '{share}' shows WRITE in a non-destructive "
                        "share-permissions read (no test file written)"),
                evidence={"share_rw": True})
        if writable is False:
            return ProbeResult(
                viable=False,
                reason=(f"share '{share}' is READ-only (no WRITE permission): a "
                        "write-readback cannot succeed -> skip"),
                evidence={"share_rw": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"share '{share or '(share)'}' not found in the share listing; "
                    "aranum marker passed through -> attempting"),
            evidence={"share_rw": None})


class ShadowCredsProbe(PreconditionProbe):
    """SHADOW-CREDS: PKINIT must be available (an ADCS CA / KDC key-trust surface)
    -- certipy find reporting no CA is a positive ``viable=False``. The required
    write-ACL over the target's ``msDS-KeyCredentialLink`` is NOT readable without
    BloodHound, so the viable path is flagged ``unknown`` rather than skipped."""
    technique = "SHADOW-CREDS"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        res = _certipy_find(ctx)
        text = _text(res)
        if _tool_errored(res) or not _RE_CERTIPY_RAN.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read ADCS/PKINIT state via certipy find; the write-ACL "
                        "over msDS-KeyCredentialLink is also not readable without "
                        "BloodHound -> attempting anyway"),
                evidence={"pkinit_available": None})
        if _RE_CA_NONE.search(text):
            return ProbeResult(
                viable=False,
                reason=("no Certificate Authority / PKINIT key-trust surface found: "
                        "shadow credentials -> PKINIT cannot authenticate -> skip"),
                evidence={"pkinit_available": False})
        if _RE_CA_PRESENT.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("ADCS CA present -> PKINIT (key-trust) available, BUT the write-ACL "
                        "over the target's msDS-KeyCredentialLink is NOT readable without "
                        "BloodHound -> ASSUMED; attempting with that flagged"),
                evidence={"pkinit_available": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("ADCS/PKINIT state inconclusive from certipy find; attempting with the "
                    "write-ACL + PKINIT uncertainty flagged"),
            evidence={"pkinit_available": None})


class ADCSESC1Probe(PreconditionProbe):
    """ADCS-ESC1: re-confirm an enrollable ESC1 template via a certipy-find style
    read; certipy reporting no vulnerable template is a positive ``viable=False``.
    A failed / inconclusive read passes the aranum ESC1 entity through as
    ``unknown`` (attempt anyway)."""
    technique = "ADCS-ESC1"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        template = (finding.entity or {}).get("template") or ""
        res = _certipy_find(ctx, vulnerable=True)
        text = _text(res)
        if _tool_errored(res) or not _RE_CERTIPY_RAN.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not re-confirm the ESC1 template via certipy find; the "
                        f"aranum ESC1 entity ({template or 'template'}) is passed through "
                        "-> attempting"),
                evidence={"esc1_template": template or None})
        esc1_here = bool(_RE_ESC1.search(text))
        tpl_here = (not template) or bool(re.search(re.escape(template), text, re.I))
        if esc1_here and tpl_here:
            return ProbeResult(
                viable=True,
                reason=("certipy find reports an enrollable ESC1 template"
                        + (f" ({template})" if template else "") + " -> viable"),
                evidence={"esc1_template": template or None, "esc1_confirmed": True})
        if _RE_NO_VULN.search(text):
            return ProbeResult(
                viable=False,
                reason=("certipy find reports no vulnerable / ESC1-enrollable template: "
                        "nothing to enroll -> skip"),
                evidence={"esc1_template": template or None, "esc1_confirmed": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("ESC1 re-confirm inconclusive; aranum ESC1 entity passed through "
                    "-> attempting"),
            evidence={"esc1_template": template or None})


class Esc8Probe(PreconditionProbe):
    """ESC8 (N1): re-confirm a relayable Web-Enrollment surface via certipy find --
    a Web-Enrollment-enabled / ESC8 marker is ``viable``; certipy reporting no CA
    is a positive ``viable=False`` (nothing to relay to); an unreadable find is
    ``unknown`` (attempt anyway). Fail-safe (unknown never skips)."""
    technique = "ESC8"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        res = _certipy_find(ctx)
        text = _text(res)
        if _tool_errored(res) or not _RE_CERTIPY_RAN.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read ADCS state via certipy find; ESC8 relay "
                        "surface unknown -> attempting anyway"),
                evidence={"web_enrollment": None})
        if _RE_CA_NONE.search(text):
            return ProbeResult(
                viable=False,
                reason=("no Certificate Authority found: nothing to relay the coerced "
                        "auth to -> skip"),
                evidence={"web_enrollment": False})
        if _RE_ESC8.search(text):
            return ProbeResult(
                viable=True,
                reason="certipy find reports a Web-Enrollment / ESC8 relay surface -> viable",
                evidence={"web_enrollment": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("ADCS CA present but Web-Enrollment/ESC8 exposure not confirmed from "
                    "certipy find -> attempting with that uncertainty flagged"),
            evidence={"web_enrollment": None})


class Esc11Probe(PreconditionProbe):
    """ESC11 (N1): like ESC8 but the RPC/ICPR enrollment surface -- a
    "Enforce Encryption for Requests: Disabled" / ESC11 marker is ``viable``;
    no CA is ``viable=False``; unreadable is ``unknown``. Fail-safe."""
    technique = "ESC11"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        res = _certipy_find(ctx)
        text = _text(res)
        if _tool_errored(res) or not _RE_CERTIPY_RAN.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read ADCS state via certipy find; ESC11 relay "
                        "surface unknown -> attempting anyway"),
                evidence={"rpc_encryption_enforced": None})
        if _RE_CA_NONE.search(text):
            return ProbeResult(
                viable=False,
                reason=("no Certificate Authority found: nothing to relay the coerced "
                        "auth to -> skip"),
                evidence={"rpc_encryption_enforced": None})
        if _RE_ESC11.search(text):
            return ProbeResult(
                viable=True,
                reason=("certipy find reports the RPC/ICPR enrollment interface does not "
                        "enforce request encryption (ESC11) -> viable"),
                evidence={"rpc_encryption_enforced": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("ADCS CA present but ESC11 (RPC encryption not enforced) not confirmed "
                    "from certipy find -> attempting with that uncertainty flagged"),
            evidence={"rpc_encryption_enforced": None})


class CertifriedProbe(PreconditionProbe):
    """CERTIFRIED (N1): the SID-extension oracle -- a CA whose issued certs LACK the
    szOID_NTDS_CA_SECURITY_EXT (Certificate object SID) extension is UNPATCHED
    (pre-May-2022) -> ``viable``; the extension present -> patched -> positive
    ``viable=False``. Plus ``ms-DS-MachineAccountQuota`` > 0 (a computer must be
    creatable); MAQ<=0 -> ``viable=False``. No CA / an unreadable find ->
    ``unknown`` (attempt anyway). Fail-safe (unknown never skips)."""
    technique = "CERTIFRIED"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        res = _certipy_find(ctx)
        text = _text(res)
        if _tool_errored(res) or not _RE_CERTIPY_RAN.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("could not read the CA SID-extension state via certipy find; "
                        "CA patch level unknown -> attempting anyway"),
                evidence={"sid_ext_present": None, "maq": None})
        if _RE_CA_NONE.search(text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=("no CA observed in certipy find (SID-ext oracle inconclusive) -> "
                        "attempting anyway"),
                evidence={"sid_ext_present": None, "maq": None})
        maq_res = _ldap_query(ctx, "(objectClass=domain)", ["ms-DS-MachineAccountQuota"])
        maq = _parse_int(_extract_attr(_text(maq_res), "ms-DS-MachineAccountQuota"))
        if maq is not None and maq <= 0:
            return ProbeResult(
                viable=False,
                reason=("ms-DS-MachineAccountQuota=0: cannot create the computer "
                        "Certifried needs -> skip"),
                evidence={"sid_ext_present": None, "maq": maq})
        if _RE_SID_EXT.search(text):
            return ProbeResult(
                viable=False,
                reason=("CA issues certs WITH the SID security extension "
                        "(szOID_NTDS_CA_SECURITY_EXT): patched (post May-2022), "
                        "Certifried mitigated -> skip"),
                evidence={"sid_ext_present": True, "maq": maq})
        return ProbeResult(
            viable=True,
            reason=("no SID security extension observed on a baseline cert (unpatched / "
                    "pre-May-2022) and MAQ>0 -> Certifried viable"),
            evidence={"sid_ext_present": False, "maq": maq})


class DCSyncProbe(PreconditionProbe):
    """DCSYNC (N1): standalone, the replication rights (DS-Replication-Get-Changes
    [-All]) are NOT readable non-destructively (they need a BloodHound ACL read or
    a DA-equivalent context the chaining engine supplies), so this probe always
    returns ``unknown`` (attempt anyway) -- NEVER a false ``viable=False`` that
    would wrongly drop the universal DA terminal. Fail-safe by construction."""
    technique = "DCSYNC"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        return ProbeResult(
            viable=True, unknown=True,
            reason=("replication rights (DS-Replication-Get-Changes[-All]) are not "
                    "readable non-destructively standalone; the chaining engine supplies "
                    "the DA-equivalent context -> attempting anyway"),
            evidence={"replication_rights": None})


# ================================================= listener-trio probes (PP-1..3)
class CoercionProbe(PreconditionProbe):
    """COERCION: enumerate the victim DC's coercion surface with ``coercer scan``.
    Scan mode is NON-MUTATING but ACTIVE -- it sends the coercion RPC calls to
    detect which methods answer (it does not complete a coercion to an external
    listener). A positively-reachable method -> ``viable``; EVERYTHING else ->
    ``unknown`` (attempt anyway), NEVER ``viable=False``: a zero-method scan is
    commonly an auth/collection failure, and a DC is near-universally coercible
    (MS-RPRN/printerbug is on by default), so "no method seen" is not a reliable
    positive "won't work" (review MEDIUM-2). UNVERIFIED markers, pin in-lab."""
    technique = "COERCION"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        victim = finding.host or (finding.entity or {}).get("host") or cfg.dc_ip
        argv = ["coercer", "scan", "-u", cfg.username or "", "-d", cfg.domain, "-t", victim]
        if cfg.nt_hash:
            argv += ["--hashes", cfg.nt_hash]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s)
        text = _text(res)
        if not _tool_errored(res) and _RE_COERCE_METHOD.search(text):
            return ProbeResult(
                viable=True,
                reason=f"coercer scan reports a reachable coercion method on {victim}",
                evidence={"coercion_methods": True})
        # No positively-reachable method (unreadable, unauth, or an ambiguous
        # zero-method scan) -> UNKNOWN, never a skip (fail-safe).
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"coercion surface on {victim or '(dc)'} not positively confirmed via "
                    "coercer scan (a zero-method/unauthenticated scan is not a reliable "
                    "negative; DCs are near-universally coercible) -> attempting anyway"),
            evidence={"coercion_methods": None})


class NTLMRelayProbe(PreconditionProbe):
    """NTLM-RELAY: a relay needs a target that does NOT enforce signing. Read the
    finding's relay target non-destructively: ``nxc smb`` banner ``signing:False``
    confirms the SMB (smb_sam) relay is viable; otherwise re-read ``nxc ldap`` for
    an un-enforced channel-binding/LDAP-signing surface (the ldap_rbcd path).

    Review HIGH-1: this probe NEVER returns ``viable=False`` on signing alone.
    SMB-signing-True does NOT rule the technique out -- the executor also relays
    over LDAP (ntlm_relay ldap_rbcd), and DCs (which REQUIRE SMB signing) are the
    prime LDAP/relay targets (GOAD truth: DCs via LDAP). So a positive signal
    (SMB off, or LDAP channel-binding/signing not enforced) -> ``viable``; anything
    else (signing enforced / unread) -> ``unknown`` (attempt anyway), so a real
    relay path is never wrongly skipped."""
    technique = "NTLM-RELAY"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        target = ((finding.entity or {}).get("relay_target") or finding.host
                  or (finding.entity or {}).get("host") or "")
        smb = ctx.runner.run(["nxc", "smb", target, *_nxc_auth(cfg)],
                             timeout=cfg.tool_timeout_s) if target else None
        smb_text = _text(smb) if smb else ""
        smb_signing: Optional[bool] = None
        if smb and not _tool_errored(smb):
            if _RE_SMB_SIGNING_OFF.search(smb_text):
                return ProbeResult(
                    viable=True,
                    reason=(f"SMB signing not required on {target} (signing:False): "
                            "relayable (smb_sam -> SAM dump)"),
                    evidence={"smb_signing": False})
            if _RE_SMB_SIGNING_ON.search(smb_text):
                smb_signing = True
        # SMB signing enforced or unread -> the SMB path is blocked, but LDAP
        # (ldap_rbcd) or an HTTP web-enroll relay may still work. Check LDAP; a
        # relayable LDAP surface is viable, otherwise UNKNOWN (never a skip).
        ldap = ctx.runner.run(["nxc", "ldap", target or cfg.dc_ip, *_nxc_auth(cfg)],
                              timeout=cfg.tool_timeout_s)
        if not _tool_errored(ldap) and _RE_LDAP_RELAYABLE.search(_text(ldap)):
            return ProbeResult(
                viable=True,
                reason=(f"LDAP channel binding/signing not enforced on {target or cfg.dc_ip}: "
                        "relayable (ldap_rbcd -> RBCD write)"),
                evidence={"smb_signing": smb_signing, "ldap_relayable": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"no relay surface positively confirmed on {target or '(target)'} "
                    "(SMB signing enforced/unread; LDAP relay surface unread/enforced); a DC "
                    "LDAP or web-enroll relay may still work -> attempting anyway"),
            evidence={"smb_signing": smb_signing, "ldap_relayable": None})


class UnconstrainedDelegProbe(PreconditionProbe):
    """UNCONSTRAINED-DELEG: the finding host must be TRUSTED FOR (unconstrained)
    DELEGATION -- ``userAccountControl & 0x80000`` (NOT 0x1000000, which is
    protocol-transition/constrained). Bit set -> ``viable`` (the onward need, a
    CONTROLLED unconstrained host to capture the coerced TGT, is not readable
    non-destructively, so it is flagged ``unknown`` like RBCD's write-ACL). A
    read-ok host WITHOUT the bit -> positive ``viable=False``; an unread/unparsed
    UAC -> ``unknown`` (attempt anyway)."""
    technique = "UNCONSTRAINED-DELEG"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        host = finding.host or (finding.entity or {}).get("host") or ""
        short = host.split(".", 1)[0]
        res = _ldap_query(ctx, f"(sAMAccountName={short}$)",
                          ["sAMAccountName", "userAccountControl"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(
                viable=True, unknown=True,
                reason=(f"could not read userAccountControl for {host or '(host)'}; "
                        "attempting anyway (unconstrained-trust state unknown)"),
                evidence={"trusted_for_delegation": None})
        uac = _parse_int(_extract_attr(text, "userAccountControl"))
        if uac is None:
            return ProbeResult(
                viable=True, unknown=True,
                reason="read ok but userAccountControl unparsed; attempting anyway",
                evidence={"trusted_for_delegation": None})
        if uac & UAC_TRUSTED_FOR_DELEGATION:
            return ProbeResult(
                viable=True, unknown=True,
                reason=(f"TRUSTED_FOR_DELEGATION set on {host} (uac=0x{uac:x}): its coerced "
                        "TGT is capturable, BUT a CONTROLLED unconstrained host to capture it "
                        "is not readable here -> ASSUMED; attempting with that flagged"),
                evidence={"trusted_for_delegation": True, "uac": uac})
        return ProbeResult(
            viable=False,
            reason=(f"TRUSTED_FOR_DELEGATION not set on {host} (uac=0x{uac:x}): not trusted "
                    "for unconstrained delegation, no onward TGT to capture -> skip"),
            evidence={"trusted_for_delegation": False, "uac": uac})


# ================================================= T3 (25NOV2026) ACL-edge probes
class WriteDaclProbe(PreconditionProbe):
    """WRITE-DACL: re-confirm the operator already holds WriteDacl/FullControl/
    GenericAll over the target via the SAME non-destructive ``confirm_ace`` read
    the executor's own step 1 uses -- a positively-insufficient ACE is a positive
    ``viable=False``; an unreadable/unlocated read is ``unknown`` (attempt
    anyway), matching every other probe's fail-safe tri-state."""
    technique = "WRITE-DACL"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        target = (finding.entity or {}).get("target") or finding.host or ""
        trustee = cfg.username or ""
        res = ctx.runner.run(dacledit_read_argv(cfg, target, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=trustee,
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_DACL))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{trustee or '(operator)'} does not hold WriteDacl/FullControl/"
                        f"GenericAll over {target or '(target)'} (confirmed via dacledit "
                        "read) -> skip"),
                evidence={"ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=(f"{trustee} confirmed holding WriteDacl/FullControl/GenericAll "
                        f"over {target}"),
                evidence={"ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the WriteDacl/FullControl/GenericAll precondition "
                    f"on {target or '(target)'} via dacledit read; attempting anyway"),
            evidence={"ace_confirmed": None})


class WriteOwnerProbe(PreconditionProbe):
    """WRITE-OWNER: re-confirm the operator already holds WriteOwner/FullControl/
    GenericAll over the target via the same ``confirm_ace`` read; a positively-
    insufficient ACE is ``viable=False``, an unreadable/unlocated read is
    ``unknown`` (attempt anyway)."""
    technique = "WRITE-OWNER"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        target = (finding.entity or {}).get("target") or finding.host or ""
        trustee = cfg.username or ""
        res = ctx.runner.run(dacledit_read_argv(cfg, target, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=trustee,
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_OWNER))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{trustee or '(operator)'} does not hold WriteOwner/FullControl/"
                        f"GenericAll over {target or '(target)'} (confirmed via dacledit "
                        "read) -> skip"),
                evidence={"ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=(f"{trustee} confirmed holding WriteOwner/FullControl/GenericAll "
                        f"over {target}"),
                evidence={"ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the WriteOwner/FullControl/GenericAll precondition "
                    f"on {target or '(target)'} via dacledit read; attempting anyway"),
            evidence={"ace_confirmed": None})


class AddMemberProbe(PreconditionProbe):
    """ADD-MEMBER/ADD-SELF: re-confirm Self-Membership/GenericWrite/GenericAll
    over the GROUP via ``confirm_ace``; PLUS a cheap fail-safe pre-check: if
    ``member`` is already in the group's membership, ``viable=False`` (nothing
    to add -- avoids offering a vacuous no-op mutation). Unreadable -> unknown."""
    technique = "ADD-MEMBER"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        entity = finding.entity or {}
        group = entity.get("group") or ""
        member = entity.get("member") or cfg.username or ""
        res = ctx.runner.run(dacledit_read_argv(cfg, group, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=cfg.username or "",
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE,
                                          _RE_ACE_SELF_MEMBERSHIP))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{cfg.username or '(operator)'} does not hold Self-Membership/"
                        f"GenericWrite/GenericAll over {group or '(group)'} (confirmed "
                        "via dacledit read) -> skip"),
                evidence={"ace_confirmed": False, "already_member": None})
        member_short = member.split("@", 1)[0].split("\\")[-1]
        mem_res = _ldap_query(ctx, f"(sAMAccountName={member_short})",
                              ["sAMAccountName", "memberOf"])
        mem_text = _text(mem_res)
        if _account_read_ok(mem_res, mem_text) and group.lower() in mem_text.lower():
            return ProbeResult(
                viable=False,
                reason=(f"{member} is already a member of {group or '(group)'} -> "
                        "nothing to add, skip"),
                evidence={"ace_confirmed": confirmed, "already_member": True})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=(f"{cfg.username} confirmed holding Self-Membership/GenericWrite/"
                        f"GenericAll over {group}"),
                evidence={"ace_confirmed": True, "already_member": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the Self-Membership/GenericWrite/GenericAll "
                    f"precondition on {group or '(group)'} via dacledit read; "
                    "attempting anyway"),
            evidence={"ace_confirmed": None, "already_member": False})


class TargetedKerberoastProbe(PreconditionProbe):
    """TARGETED-KERBEROAST: mirrors ``KerberoastProbe`` -- the victim must be a
    user (not computer/MSA: 120-char machine password, uncrackable) -- PLUS the
    GenericAll/GenericWrite ACE precondition over the victim via the same
    ``confirm_ace`` read the executor's own step 1 uses."""
    technique = "TARGETED-KERBEROAST"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        victim = (finding.entity or {}).get("principal") or ""
        is_user = bool(victim) and not victim.rstrip().endswith("$")
        if victim and not is_user:
            return ProbeResult(
                viable=False,
                reason=(f"{victim} is a computer/MSA account (trailing '$'): "
                        "120-char machine password, not crackable -> skip"),
                evidence={"is_user": False, "ace_confirmed": None})
        res = ctx.runner.run(dacledit_read_argv(cfg, victim, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=cfg.username or "",
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{cfg.username or '(operator)'} does not hold GenericAll/"
                        f"GenericWrite over {victim or '(victim)'} (confirmed via "
                        "dacledit read) -> skip"),
                evidence={"is_user": is_user, "ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=(f"{cfg.username} confirmed holding GenericAll/GenericWrite "
                        f"over {victim}"),
                evidence={"is_user": is_user, "ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the GenericAll/GenericWrite precondition on "
                    f"{victim or '(victim)'} via dacledit read; attempting anyway"),
            evidence={"is_user": is_user, "ace_confirmed": None})


class ForceChangePasswordProbe(PreconditionProbe):
    """FORCE-CHANGE-PASSWORD: re-confirm the User-Force-Change-Password extended
    right (or GenericAll) over the victim via the same ``confirm_ace`` read the
    executor's own step 1 uses; PLUS the same computer/MSA exclusion as
    ``TargetedKerberoastProbe`` (resetting a machine account's password breaks
    its secure channel for no useful proof -- not the technique's intent)."""
    technique = "FORCE-CHANGE-PASSWORD"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        victim = (finding.entity or {}).get("principal") or ""
        is_user = bool(victim) and not victim.rstrip().endswith("$")
        if victim and not is_user:
            return ProbeResult(
                viable=False,
                reason=(f"{victim} is a computer/MSA account (trailing '$'): "
                        "resetting its password breaks its secure channel, not "
                        "a useful authn proof -> skip"),
                evidence={"is_user": False, "ace_confirmed": None})
        res = ctx.runner.run(dacledit_read_argv(cfg, victim, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=cfg.username or "",
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_FORCE_CHANGE_PW_RIGHT))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{cfg.username or '(operator)'} does not hold "
                        f"User-Force-Change-Password/GenericAll over "
                        f"{victim or '(victim)'} (confirmed via dacledit read) -> skip"),
                evidence={"is_user": is_user, "ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=(f"{cfg.username} confirmed holding User-Force-Change-Password/"
                        f"GenericAll over {victim}"),
                evidence={"is_user": is_user, "ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the User-Force-Change-Password/GenericAll "
                    f"precondition on {victim or '(victim)'} via dacledit read; "
                    "attempting anyway"),
            evidence={"is_user": is_user, "ace_confirmed": None})


class GenericAllProbe(PreconditionProbe):
    """GENERIC-ALL: re-confirm the GenericAll/GenericWrite ACE over ``target``
    via the same ``confirm_ace`` read every pivot's own step 0 uses. A
    positively-insufficient ACE is ``viable=False``; an unreadable/unlocated
    read is ``unknown`` (attempt anyway) -- the pivot choice itself is not this
    probe's concern (every pivot shares the identical precondition)."""
    technique = "GENERIC-ALL"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        target = (finding.entity or {}).get("target") or finding.host or ""
        trustee = cfg.username or ""
        res = ctx.runner.run(dacledit_read_argv(cfg, target, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=trustee,
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{trustee or '(operator)'} does not hold GenericAll/"
                        f"GenericWrite over {target or '(target)'} (confirmed via "
                        "dacledit read) -> skip"),
                evidence={"ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=f"{trustee} confirmed holding GenericAll/GenericWrite over {target}",
                evidence={"ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the GenericAll/GenericWrite precondition on "
                    f"{target or '(target)'} via dacledit read; attempting anyway"),
            evidence={"ace_confirmed": None})


def _gpo_domain_dn(domain: str) -> str:
    """Local duplicate of ``gpo_abuse.py``'s ``_domain_dn`` -- probes.py never
    imports from an individual technique's own executor module (only from
    ``executors.base``/``executors.acl_common``, see the import block above),
    so this tiny GPO-specific DN helper is re-derived here, same "modest
    duplication, zero cross-module coupling" convention as every other T3
    probe/executor pair in this codebase."""
    return ",".join(f"DC={label}" for label in (domain or "").split(".") if label)


def _gpo_object_dn(gpo_guid: str, domain: str) -> str:
    guid = (gpo_guid or "").strip("{}")
    return f"CN={{{guid}}},CN=Policies,CN=System,{_gpo_domain_dn(domain)}"


class GpoAbuseProbe(PreconditionProbe):
    """GPO-ABUSE: re-confirm the GenericAll/GenericWrite ACE over the GPO's own
    AD object via the same ``confirm_ace`` read the executor's own step 1 uses.
    A positively-insufficient ACE is ``viable=False``; an unreadable/unlocated
    read is ``unknown`` (attempt anyway) -- whether ``linked_host`` was supplied
    is not this probe's concern (the executor itself degrades to a narrower,
    advisory-flagged proof when it is absent, never a precondition failure)."""
    technique = "GPO-ABUSE"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        gpo_guid = (finding.entity or {}).get("gpo_guid") or ""
        trustee = cfg.username or ""
        gpo_dn = _gpo_object_dn(gpo_guid, cfg.domain)
        res = ctx.runner.run(dacledit_read_argv(cfg, gpo_dn, cfg.dc_ip),
                             timeout=cfg.tool_timeout_s)
        text = _text(res)
        confirmed = confirm_ace(res, text, trustee=trustee,
                                right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        if confirmed is False:
            return ProbeResult(
                viable=False,
                reason=(f"{trustee or '(operator)'} does not hold GenericAll/"
                        f"GenericWrite over GPO {gpo_guid or '(gpo)'} (confirmed via "
                        "dacledit read) -> skip"),
                evidence={"ace_confirmed": False})
        if confirmed is True:
            return ProbeResult(
                viable=True,
                reason=f"{trustee} confirmed holding GenericAll/GenericWrite over GPO {gpo_guid}",
                evidence={"ace_confirmed": True})
        return ProbeResult(
            viable=True, unknown=True,
            reason=(f"could not confirm the GenericAll/GenericWrite precondition on "
                    f"GPO {gpo_guid or '(gpo)'} via dacledit read; attempting anyway"),
            evidence={"ace_confirmed": None})


class _ForgeTicketProbe(PreconditionProbe):
    """T4 ticket forging: the precondition is possession of the SIGNING KEY
    (krbtgt / service key), supplied OUT-OF-BAND by the operator (or threaded from
    an upstream KRBTGT edge in a chain) -- not a target-readable property. So this
    probe only checks key AVAILABILITY (never reading or logging the key): no key
    at all is a positive ``viable=False`` (the forge cannot run); otherwise
    ``unknown=True`` (attempt anyway), since forge viability is not otherwise
    detectable from the target. Non-destructive (no tool call)."""

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        from .executors.forge_common import signing_key
        key, _ = signing_key(ctx)
        if not key:
            return ProbeResult(
                viable=False,
                reason=("no signing key available (ticket forging needs the krbtgt/service "
                        "key supplied out-of-band or threaded) -> skip"),
                evidence={"signing_key_present": False})
        return ProbeResult(
            viable=True, unknown=True,
            reason=("signing key present; forge viability is not otherwise target-detectable "
                    "-- attempting anyway"),
            evidence={"signing_key_present": True})


class GoldenTicketProbe(_ForgeTicketProbe):
    technique = "GOLDEN-TICKET"


class SilverTicketProbe(_ForgeTicketProbe):
    technique = "SILVER-TICKET"


class DiamondTicketProbe(_ForgeTicketProbe):
    technique = "DIAMOND-TICKET"


class SapphireTicketProbe(_ForgeTicketProbe):
    technique = "SAPPHIRE-TICKET"


class ShareLootProbe(PreconditionProbe):
    """SHARE-LOOT: read-only SMB share discovery + crawl. Viable when the operator
    has SMB credentials to authenticate the enumeration. No network probe here (and
    deliberately NOT the mutating ``nxc --shares``) -- the executor itself records
    per-host reachability/denial, so this stays a cheap, read-only applicability
    check."""
    technique = "SHARE-LOOT"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        if cfg.username and cfg.has_credentials():
            return ProbeResult(
                viable=True,
                reason="SMB credentials present; read-only share enumeration is applicable",
                evidence={"has_creds": True})
        return ProbeResult(
            viable=False,
            reason="no SMB credentials to authenticate share enumeration",
            evidence={"has_creds": False})


class BronzeBitProbe(PreconditionProbe):
    """BRONZE-BIT (CVE-2020-17049): the service account (operator default) should hold
    ``msDS-AllowedToDelegateTo``; the no-protocol-transition case is Bronze Bit's
    target (with protocol transition, CONSTRAINED-DELEG-PT is the simpler fit).
    Exploitation ALSO needs an unpatched KDC -- the executor classifies that at run
    time (``kdc_patched`` on an enforcing KDC), so this stays a config-only check."""
    technique = "BRONZE-BIT"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        principal = ctx.config.username or ""
        res = _ldap_query(ctx, f"(sAMAccountName={principal})",
                          ["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"])
        text = _text(res)
        if not _account_read_ok(res, text):
            return ProbeResult(viable=True, unknown=True,
                reason=f"could not read delegation attrs for {principal or '(principal)'}; attempting anyway",
                evidence={"allowed_to_delegate_to": None, "protocol_transition": None})
        a2d = _extract_attr(text, "msDS-AllowedToDelegateTo")
        uac = _parse_int(_extract_attr(text, "userAccountControl"))
        has_a2d = bool(a2d) and a2d.strip().lower() not in (
            "", "(not set)", "<not set>", "none", "-", "n/a")
        if not has_a2d:
            return ProbeResult(viable=False,
                reason=f"msDS-AllowedToDelegateTo empty on {principal}: no constrained delegation -> skip",
                evidence={"allowed_to_delegate_to": None, "protocol_transition": None})
        pt = bool(uac is not None and (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION))
        reason = (f"msDS-AllowedToDelegateTo set ({a2d}); "
                  + ("protocol transition present -> CONSTRAINED-DELEG-PT is simpler, Bronze Bit still applies"
                     if pt else "no protocol transition -> Bronze Bit's target case")
                  + "; exploitation also requires an unpatched KDC (classified at run time)")
        return ProbeResult(viable=True, reason=reason,
            evidence={"allowed_to_delegate_to": a2d, "protocol_transition": pt})


class S4U2SelfProbe(PreconditionProbe):
    """S4U2SELF: viable when the operator controls a computer/service account (one with
    a ``servicePrincipalName``, or a computer account ending ``$``) whose key they hold
    -- S4U2self needs a service identity to request a ticket to itself."""
    technique = "S4U2SELF"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        if not (cfg.username and cfg.has_credentials()):
            return ProbeResult(viable=False,
                reason="no credential for the controlled computer/service account",
                evidence={"has_creds": False})
        principal = cfg.username
        res = _ldap_query(ctx, f"(sAMAccountName={principal})",
                          ["sAMAccountName", "servicePrincipalName"])
        text = _text(res)
        is_computer = principal.endswith("$")
        if not _account_read_ok(res, text):
            return ProbeResult(viable=True, unknown=True,
                reason=f"could not read servicePrincipalName for {principal}; attempting anyway"
                       + (" (computer account)" if is_computer else ""),
                evidence={"has_spn": None, "is_computer": is_computer})
        spn = _extract_attr(text, "servicePrincipalName")
        has_spn = bool(spn) and spn.strip().lower() not in (
            "", "(not set)", "<not set>", "none", "-", "n/a")
        if has_spn or is_computer:
            return ProbeResult(viable=True,
                reason=f"{principal} is a service/computer account (SPN={has_spn}, computer={is_computer}): "
                       "S4U2self applicable",
                evidence={"has_spn": has_spn, "is_computer": is_computer})
        return ProbeResult(viable=False,
            reason=f"{principal} has no SPN and is not a computer account: S4U2self needs a service identity",
            evidence={"has_spn": False, "is_computer": False})


class SigningRelayProbe(PreconditionProbe):
    """SIGNING-RELAY: read SMB/LDAP signing posture. Viable whenever the operator can
    authenticate an nxc read (the posture itself is the finding); no special right needed."""
    technique = "SIGNING-RELAY"

    def check(self, ctx: ExecutorContext, finding) -> ProbeResult:
        cfg = ctx.config
        if cfg.username and cfg.has_credentials():
            return ProbeResult(viable=True,
                reason="credentials present; SMB/LDAP signing posture is readable",
                evidence={"has_creds": True})
        return ProbeResult(viable=False,
            reason="no credentials to authenticate the nxc signing-posture read",
            evidence={"has_creds": False})


# ---------------------------------------------------------------- registry
_PROBES: tuple[type[PreconditionProbe], ...] = (
    KerberoastProbe, ASREPProbe, LapsProbe, ConstrainedDelegProbe,
    RbcdProbe, OpenSharesProbe, ShadowCredsProbe, ADCSESC1Probe,
    # N1 -- ADCS relay fronts + the DCSync terminal.
    Esc8Probe, Esc11Probe, CertifriedProbe, DCSyncProbe,
    # PP (25NOV2026) -- the listener trio, completing detect coverage for all 15.
    CoercionProbe, NTLMRelayProbe, UnconstrainedDelegProbe,
    # T3 (25NOV2026) -- ACL / object-takeover edges. All 7 now registered.
    WriteDaclProbe, WriteOwnerProbe, AddMemberProbe, TargetedKerberoastProbe,
    ForceChangePasswordProbe, GenericAllProbe, GpoAbuseProbe,
    # T4 (26NOV2026) -- Kerberos ticket forging (key-availability probes).
    GoldenTicketProbe, SilverTicketProbe, DiamondTicketProbe, SapphireTicketProbe,
    # SHARELOOT S1 (27NOV2026) -- read-only SMB share discovery + crawl.
    ShareLootProbe,
    # T6 (27NOV2026) -- delegation extras (config-only applicability checks).
    BronzeBitProbe, S4U2SelfProbe,
    # SIGNING-RELAY (27NOV2026) -- SMB/LDAP signing-posture read.
    SigningRelayProbe,
)

# Technique -> probe class.
PROBE_REGISTRY: dict[str, type[PreconditionProbe]] = {
    cls.technique: cls for cls in _PROBES
}


def get_probe(technique: Optional[str]) -> Optional[PreconditionProbe]:
    """Instantiate the probe for ``technique``, or ``None`` if none is registered."""
    cls = PROBE_REGISTRY.get(technique or "")
    return cls() if cls is not None else None


def probe_finding(ctx: ExecutorContext, finding) -> Optional[ProbeResult]:
    """Run the probe for ``finding`` (if registered); ``None`` if none.

    A probe that raises is caught and reported as ``unknown`` (attempt anyway) --
    a probe error must never become a false ``viable=False`` that drops a finding.
    """
    probe = get_probe(getattr(finding, "technique", None))
    if probe is None:
        return None
    try:
        return probe.check(ctx, finding)
    except Exception as exc:  # fail safe -> unknown, never a false viable=False
        # Only the exception TYPE enters the public reason -- the message could carry
        # credential-bearing tool argv; the full error goes to the private error log.
        try:
            ctx._private_errors.append(f"probe {getattr(probe,'technique','?')}: {exc}")
        except Exception:
            pass
        return ProbeResult(
            viable=True, unknown=True,
            reason=f"probe error ({type(exc).__name__}); attempting anyway",
            evidence={})


def run_probes(ctx: ExecutorContext, findings: list[Any],
               max_workers: int = 8) -> list[Optional[ProbeResult]]:
    """Run each finding's probe concurrently and independently (ADR-002 D1).

    Returns a list aligned to ``findings`` (``None`` where no probe is registered).
    Probes are non-destructive reads with no shared state, so thread concurrency
    is safe; a probe error degrades to ``unknown`` rather than aborting the batch.
    """
    if not findings:
        return []
    workers = max(1, min(max_workers, len(findings)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda f: probe_finding(ctx, f), findings))


__all__ = [
    "ProbeResult", "PreconditionProbe", "PROBE_REGISTRY", "get_probe",
    "probe_finding", "run_probes",
    "KerberoastProbe", "ASREPProbe", "LapsProbe", "ConstrainedDelegProbe",
    "RbcdProbe", "OpenSharesProbe", "ShadowCredsProbe", "ADCSESC1Probe",
    "Esc8Probe", "Esc11Probe", "CertifriedProbe", "DCSyncProbe",
    "CoercionProbe", "NTLMRelayProbe", "UnconstrainedDelegProbe",
    "WriteDaclProbe", "WriteOwnerProbe", "AddMemberProbe", "TargetedKerberoastProbe",
    "ForceChangePasswordProbe", "GenericAllProbe", "GpoAbuseProbe",
    "GoldenTicketProbe", "SilverTicketProbe", "DiamondTicketProbe", "SapphireTicketProbe",
]
