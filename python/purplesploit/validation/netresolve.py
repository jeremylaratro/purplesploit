"""Shared AD name-resolution helpers (DNSHARDEN S1) — the single resolution authority.

Dependency-free by design: every function takes a **duck-typed** ``cfg`` (anything
with ``domain`` / ``dc_ip`` and optional ``netbios_domain`` / ``kdc_host`` /
``dns_server``) and imports NOTHING from this package, so ``config`` can delegate
to it one-way without an import cycle. No host-pinning — every value derives from
``cfg``.

Scope (re-scoped after plan review r1/r2, see PLAN-DNSHARDEN):
- Canonical NetBIOS short name + GC-ambiguity qualification (replaces 3 divergent copies).
- Kerberos discovery flags: ``--kdcHost`` is always safe (it only names the KDC and does
  NOT disable target-host resolution); ``--dns-server`` is OPT-IN (``cfg.dns_server``),
  because forcing it bypasses the tool's system/``/etc/hosts`` resolver.
- A post-hoc classifier that turns a FAILED tool call's output into a rich, actionable
  diagnostic. It NEVER decides success — it only labels an already-failed call.

Deferred (NOT here): host_map→IP transport substitution, auth-mode-aware up-front
preflight, SPN/LDAP-vs-LDAPS/DC-vs-GC routing.
"""
from __future__ import annotations

import re
from typing import Optional


# ---------------------------------------------------------------- name helpers
def netbios(cfg) -> str:
    """THE canonical NetBIOS short name: explicit ``cfg.netbios_domain`` (trimmed),
    else the domain FQDN's first label; upper-cased. Honors the override (the old
    ``config.netbios`` property did not — latent bug, fixed by delegating here)."""
    raw = getattr(cfg, "netbios_domain", None) or (getattr(cfg, "domain", "") or "").split(".", 1)[0]
    return (raw or "").strip().upper()


def gc_qualify(cfg, sam: str) -> str:
    """NetBIOS-qualify a possibly GC-ambiguous account name → ``<NETBIOS>/<sam>``
    (the generalization of DCSYNC's ``krbtgt`` qualification that avoids
    ``ERROR_DS_NAME_ERROR_NOT_UNIQUE`` in a multi-domain forest). Falls back to the
    bare name only when no NetBIOS name can be derived. Uses whatever
    :func:`netbios` returns -- i.e. the operator override, a value cached by
    :func:`ensure_netbios`, or the heuristic."""
    nb = netbios(cfg)
    return f"{nb}/{sam}" if nb else sam


# ---------------------------------------------------- active NetBIOS resolution
# The heuristic above (FQDN first label) is a GUESS -- the NetBIOS short name can
# differ from the first DNS label. These methods ACTIVELY determine it from the DC.
# Layering (owner request 27NOV2026): ONE main method, retried up to `attempts`
# (default 3) times; then one-or-two BACKUP methods, each tried once; then the
# deterministic heuristic as the final fallback. All verified live on GOAD.
_NB_CHARS = re.compile(r"^[A-Za-z0-9._-]{1,15}$")        # a plausible NetBIOS short name
_NB_NOISE = frozenset({"NAME", "SID", "DOMAIN", "SERVER", "POLICY", "NONE"})
_RE_LSAQUERY = re.compile(r"^\s*Domain Name:\s*(\S+)\s*$", re.I | re.M)     # rpcclient lsaquery
_RE_QUERYDOMINFO = re.compile(r"^\s*Domain:\s*(\S+)\s*$", re.I | re.M)      # rpcclient querydominfo
_RE_LOOKUPSID_PFX = re.compile(r"([A-Za-z0-9._-]{1,15})\\[^\s\\]+\s+\(Sid", re.M)  # lookupsid "<rid>: NETBIOS\acct (Sid...)"


def _nb_valid(name: Optional[str]) -> bool:
    return bool(name) and bool(_NB_CHARS.match(name)) and name.strip().upper() not in _NB_NOISE


def _text(res) -> str:
    return (getattr(res, "stdout", "") or "") + "\n" + (getattr(res, "stderr", "") or "")


def _rpc_user(cfg):
    """``(user_value, extra_flags)`` for ``rpcclient -U`` from cfg, or ``None`` when
    there is no usable password/NT-hash credential (Kerberos-only → fall back)."""
    user = getattr(cfg, "username", None)
    if not user:
        return None
    if getattr(cfg, "nt_hash", None):
        nt = cfg.nt_hash.split(":")[-1]                 # 'LM:NT' / ':NT' / bare → NT
        return f"{user}%{nt}", ["--pw-nt-hash"]
    if getattr(cfg, "password", None) is not None:
        return f"{user}%{cfg.password}", []
    return None


def _lookupsid_target(cfg) -> Optional[tuple]:
    """``(target, extra_flags)`` for impacket-lookupsid, or ``None`` (Kerberos-only)."""
    user = getattr(cfg, "username", None)
    if not user:
        return None
    dom = getattr(cfg, "domain", "") or ""
    if getattr(cfg, "nt_hash", None):
        return f"{dom}/{user}@{cfg.dc_ip}", ["-hashes", cfg.nt_hash]
    if getattr(cfg, "password", None) is not None:
        return f"{dom}/{user}:{cfg.password}@{cfg.dc_ip}", []
    return None


def _nb_from_lsaquery(cfg, runner, timeout):
    u = _rpc_user(cfg)
    if u is None:
        return None
    user_val, extra = u
    argv = ["rpcclient", "-U", user_val, *extra, cfg.dc_ip, "-c", "lsaquery"]
    m = _RE_LSAQUERY.search(_text(runner.run(argv, timeout=timeout)))
    return m.group(1) if m else None


def _nb_from_querydominfo(cfg, runner, timeout):
    u = _rpc_user(cfg)
    if u is None:
        return None
    user_val, extra = u
    argv = ["rpcclient", "-U", user_val, *extra, cfg.dc_ip, "-c", "querydominfo"]
    m = _RE_QUERYDOMINFO.search(_text(runner.run(argv, timeout=timeout)))
    return m.group(1) if m else None


def _nb_from_lookupsid(cfg, runner, timeout):
    t = _lookupsid_target(cfg)
    if t is None:
        return None
    target, extra = t
    argv = ["impacket-lookupsid", target, *extra, "1200"]
    m = _RE_LOOKUPSID_PFX.search(_text(runner.run(argv, timeout=timeout)))
    return m.group(1) if m else None


def _try(fn, cfg, runner, timeout) -> Optional[str]:
    try:
        name = fn(cfg, runner, timeout)
    except Exception:
        return None
    return name.strip().upper() if (name and _nb_valid(name)) else None


def resolve_netbios(cfg, runner, *, attempts: int = 3, timeout=None):
    """Actively resolve the domain's NetBIOS short name from the DC.

    MAIN (``rpcclient lsaquery``) is retried up to ``attempts`` (default 3) times;
    if every attempt fails, the BACKUP methods (``rpcclient querydominfo`` then
    ``impacket-lookupsid``) are each tried once; if all fail, the deterministic
    heuristic (:func:`netbios` — operator override or FQDN first label) is used.
    An explicit ``cfg.netbios_domain`` override short-circuits (never queries).

    Returns ``(netbios_name, method, trail)`` where ``trail`` is a list of
    ``(method, attempt, ok)`` for provenance. PUBLIC data only (a short domain
    name); the credentialed argv is masked by ``redact_argv`` when recorded.
    """
    trail: list = []
    if getattr(cfg, "netbios_domain", None):
        return netbios(cfg), "override", trail
    timeout = timeout or getattr(cfg, "tool_timeout_s", 60)
    for i in range(max(1, int(attempts))):
        name = _try(_nb_from_lsaquery, cfg, runner, timeout)
        trail.append(("lsaquery", i + 1, bool(name)))
        if name:
            return name, f"lsaquery(attempt {i + 1})", trail
    for fn, label in ((_nb_from_querydominfo, "querydominfo"), (_nb_from_lookupsid, "lookupsid")):
        name = _try(fn, cfg, runner, timeout)
        trail.append((label, 1, bool(name)))
        if name:
            return name, label, trail
    return netbios(cfg), "heuristic", trail


def ensure_netbios(cfg, runner, **kw):
    """Resolve the NetBIOS name and CACHE it onto ``cfg.netbios_domain`` so later
    :func:`netbios`/:func:`gc_qualify` calls use the authoritative value. Only a
    value from a NETWORK method is cached — a heuristic fallback is NOT cached, so
    a transient failure never permanently pins the guess. Returns
    ``(name, method, trail)``; an explicit override is respected (no query)."""
    name, method, trail = resolve_netbios(cfg, runner, **kw)
    if method not in ("heuristic", "override") and not getattr(cfg, "netbios_domain", None):
        try:
            cfg.netbios_domain = name
        except Exception:
            pass
    return name, method, trail


# ---------------------------------------------------------- Kerberos discovery
def kdc_host(cfg) -> str:
    """The KDC host for Kerberos discovery: explicit ``cfg.kdc_host`` else the DC IP.
    ``--kdcHost`` only NAMES the KDC; it does not disable target-host resolution,
    so deriving + always passing it is safe."""
    return getattr(cfg, "kdc_host", None) or cfg.dc_ip


def dns_server(cfg) -> Optional[str]:
    """OPT-IN resolver: ``cfg.dns_server`` or ``None``. ``None`` means DO NOT pass
    ``--dns-server`` — forcing it bypasses the tool's system/``/etc/hosts`` resolver
    (which would break a carrier that relies on ``/etc/hosts``)."""
    return getattr(cfg, "dns_server", None) or None


def nxc_kerberos_flags(cfg) -> list[str]:
    """Discovery flags for a Kerberos-mode nxc call: always ``--kdcHost`` (safe),
    plus ``--dns-server`` ONLY when the operator set ``cfg.dns_server``. Exactly one
    of each; never duplicated."""
    flags = ["--kdcHost", kdc_host(cfg)]
    ds = dns_server(cfg)
    if ds:
        flags += ["--dns-server", ds]
    return flags


def nxc_auth_flags(cfg) -> list[str]:
    """THE canonical NetExec auth flags from ``cfg``: ``-u <user>`` then
    ``-H <nthash>`` / ``--aesKey <key>`` / ``-p <pass>`` by mode (replaces 6 identical
    per-executor copies). When the mode is **Kerberos** (``--aesKey``), ALSO appends
    the Kerberos discovery flags (``--kdcHost``, opt-in ``--dns-server``) so
    realm→KDC resolution works without a carrier ``/etc/hosts``. NTLM modes
    (``-H``/``-p``) connect to the host/IP and get NO discovery flags. The secret
    (hash/key/password) rides a flag that ``redact_argv`` masks."""
    argv = ["-u", getattr(cfg, "username", None) or ""]
    if getattr(cfg, "nt_hash", None):
        argv += ["-H", cfg.nt_hash]                       # NTLM pass-the-hash (no KDC)
    elif getattr(cfg, "aes_key", None):
        argv += ["--aesKey", cfg.aes_key]                 # Kerberos -> needs discovery
        argv += nxc_kerberos_flags(cfg)
    elif getattr(cfg, "password", None) is not None:
        argv += ["-p", cfg.password]                      # NTLM password (no KDC)
    return argv


# ------------------------------------------------- post-hoc failure classifier
# Signatures of a NAME-RESOLUTION / KDC-DISCOVERY failure (not an auth failure).
# Conservative by design — tuned against the real nxc/impacket output in S2's live
# proof. A miss degrades to "no diagnostic" (the raw tool error still surfaces),
# never a false success.
# NOTE: match only KDC *discovery/resolution* failures -- NOT KDC error codes
# (``KDC_ERR_*`` means the KDC WAS reached and responded, e.g.
# ``KDC_ERR_BADOPTION(KDC cannot accommodate requested option)`` -- a reachable KDC
# rejecting an option, which must NOT be labelled "KDC not found").
_RE_REALM_KDC = re.compile(
    r"cannot\s+find\s+kdc|couldn'?t\s+find\s+kdc"
    r"|kdc\b[^\n]{0,40}\b(?:not\s+found|unreachable)"
    r"|no\s+kdc\s+(?:found|for\b)"
    r"|unable\s+to\s+(?:find|reach|resolve)[^\n]{0,20}kdc"
    r"|\brealm\b[^\n]{0,40}(?:not\s+found|unreachable|could\s+not\s+(?:be\s+)?(?:found|resolved?))"
    r"|kerberos[^\n]{0,40}name\s+resolution",
    re.I)
_RE_FQDN = re.compile(
    r"temporary\s+failure\s+in\s+name\s+resolution|name\s+or\s+service\s+not\s+known"
    r"|nxdomain|could\s+not\s+resolve|getaddrinfo|no\s+address\s+associated"
    r"|servname\s+not\s+supported|name\s+does\s+not\s+resolve",
    re.I)


def classify_resolution_failure(cfg, target: str, text: str) -> Optional[str]:
    """Turn a FAILED remote/Kerberos tool call's combined stdout+stderr into a rich,
    actionable diagnostic string, or ``None`` if it is not a resolution-shaped
    failure. Names/realms/IPs only (public — no secrets). NEVER decides success.

    Shape: ``resolution_failed:<which>: <name> via <resolver> — <reason>; fix: <action>``.
    """
    t = text or ""
    if _RE_REALM_KDC.search(t):
        realm = (getattr(cfg, "domain", "") or "").upper() or "<realm>"
        return (f"resolution_failed:realm_kdc: {realm}:88 via kdcHost={kdc_host(cfg)} "
                f"— KDC not found/unreachable; fix: set cfg.kdc_host to the DC's address")
    if _RE_FQDN.search(t):
        res = dns_server(cfg) or "system/etc-hosts"
        return (f"resolution_failed:fqdn: {target or '<target>'} via {res} "
                f"— name resolution failed; fix: set cfg.dns_server to the DC, or add the host")
    return None
