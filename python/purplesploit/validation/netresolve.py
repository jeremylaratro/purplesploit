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
    bare name only when no NetBIOS name can be derived."""
    nb = netbios(cfg)
    return f"{nb}/{sam}" if nb else sam


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


# ------------------------------------------------- post-hoc failure classifier
# Signatures of a NAME-RESOLUTION / KDC-DISCOVERY failure (not an auth failure).
# Conservative by design — tuned against the real nxc/impacket output in S2's live
# proof. A miss degrades to "no diagnostic" (the raw tool error still surfaces),
# never a false success.
_RE_REALM_KDC = re.compile(
    r"cannot\s+find\s+kdc|kdc\b[^\n]{0,40}\b(?:not\s+found|unreachable|cannot|no\s+such)"
    r"|unable\s+to\s+(?:find|reach|resolve)[^\n]{0,20}kdc"
    r"|\brealm\b[^\n]{0,40}(?:not\s+found|unknown|could\s+not|cannot|unreachable)"
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
