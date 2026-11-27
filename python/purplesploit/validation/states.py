"""Capability-state constants shared across validation executors (toward C).

A single source of state names so the chaining engine (C) can match one edge's
``eff`` (what it establishes) to another edge's ``pre`` (what it needs) *by
identity*, rather than by free-form per-executor strings (PLAN-N1 review Q2).
Each NEW executor declares class attrs ``pre: frozenset[str]`` and
``eff: frozenset[str]`` over these constants:

* ESC8 / ESC11   -- ``pre={S0_USER_CREDS}``,            ``eff={DC_TGT}``
  (relay a coerced DC's auth to the CA -> a DC cert -> PKINIT -> a DC-context TGT;
  the intermediate cert-possession state is :func:`cert_for` for C's finer plans).
* Certifried     -- ``pre={S0_USER_CREDS}``,            ``eff={DC_TGT}``.
* DCSync (``b1``) -- ``pre={DC_TGT, DA_CREDS}`` (either satisfies),
                     ``eff={KRBTGT, S_DA}``.

Valid ``a_i + b1`` paths delivered in N1: ``ESC8->DCSync``, ``ESC11->DCSync``,
``Certifried->DCSync`` -- each front's ``eff`` (``DC_TGT``) satisfies ``b1``'s
``pre``. (Review H5: a DCSYNC receipt alone proves only "DA given replication
creds"; a chain may NOT hand ``b1`` pre-supplied ``DA_CREDS`` and call it an
escalation -- C must record BOTH the front receipt and the DCSYNC receipt.)

Deliberately minimal: only the states the N1 edges need. The existing 11
executors get their ``pre``/``eff`` in the C tranche, not here. Stdlib only.
"""
from __future__ import annotations

from typing import Iterable

# Operator-supplied starting credentials (a low-privilege domain user). The
# fronts' precondition: ESC8/ESC11/Certifried run coercion / relay / enrollment
# from here.
S0_USER_CREDS = "S0_user_creds"

# A DC-context Kerberos TGT (PKINIT with a DC / machine certificate yields this).
# The ADCS/Certifried fronts' effect, and DCSync's (replication-capable)
# precondition.
DC_TGT = "dc_tgt"

# Pre-supplied Domain-Admin-equivalent credentials carrying replication rights.
# An ALTERNATIVE precondition for DCSync -- but a chain that hands these to b1 is
# not an escalation (review H5), so C must corroborate with a real front.
DA_CREDS = "da_creds"

# The krbtgt secret -- DCSync's effect (the universal, non-destructive DA proof).
KRBTGT = "krbtgt"

# Domain-Admin control achieved -- DCSync's effect.
S_DA = "S_DA"

# ---- intermediate states the existing 11 fronts traverse (C tranche, H5a) -----
# A coerced machine account's NTLM auth, captured by a listener (COERCION's eff;
# the relay/unconstrained fronts' pre).
S_COERCED_AUTH = "S_coerced_auth"

# Control of a computer account we can write delegation attrs on (RBCD's pre when
# not satisfied by MachineAccountQuota).
S_COMPUTER_CONTROL = "S_computer_control"

# A written msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD/relay-ldap eff);
# feeds the S4U step, NOT S_DA directly.
S_RBCD_WRITE = "S_rbcd_write"

# A service ticket impersonating a chosen principal to a specific SPN (the S4U /
# constrained-delegation eff). Lateral/service access, NOT domain replication.
S_IMPERSONATION_TGT = "S_impersonation_tgt"

# ---- T3 additions -----------------------------------------------------------
# A principal-typed CONTROL state (an ACE/ownership/group-membership/GPO-link the
# operator now holds over SOME principal, not yet typed to a specific one -- the
# coarse SHAPE used for engine eligibility; the precise binding is control_for().
S_ACL_CONTROL = "S_acl_control"

# Coarse shape only; the lateral engine binds cred_for(X). No recovered lateral
# credential is promoted to DA_CREDS or DC_TGT in this sprint.
S_ACL_CRED = "S_acl_cred"

# The base (parameter-free) capability states.
BASE_STATES: frozenset = frozenset({
    S0_USER_CREDS, DC_TGT, DA_CREDS, KRBTGT, S_DA,
    S_COERCED_AUTH, S_COMPUTER_CONTROL, S_RBCD_WRITE, S_IMPERSONATION_TGT,
    S_ACL_CONTROL, S_ACL_CRED,
})

_CERT_PREFIX = "cert:"
_LOCAL_ADMIN_PREFIX = "local_admin:"
_CRED_PREFIX = "cred:"
_CONTROL_PREFIX = "control:"


def cert_for(host: str) -> str:
    """A per-host certificate-possession state (``cert:<host>``).

    ESC8/ESC11/Certifried issue a certificate for a CA/DC host; conceptually that
    is a front's intermediate effect. The N1 executors model the downstream
    ``eff`` as :data:`DC_TGT` (PKINIT with the cert), but ``cert_for`` names the
    cert-possession state so C can plan at finer granularity if it wants to.
    """
    return f"{_CERT_PREFIX}{host or ''}"


def local_admin_for(host: str) -> str:
    """A per-host LOCAL-admin state (``local_admin:<host>``) -- review H5a.

    An NTLM-RELAY ``smb_sam`` dump yields local administrator on the relayed
    member, NOT domain credentials. This state DELIBERATELY does not feed
    :data:`S_DA`/:data:`DCSync.pre`, so the search can never mistake a SAM dump
    for Domain Admin. (A member's local SAM cannot DRSUAPI-replicate.)
    """
    return f"{_LOCAL_ADMIN_PREFIX}{host or ''}"


def cred_for(principal: str) -> str:
    """A per-PRINCIPAL recovered-credential state (``cred:<principal>``) -- H5a.

    A lateral credential NEVER satisfies DA_CREDS, DC_TGT or S_DA in this
    sprint. DA-equivalence and terminal credential-usability authority are
    deferred; there is no principal-name based DA promotion.
    """
    return f"{_CRED_PREFIX}{principal or ''}"


def control_for(principal: str) -> str:
    """A per-PRINCIPAL CONTROL state (``control:<principal>``) -- mirrors cred_for.

    Composed ACL producers bind a typed actor/object/right/lifetime grant.
    Finding-bound planning links it only to a consumer of this exact object;
    runtime applicability additionally requires the actual produced capability.
    Broader principal escalation to DA is not yet built.
    """
    return f"{_CONTROL_PREFIX}{principal or ''}"


def _is_prefixed(value: str, prefix: str) -> bool:
    return (isinstance(value, str) and value.startswith(prefix)
            and len(value) > len(prefix))


def is_state(value: str) -> bool:
    """True iff ``value`` is a known capability-state: a base state, or a
    parametrized token -- :func:`cert_for` (``cert:<host>``),
    :func:`local_admin_for` (``local_admin:<host>``), :func:`cred_for`
    (``cred:<principal>``), or :func:`control_for` (``control:<principal>``) --
    each with a non-empty argument."""
    if value in BASE_STATES:
        return True
    return (_is_prefixed(value, _CERT_PREFIX)
            or _is_prefixed(value, _LOCAL_ADMIN_PREFIX)
            or _is_prefixed(value, _CRED_PREFIX)
            or _is_prefixed(value, _CONTROL_PREFIX))


def cred_principal(value: str) -> str:
    """The principal inside a :func:`cred_for` token, or ``""`` if not one."""
    return value[len(_CRED_PREFIX):] if _is_prefixed(value, _CRED_PREFIX) else ""


def all_states(states: Iterable[str]) -> bool:
    """True iff every item in ``states`` is a known capability-state. Used to
    validate that each edge's ``pre``/``eff`` is expressed over these constants."""
    return all(is_state(s) for s in states)


__all__ = [
    "S0_USER_CREDS", "DC_TGT", "DA_CREDS", "KRBTGT", "S_DA",
    "S_COERCED_AUTH", "S_COMPUTER_CONTROL", "S_RBCD_WRITE", "S_IMPERSONATION_TGT",
    "S_ACL_CONTROL", "S_ACL_CRED",
    "BASE_STATES", "cert_for", "local_admin_for", "cred_for", "cred_principal",
    "control_for", "is_state", "all_states",
]
