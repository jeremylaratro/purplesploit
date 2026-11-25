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

# The base (parameter-free) capability states.
BASE_STATES: frozenset = frozenset({
    S0_USER_CREDS, DC_TGT, DA_CREDS, KRBTGT, S_DA,
})

_CERT_PREFIX = "cert:"


def cert_for(host: str) -> str:
    """A per-host certificate-possession state (``cert:<host>``).

    ESC8/ESC11/Certifried issue a certificate for a CA/DC host; conceptually that
    is a front's intermediate effect. The N1 executors model the downstream
    ``eff`` as :data:`DC_TGT` (PKINIT with the cert), but ``cert_for`` names the
    cert-possession state so C can plan at finer granularity if it wants to.
    """
    return f"{_CERT_PREFIX}{host or ''}"


def is_state(value: str) -> bool:
    """True iff ``value`` is a known capability-state: a base state, or a
    :func:`cert_for` token (``cert:<host>`` with a non-empty host)."""
    if value in BASE_STATES:
        return True
    return (isinstance(value, str) and value.startswith(_CERT_PREFIX)
            and len(value) > len(_CERT_PREFIX))


def all_states(states: Iterable[str]) -> bool:
    """True iff every item in ``states`` is a known capability-state. Used to
    validate that each edge's ``pre``/``eff`` is expressed over these constants."""
    return all(is_state(s) for s in states)


__all__ = [
    "S0_USER_CREDS", "DC_TGT", "DA_CREDS", "KRBTGT", "S_DA",
    "BASE_STATES", "cert_for", "is_state", "all_states",
]
