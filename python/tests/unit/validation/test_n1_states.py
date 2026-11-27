"""N1 capability-state module (states.py) + each new edge's pre/eff over it.

The constants module is the single source of state names so the chaining engine
(C) matches one edge's ``eff`` to another's ``pre`` by identity (review Q2). These
tests pin that each NEW executor declares ``pre``/``eff`` as frozensets expressed
ENTIRELY over the ``states`` constants, and that the N1 ``a_i + b1`` paths
(ESC8/ESC11/Certifried -> DCSync) actually compose (front ``eff`` meets DCSync
``pre``).
"""
from __future__ import annotations

from purplesploit.validation import states
from purplesploit.validation.executors import (
    ESC8Executor, ESC11Executor, CertifriedExecutor, DCSyncExecutor)


def test_base_states_are_distinct_nonempty_strings():
    base = [states.S0_USER_CREDS, states.DC_TGT, states.DA_CREDS,
            states.KRBTGT, states.S_DA,
            # C-tranche intermediate states the existing 11 fronts traverse (H5a).
            states.S_COERCED_AUTH, states.S_COMPUTER_CONTROL,
            states.S_RBCD_WRITE, states.S_IMPERSONATION_TGT,
            # T3 additions (ACL/object-takeover edges).
            states.S_ACL_CONTROL, states.S_ACL_CRED,
            # T4 addition (Kerberos ticket forging -> reusable authenticator).
            states.S_PERSISTENCE,
            # SHARELOOT S4 addition (usable looted credential).
            states.S_LOOTED_CREDS]
    assert all(isinstance(s, str) and s for s in base)
    assert len(set(base)) == len(base)                   # no collisions
    assert set(base) == set(states.BASE_STATES)


def test_cert_for_token_is_a_known_state():
    c = states.cert_for("srv03.essos.local")
    assert c.startswith("cert:") and states.is_state(c)
    assert states.is_state(states.DC_TGT)
    assert not states.is_state("cert:")                  # empty host -> not a state
    assert not states.is_state("not_a_real_state")


def test_new_edges_pre_eff_are_frozensets_over_states_constants():
    for ex in (ESC8Executor, ESC11Executor, CertifriedExecutor, DCSyncExecutor):
        assert isinstance(ex.pre, frozenset) and isinstance(ex.eff, frozenset)
        assert ex.pre and ex.eff                         # non-empty
        assert states.all_states(ex.pre), f"{ex.__name__}.pre not over states constants"
        assert states.all_states(ex.eff), f"{ex.__name__}.eff not over states constants"


def test_edge_pre_eff_values_match_the_plan():
    s0, dc_tgt = frozenset({states.S0_USER_CREDS}), frozenset({states.DC_TGT})
    for front in (ESC8Executor, ESC11Executor, CertifriedExecutor):
        assert front.pre == s0 and front.eff == dc_tgt
    assert DCSyncExecutor.pre == frozenset({states.DC_TGT, states.DA_CREDS})
    assert DCSyncExecutor.eff == frozenset({states.KRBTGT, states.S_DA})


def test_front_eff_satisfies_dcsync_pre():
    # The composable N1 paths: each front's eff (dc_tgt) is accepted by DCSync.pre.
    for front in (ESC8Executor, ESC11Executor, CertifriedExecutor):
        assert front.eff & DCSyncExecutor.pre, f"{front.__name__} does not chain to DCSync"


def test_fronts_declare_composable_rollback_deferral():
    # H3: the mutating fronts flag that a composed rollback defers to chain teardown.
    for front in (ESC8Executor, ESC11Executor, CertifriedExecutor):
        assert getattr(front, "composable_rollback_defers", False) is True
