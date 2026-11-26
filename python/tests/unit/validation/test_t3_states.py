"""T3 capability-state coverage (states.py's S_ACL_CONTROL/S_ACL_CRED +
control_for/cred_for) and each of the 7 T3 executors' own pre/eff declarations
over those constants (plan §3). Mirrors test_n1_states.py's style, scoped to
the ACL/object-takeover tranche.
"""
from __future__ import annotations

from purplesploit.validation import states
from purplesploit.validation.executors import (
    WriteDaclExecutor, WriteOwnerExecutor, AddMemberExecutor,
    TargetedKerberoastExecutor, ForceChangePasswordExecutor, GenericAllExecutor,
)
from purplesploit.validation.executors.gpo_abuse import GpoAbuseExecutor

_T3_EXECUTORS = (
    WriteDaclExecutor, WriteOwnerExecutor, AddMemberExecutor,
    TargetedKerberoastExecutor, ForceChangePasswordExecutor, GenericAllExecutor,
    GpoAbuseExecutor,
)


def test_t3_states_are_known_base_states():
    assert states.is_state(states.S_ACL_CONTROL)
    assert states.is_state(states.S_ACL_CRED)
    assert states.S_ACL_CONTROL in states.BASE_STATES
    assert states.S_ACL_CRED in states.BASE_STATES


def test_control_for_and_cred_for_are_principal_typed_and_distinct():
    a, b = states.control_for("arya.stark"), states.control_for("sansa.stark")
    assert a != b and a.startswith("control:") and b.startswith("control:")
    assert states.is_state(a) and states.is_state(b)
    c = states.cred_for("arya.stark")
    assert c.startswith("cred:") and c != a  # same principal, different capability kind
    assert not states.is_state("control:")   # empty principal -> not a state
    assert not states.is_state("cred:")


def test_every_t3_executor_declares_pre_eff_as_frozensets_over_states_constants():
    for ex in _T3_EXECUTORS:
        assert isinstance(ex.pre, frozenset) and isinstance(ex.eff, frozenset)
        assert ex.pre and ex.eff
        assert states.all_states(ex.pre), f"{ex.__name__}.pre not over states constants"
        assert states.all_states(ex.eff), f"{ex.__name__}.eff not over states constants"


def test_t3_pre_eff_values_match_the_plan():
    s0 = frozenset({states.S0_USER_CREDS})
    acl_control = frozenset({states.S_ACL_CONTROL})
    acl_cred = frozenset({states.S_ACL_CRED})
    # The 5 "take control" / "recover a credential" edges that start from a
    # bare operator principal.
    for ex in (WriteDaclExecutor, WriteOwnerExecutor, AddMemberExecutor):
        assert ex.pre == s0 and ex.eff == acl_control, ex.__name__
    for ex in (TargetedKerberoastExecutor, ForceChangePasswordExecutor):
        assert ex.pre == s0 and ex.eff == acl_cred, ex.__name__
    # GENERIC-ALL additionally accepts an already-held S_ACL_CONTROL (it IS a
    # control primitive), and its 4-pivot eff spans BOTH a credential outcome
    # and the RBCD pivot's impersonation-ticket outcome.
    assert GenericAllExecutor.pre == frozenset({states.S0_USER_CREDS, states.S_ACL_CONTROL})
    assert GenericAllExecutor.eff == frozenset({states.S_ACL_CRED, states.S_IMPERSONATION_TGT})
    # GPO-ABUSE: a code-exec-as-SYSTEM control primitive, same shape as
    # WRITE-DACL/WRITE-OWNER/ADD-MEMBER.
    assert GpoAbuseExecutor.pre == s0 and GpoAbuseExecutor.eff == acl_control


def test_t3_destructive_flags_match_the_plan():
    # FORCE-CHANGE-PASSWORD and GPO-ABUSE are FIXED-destructive (irreversible /
    # code-exec by design); GENERIC-ALL is a CONSERVATIVE class-level flag
    # (only its reset_password pivot body actually gates); the other 4 are
    # non-destructive entirely.
    assert ForceChangePasswordExecutor.destructive is True
    assert GpoAbuseExecutor.destructive is True
    assert GenericAllExecutor.destructive is True
    for ex in (WriteDaclExecutor, WriteOwnerExecutor, AddMemberExecutor,
              TargetedKerberoastExecutor):
        assert ex.destructive is False, ex.__name__


# Lab-proven (scored proved+clean) on GOAD 26NOV2026. FORCE-CHANGE-PASSWORD is
# included: it is live-proven (authn_success) and the harness certifies it via
# the reviewed irreversible-technique carve-out (a password reset is IRREVERSIBLE,
# so no rollback can exist; the scorer accepts it on the facet's `irreversible:
# true` + the receipt's explicit acknowledgment). GPO-ABUSE is not in the
# live-prove set (handled separately), so its verified_recipe stays False.
_T3_LAB_PROVEN = frozenset({
    "ADD-MEMBER", "GENERIC-ALL", "WRITE-DACL", "WRITE-OWNER", "TARGETED-KERBEROAST",
    "FORCE-CHANGE-PASSWORD",
})


def test_t3_mutating_and_verified_recipe_flags():
    for ex in _T3_EXECUTORS:
        assert ex.mutating is True, ex.__name__           # every T3 technique mutates AD
        if ex.technique in _T3_LAB_PROVEN:
            assert ex.verified_recipe is True, ex.__name__   # lab-proven on GOAD 26NOV2026
        else:
            assert ex.verified_recipe is False, ex.__name__  # recipe-known, lab proof pending/not-yet-certified
