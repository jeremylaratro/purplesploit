"""Stub validation executors -- recipe documented (#66146), not yet wired.

Each class below is a real, importable :class:`ValidationExecutor` whose metadata
(technique / class / terminal kind / mutating / recipe) is filled in from the
PROVEN recipes (claude-mem #66146) so the orchestrator can list and plan them,
but whose :meth:`execute` raises :class:`StubNotImplemented`. The base-class
``run`` catches that and emits an honest *incomplete* receipt (the scorer reads
it as ``inconclusive``/``stub_not_implemented``), never a fabricated proof.

To implement one: mirror ``rbcd.py`` -- declare ``param_specs`` with
recommended-default + override params, encode the recipe steps through
``ctx.runner``, gate mutating ops, add a verified rollback if mutating, and
build the terminal fact. Replace the ``execute`` body. TODOs mark each.

Recipe status (#66146): PROVED = C1 ADCS, C3 kerberoast, C4 asrep,
C6 constrained-deleg, C7 RBCD, C9 shadow, C11 openshares; C10 LAPS inconclusive
(lab quirk); C2 relay / C5 unconstrained / C8 coercion recipe-known-not-run.

IMPLEMENTED (no longer stubs): RBCD (``rbcd.py``); KERBEROAST + ASREP
(``roast.py``); LAPS (``laps.py``) -- T1a; CONSTRAINED-DELEG-PT
(``constrained_deleg.py``); OPENSHARES-WRITE (``openshares.py``); SHADOW-CREDS
(``shadow_creds.py``) -- T1b; ADCS-ESC1 (``adcs_esc1.py``) -- T1c. The classes
below are the remaining three stubs (COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG).
"""
from __future__ import annotations

from ..recommend import ParamSpec
from .base import ValidationExecutor, ExecutorContext, StubNotImplemented


class _Stub(ValidationExecutor):
    """Shared stub body. Subclasses set the class attrs + (optionally) params."""

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        # TODO: declare the overridable params this technique needs, each with a
        # recommended default derived from ctx.config (see rbcd.py.param_specs).
        return []

    def execute(self, ctx: ExecutorContext, finding, params) -> dict:
        raise StubNotImplemented(
            f"{self.technique} executor not implemented; recipe: {self.recipe_ref}")


class CoercionExecutor(_Stub):
    technique = "COERCION"
    technique_class = "coerce"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = False   # recipe-known-not-run (#66146)
    recipe_ref = "#66146 COERCION = Coercer/PetitPotam trigger -> captured auth is the proof"
    # TODO: params -> {victim (DC from finding.host), listener_ip (recommended the
    # operator host)}. Pairs with NTLM-RELAY (feeds the listener).


class NTLMRelayExecutor(_Stub):
    technique = "NTLM-RELAY"
    technique_class = "relay"
    terminal_kind = "replication_dump"   # or rbcd_access (facet accepts both)
    mutating = False
    verified_recipe = False   # recipe-known-not-run (#66146)
    recipe_ref = ("#66146 NTLM-RELAY = impacket-ntlmrelayx listener + coercion -> relay "
                  "to LDAP(RBCD)/SMB; terminal = SAM dump (replication_dump) or LDAP "
                  "RBCD write (rbcd_access, mutating -> rollback)")
    # TODO: params -> {relay_target (from finding.host, signing-off), mode LDAP|SMB}.
    # LDAP-RBCD mode mutates -> rollback required; SMB-SAM-dump mode is read-only.


class UnconstrainedDelegExecutor(_Stub):
    technique = "UNCONSTRAINED-DELEG"
    technique_class = "delegation"
    terminal_kind = "replication_dump"
    mutating = False
    verified_recipe = False   # recipe-known-not-run (#66146)
    recipe_ref = ("#66146 UNCONSTRAINED-DELEG = coerce DC -> capture TGT on unconstrained "
                  "host -> secretsdump DCSync")
    # TODO: params -> {victim_dc (from finding.host), unconstrained_host}. Terminal =
    # DCSync replication dump; coercion sub-step reuses CoercionExecutor's recipe.


STUB_EXECUTORS: dict[str, type[ValidationExecutor]] = {
    cls.technique: cls for cls in (
        CoercionExecutor, NTLMRelayExecutor, UnconstrainedDelegExecutor,
    )
}
