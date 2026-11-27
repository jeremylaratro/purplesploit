"""H9 non-vacuous verification of the LATERAL T3 chain (PLAN-DUALMODE S2).

Proves that WRITE-DACL (grant control over X) -> GENERIC-ALL (abuse that control
to recover X's NT hash) -> cred_for(X) is a REAL, FOUND, ESCALATION path -- and,
critically, that it is an escalation ONLY because WRITE-DACL's *produced*
control_for(X) is what makes GENERIC-ALL applicable for X (GENERIC-ALL's
chain_pre deliberately excludes the operator seed). Driven with scripted fakes
(no lab). The negatives are isolated so the positive cannot pass vacuously.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation import states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.engine import ChainEngine, default_edges
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider, Capability,
    CAP_CONTROL, ControlGrant,
)
from purplesploit.validation.inputs import finding_from_inputs

_OPERATOR = "jon.snow"
_X = "arya.stark"
_NT = "00112233445566778899aabbccddeeff"


def _ace(mask: str, trustee: str) -> str:
    return ("[*] Parsing DACL\n[*] Printing parsed DACL\n[*]   ACE[0] info\n"
            f"[*]     ACE Type                  : ACCESS_ALLOWED_ACE\n"
            f"[*]     Access mask               : {mask}\n"
            f"[*]     Trustee (SID)             : {trustee} (S-1-5-21-1-2-3-1100)\n")


class _Fake(CommandRunner):
    """dacledit read/write/remove + certipy shadow auto. Stateful: a dacledit
    read shows the operator with FullControl until the ACE is removed (teardown),
    then shows it insufficient -- so WRITE-DACL's deferred teardown verifies."""

    def __init__(self, operator=_OPERATOR, target=_X, nt=_NT, write_ok=True):
        self.operator, self.target, self.nt = operator, target, nt
        self.write_ok = write_ok
        self.removed = False
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-dacledit":
            action = argv[argv.index("-action") + 1]
            if action == "read":
                mask = "ReadProperty (0x10)" if self.removed else "FullControl (0xf01ff)"
                return RunResult(0, stdout=_ace(mask, self.operator))
            if action == "write":
                return RunResult(0, stdout="[*] DACL modified successfully!"
                                 if self.write_ok else "[-] access denied")
            if action == "remove":
                self.removed = True
                return RunResult(0, stdout="[*] DACL modified successfully!")
        if tool == "certipy-ad":
            return RunResult(0, stdout=f"[*] NT hash for '{self.target}': {self.nt}\n"
                                       "[*] Restored the old Key Credentials\n")
        return RunResult(0, stdout="")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username=_OPERATOR, password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(runner, tmp_path) -> ExecutorContext:
    return ExecutorContext(_cfg(), runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _finding_for(ctx):
    def finding_for(edge):
        if edge.technique == "WRITE-DACL":
            return finding_from_inputs(ctx, edge, target=_X,
                                       params={"trustee": _OPERATOR, "rights": "FullControl"})
        if edge.technique == "GENERIC-ALL":
            return finding_from_inputs(ctx, edge, target=_X, params={"pivot": "shadow_creds"})
        return None
    return finding_for


def _engine(goal, **kw):
    return ChainEngine(default_edges(), goal=goal, allow_crack=True,
                       allow_destructive=True, **kw)


# ---------------------------------------------------------------- POSITIVE (H9)

def test_lateral_chain_is_a_real_found_escalation(tmp_path):
    ctx = _ctx(_Fake(), tmp_path)
    report = _engine(states.cred_for(_X)).run(ctx, _finding_for(ctx))
    assert report.reached is True
    assert report.escalation is True
    # The EXACT path: GENERIC-ALL is applicable for X only because WRITE-DACL
    # produced control_for(X). Not a front, not a single edge.
    assert report.path == ["WRITE-DACL", "GENERIC-ALL"]
    # H8: the recovered NT hash (a secret) never appears anywhere in the report.
    assert _NT not in json.dumps(report.to_dict())


# ---------------------------------------------------------------- NEGATIVES

def test_seed_control_is_not_an_escalation(tmp_path):
    # Operator ALREADY controls X (seed): GENERIC-ALL runs directly, WRITE-DACL is
    # not needed, and it is NOT an escalation.
    ctx = _ctx(_Fake(), tmp_path)
    report = _engine(states.cred_for(_X),
                     seed=frozenset({states.S0_USER_CREDS, states.control_for(_X)})
                     ).run(ctx, _finding_for(ctx))
    assert report.reached is True
    assert report.escalation is False
    assert "WRITE-DACL" not in report.path


def test_incomplete_writedacl_blocks_the_chain(tmp_path):
    # WRITE-DACL's ACE write fails -> it never produces control_for(X) -> GENERIC-ALL
    # (whose chain_pre is control_for(X), NOT the seed) is never applicable for X.
    ctx = _ctx(_Fake(write_ok=False), tmp_path)
    report = _engine(states.cred_for(_X)).run(ctx, _finding_for(ctx))
    assert report.reached is False
    assert report.escalation is False


def test_lateral_cred_never_reaches_domain_admin(tmp_path):
    # Even with DCSYNC bound, a lateral cred_for(X) must NOT satisfy DCSYNC's
    # da_creds pre -> S_DA is unreachable from the T3 lateral chain this sprint.
    ctx = _ctx(_Fake(), tmp_path)

    def finding_for(edge):
        if edge.technique == "DCSYNC":
            return finding_from_inputs(ctx, edge)
        return _finding_for(ctx)(edge)

    report = _engine(states.S_DA).run(ctx, finding_for)
    assert report.reached is False
    assert report.escalation is False


def test_genericall_rejects_a_forged_control_grant(tmp_path):
    # accepts_control must reject a grant whose object/actor/channel does not
    # match the target -> a tool cannot forge its way to control_for(X).
    ctx = _ctx(_Fake(), tmp_path)
    ga = get_executor("GENERIC-ALL")
    finding = finding_from_inputs(ctx, ga, target=_X, params={"pivot": "shadow_creds"})
    good = Capability(states.control_for(_X), CAP_CONTROL,
                      ControlGrant(_OPERATOR, _X, "FullControl"), _OPERATOR)
    assert ga.accepts_control(ctx, finding, good) is True
    # wrong object
    bad_obj = Capability(states.control_for("sansa.stark"), CAP_CONTROL,
                         ControlGrant(_OPERATOR, "sansa.stark", "FullControl"), _OPERATOR)
    assert ga.accepts_control(ctx, finding, bad_obj) is False
    # wrong actor (someone else's grant, not the operator's)
    bad_actor = Capability(states.control_for(_X), CAP_CONTROL,
                           ControlGrant("eddard.stark", _X, "FullControl"), "eddard.stark")
    assert ga.accepts_control(ctx, finding, bad_actor) is False
    # not a control capability at all
    not_control = Capability(states.control_for(_X), "nt_hash", _NT, _X)
    assert ga.accepts_control(ctx, finding, not_control) is False
