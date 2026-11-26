"""T3 GENERIC-ALL (GenericAllExecutor): ONE executor, 4 pivots, sharing a
single confirm_ace precondition over `target`:

  pivot == "reset_password"  -> bloodyAD set password + nxc reauth (destructive, no rollback)
  pivot == "spn_kerberoast"  -> write SPN -> roast -> gated crack -> reauth -> rollback clears SPN
  pivot == "shadow_creds"    -> certipy-ad shadow auto (reuses ShadowCredsExecutor's own markers)
  pivot == "rbcd"            -> addcomputer -> rbcd write -> getST S4U -> nxc -k (reuses RBCDExecutor's shape)
"""
from __future__ import annotations

from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
    NonInteractiveDestructiveConfirmer,
)
from purplesploit.validation import states
from purplesploit.validation import proof
from purplesploit.validation.probes import get_probe


class _FakeRunner(CommandRunner):
    """Scripted fake keyed on tool + distinguishing argv shape."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "dacledit.py":
            return "dacledit"
        if tool == "bloodyAD":
            if "password" in argv:
                return "bloodyad:set_pw"
            if "rbcd" in argv:
                return "bloodyad:rbcd"
            if "object" in argv:
                return "bloodyad:clear_spn" if argv[-1] == "" else "bloodyad:set_spn"
            return "bloodyad:other"
        if tool == "impacket-GetUserSPNs":
            return "roast"
        if tool == "hashcat":
            return "hashcat:show" if "--show" in argv else "hashcat:crack"
        if tool == "nxc":
            if argv[1] == "smb":
                return "nxc:access" if "-k" in argv else "nxc:reauth"
            return "nxc:query"
        if tool == "certipy-ad":
            return "shadow"
        if tool == "impacket-addcomputer":
            return "addcomputer:del" if "-delete" in argv else "addcomputer:add"
        if tool == "impacket-rbcd":
            return f"rbcd:{argv[argv.index('-action') + 1]}"
        if tool == "impacket-getST":
            return "getst"
        return tool


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(target="arya.stark"):
    return map_finding({
        "finding_id": "AR-acl6", "host": target, "category": "acl",
        "severity": "high", "line": f"jon.snow has GenericAll over {target}",
    })


def _ctx(cfg, runner, tmp_path, authorizer=None, destructive_confirmer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path,
                           destructive_confirmer=destructive_confirmer)


class _Deny(AuthorizedLabProvider):
    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


_PRECONDITION_GENERICALL = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericAll\n"
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"


def _base_script():
    return {"dacledit": RunResult(0, stdout=_PRECONDITION_GENERICALL)}


def _approved_confirmer():
    return NonInteractiveDestructiveConfirmer(allowed=True)


# ======================================================================= mapping
def test_genericall_maps_and_is_implemented(tmp_path):
    f = _finding()
    assert f.technique == "GENERIC-ALL" and f.entity.get("target") == "arya.stark"
    assert is_implemented("GENERIC-ALL")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("GENERIC-ALL").param_specs(
        _ctx(cfg, _FakeRunner({}), tmp_path), f)}
    assert specs["target"].recommended == "arya.stark"
    assert specs["pivot"].recommended == "shadow_creds"
    assert specs["pivot"].choices == ["reset_password", "spn_kerberoast",
                                      "shadow_creds", "rbcd"]


def test_genericall_plan_terminal_kind_per_pivot(tmp_path):
    cfg = _cfg()
    ex = get_executor("GENERIC-ALL")
    ctx = _ctx(cfg, _FakeRunner({}), tmp_path)
    expected = {"reset_password": "authn_success", "spn_kerberoast": "authn_success",
               "shadow_creds": "secret_recovered", "rbcd": "rbcd_access"}
    for pivot, kind in expected.items():
        plan = ex.plan(ctx, _finding(),
                       overrides={"pivot": pivot, "new_computer": "testpc"})
        assert plan.terminal_kind == kind, pivot


# ======================================================================= precondition
def test_genericall_precondition_insufficient_aborts_before_any_pivot(tmp_path):
    cfg = _cfg(allow_destructive=True)
    script = _base_script()
    script["dacledit"] = RunResult(0, stdout=_INSUFFICIENT_RIGHTS)
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"new_computer": "testpc"})
    assert receipt["complete"] is False
    assert "generic_all_not_confirmed" in receipt["errors"]
    assert not any(Path(c[0]).name in ("bloodyAD", "certipy-ad", "impacket-addcomputer")
                  for c in runner.calls)


def test_genericall_precondition_unknown_still_attempts(tmp_path):
    cfg = _cfg()
    script = _base_script()
    script["dacledit"] = RunResult(None, stdout="", timed_out=True)
    script["shadow"] = RunResult(0, stdout="[*] Got hash for 'arya.stark': "
                                 "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef\n"
                                 "[*] Restoring the old Key Credentials\n"
                                 "[*] Successfully restored previous object\n")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"new_computer": "testpc"})
    assert "advisory:generic_all_unconfirmed_attempting_anyway" in receipt["errors"]
    assert any(Path(c[0]).name == "certipy-ad" for c in runner.calls)


# ======================================================================= reset_password
def test_genericall_reset_password_proved(tmp_path):
    cfg = _cfg()
    script = _base_script()
    script["bloodyad:set_pw"] = RunResult(0, stdout="[*] Password successfully set\n")
    script["nxc:reauth"] = RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL "
                                     "[+] north\\arya.stark (Pwn3d!)")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()),
        _finding(), overrides={"pivot": "reset_password", "new_computer": "testpc"})
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["complete"] is True
    assert receipt["gate"]["classifier"] == "approved"
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is False
    assert any(e.startswith("advisory:irreversible:") for e in receipt["errors"])
    tf = receipt["terminal_fact"]
    assert tf["kind"] == "authn_success" and tf["ok"] is True


def test_genericall_reset_password_gate_denied(tmp_path):
    # no explicit confirmer + allow_destructive not set -> fail-closed default.
    cfg = _cfg(allow_destructive=False)
    runner = _FakeRunner(_base_script())
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "reset_password", "new_computer": "testpc"})
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["gate"]["op"] == "generic_all_reset_password"
    assert receipt["complete"] is False
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)
    assert not any(e.startswith("advisory:irreversible:") for e in receipt["errors"])


# ======================================================================= spn_kerberoast
def _spn_script():
    script = _base_script()
    script["bloodyad:set_spn"] = RunResult(0, stdout="[*] Attribute servicePrincipalName "
                                           "successfully set\n")
    script["bloodyad:clear_spn"] = RunResult(0, stdout="[*] Attribute servicePrincipalName "
                                             "successfully set\n")
    script["roast"] = RunResult(0, stdout="$krb5tgs$23$*arya.stark$NORTH$http/arya.stark*"
                                "$abcd$ef0011223344556677\n")
    script["hashcat:crack"] = RunResult(0, stdout="Recovered........: 1/1 (100.00%)")
    script["hashcat:show"] = RunResult(0, stdout="Needle1n4Haystack!")
    script["nxc:reauth"] = RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL "
                                     "[+] north\\arya.stark (Pwn3d!)")
    script["nxc:query"] = RunResult(0, stdout="LDAP 10.0.0.11 389 DC01 "
                                    "sAMAccountName: arya.stark\n"
                                    "LDAP 10.0.0.11 389 DC01 servicePrincipalName: \n")
    return script


def test_genericall_spn_kerberoast_proved(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_spn_script())
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "spn_kerberoast", "new_computer": "testpc"})
    assert receipt["complete"] is True
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "Needle1n4Haystack!" not in str(receipt)
    tf = receipt["terminal_fact"]
    assert tf["kind"] == "authn_success" and tf["ok"] is True


def test_genericall_spn_kerberoast_offline_crack_denied_still_rolls_back(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_spn_script())
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path, authorizer=_Deny("offline_crack")),
        _finding(), overrides={"pivot": "spn_kerberoast", "new_computer": "testpc"})
    assert receipt["gate"]["classifier"] == "denied" and receipt["gate"]["op"] == "offline_crack"
    assert receipt["complete"] is False
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert not any(Path(c[0]).name == "hashcat" for c in runner.calls)
    assert any(Path(c[0]).name == "bloodyAD" and c[-1] == "" for c in runner.calls)


def test_genericall_spn_kerberoast_rollback_unverified_on_read_error(tmp_path):
    cfg = _cfg()
    script = _spn_script()
    script["nxc:query"] = RunResult(None, stdout="", error="OSError: reset")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "spn_kerberoast", "new_computer": "testpc"})
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


# ======================================================================= shadow_creds
def test_genericall_shadow_creds_proved(tmp_path):
    cfg = _cfg()
    script = _base_script()
    script["shadow"] = RunResult(0, stdout="[*] Got hash for 'arya.stark': "
                                 "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef\n"
                                 "[*] Restoring the old Key Credentials\n"
                                 "[*] Successfully restored previous object\n")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "shadow_creds", "new_computer": "testpc"})
    assert receipt["complete"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "deadbeefdeadbeefdeadbeefdeadbeef" not in str(receipt)
    tf = receipt["terminal_fact"]
    assert tf["kind"] == "secret_recovered" and tf["ok"] is True


def test_genericall_shadow_creds_gate_denied(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_base_script())
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path, authorizer=_Deny("shadow_write")),
        _finding(), overrides={"pivot": "shadow_creds", "new_computer": "testpc"})
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False
    assert not any(Path(c[0]).name == "certipy-ad" for c in runner.calls)


# ======================================================================= rbcd
def _rbcd_script():
    script = _base_script()
    script["addcomputer:add"] = RunResult(0, stdout="[*] Successfully added machine "
                                          "account arya.stark_cmp_delegation$ with password\n")
    script["addcomputer:del"] = RunResult(0, stdout="[*] Successfully deleted machine "
                                          "account arya.stark_cmp_delegation$.\n")
    script["rbcd:write"] = RunResult(0, stdout="[*] Delegation rights modified successfully!\n")
    script["rbcd:flush"] = RunResult(0, stdout="[*] Delegation rights flushed successfully!\n")
    script["rbcd:read"] = RunResult(0, stdout="[*] Accounts allowed to act on behalf "
                                    "of other identity:\n")
    script["getst"] = RunResult(0, stdout="[*] Saving ticket in arya.stark.ccache\n")
    script["nxc:access"] = RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL "
                                     "[+] north\\Administrator (Pwn3d!)")
    return script


def test_genericall_rbcd_proved(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_rbcd_script())
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "rbcd", "new_computer": "testpc"})
    assert receipt["complete"] is True
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf["kind"] == "rbcd_access" and tf["ok"] is True and tf["impersonated"] == "Administrator"


def test_genericall_rbcd_rollback_flush_fail(tmp_path):
    cfg = _cfg()
    script = _rbcd_script()
    script["rbcd:flush"] = RunResult(0, stdout="[-] error\n")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "rbcd", "new_computer": "testpc"})
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_genericall_rbcd_rollback_read_vacuous(tmp_path):
    cfg = _cfg()
    script = _rbcd_script()
    script["rbcd:read"] = RunResult(None, stdout="", error="OSError: reset")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "rbcd", "new_computer": "testpc"})
    assert receipt["mutation"]["rollback"]["verified"] is False


def test_genericall_rbcd_rollback_delete_fail(tmp_path):
    cfg = _cfg()
    script = _rbcd_script()
    script["addcomputer:del"] = RunResult(0, stdout="[-] error\n")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "rbcd", "new_computer": "testpc"})
    assert receipt["mutation"]["rollback"]["verified"] is False


def test_genericall_rbcd_addcomputer_fails_no_further_calls(tmp_path):
    cfg = _cfg()
    script = _rbcd_script()
    script["addcomputer:add"] = RunResult(0, stdout="[-] access denied\n")
    runner = _FakeRunner(script)
    receipt = get_executor("GENERIC-ALL").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"pivot": "rbcd", "new_computer": "testpc"})
    assert receipt["complete"] is False
    assert "addcomputer_failed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is False
    assert not any(Path(c[0]).name == "impacket-rbcd" for c in runner.calls)


# ======================================================================= target_identity
def test_genericall_target_identity_per_pivot(tmp_path):
    cfg = _cfg()
    ex = get_executor("GENERIC-ALL")
    ctx = _ctx(cfg, _FakeRunner({}), tmp_path)
    f = _finding()
    for pivot in ("reset_password", "spn_kerberoast"):
        params = {"target": type("V", (), {"value": "arya.stark"})(),
                 "pivot": type("V", (), {"value": pivot})()}
        ident = ex.target_identity(ctx, f, params)
        assert ident == {"domain": "north.sevenkingdoms.local", "principal": "arya.stark"}
    params = {"target": type("V", (), {"value": "arya.stark"})(),
             "pivot": type("V", (), {"value": "shadow_creds"})()}
    ident = ex.target_identity(ctx, f, params)
    assert ident == {"domain": "north.sevenkingdoms.local", "account": "arya.stark"}
    params = {"target": type("V", (), {"value": "winterfell.north.sevenkingdoms.local"})(),
             "pivot": type("V", (), {"value": "rbcd"})()}
    ident = ex.target_identity(ctx, f, params)
    assert ident == cfg.resolve_target_identity("winterfell.north.sevenkingdoms.local")


# ======================================================================= produced()
def test_genericall_produced_per_pivot(tmp_path):
    cfg = _cfg()
    ex = get_executor("GENERIC-ALL")
    ctx = _ctx(cfg, _FakeRunner({}), tmp_path)
    for pivot in ("reset_password", "spn_kerberoast", "shadow_creds"):
        params = {"target": type("V", (), {"value": "arya.stark"})(),
                 "pivot": type("V", (), {"value": pivot})()}
        caps = ex.produced(ctx, _finding(), params, {"complete": True})
        assert len(caps) == 1 and caps[0].state == states.cred_for("arya.stark")
    params = {"target": type("V", (), {"value": "winterfell"})(),
             "pivot": type("V", (), {"value": "rbcd"})(),
             "impersonate": type("V", (), {"value": "Administrator"})()}
    caps = ex.produced(ctx, _finding(), params, {"complete": True})
    assert len(caps) == 1 and caps[0].state == states.S_IMPERSONATION_TGT
    assert caps[0].principal == "Administrator"
    # incomplete -> nothing produced, for every pivot
    params["pivot"] = type("V", (), {"value": "shadow_creds"})()
    assert ex.produced(ctx, _finding(), params, {"complete": False}) == []


# ======================================================================= probe
def test_genericallprobe_viable_when_confirmed(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_base_script())
    pr = get_probe("GENERIC-ALL").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is True and pr.unknown is False


def test_genericallprobe_insufficient_skips(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner({"dacledit": RunResult(0, stdout=_INSUFFICIENT_RIGHTS)})
    pr = get_probe("GENERIC-ALL").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is False
