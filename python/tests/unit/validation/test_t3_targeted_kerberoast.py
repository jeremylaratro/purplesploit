"""T3 TARGETED-KERBEROAST (TargetedKerberoastExecutor): dacledit precondition
confirm over the VICTIM -> bloodyAD-written SPN -> impacket-GetUserSPNs roast
-> gated hashcat crack -> nxc reauth as the terminal proof -> verified
rollback (clear SPN + positive_absence memberOf-style LDAP readback).
"""
from __future__ import annotations

from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof
from purplesploit.validation.probes import get_probe


class _FakeRunner(CommandRunner):
    """Scripted fake keyed on tool + a distinguishing flag."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "impacket-dacledit":
            return "dacledit"
        if tool == "bloodyAD":
            # ["...", "set", "object", victim, "servicePrincipalName", "-v", value]
            value = argv[-1]
            return "bloodyad:clear" if value == "" else "bloodyad:set"
        if tool == "impacket-GetUserSPNs":
            return "roast"
        if tool == "hashcat":
            return "hashcat:show" if "--show" in argv else "hashcat:crack"
        if tool == "nxc":
            return "nxc:reauth" if argv[1] == "smb" else "nxc:query"
        return tool


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(principal="arya.stark"):
    return map_finding({
        "finding_id": "AR-acl4", "host": principal, "category": "acl",
        "severity": "high", "line": f"jon.snow has GenericWrite over {principal}",
    })


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


class _Deny(AuthorizedLabProvider):
    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


_PRECONDITION_GENERICWRITE = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericWrite\n"
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
_SET_OK = "[*] Attribute servicePrincipalName successfully set\n"
_ROAST_HASH = ("$krb5tgs$23$*arya.stark$NORTH$http/arya.stark*$abcd$"
              "ef0011223344556677\n")


def _proved_script():
    return {
        "dacledit": RunResult(0, stdout=_PRECONDITION_GENERICWRITE),
        "bloodyad:set": RunResult(0, stdout=_SET_OK),
        "bloodyad:clear": RunResult(0, stdout=_SET_OK),
        "roast": RunResult(0, stdout=_ROAST_HASH),
        "hashcat:crack": RunResult(0, stdout="Recovered........: 1/1 (100.00%)"),
        "hashcat:show": RunResult(0, stdout="Needle1n4Haystack!"),
        "nxc:reauth": RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL "
                                         "[+] north\\arya.stark (Pwn3d!)"),
        "nxc:query": RunResult(0, stdout="LDAP 10.0.0.11 389 DC01 "
                                        "sAMAccountName: arya.stark\n"
                                        "LDAP 10.0.0.11 389 DC01 "
                                        "servicePrincipalName: \n"),
    }


def test_targetedkerberoast_maps_and_is_implemented(tmp_path):
    f = _finding()
    assert f.technique == "TARGETED-KERBEROAST" and f.entity.get("principal") == "arya.stark"
    assert is_implemented("TARGETED-KERBEROAST")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("TARGETED-KERBEROAST").param_specs(
        _ctx(cfg, _FakeRunner({}), tmp_path), f)}
    assert specs["victim"].recommended == "arya.stark"
    assert specs["spn"].recommended == "http/arya.stark"


def test_targetedkerberoast_emits_proved_shaped_receipt(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    receipt = get_executor("TARGETED-KERBEROAST").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "TARGETED-KERBEROAST" and receipt["class"] == "acl"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    # the recovered plaintext never appears anywhere in the receipt
    assert "Needle1n4Haystack!" not in str(receipt)
    assert "rollback_unverified" not in receipt["errors"]


def test_targetedkerberoast_precondition_insufficient_aborts(tmp_path):
    cfg = _cfg()
    script = _proved_script()
    script["dacledit"] = RunResult(0, stdout=_INSUFFICIENT_RIGHTS)
    runner = _FakeRunner(script)
    receipt = get_executor("TARGETED-KERBEROAST").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "targeted_kerberoast_not_confirmed" in receipt["errors"]
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)
    assert not any(Path(c[0]).name == "impacket-GetUserSPNs" for c in runner.calls)


def test_targetedkerberoast_writespn_gate_denied_no_mutation(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    receipt = get_executor("TARGETED-KERBEROAST").run(
        _ctx(cfg, runner, tmp_path, _Deny("targeted_kerberoast_write_spn")), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"] is False
    assert receipt["mutation"]["rollback"]["performed"] is False
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)


def test_targetedkerberoast_offlinecrack_gate_denied_still_rolls_back(tmp_path):
    # the SPN write already happened (mutation applied) by the time the
    # offline_crack gate is checked, so a denial here must still trigger the
    # (gated) rollback -- the write is never left dangling.
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    receipt = get_executor("TARGETED-KERBEROAST").run(
        _ctx(cfg, runner, tmp_path, _Deny("offline_crack")), _finding())
    assert receipt["gate"]["classifier"] == "denied" and receipt["gate"]["op"] == "offline_crack"
    assert receipt["complete"] is False
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert not any(Path(c[0]).name == "hashcat" for c in runner.calls)
    assert any(Path(c[0]).name == "bloodyAD" and c[-1] == "" for c in runner.calls)


def test_targetedkerberoast_crack_fails(tmp_path):
    cfg = _cfg()
    script = _proved_script()
    script["hashcat:show"] = RunResult(0, stdout="")   # --show yields no plaintext
    runner = _FakeRunner(script)
    receipt = get_executor("TARGETED-KERBEROAST").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "crack_failed" in receipt["errors"]
    assert receipt["terminal_fact"] is None


def test_targetedkerberoast_rollback_unverified_on_read_error(tmp_path):
    cfg = _cfg()
    script = _proved_script()
    script["nxc:query"] = RunResult(1, stdout="", error="OSError: reset")
    runner = _FakeRunner(script)
    receipt = get_executor("TARGETED-KERBEROAST").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_targetedkerberoastprobe_excludes_computer_account(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    pr = get_probe("TARGETED-KERBEROAST").check(_ctx(cfg, runner, tmp_path),
                                                _finding(principal="WEB01$"))
    assert pr.viable is False and pr.evidence.get("is_user") is False


def test_targetedkerberoastprobe_viable_when_confirmed(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    pr = get_probe("TARGETED-KERBEROAST").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is True and pr.unknown is False
