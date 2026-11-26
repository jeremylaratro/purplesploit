"""T3 FORCE-CHANGE-PASSWORD (ForceChangePasswordExecutor): the destructive
reference case -- dacledit precondition confirm over the VICTIM -> the
``ctx.destructive_confirmer`` runtime gate (exercised end-to-end here for the
FIRST time in the tree) -> bloodyAD password reset -> nxc reauth as the
terminal proof. Rollback is DELIBERATELY NONE, by design: the original
password can never be recovered, so every run that reaches the password-set
step records an ``advisory:irreversible:...`` error and leaves
``mutation.rollback.performed`` permanently ``False`` -- success or not.
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
from purplesploit.validation import proof
from purplesploit.validation.probes import get_probe


class _FakeRunner(CommandRunner):
    """Scripted fake keyed on tool only (the generated password is a random
    secret -- never matched on, exactly like every other T3 fake runner that
    sees a `secrets.token_urlsafe` value)."""

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
            return "bloodyad:set"
        if tool == "nxc":
            return "nxc:reauth" if argv[1] == "smb" else "nxc:other"
        return tool


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(principal="arya.stark"):
    return map_finding({
        "finding_id": "AR-acl5", "host": principal, "category": "acl",
        "severity": "high", "line": f"jon.snow has ForceChangePassword over {principal}",
    })


def _ctx(cfg, runner, tmp_path, authorizer=None, destructive_confirmer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path,
                           destructive_confirmer=destructive_confirmer)


_PRECONDITION_FORCECHANGE = ("ACCESS ALLOWED ACE\n  Trustee: jon.snow  "
                             "Rights: User-Force-Change-Password\n")
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
_SET_OK = "[*] Password for arya.stark successfully set\n"


def _proved_script():
    return {
        "dacledit": RunResult(0, stdout=_PRECONDITION_FORCECHANGE),
        "bloodyad:set": RunResult(0, stdout=_SET_OK),
        "nxc:reauth": RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL "
                                         "[+] north\\arya.stark (Pwn3d!)"),
    }


def test_forcechangepassword_maps_and_is_implemented(tmp_path):
    f = _finding()
    assert f.technique == "FORCE-CHANGE-PASSWORD" and f.entity.get("principal") == "arya.stark"
    assert is_implemented("FORCE-CHANGE-PASSWORD")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("FORCE-CHANGE-PASSWORD").param_specs(
        _ctx(cfg, _FakeRunner({}), tmp_path), f)}
    assert specs["victim"].recommended == "arya.stark"
    assert specs["victim"].required is True


def test_forcechangepassword_emits_proved_shaped_receipt(tmp_path, monkeypatch):
    cfg = _cfg(allow_destructive=True)
    runner = _FakeRunner(_proved_script())
    # pin the generated password to a known marker so its non-leak is a real
    # assertion, not a tautology (mirrors roast.py/targeted_kerberoast.py's own
    # "cracked plaintext never appears in the receipt" discipline).
    monkeypatch.setattr(
        "purplesploit.validation.executors.force_change_password.secrets.token_urlsafe",
        lambda n: "Needle1n4Haystack!")
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "FORCE-CHANGE-PASSWORD" and receipt["class"] == "acl"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["gate"]["classifier"] == "approved"
    assert receipt["mutation"]["applied"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    # neither the operator's own password nor the freshly generated one
    # appears anywhere in the (fully serializable) receipt
    assert "iknownothing" not in str(receipt)
    assert "Needle1n4Haystack!" not in str(receipt)
    # rollback is DELIBERATELY never performed for this technique
    assert receipt["mutation"]["rollback"]["performed"] is False
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert any(e.startswith("advisory:irreversible:") for e in receipt["errors"])
    assert "arya.stark@north.sevenkingdoms.local" in next(
        e for e in receipt["errors"] if e.startswith("advisory:irreversible:"))


def test_forcechangepassword_precondition_insufficient_aborts(tmp_path):
    cfg = _cfg(allow_destructive=True)
    script = _proved_script()
    script["dacledit"] = RunResult(0, stdout=_INSUFFICIENT_RIGHTS)
    runner = _FakeRunner(script)
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "force_change_password_not_confirmed" in receipt["errors"]
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)
    assert not any(e.startswith("advisory:irreversible:") for e in receipt["errors"])


def test_forcechangepassword_destructive_gate_denied_no_mutation(tmp_path):
    # allow_destructive NOT set -> the default NonInteractiveDestructiveConfirmer
    # (ExecutorContext.__post_init__) fail-closes to False.
    cfg = _cfg(allow_destructive=False)
    runner = _FakeRunner(_proved_script())
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["gate"]["op"] == "force_change_password"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"] is False
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)
    assert not any(e.startswith("advisory:irreversible:") for e in receipt["errors"])
    assert "gate_denied:force_change_password" in receipt["errors"]


def test_forcechangepassword_destructive_gate_approved_explicit_confirmer(tmp_path):
    cfg = _cfg()
    confirmer = NonInteractiveDestructiveConfirmer(allowed=True)
    runner = _FakeRunner(_proved_script())
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=confirmer), _finding())
    assert receipt["gate"]["classifier"] == "approved"
    assert receipt["complete"] is True
    assert any(Path(c[0]).name == "bloodyAD" for c in runner.calls)


def test_forcechangepassword_reauth_fails_still_irreversible(tmp_path):
    cfg = _cfg(allow_destructive=True)
    script = _proved_script()
    script["nxc:reauth"] = RunResult(0, stdout="SMB 10.0.0.11 445 WINTERFELL [-] auth failed")
    runner = _FakeRunner(script)
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "reauth_failed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is True
    # the set call was issued -> irreversible from here, success or not
    assert any(e.startswith("advisory:irreversible:") for e in receipt["errors"])
    assert receipt["mutation"]["rollback"]["performed"] is False
    tf = receipt["terminal_fact"]
    assert tf is not None and tf["ok"] is False


def test_forcechangepassword_set_fails_no_irreversible_advisory(tmp_path):
    # the set call itself never ran successfully -- still, once issued, the
    # advisory is recorded (the write was attempted against AD regardless of
    # whether our success marker matched the tool's own output).
    cfg = _cfg(allow_destructive=True)
    script = _proved_script()
    script["bloodyad:set"] = RunResult(0, stdout="[-] access denied")
    runner = _FakeRunner(script)
    receipt = get_executor("FORCE-CHANGE-PASSWORD").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "password_set_failed" in receipt["errors"]
    assert receipt["terminal_fact"] is None
    assert not any(Path(c[0]).name == "nxc" for c in runner.calls)
    assert any(e.startswith("advisory:irreversible:") for e in receipt["errors"])
    assert receipt["mutation"]["rollback"]["performed"] is False


def test_forcechangepasswordprobe_excludes_computer_account(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    pr = get_probe("FORCE-CHANGE-PASSWORD").check(_ctx(cfg, runner, tmp_path),
                                                   _finding(principal="WEB01$"))
    assert pr.viable is False and pr.evidence.get("is_user") is False


def test_forcechangepasswordprobe_viable_when_confirmed(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(_proved_script())
    pr = get_probe("FORCE-CHANGE-PASSWORD").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is True and pr.unknown is False
