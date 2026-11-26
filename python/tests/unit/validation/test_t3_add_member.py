"""T3 ADD-MEMBER / ADD-SELF (AddMemberExecutor): dacledit precondition confirm
over the GROUP -> bloodyAD add groupMember -> POSITIVE memberOf read-back as
the terminal proof -> verified rollback (remove + positive_absence read-back).
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
    """Scripted dacledit/bloodyAD/nxc fake. ``ldap_reads`` is a queue consumed
    in order for each ``nxc ldap --query`` call."""

    def __init__(self, dacl_read: RunResult, ldap_reads: list, add_res: RunResult,
                remove_res: RunResult = None):
        self.dacl_read = dacl_read
        self.ldap_reads = list(ldap_reads)
        self.add_res = add_res
        self.remove_res = remove_res or RunResult(0, stdout="")
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-dacledit":
            return self.dacl_read
        if tool == "nxc":
            return self.ldap_reads.pop(0) if self.ldap_reads else RunResult(0, stdout="")
        if tool == "bloodyAD":
            verb = argv[argv.index("--host") + 2]
            return self.add_res if verb == "add" else self.remove_res
        return RunResult(0, stdout="")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(line="jon.snow has Self-Membership over group it_admins"):
    return map_finding({
        "finding_id": "AR-acl3", "host": "it_admins", "category": "acl",
        "severity": "high", "line": line,
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


_PRECONDITION_SELFMEMBER = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: Self-Membership\n"
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
_ADD_OK = "[*] jon.snow successfully added to it_admins\n"


def _member_of_present(member="jon.snow", group="it_admins"):
    return RunResult(0, stdout=f"LDAP 10.0.0.11 389 DC01 sAMAccountName: {member}\n"
                              f"LDAP 10.0.0.11 389 DC01 memberOf: CN={group},OU=Groups,"
                              "DC=north,DC=sevenkingdoms,DC=local\n")


def _member_of_absent(member="jon.snow"):
    return RunResult(0, stdout=f"LDAP 10.0.0.11 389 DC01 sAMAccountName: {member}\n"
                              "LDAP 10.0.0.11 389 DC01 memberOf: CN=Domain Users,"
                              "DC=north,DC=sevenkingdoms,DC=local\n")


def test_addmember_maps_and_defaults(tmp_path):
    f = _finding()
    assert f.technique == "ADD-MEMBER" and f.entity.get("group") == "it_admins"
    assert is_implemented("ADD-MEMBER")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("ADD-MEMBER").param_specs(
        _ctx(cfg, _FakeRunner(RunResult(0), [], RunResult(0)), tmp_path), f)}
    assert specs["group"].recommended == "it_admins"
    assert specs["member"].recommended == "jon.snow"           # ADD-SELF default


def test_addself_emits_proved_shaped_receipt(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_present(), _member_of_absent()],   # terminal, rollback-verify
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    receipt = get_executor("ADD-MEMBER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "ADD-MEMBER" and receipt["class"] == "acl"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "file_write_readback" and tf["ok"] is True and tf["proof_token"]
    assert "rollback_unverified" not in receipt["errors"]


def test_addmember_override_different_member(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_present(member="sql_svc"), _member_of_absent(member="sql_svc")],
        add_res=RunResult(0, stdout="[*] sql_svc successfully added to it_admins\n"),
    )
    receipt = get_executor("ADD-MEMBER").run(
        _ctx(cfg, runner, tmp_path), _finding(), overrides={"member": "sql_svc"})
    assert receipt["complete"] is True
    add_call = next(c for c in runner.calls if Path(c[0]).name == "bloodyAD"
                    and c[c.index("--host") + 2] == "add")
    assert "sql_svc" in add_call


def test_addmember_precondition_insufficient_aborts(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_INSUFFICIENT_RIGHTS),
        ldap_reads=[],
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    receipt = get_executor("ADD-MEMBER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "add_member_not_confirmed" in receipt["errors"]
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)


def test_addmember_gate_denied_inconclusive(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[],
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    receipt = get_executor("ADD-MEMBER").run(
        _ctx(cfg, runner, tmp_path, _Deny("add_member")), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert not any(Path(c[0]).name == "bloodyAD" for c in runner.calls)


def test_addmember_terminal_non_vacuous_when_memberof_omits_group(tmp_path):
    # add groupMember reports success but the memberOf re-read never shows the
    # group -> complete=False, never a fabricated proof.
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_absent()],   # terminal readback: group absent
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    receipt = get_executor("ADD-MEMBER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["terminal_fact"]["ok"] is False
    assert receipt["complete"] is False


def test_addmember_rollback_unverified_on_read_error(tmp_path):
    # post-remove memberOf re-read errors -> verified=False even though the
    # remove call itself did not error.
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_present(), RunResult(1, stdout="", error="OSError: reset")],
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    receipt = get_executor("ADD-MEMBER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_addmemberprobe_already_member_skips(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_present()],
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    pr = get_probe("ADD-MEMBER").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is False and pr.evidence.get("already_member") is True


def test_addmemberprobe_viable_when_not_already_member(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_read=RunResult(0, stdout=_PRECONDITION_SELFMEMBER),
        ldap_reads=[_member_of_absent()],
        add_res=RunResult(0, stdout=_ADD_OK),
    )
    pr = get_probe("ADD-MEMBER").check(_ctx(cfg, runner, tmp_path), _finding())
    assert pr.viable is True and pr.unknown is False
