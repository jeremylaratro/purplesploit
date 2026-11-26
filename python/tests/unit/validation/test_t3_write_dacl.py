"""T3 WRITE-DACL (WriteDaclExecutor): dacledit precondition confirm -> write a new
ACE -> POSITIVE DACL read-back as the terminal proof (never the write call's own
exit code) -> verified rollback (remove + non-vacuous re-read).
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


class _FakeRunner(CommandRunner):
    """Scripted dacledit fake: same read transcript each call unless replaced
    via ``self.reads`` (a queue consumed in order), so pre-write / readback /
    rollback reads can each return different transcripts."""

    def __init__(self, reads: list[RunResult], write_res: RunResult, remove_res: RunResult):
        self.reads = list(reads)
        self.write_res = write_res
        self.remove_res = remove_res
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool != "impacket-dacledit":
            return RunResult(0, stdout="")
        action = argv[argv.index("-action") + 1]
        if action == "read":
            if self.reads:
                return self.reads.pop(0)
            return RunResult(0, stdout="")
        if action == "write":
            return self.write_res
        if action == "remove":
            return self.remove_res
        return RunResult(0, stdout="")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-acl1", "host": host, "category": "acl", "severity": "high",
        "line": f"jon.snow has WriteDacl over {host}",
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


# confirm_ace groups by LINE containing the trustee string, so a fixture must
# carry trustee + rights on the SAME line (matches the plan's own confirm_ace
# grouping, not necessarily the real impacket wording -- that part is
# UNVERIFIED per acl_common.py's module docstring).
_PRECONDITION_ACE = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericAll\n"
_NEW_ACE_PRESENT = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericAll\n"
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
_NO_TRUSTEE_LINE = "ACCESS ALLOWED ACE\n  Trustee: Administrator  Rights: FullControl\n"
_UNREADABLE = "connection refused\n"


def test_writedacl_maps_and_is_implemented():
    f = _finding()
    assert f.technique == "WRITE-DACL" and f.entity.get("target") == f.host
    assert f.entity.get("trustee") == "jon.snow"
    assert is_implemented("WRITE-DACL")


def test_writedacl_emits_proved_shaped_receipt(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_PRECONDITION_ACE),      # 1) confirm precondition
               RunResult(0, stdout=_NEW_ACE_PRESENT),         # 4) positive readback (terminal)
               RunResult(0, stdout=_NO_TRUSTEE_LINE)],         # rollback verify read (ACE gone)
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    ex = get_executor("WRITE-DACL")
    receipt = ex.run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "WRITE-DACL" and receipt["class"] == "acl"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "file_write_readback" and tf["ok"] is True and tf["proof_token"]
    assert "rollback_unverified" not in receipt["errors"]


def test_writedacl_precondition_insufficient_aborts(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_INSUFFICIENT_RIGHTS)],  # trustee's ACE present, wrong rights
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-DACL").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "write_dacl_not_confirmed" in receipt["errors"]
    # dacledit -action write must NEVER have been issued.
    actions = [argv[argv.index("-action") + 1] for argv in runner.calls]
    assert "write" not in actions


def test_writedacl_gate_denied_inconclusive(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_PRECONDITION_ACE)],
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-DACL").run(
        _ctx(cfg, runner, tmp_path, _Deny("write_dacl")), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    actions = [argv[argv.index("-action") + 1] for argv in runner.calls]
    assert "write" not in actions


def test_writedacl_readback_absent_is_not_proved(tmp_path):
    # Write call reports success but the re-read doesn't show the rights ->
    # complete=False, never a fabricated proof.
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_PRECONDITION_ACE),
               RunResult(0, stdout=_NO_TRUSTEE_LINE)],   # readback: rights absent
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-DACL").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["terminal_fact"]["ok"] is False
    assert receipt["complete"] is False


def test_writedacl_rollback_unverified_on_unreadable_reread(tmp_path):
    # remove call reports success, but the post-remove re-read errors out ->
    # verified=False even though the remove call itself "succeeded".
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_PRECONDITION_ACE),
               RunResult(0, stdout=_NEW_ACE_PRESENT),
               RunResult(1, stdout="", error="OSError: connection reset")],
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-DACL").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_writedacl_rollback_verified_when_ace_line_fully_gone(tmp_path):
    # The successful-removal case: the trustee's ACE line disappears ENTIRELY
    # from the re-read (not merely "present but rights unlisted"). confirm_ace
    # returns None here (trustee line not located) -- this must still count as
    # a verified rollback, not an unreadable one.
    cfg = _cfg()
    runner = _FakeRunner(
        reads=[RunResult(0, stdout=_PRECONDITION_ACE),
               RunResult(0, stdout=_NEW_ACE_PRESENT),
               RunResult(0, stdout=_NO_TRUSTEE_LINE)],   # bind-ok, trustee line gone
        write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-DACL").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "rollback_unverified" not in receipt["errors"]
