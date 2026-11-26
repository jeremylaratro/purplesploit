"""T3 WRITE-OWNER (WriteOwnerExecutor): dacledit precondition confirm -> baseline
owner read -> take ownership -> self-grant FullControl via DACL write ->
POSITIVE ACE read-back as the terminal proof -> TWO-part verified rollback
(remove ACE + restore the ORIGINAL owner), both required for verified=True.
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
    """Scripted dacledit/owneredit fake. ``dacl_reads``/``owner_reads`` are
    queues consumed in call order for each tool's ``-action read``."""

    def __init__(self, dacl_reads, owner_reads, owner_write_res, ace_write_res,
                remove_res, owner_restore_res=None):
        self.dacl_reads = list(dacl_reads)
        self.owner_reads = list(owner_reads)
        self.owner_write_res = owner_write_res
        self.ace_write_res = ace_write_res
        self.remove_res = remove_res
        self.owner_restore_res = owner_restore_res or owner_write_res
        self.calls: list[list[str]] = []
        self._owner_write_count = 0

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        action = argv[argv.index("-action") + 1]
        if tool == "impacket-dacledit":
            if action == "read":
                return self.dacl_reads.pop(0) if self.dacl_reads else RunResult(0, stdout="")
            if action == "write":
                return self.ace_write_res
            if action == "remove":
                return self.remove_res
        if tool == "impacket-owneredit":
            if action == "read":
                return self.owner_reads.pop(0) if self.owner_reads else RunResult(0, stdout="")
            if action == "write":
                self._owner_write_count += 1
                return (self.owner_write_res if self._owner_write_count == 1
                       else self.owner_restore_res)
        return RunResult(0, stdout="")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-acl2", "host": host, "category": "acl", "severity": "high",
        "line": f"jon.snow has WriteOwner over {host}",
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


_PRECONDITION_WRITEOWNER = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: WriteOwner\n"
_INSUFFICIENT_RIGHTS = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: ReadProperty\n"
_ACE_PRESENT = "ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: GenericAll\n"
_ACE_GONE = "ACCESS ALLOWED ACE\n  Trustee: Administrator  Rights: FullControl\n"
_BASELINE_OWNER = "current owner: NORTH\\Administrator\n"
_RESTORED_OWNER = "current owner: NORTH\\Administrator\n"
_WRONG_OWNER = "current owner: NORTH\\jon.snow\n"
_UNREADABLE_OWNER = ""


def test_writeowner_maps_and_is_implemented():
    f = _finding()
    assert f.technique == "WRITE-OWNER" and f.entity.get("target") == f.host
    assert is_implemented("WRITE-OWNER")


def test_writeowner_emits_proved_shaped_receipt(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_PRECONDITION_WRITEOWNER),  # 1) precondition
                    RunResult(0, stdout=_ACE_PRESENT),                # 6) terminal readback
                    RunResult(0, stdout=_ACE_GONE)],                  # rollback: ace removed
        owner_reads=[RunResult(0, stdout=_BASELINE_OWNER),            # 2) baseline
                     RunResult(0, stdout=_RESTORED_OWNER)],            # rollback: owner restored
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "WRITE-OWNER" and receipt["class"] == "acl"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "file_write_readback" and tf["ok"] is True and tf["proof_token"]
    assert "rollback_unverified" not in receipt["errors"]
    assert "advisory:original_owner_unknown_rollback_unverifiable" not in receipt["errors"]


def test_writeowner_precondition_insufficient_aborts(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_INSUFFICIENT_RIGHTS)],
        owner_reads=[],
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "write_owner_not_confirmed" in receipt["errors"]
    # owneredit must NEVER have been touched.
    assert not any(Path(c[0]).name == "impacket-owneredit" for c in runner.calls)


def test_writeowner_gate_denied_inconclusive(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_PRECONDITION_WRITEOWNER)],
        owner_reads=[RunResult(0, stdout=_BASELINE_OWNER)],
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(
        _ctx(cfg, runner, tmp_path, _Deny("write_owner")), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    owner_writes = [c for c in runner.calls
                    if Path(c[0]).name == "impacket-owneredit" and c[c.index("-action") + 1] == "write"]
    assert owner_writes == []


def test_writeowner_rollback_ace_removal_unverified_on_read_error(tmp_path):
    # ACE removal re-read errors out -> verified=False even though BOTH the
    # remove call and the owner-restore sub-step independently "succeeded".
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_PRECONDITION_WRITEOWNER),
                    RunResult(0, stdout=_ACE_PRESENT),
                    RunResult(1, stdout="", error="OSError: connection reset")],
        owner_reads=[RunResult(0, stdout=_BASELINE_OWNER),
                     RunResult(0, stdout=_RESTORED_OWNER)],
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_writeowner_rollback_owner_restore_unverified_on_mismatch(tmp_path):
    # ACE removal verifies cleanly, but the post-restore owner read shows a
    # DIFFERENT owner than the captured baseline -> verified=False.
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_PRECONDITION_WRITEOWNER),
                    RunResult(0, stdout=_ACE_PRESENT),
                    RunResult(0, stdout=_ACE_GONE)],
        owner_reads=[RunResult(0, stdout=_BASELINE_OWNER),
                     RunResult(0, stdout=_WRONG_OWNER)],
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_writeowner_unreadable_baseline_never_reports_verified_true(tmp_path):
    # Baseline owner read fails -> original_owner never captured -> the owner
    # half of rollback is unverifiable BY CONSTRUCTION, never silently True.
    cfg = _cfg()
    runner = _FakeRunner(
        dacl_reads=[RunResult(0, stdout=_PRECONDITION_WRITEOWNER),
                    RunResult(0, stdout=_ACE_PRESENT),
                    RunResult(0, stdout=_ACE_GONE)],
        owner_reads=[RunResult(1, stdout=_UNREADABLE_OWNER, error="OSError: refused")],
        owner_write_res=RunResult(0, stdout="[*] Owner modified successfully"),
        ace_write_res=RunResult(0, stdout="[*] DACL modified successfully"),
        remove_res=RunResult(0, stdout="[*] DACL modified successfully"),
    )
    receipt = get_executor("WRITE-OWNER").run(_ctx(cfg, runner, tmp_path), _finding())
    assert "advisory:original_owner_unknown_rollback_unverifiable" in receipt["errors"]
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
