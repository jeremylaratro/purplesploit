"""T3 GPO-ABUSE (GpoAbuseExecutor): dacledit precondition confirm (GenericAll/
GenericWrite over the GPO's own AD object) -> DESTRUCTIVE-CONFIRM gate ->
baseline ScheduledTasks.xml snapshot -> malicious immediate-task write +
byte-identical readback confirm -> best-effort versionNumber bump ->
best-effort exercise poll (if `linked_host` given) -> byte-identical rollback
(restore baseline, or an empty skeleton if none existed) + versionNumber
bumped forward again (monotonic, never decremented).

Unlike every other T3 executor's fake, this one simulates a real remote file
STORE across nxc --get-file/--put-file calls (mirrors `_FakeShareRunner` in
test_t1b_deleg_shares_shadow.py), since GpoAbuseExecutor decides GET/PUT
success purely via local-artifact presence + byte-compare, never via nxc's
own (UNVERIFIED) stdout wording -- see gpo_abuse.py's module docstring.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

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
    """dacledit/bloodyAD responses are scripted via simple flags; nxc
    --get-file/--put-file simulate a real remote file store keyed by remote
    path, exactly like a real SMB share would behave."""

    def __init__(self):
        self.store: dict[str, bytes] = {}
        self.calls: list[list[str]] = []
        self.dacledit_ok: Optional[bool] = True     # True/False/None (unreadable)
        self.exercise_succeeds = False
        self.version_number = 5
        self.version_get_fails = False
        self.version_set_fails = False
        self.get_errors: set[str] = set()
        self.put_errors: set[str] = set()
        # remote path -> N: the (N+1)-th and later PUTs to that path are
        # silently no-ops (the call "succeeds" but the store never updates),
        # simulating a restore that issues cleanly but never actually sticks.
        self.freeze_remote_after: dict[str, int] = {}
        self._put_counts: dict[str, int] = {}

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-dacledit":
            return self._dacledit()
        if tool == "bloodyAD":
            return self._bloodyad(argv)
        if tool == "nxc":
            return self._nxc(argv)
        return RunResult(returncode=1, stderr=f"unexpected tool {tool}")

    def _dacledit(self) -> RunResult:
        if self.dacledit_ok is None:
            return RunResult(0, stdout="")
        rights = "GenericAll" if self.dacledit_ok else "ReadProperty"
        return RunResult(0, stdout=f"ACCESS ALLOWED ACE\n  Trustee: jon.snow  Rights: {rights}\n")

    def _bloodyad(self, argv) -> RunResult:
        if "get" in argv:
            if self.version_get_fails:
                return RunResult(0, stdout="[*] no such attribute")
            return RunResult(0, stdout=f"versionNumber: {self.version_number}")
        if "set" in argv:
            if self.version_set_fails:
                return RunResult(1, stdout="", stderr="attribute update failed")
            i = argv.index("-v")
            self.version_number = int(argv[i + 1])
            return RunResult(0, stdout="[+] Attribute versionNumber successfully updated")
        return RunResult(returncode=1, stderr="unexpected bloodyAD invocation")

    def _nxc(self, argv) -> RunResult:
        if "--get-file" in argv:
            i = argv.index("--get-file")
            return self._get(argv[i + 1], argv[i + 2])
        if "--put-file" in argv:
            i = argv.index("--put-file")
            return self._put(argv[i + 2], argv[i + 1])
        return RunResult(returncode=1, stderr="unexpected nxc invocation")

    def _get(self, remote: str, local: str) -> RunResult:
        if remote in self.get_errors:
            return RunResult(returncode=None, error="OSError: transport failure")
        if remote.startswith("C:\\Windows\\Temp\\t3_gpo_abuse_"):
            if self.exercise_succeeds:
                Path(local).write_bytes(b"nt authority\\system\n")
                return RunResult(0, stdout=f"[*] marker found on {remote}")
            return RunResult(0, stdout=f"[-] {remote}: file not found")
        data = self.store.get(remote)
        if data is not None:
            Path(local).write_bytes(data)
            return RunResult(0, stdout=f"[*] Copying {remote} to {local}")
        return RunResult(0, stdout=f"[-] {remote}: file not found")

    def _put(self, remote: str, local: str) -> RunResult:
        if remote in self.put_errors:
            return RunResult(returncode=None, error="OSError: transport failure")
        n = self._put_counts.get(remote, 0) + 1
        self._put_counts[remote] = n
        threshold = self.freeze_remote_after.get(remote)
        if threshold is not None and n > threshold:
            return RunResult(0, stdout=f"[*] Copying {local} to {remote} (frozen no-op)")
        self.store[remote] = Path(local).read_bytes()
        return RunResult(0, stdout=f"[*] Copying {local} to {remote}")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


_GPO_GUID = "31B2F340-016D-11D2-945F-00C04FB984F9"


def _finding(gpo_guid=_GPO_GUID, linked_host=""):
    line = f"jon.snow has WriteGPO over {{{gpo_guid}}}"
    if linked_host:
        line += f", linked to {linked_host}"
    return map_finding({
        "finding_id": "AR-acl7", "host": gpo_guid, "category": "acl",
        "severity": "high", "line": line,
    })


def _unc(cfg, gpo_guid=_GPO_GUID) -> str:
    return (f"SYSVOL\\{cfg.domain}\\Policies\\{{{gpo_guid}}}\\Machine\\Preferences\\"
            "ScheduledTasks\\ScheduledTasks.xml")


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


def _approved_confirmer():
    return NonInteractiveDestructiveConfirmer(allowed=True)


# ======================================================================= mapping
def test_gpoabuse_maps_and_is_implemented():
    f = _finding()
    assert f.technique == "GPO-ABUSE" and f.entity.get("gpo_guid") == _GPO_GUID
    assert is_implemented("GPO-ABUSE")


def test_gpoabuse_mapping_extracts_linked_host():
    f = _finding(linked_host="winsrv01.north.sevenkingdoms.local")
    assert f.entity.get("linked_host") == "winsrv01.north.sevenkingdoms.local"


def test_gpoabuse_param_specs_defaults(tmp_path):
    cfg = _cfg()
    ex = get_executor("GPO-ABUSE")
    ctx = _ctx(cfg, _FakeRunner(), tmp_path)
    specs = {s.name: s for s in ex.param_specs(
        ctx, _finding(linked_host="winsrv01.north.sevenkingdoms.local"))}
    assert specs["gpo_guid"].recommended == _GPO_GUID
    assert specs["dc_host"].recommended == cfg.dc_ip
    assert specs["linked_host"].recommended == "winsrv01.north.sevenkingdoms.local"
    assert specs["linked_host"].required is False
    assert specs["gpo_guid"].required is True


def test_gpoabuse_plan_shape(tmp_path):
    cfg = _cfg()
    ex = get_executor("GPO-ABUSE")
    ctx = _ctx(cfg, _FakeRunner(), tmp_path)
    plan = ex.plan(ctx, _finding())
    assert plan.terminal_kind == "file_write_readback"
    assert plan.mutating is True
    assert plan.target == {"domain": cfg.domain, "gpo_guid": _GPO_GUID}
    assert ex.destructive is True
    assert plan.steps_preview


# ======================================================================= precondition
def test_gpoabuse_precondition_insufficient_aborts_before_any_write(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner()
    runner.dacledit_ok = False
    receipt = get_executor("GPO-ABUSE").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["complete"] is False
    assert "gpo_abuse_not_confirmed" in receipt["errors"]
    assert len(runner.calls) == 1  # only the precondition dacledit read ever ran


def test_gpoabuse_precondition_unknown_still_attempts(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    runner.dacledit_ok = None
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert "advisory:gpo_abuse_unconfirmed_attempting_anyway" in receipt["errors"]
    assert receipt["complete"] is True  # unknown never blocks -- only a positive negative does


# ======================================================================= destructive gate
def test_gpoabuse_destructive_gate_denied_no_write_issued(tmp_path):
    cfg = _cfg(allow_destructive=False)
    runner = _FakeRunner()
    receipt = get_executor("GPO-ABUSE").run(_ctx(cfg, runner, tmp_path), _finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["gate"]["op"] == "gpo_abuse_immediate_task"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "gate_denied:gpo_abuse_immediate_task" in receipt["errors"]
    assert not any("--put-file" in call for call in runner.calls)
    assert not any("--get-file" in call for call in runner.calls)


# ======================================================================= proved shapes
def test_gpoabuse_proved_with_linked_host_exercise_confirmed(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    runner.exercise_succeeds = True
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()),
        _finding(linked_host="winsrv01.north.sevenkingdoms.local"))
    assert receipt["complete"] is True
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "file_write_readback" and tf["ok"] is True and tf["proof_token"]
    assert "advisory:no_linked_host_exercise_not_confirmed" not in receipt["errors"]


def test_gpoabuse_proved_without_linked_host_is_narrower_with_advisory(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert receipt["complete"] is True
    assert receipt["terminal_fact"]["ok"] is True
    assert "advisory:no_linked_host_exercise_not_confirmed" in receipt["errors"]
    # the exercise poll must never have been attempted at all without a target.
    assert not any("C:\\Windows\\Temp\\t3_gpo_abuse_" in a
                   for call in runner.calls for a in call)


def test_gpoabuse_exercise_times_out_never_fabricates_ok(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=0, poll_interval_s=0)
    runner = _FakeRunner()
    runner.exercise_succeeds = False
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()),
        _finding(linked_host="winsrv01.north.sevenkingdoms.local"))
    assert receipt["terminal_fact"]["ok"] is False
    assert receipt["complete"] is False
    # the write + rollback still ran honestly -- only the exercise failed.
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True


# ======================================================================= rollback
def test_gpoabuse_rollback_with_no_baseline_restores_empty_skeleton(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()  # store starts empty -- no pre-existing baseline
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "rollback_unverified" not in receipt["errors"]
    assert "advisory:gpo_version_number_not_reverted_monotonic_versioning" in receipt["errors"]
    restored = runner.store[_unc(cfg)]
    assert restored.startswith(b"<ScheduledTasks")
    assert b"ImmediateTaskV2" not in restored  # the malicious task is gone


def test_gpoabuse_rollback_unverified_when_restore_doesnt_stick(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    unc = _unc(cfg)
    runner.store[unc] = b"<ScheduledTasks><!-- pre-existing baseline --></ScheduledTasks>"
    # call #1 (the malicious write) proceeds normally; call #2 (the rollback
    # restore) is silently frozen -- the remote file never actually reverts,
    # so the post-restore readback still shows the malicious bytes.
    runner.freeze_remote_after[unc] = 1
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_gpoabuse_task_write_not_confirmed_still_rolls_back(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    unc = _unc(cfg)
    # the put "succeeds" (no transport error) but the readback never shows it
    # -- simulated by freezing the remote from the very first write onward.
    runner.freeze_remote_after[unc] = 0
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert receipt["complete"] is False
    assert "gpo_abuse_task_write_not_confirmed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["dirty"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert receipt["mutation"]["rollback"]["performed"] is True


def test_gpoabuse_rollback_gate_denied(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, authorizer=_Deny("rollback"),
            destructive_confirmer=_approved_confirmer()), _finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is False
    assert "gate_denied:rollback" in receipt["errors"]
    assert receipt["complete"] is False  # rollback never performed -> complete requires it


# ======================================================================= version bump
def test_gpoabuse_version_unreadable_bump_still_attempted(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    runner.version_get_fails = True
    receipt = get_executor("GPO-ABUSE").run(
        _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer()), _finding())
    assert "advisory:gpo_baseline_version_unreadable_bump_best_effort" in receipt["errors"]
    assert receipt["complete"] is True


# ======================================================================= composition (C)
def test_gpoabuse_produced_capability_prefers_linked_host(tmp_path):
    cfg = _cfg(allow_destructive=True, tool_timeout_s=5, poll_interval_s=0)
    runner = _FakeRunner()
    runner.exercise_succeeds = True
    ctx = _ctx(cfg, runner, tmp_path, destructive_confirmer=_approved_confirmer())
    ex = get_executor("GPO-ABUSE")
    result = ex.run_composable(ctx, _finding(linked_host="winsrv01.north.sevenkingdoms.local"))
    assert result.complete is True
    assert len(result.capabilities) == 1
    cap = result.capabilities[0]
    assert cap.state == states.control_for("winsrv01.north.sevenkingdoms.local")
    assert cap.principal == "winsrv01.north.sevenkingdoms.local"
    assert cap.channel == "none"


def test_gpoabuse_produced_empty_when_incomplete(tmp_path):
    cfg = _cfg(allow_destructive=False)
    runner = _FakeRunner()
    ex = get_executor("GPO-ABUSE")
    result = ex.run_composable(_ctx(cfg, runner, tmp_path), _finding())
    assert result.complete is False
    assert result.capabilities == []


# ======================================================================= probe
def test_gpoabuse_probe_viable(tmp_path):
    cfg = _cfg()
    ctx = _ctx(cfg, _FakeRunner(), tmp_path)
    result = get_probe("GPO-ABUSE").check(ctx, _finding())
    assert result.viable is True and result.unknown is False


def test_gpoabuse_probe_insufficient(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner()
    runner.dacledit_ok = False
    ctx = _ctx(cfg, runner, tmp_path)
    result = get_probe("GPO-ABUSE").check(ctx, _finding())
    assert result.viable is False


def test_gpoabuse_probe_unknown_on_unreadable(tmp_path):
    cfg = _cfg()
    runner = _FakeRunner()
    runner.dacledit_ok = None
    ctx = _ctx(cfg, runner, tmp_path)
    result = get_probe("GPO-ABUSE").check(ctx, _finding())
    assert result.viable is True and result.unknown is True
