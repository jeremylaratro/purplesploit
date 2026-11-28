"""Interrupt/exception recovery uses fake runners only; no network or tooling."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from purplesploit.validation import proof
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    AuthorizedLabProvider, CommandRunner, ExecutorContext, RunResult, StubNotImplemented,
)
from purplesploit.validation.executors.process_manager import ProcessManager, ProcHandle


_HOST = "dc01.north.sevenkingdoms.local"
_PRECONDITION = "ACCESS ALLOWED ACE\n  Trustee: jon.snow Rights: GenericAll\n"


def _ctx(tmp_path, runner, *, composed=False):
    cfg = ValidationConfig(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                           username="jon.snow", password="private-operator-password",
                           allow_destructive=True, tool_timeout_s=0, poll_interval_s=0)
    ctx = ExecutorContext(cfg, runner, AuthorizedLabProvider(True), tmp_path, composed=composed)
    runner.ctx = ctx
    return ctx


def _finding():
    return map_finding({"finding_id": "rollback-test", "host": _HOST,
                        "category": "acl", "severity": "high",
                        "line": f"jon.snow has GenericAll over {_HOST}"})


# Every requested executor, including every GENERIC-ALL pivot, reaches its first
# mutating call with a registered obligation in standalone AND composed mode.
_CASES = [
    ("RBCD", {"new_computer": "testpc", "delegate_to": _HOST}),
    ("ADCS-ESC1", {"ca": "LAB-CA", "template": "User", "ca_host": _HOST}),
    ("ESC8", {"ca_host": _HOST, "victim_dc": _HOST, "listener_host": "10.0.0.2"}),
    ("CERTIFRIED", {"ca": "LAB-CA", "ca_host": _HOST, "dc_fqdn": _HOST,
                    "new_computer": "testpc"}),
    ("WRITE-DACL", {"target": "victim", "trustee": "jon.snow"}),
    ("WRITE-OWNER", {"target": "victim", "trustee": "jon.snow"}),
    ("ADD-MEMBER", {"group": "it_admins", "member": "jon.snow"}),
    ("GPO-ABUSE", {"gpo_guid": "31B2F340-016D-11D2-945F-00C04FB984F9"}),
    ("FORCE-CHANGE-PASSWORD", {"victim": "victim"}),
    ("TARGETED-KERBEROAST", {"victim": "victim"}),
    ("GENERIC-ALL", {"target": "victim", "pivot": "reset_password"}),
    ("GENERIC-ALL", {"target": "victim", "pivot": "spn_kerberoast"}),
    ("GENERIC-ALL", {"target": "victim", "pivot": "shadow_creds"}),
    ("GENERIC-ALL", {"target": _HOST, "pivot": "rbcd", "new_computer": "testpc"}),
    ("SHADOW-CREDS", {"account": "victim"}),
    ("OPENSHARES-WRITE", {"share": "all", "canary_name": "rollback_canary.txt"}),
]


class _WriteThenStop(CommandRunner):
    def __init__(self, failure):
        self.failure = failure
        self.written = False

    def write(self):
        assert self.ctx._pending_teardown is not None, "obligation missing at write time"
        self.written = True  # model the remote mutation BEFORE the runner raises
        raise self.failure("stopped after the write")

    def run(self, argv, **kwargs):
        tool = argv[0]
        mutating = (
            tool == "impacket-addcomputer"
            or tool in {"impacket-dacledit", "impacket-owneredit"} and "write" in argv
            or tool == "bloodyAD" and ("add" in argv or "set" in argv)
            or tool == "certipy-ad" and argv[1] in {"req", "account", "shadow"}
            or tool == "nxc" and "--put-file" in argv
            or tool == "smbclient" and argv[-1].startswith("put ")
        )
        if mutating:
            self.write()
        return RunResult(0, stdout=_PRECONDITION)


class _WriteOnStart(ProcessManager):
    """A relay can issue a certificate as soon as the listener starts."""
    def __init__(self, runner):
        self.runner = runner

    def start(self, argv, **kwargs):
        self.runner.write()

    def read(self, handle):
        return ""

    def poll(self, handle):
        return None

    def stop(self, handle):
        return ""


@pytest.mark.parametrize("technique,overrides", _CASES,
                         ids=[t + ":" + o.get("pivot", "write") for t, o in _CASES])
@pytest.mark.parametrize("composed", [False, True], ids=["standalone", "composed"])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt], ids=["error", "sigint"])
def test_every_write_preregisters_and_recovers(tmp_path, monkeypatch, technique, overrides,
                                              composed, failure):
    runner = _WriteThenStop(failure)
    ctx = _ctx(tmp_path, runner, composed=composed)
    ctx.proc_manager = _WriteOnStart(runner)
    ex = get_executor(technique)
    finding = _finding()
    params = ex._params(ctx, finding, overrides)
    # GENERIC-ALL's composed precondition needs an established control grant;
    # the test concerns write registration, not the separately tested grant gate.
    if technique == "GENERIC-ALL":
        monkeypatch.setattr(ex, "accepts_control", lambda *args: True)
    cleaned = []

    def teardown(context, obligation):
        assert runner.written
        assert obligation is context._pending_teardown
        cleaned.append(obligation)
        return {"performed": True, "verified": False, "method": "fake unverified restore"}

    monkeypatch.setattr(ex, "teardown", teardown)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt, match="stopped after the write"):
            ex._execute_to_artifact(ctx, finding, params)
        artifact = ctx._last_artifact
    else:
        artifact = ex._execute_to_artifact(ctx, finding, params)
    assert len(cleaned) == 1
    assert artifact["complete"] is False
    assert artifact["mutation"]["applied"] is True
    assert artifact["mutation"]["dirty"] is True
    assert artifact["mutation"]["rollback"]["verified"] is False
    receipt = ex._receipt_from(ctx, finding, params, artifact)
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["dirty"] is True
    assert "teardown_obligation" not in json.dumps(receipt)
    assert "private-operator-password" not in json.dumps(receipt)
    assert str(tmp_path) not in json.dumps(receipt)


class _RBCDRunner(CommandRunner):
    """Models the computer + SD, with a stop after a real fake-state write."""
    def __init__(self, *, failure=None, stop_at="getst", verify=True, cleanup_failure=None):
        self.failure = failure
        self.stop_at = stop_at
        self.verify = verify
        self.cleanup_failure = cleanup_failure
        self.computer = False
        self.delegation = False
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        tool = argv[0]
        if tool == "impacket-addcomputer":
            if "-delete" in argv:
                self.computer = False
                return RunResult(0, stdout="Successfully deleted computer account")
            assert self.ctx._pending_teardown is not None
            self.computer = True
            self._stop("add")
            return RunResult(0, stdout="Successfully added computer account")
        if tool == "impacket-rbcd":
            action = argv[argv.index("-action") + 1]
            if action == "write":
                assert self.ctx._pending_teardown is not None
                self.delegation = True
                self._stop("write")
                return RunResult(0, stdout="Delegation rights modified successfully")
            if action == "flush":
                if self.cleanup_failure:
                    raise self.cleanup_failure("cleanup stopped")
                self.delegation = False
                return RunResult(0, stdout="Delegation rights flushed")
            return RunResult(0, stdout="Accounts allowed to act on behalf" if self.verify else "")
        if tool == "impacket-getST":
            self._stop("getst")
            return RunResult(0, stdout="Saving ticket in Administrator.ccache")
        return RunResult(0, stdout="SMB [+] auth success")

    def _stop(self, step):
        if self.failure and step == self.stop_at:
            raise self.failure("mutation stopped")


def _run_rbcd(ctx):
    return get_executor("RBCD").run(ctx, _finding(), overrides={"new_computer": "testpc"})


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stop_at", ["add", "write", "getst"])
@pytest.mark.parametrize("verify", [False, True])
def test_rbcd_real_teardown_and_verified_gate(tmp_path, failure, stop_at, verify):
    runner = _RBCDRunner(failure=failure, stop_at=stop_at, verify=verify)
    ctx = _ctx(tmp_path, runner)
    if failure is RuntimeError:
        receipt = _run_rbcd(ctx)
    else:
        with pytest.raises(failure, match="mutation stopped"):
            _run_rbcd(ctx)
    artifact = ctx._last_artifact
    assert not runner.computer and not runner.delegation
    assert artifact["mutation"]["applied"] is True
    assert artifact["mutation"]["rollback"]["verified"] is verify
    assert artifact["mutation"]["dirty"] is (not verify)
    if failure is RuntimeError:
        assert receipt["mutation"] == artifact["mutation"]
    assert sum("-delete" in a for a in runner.calls) == 1
    assert ("teardown_obligation" in artifact) is (not verify)


@pytest.mark.parametrize("verify", [False, True])
def test_normal_rbcd_rollback_runs_once(tmp_path, verify):
    runner = _RBCDRunner(verify=verify)
    ctx = _ctx(tmp_path, runner)
    receipt = _run_rbcd(ctx)
    assert receipt["complete"] is True
    assert receipt["mutation"]["rollback"]["verified"] is verify
    assert receipt["mutation"]["dirty"] is (not verify)
    assert sum("flush" in a for a in runner.calls) == 1
    assert sum("-delete" in a for a in runner.calls) == 1


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("cleanup_failure", [RuntimeError, KeyboardInterrupt])
def test_cleanup_failure_preserves_dirty_and_original_interrupt(tmp_path, failure, cleanup_failure):
    runner = _RBCDRunner(failure=failure, cleanup_failure=cleanup_failure)
    ctx = _ctx(tmp_path, runner)
    expected_stop = failure is KeyboardInterrupt or cleanup_failure is KeyboardInterrupt
    if expected_stop:
        with pytest.raises(KeyboardInterrupt):
            _run_rbcd(ctx)
    else:
        _run_rbcd(ctx)
    mutation = ctx._last_artifact["mutation"]
    assert mutation["applied"] is True and mutation["dirty"] is True
    assert mutation["rollback"]["verified"] is False
    assert "teardown_exception" in ctx._last_artifact["errors"]
    assert ctx._last_artifact["teardown_obligation"] is ctx._pending_teardown
    assert sum("flush" in a for a in runner.calls) == 1


def test_stub_handling_is_preserved(tmp_path, monkeypatch):
    runner = _RBCDRunner()
    ctx = _ctx(tmp_path, runner)
    ex = get_executor("RBCD")

    def stub(*args):
        raise StubNotImplemented("private detail")

    monkeypatch.setattr(ex, "execute", stub)
    artifact = ex._execute_to_artifact(ctx, _finding(), {})
    assert artifact == {"steps": [], "complete": False, "errors": ["stub_not_implemented"]}
    assert ctx._pending_teardown is None


def test_dirty_normalization_cannot_fabricate_clean_or_unapplied():
    mutation = proof.normalize_mutation({"applied": False, "dirty": True,
                                         "rollback": {"performed": True, "verified": True}})
    assert mutation["applied"] is True and mutation["dirty"] is True
    assert mutation["rollback"]["verified"] is False


class _CertificateRunner(CommandRunner):
    def __init__(self, technique, failure, stop_at, *, create_files=True):
        self.technique = technique
        self.failure = failure
        self.stop_at = stop_at
        self.create_files = create_files
        self.calls = []

    def _issue(self):
        assert self.ctx._pending_teardown is not None
        if self.create_files:
            (Path(self.ctx.output_dir) / "unreported-identity.pfx").write_bytes(b"PFX")
        if self.stop_at == "request":
            raise self.failure("issuance stopped")
        return RunResult(0, stdout="Successfully requested certificate\n"
                         "Saved certificate and private key to 'unreported-identity.pfx'")

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == "certipy-ad":
            if argv[1:3] == ["account", "create"]:
                assert self.ctx._pending_teardown is not None
                return RunResult(0, stdout="Successfully created account")
            if argv[1:3] == ["account", "delete"]:
                return RunResult(0, stdout="Successfully deleted account")
            if argv[1] == "req":
                return self._issue()
            if argv[1] == "auth":
                assert self.ctx._pending_teardown is not None
                if self.create_files:
                    (Path(self.ctx.output_dir) / "unreported-cache.ccache").write_bytes(b"CC")
                raise self.failure("auth stopped")
        if argv[0] == "nxc":
            return RunResult(0, stdout="LDAP [+] bound\nsAMAccountName: dc01$")
        # ESC8's coercion triggers issuance in the fake listener.
        return self._issue()


class _CertificatePM(ProcessManager):
    def __init__(self, ctx):
        self.ctx = ctx
        self.stopped = []

    def start(self, argv, **kwargs):
        assert self.ctx._pending_teardown is not None
        return ProcHandle(id="relay")

    def read(self, handle):
        return "GOT certificate"

    def poll(self, handle):
        return None

    def stop(self, handle):
        self.stopped.append(handle.id)
        return "GOT certificate"


@pytest.mark.parametrize("technique", ["ADCS-ESC1", "ESC8", "CERTIFRIED"])
@pytest.mark.parametrize("stop_at", ["request", "auth"])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("create_files", [False, True], ids=["unknown-output", "files-created"])
def test_certificate_recovery_finds_unreported_paths(tmp_path, technique, stop_at,
                                                    failure, create_files):
    runner = _CertificateRunner(technique, failure, stop_at, create_files=create_files)
    ctx = _ctx(tmp_path, runner, composed=True)
    pm = ctx.proc_manager = _CertificatePM(ctx)
    # Do not delete unrelated credentials that predate the mutation.
    unrelated = tmp_path / "preexisting.ccache"
    unrelated.write_bytes(b"keep")
    overrides = next(o for t, o in _CASES if t == technique)
    ex = get_executor(technique)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            ex.run_composable(ctx, _finding(), overrides=overrides)
    else:
        result = ex.run_composable(ctx, _finding(), overrides=overrides)
        assert result.complete is False
        assert (result.teardown_obligation is None) is create_files
    mutation = ctx._last_artifact["mutation"]
    assert mutation["applied"] is True
    assert mutation["rollback"]["verified"] is create_files
    assert mutation["dirty"] is (not create_files)
    assert not (tmp_path / "unreported-identity.pfx").exists()
    assert not (tmp_path / "unreported-cache.ccache").exists()
    assert unrelated.read_bytes() == b"keep"
    if technique == "ESC8":
        assert pm.stopped == ["relay"]
    if technique == "CERTIFRIED":
        assert sum(a[1:3] == ["account", "delete"] for a in runner.calls) == 1


@pytest.mark.parametrize("technique", ["FORCE-CHANGE-PASSWORD", "SHADOW-CREDS",
                                       "GENERIC-ALL:reset_password", "GENERIC-ALL:shadow_creds"])
def test_unrecoverable_original_state_is_dirty(tmp_path, technique):
    name, _, pivot = technique.partition(":")
    overrides = next(o for t, o in _CASES if t == name and (not pivot or o.get("pivot") == pivot))
    runner = _WriteThenStop(RuntimeError)
    ctx = _ctx(tmp_path, runner)
    receipt = get_executor(name).run(ctx, _finding(), overrides=overrides)
    assert runner.written
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["dirty"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert ctx._pending_teardown is not None


def test_noop_teardown_cannot_verify_a_registered_mutation(tmp_path, monkeypatch):
    runner = _WriteThenStop(RuntimeError)
    ctx = _ctx(tmp_path, runner)
    ex = get_executor("RBCD")
    monkeypatch.setattr(ex, "teardown", lambda *args: {"performed": False, "verified": True})
    receipt = ex.run(ctx, _finding(), overrides={"new_computer": "testpc"})
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["dirty"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False


def test_empty_obligation_is_not_a_verified_noop(tmp_path, monkeypatch):
    runner = _RBCDRunner()
    ctx = _ctx(tmp_path, runner)
    ex = get_executor("SHADOW-CREDS")

    def execute(context, *args):
        context._pending_teardown = {}
        raise RuntimeError("write status unknown")

    monkeypatch.setattr(ex, "execute", execute)
    artifact = ex._execute_to_artifact(ctx, _finding(), {})
    assert artifact["mutation"]["applied"] is True
    assert artifact["mutation"]["dirty"] is True
    assert artifact["mutation"]["rollback"]["verified"] is False


def test_recovery_includes_overwritten_unreported_key_material(tmp_path):
    runner = _CertificateRunner("ADCS-ESC1", RuntimeError, "auth")
    ctx = _ctx(tmp_path, runner)
    # auth replaces this credential, but raises before reporting its filename.
    cache = tmp_path / "unreported-cache.ccache"
    cache.write_bytes(b"old unrelated contents")
    overrides = next(o for t, o in _CASES if t == "ADCS-ESC1")
    receipt = get_executor("ADCS-ESC1").run(ctx, _finding(), overrides=overrides)
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert not cache.exists()


def test_partial_key_material_destruction_stays_dirty(tmp_path, monkeypatch):
    runner = _CertificateRunner("ADCS-ESC1", KeyboardInterrupt, "auth")
    ctx = _ctx(tmp_path, runner)
    unlink = Path.unlink

    def deny_cache(path, *args, **kwargs):
        if path.suffix == ".ccache":
            raise PermissionError("cannot destroy credential")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_cache)
    overrides = next(o for t, o in _CASES if t == "ADCS-ESC1")
    with pytest.raises(KeyboardInterrupt):
        get_executor("ADCS-ESC1").run(ctx, _finding(), overrides=overrides)
    mutation = ctx._last_artifact["mutation"]
    assert mutation["applied"] is True and mutation["dirty"] is True
    assert mutation["rollback"]["verified"] is False
    assert (tmp_path / "unreported-cache.ccache").exists()
    assert not (tmp_path / "unreported-identity.pfx").exists()
