"""Phase 0: real CLI dispatch with fake tools; reveal is a separate live channel."""
from __future__ import annotations

import io
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from purplesploit.validation import cli, discovery, engine, proof, reveal_sink, states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    AuthorizedLabProvider, CommandRunner, ExecutorContext, RunResult, SecretReveal,
)
from purplesploit.validation.inputs import finding_from_inputs
from purplesploit.validation.orchestrator import AutoConfirm
from purplesploit.validation.probes import ProbeResult


TECHNIQUES = ("DCSYNC", "LAPS", "KERBEROAST")
TARGETS = {"DCSYNC": "dc.example.test", "LAPS": "member.example.test",
           "KERBEROAST": "svc_sql"}
NOTICE = "[--show-flag] suppressed: no interactive terminal\n"


def _secrets(technique, variant=0):
    if technique == "DCSYNC":
        return [("nt_hash", "EXAMPLE\\krbtgt", ("10" if variant == 0 else "20") * 16),
                ("nt_hash", "EXAMPLE\\svc_sql", ("30" if variant == 0 else "40") * 16),
                ("aes_key", "EXAMPLE\\krbtgt", ("50" if variant == 0 else "60") * 32),
                ("aes_key", "EXAMPLE\\svc_sql", ("70" if variant == 0 else "80") * 16)]
    if technique == "LAPS":
        return [("password", "member.example.test\\administrator", f"LAPS_SENTINEL_{variant}!")]
    return [("crackable_hash", "svc_sql", f"$krb5tgs$23$*svc_sql$EXAMPLE*$HASH_SENTINEL_{variant}"),
            ("password", "svc_sql", f"CRACKED_SENTINEL_{variant}!")]


class _Runner(CommandRunner):
    def __init__(self, technique, variant=0, *, success=True, cracked=True, deny_crack=False):
        self.technique = technique
        self.secrets = _secrets(technique, variant)
        self.success = success
        self.cracked = cracked
        self.deny_crack = deny_crack
        self.calls = []

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-secretsdump":
            rows = self.secrets
            output = (f"{rows[0][1]}:502:{'00' * 16}:{rows[0][2]}:::\n"
                      f"{rows[1][1]}:1100:{'00' * 16}:{rows[1][2]}:::\n"
                      f"{rows[2][1]}:aes256-cts-hmac-sha1-96:{rows[2][2]}\n"
                      f"{rows[3][1]}:aes128-cts-hmac-sha1-96:{rows[3][2]}\n")
            # A failure may still have recovered usable data, including on stderr.
            return RunResult(0 if self.success else 1, stdout=output if self.success else "",
                             stderr="" if self.success else output)
        if tool == "impacket-GetLAPSPassword":
            return RunResult(0, stdout="Password: " + self.secrets[0][2])
        if tool == "impacket-GetUserSPNs":
            return RunResult(0, stdout=self.secrets[0][2])
        if tool == "hashcat":
            assert not self.deny_crack, "crack gate was bypassed"
            return RunResult(0, stdout=(self.secrets[1][2] if self.cracked else "")
                             if "--show" in argv else "")
        if tool == "nxc" and argv[1] == "smb":
            return RunResult(0, stdout="SMB [+] authenticated (Pwn3d!)") if self.success else RunResult(
                1, stdout="SMB [-] access denied")
        return RunResult(0, stdout="")


@pytest.fixture
def dispatch(monkeypatch):
    """Inject only tools/confirmation/sink; keep CLI, executor, writers and engine real."""
    original = cli.ValidationOrchestrator.__init__
    delivered = []
    contexts = []
    monkeypatch.setattr(cli, "reveal_to_terminal", delivered.extend)

    def install(runner, *, authorizer=None):
        delivered.clear()
        contexts.clear()

        def init(self, *args, **kwargs):
            kwargs["runner"] = runner
            kwargs["confirmer"] = AutoConfirm(include_unverified=True)
            if authorizer is not None:
                kwargs["authorizer"] = authorizer
            original(self, *args, **kwargs)
            contexts.append(self.context)

        monkeypatch.setattr(cli.ValidationOrchestrator, "__init__", init)
        return delivered, contexts

    return install


def _args(mode, output, show=True):
    args = [mode, "--domain", "example.test", "--dc-ip", "192.0.2.1", "--user", "operator",
            "--password", "operator-input", "--yes", "--output", str(output)]
    return args + (["--show-flag"] if show else [])


def _assert_clean(receipt, secrets, path):
    """Exercise the REAL receipt writer as well as the returned object/token."""
    encoded = json.dumps(receipt)
    proof.write_receipt(receipt, path)
    raw = path.read_bytes()
    for _, _, secret in secrets:
        assert secret not in repr(receipt)
        assert secret not in encoded
        assert secret.encode() not in raw
        assert secret not in (receipt.get("terminal_fact") or {}).get("proof_token", "")
    assert "_reveal" not in encoded


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("show", [False, True])
@pytest.mark.parametrize("success", [False, True])
def test_real_run_invariant_and_token_independence(technique, show, success, tmp_path,
                                                   monkeypatch, dispatch, capsys):
    tokens = []
    for variant in (0, 1):
        runner = _Runner(technique, variant, success=success)
        delivered, contexts = dispatch(runner)
        if not show:
            # Opt-out must not even call the reveal hook (or derive from produced()).
            monkeypatch.setattr(type(get_executor(technique)), "revealed_secrets",
                                lambda *a: pytest.fail("reveal hook called without opt-in"))
        output = tmp_path / str(variant)
        status = cli.main(_args("run", output, show) + [technique, "--target", TARGETS[technique]])
        captured = capsys.readouterr()
        receipt = json.loads(captured.out)
        assert status == (0 if success else 1)
        assert receipt["complete"] is success
        assert contexts[0].config.show_flag is show
        expected = [SecretReveal(technique, *row) for row in runner.secrets]
        assert delivered == (expected if show else [])
        _assert_clean(receipt, runner.secrets, output / "verification-receipt.json")
        for _, _, secret in runner.secrets:
            assert secret not in captured.out + captured.err
            assert secret.encode() not in (output / "receipts" / f"{technique}.json").read_bytes()
        tokens.append((receipt.get("terminal_fact") or {}).get("proof_token"))
    assert tokens[0] == tokens[1]
    if success or technique != "DCSYNC":
        assert tokens[0]  # Compare real proof bytes, not two absent tokens.


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_opt_in_leaves_standalone_receipt_bytes_identical(technique, tmp_path, dispatch, capsys):
    results = []
    for show in (False, True):
        delivered, _ = dispatch(_Runner(technique))
        assert cli.main(_args("run", tmp_path, show) + [technique, "--target", TARGETS[technique]]) == 0
        captured = capsys.readouterr()
        results.append((captured.out, (tmp_path / "receipts" / f"{technique}.json").read_bytes()))
        assert bool(delivered) is show
    assert results[0] == results[1]


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("show", [False, True])
@pytest.mark.parametrize("success", [False, True])
def test_real_chain_dispatch_keeps_report_secret_free(technique, show, success, tmp_path,
                                                      monkeypatch, dispatch, capsys):
    # Phase 0 does not add producer metadata to LAPS/KERBEROAST. A one-edge test
    # graph exercises the real composed dispatch/report writer for each shape.
    edge = get_executor(technique)
    edge.pre = frozenset({states.S0_USER_CREDS})
    edge.eff = frozenset({states.S_DA})
    monkeypatch.setattr(cli, "default_edges", lambda: [edge])
    monkeypatch.setattr(engine, "default_edges", lambda: [edge])
    tokens = []
    for variant in (0, 1):
        runner = _Runner(technique, variant, success=success)
        delivered, _ = dispatch(runner)
        output = tmp_path / str(variant)
        status = cli.main(_args("chain", output, show) + ["--map", f"{technique}={TARGETS[technique]}"])
        assert status == (0 if success else 1)
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["path"] == [technique]
        assert len(report["receipts"]) == 1
        receipt = report["receipts"][0]
        assert delivered == ([SecretReveal(technique, *row) for row in runner.secrets] if show else [])
        _assert_clean(receipt, runner.secrets, output / "verification-receipt.json")
        for _, _, secret in runner.secrets:
            assert secret not in repr(report)
            assert secret not in captured.out + captured.err
            assert secret.encode() not in (output / "chain-report.json").read_bytes()
        tokens.append((receipt.get("terminal_fact") or {}).get("proof_token"))
    assert tokens[0] == tokens[1]


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_pipeline_display_uses_separate_channel(technique, tmp_path, monkeypatch, dispatch, capsys):
    runner = _Runner(technique)
    delivered, _ = dispatch(runner)

    def enumerate_one(orch):
        return [finding_from_inputs(orch.context, get_executor(technique), TARGETS[technique])]

    monkeypatch.setattr(cli.ValidationOrchestrator, "enumerate", enumerate_one)
    monkeypatch.setattr("purplesploit.validation.orchestrator.run_probes",
                        lambda ctx, findings: [ProbeResult(viable=True, reason="fake viable") for _ in findings])
    assert cli.main(_args("pipeline", tmp_path)) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert len(report["executed"]) == 1
    assert delivered == [SecretReveal(technique, *row) for row in runner.secrets]
    receipt_path = Path(report["executed"][0]["receipt"])
    receipt = json.loads(receipt_path.read_text())
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")
    for _, _, secret in runner.secrets:
        assert secret not in captured.out + captured.err
        assert secret.encode() not in receipt_path.read_bytes()


@pytest.mark.parametrize("technique", ["DCSYNC", "KERBEROAST"])
@pytest.mark.parametrize("exploit", [False, True])
def test_discover_display_only_for_exploitation(technique, exploit, tmp_path,
                                                monkeypatch, dispatch, capsys):
    runner = _Runner(technique)
    delivered, _ = dispatch(runner)
    # Keep the real discovery eligibility checks; isolate scope/probes from tooling.
    monkeypatch.setattr(discovery, "candidate_findings", lambda cfg, hosts: [finding_from_inputs(
        ExecutorContext(cfg, runner, AuthorizedLabProvider(), tmp_path),
        get_executor(technique), TARGETS[technique])])
    monkeypatch.setattr(discovery, "recon", lambda ctx: discovery._Recon(None, None, False, None, False))
    monkeypatch.setattr(discovery.probes_mod, "run_probes",
                        lambda ctx, findings: [ProbeResult(viable=True, reason="fake viable") for _ in findings])
    assert cli.main(_args("discover", tmp_path) + (["--exploit"] if exploit else [])) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert len(report["exploited"]) == int(exploit)
    assert delivered == ([SecretReveal(technique, *row) for row in runner.secrets] if exploit else [])
    for _, _, secret in runner.secrets:
        assert secret not in captured.out + captured.err
    for entry in report["exploited"]:
        path = Path(entry["receipt"])
        _assert_clean(json.loads(path.read_text()), runner.secrets, tmp_path / "verification-receipt.json")
        for _, _, secret in runner.secrets:
            assert secret.encode() not in path.read_bytes()


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("composed", [False, True])
def test_recovery_survives_a_later_proof_exception(technique, composed, tmp_path,
                                                  monkeypatch, dispatch, capsys):
    runner = _Runner(technique)
    delivered, contexts = dispatch(runner)

    def proof_failed(*args, **kwargs):
        raise RuntimeError("proof failed after recovery")

    monkeypatch.setattr(proof, "build_terminal_fact", proof_failed)
    if composed:
        edge = get_executor(technique)
        edge.pre = frozenset({states.S0_USER_CREDS})
        edge.eff = frozenset({states.S_DA})
        monkeypatch.setattr(cli, "default_edges", lambda: [edge])
        monkeypatch.setattr(engine, "default_edges", lambda: [edge])
        args = _args("chain", tmp_path) + ["--map", f"{technique}={TARGETS[technique]}"]
    else:
        args = _args("run", tmp_path) + [technique, "--target", TARGETS[technique]]
    assert cli.main(args) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    receipt = report["receipts"][0] if composed else report
    assert receipt["complete"] is False
    assert "executor_exception" in receipt["errors"]
    assert contexts[0]._pending_reveal_artifact is None
    assert delivered == [SecretReveal(technique, *row) for row in runner.secrets]
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")
    for _, _, secret in runner.secrets:
        assert secret not in captured.out + captured.err
        if composed:
            assert secret.encode() not in (tmp_path / "chain-report.json").read_bytes()


@pytest.mark.parametrize("denied", [False, True])
def test_roast_reveals_hash_even_without_crack(denied, tmp_path, dispatch, capsys):
    class DenyCrack(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied" if op == "offline_crack" else "not_required"

    runner = _Runner("KERBEROAST", cracked=False, deny_crack=denied)
    delivered, _ = dispatch(runner, authorizer=DenyCrack() if denied else None)
    assert cli.main(_args("run", tmp_path) + ["KERBEROAST", "--target", "svc_sql"]) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert delivered == [SecretReveal("KERBEROAST", *runner.secrets[0])]
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_no_tty_refuses_real_dispatch(technique, tmp_path, monkeypatch, dispatch, capsys):
    runner = _Runner(technique)
    dispatch(runner)
    monkeypatch.setattr(cli, "reveal_to_terminal", reveal_sink.reveal_to_terminal)
    attempts = []

    def unopened(*args, **kwargs):
        attempts.append((args, kwargs))
        raise OSError("no controlling terminal")

    monkeypatch.setattr(reveal_sink, "open", unopened, raising=False)
    assert cli.main(_args("run", tmp_path) + [technique, "--target", TARGETS[technique]]) == 0
    captured = capsys.readouterr()
    assert captured.err == NOTICE
    assert len(attempts) == 1 and attempts[0][0] == ("/dev/tty", "w")
    receipt = json.loads(captured.out)
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")
    for _, _, secret in runner.secrets:
        assert secret not in captured.out + captured.err


def test_terminal_sink_writes_only_to_tty(monkeypatch, capsys):
    class Terminal(io.StringIO):
        def isatty(self):
            return True

        def close(self):
            self.saved = self.getvalue()
            super().close()

    terminal = Terminal()
    monkeypatch.setattr(reveal_sink, "open", lambda *a, **k: terminal, raising=False)
    reveal = SecretReveal("LAPS", "password", "member\\administrator", "TTY_SENTINEL!")
    reveal_sink.reveal_to_terminal([reveal])
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert "LIVE SECRETS" in terminal.saved
    assert "[LAPS]  password  member\\administrator  TTY_SENTINEL!" in terminal.saved
    assert terminal.closed


def test_non_terminal_handle_is_refused_before_writing(monkeypatch, capsys):
    class NotTerminal(io.StringIO):
        def close(self):
            assert self.getvalue() == ""
            super().close()

    monkeypatch.setattr(reveal_sink, "open", lambda *a, **k: NotTerminal(), raising=False)
    reveal_sink.reveal_to_terminal([SecretReveal("LAPS", "password", "admin", "NOT_WRITTEN!")])
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == NOTICE


def test_lost_terminal_never_falls_back_to_log(monkeypatch, capsys):
    class LostTerminal(io.StringIO):
        def isatty(self):
            return True

        def write(self, text):
            raise OSError("PRIVATE_ERROR_SENTINEL!")

    monkeypatch.setattr(reveal_sink, "open", lambda *a, **k: LostTerminal(), raising=False)
    reveal_sink.reveal_to_terminal([SecretReveal("LAPS", "password", "admin", "NOT_LOGGED!")])
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == NOTICE


def test_reveal_contract_is_frozen_and_default_hook_has_no_products():
    reveal = SecretReveal("LAPS", "password", "admin", "value")
    with pytest.raises(FrozenInstanceError):
        reveal.value = "changed"
    edge = get_executor("ASREP")  # Phase 0 adds no capture/reveal to other techniques.
    assert edge.revealed_secrets({"_reveal": [reveal], "password": "public-key trap"}) == []
    for technique in TECHNIQUES:
        # Each reference hook ignores every public artifact field.
        assert get_executor(technique).revealed_secrets({"reveal": [reveal], "password": "trap"}) == []


@pytest.mark.parametrize("mode", ["run", "chain", "pipeline", "discover"])
def test_shared_flag_parsing_and_default_report_compatibility(mode):
    suffix = ["LAPS"] if mode == "run" else []
    parser = cli.build_parser()
    args = parser.parse_args(["--show-flag", mode, "--domain", "example.test", "--dc-ip", "192.0.2.1"] + suffix)
    assert cli.build_config(args).show_flag is True
    cfg = ValidationConfig("example.test", "192.0.2.1")
    assert cfg.show_flag is False
    assert "show_flag" not in cfg.redacted()
