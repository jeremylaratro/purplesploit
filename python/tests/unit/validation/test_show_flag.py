"""Phase 0: real CLI dispatch with fake tools; reveal is a separate live channel."""
from __future__ import annotations

import base64
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
    Capability, ControlGrant, CAP_CONTROL,
)
from purplesploit.validation.executors.process_manager import ProcessManager, ProcHandle
from purplesploit.validation.executors.share_loot import ShareReader, _Entry
from purplesploit.validation.inputs import finding_from_inputs
from purplesploit.validation.orchestrator import AutoConfirm
from purplesploit.validation.probes import ProbeResult


TECHNIQUES = ("DCSYNC", "LAPS", "KERBEROAST", "ASREP")
TARGETS = {"DCSYNC": "dc.example.test", "LAPS": "member.example.test",
           "KERBEROAST": "svc_sql", "ASREP": "svc_sql"}
NOTICE = "[--show-flag] suppressed: no interactive terminal\n"


def _secrets(technique, variant=0):
    if technique == "DCSYNC":
        return [("nt_hash", "EXAMPLE\\krbtgt", ("10" if variant == 0 else "20") * 16),
                ("nt_hash", "EXAMPLE\\svc_sql", ("30" if variant == 0 else "40") * 16),
                ("aes_key", "EXAMPLE\\krbtgt", ("50" if variant == 0 else "60") * 32),
                ("aes_key", "EXAMPLE\\svc_sql", ("70" if variant == 0 else "80") * 16)]
    if technique == "LAPS":
        return [("password", "member.example.test\\administrator", f"LAPS_SENTINEL_{variant}!")]
    prefix = "$krb5asrep$23$svc_sql@EXAMPLE:" if technique == "ASREP" else "$krb5tgs$23$*svc_sql$EXAMPLE*$"
    return [("crackable_hash", "svc_sql", f"{prefix}HASH_SENTINEL_{variant}"),
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
        if tool in ("impacket-GetUserSPNs", "impacket-GetNPUsers"):
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
            if hasattr(runner, "configure"):
                runner.configure(self.context)
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
    assert '"_reveal":' not in encoded


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
@pytest.mark.parametrize("technique", ["KERBEROAST", "ASREP"])
def test_roast_reveals_hash_even_without_crack(technique, denied, tmp_path, dispatch, capsys):
    class DenyCrack(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied" if op == "offline_crack" else "not_required"

    runner = _Runner(technique, cracked=False, deny_crack=denied)
    delivered, _ = dispatch(runner, authorizer=DenyCrack() if denied else None)
    assert cli.main(_args("run", tmp_path) + [technique, "--target", "svc_sql"]) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert delivered == [SecretReveal(technique, *runner.secrets[0])]
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
    edge = get_executor("ADD-MEMBER")  # Pure mutation primitives recover nothing.
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


# Full rollout: expected lists are independent of production reveal parsers.


_COVERAGE_CASES = [
    "TARGETED-KERBEROAST", "SHADOW-CREDS", "ADCS-ESC1", "ESC8", "ESC11", "CERTIFRIED",
    "GENERIC-ALL:shadow_creds", "GENERIC-ALL:reset_password", "GENERIC-ALL:spn_kerberoast",
    "GENERIC-ALL:rbcd", "FORCE-CHANGE-PASSWORD", "GOLDEN-TICKET", "SILVER-TICKET",
    "DIAMOND-TICKET", "SAPPHIRE-TICKET", "BRONZE-BIT", "S4U2SELF", "CONSTRAINED-DELEG-PT",
    "SHARE-LOOT", "UNCONSTRAINED-DELEG", "NTLM-RELAY", "RBCD",
]
_FORGERS = {"GOLDEN-TICKET", "SILVER-TICKET", "DIAMOND-TICKET", "SAPPHIRE-TICKET"}
_TICKETS = _FORGERS | {"BRONZE-BIT", "S4U2SELF", "CONSTRAINED-DELEG-PT", "RBCD"}
_DC = "dc.example.test"


def _coverage_params(case):
    technique, _, pivot = case.partition(":")
    params = {
        "TARGETED-KERBEROAST": {"victim": "svc_sql"},
        "SHADOW-CREDS": {"account": "svc_sql"},
        "ADCS-ESC1": {"ca": "EXAMPLE-CA", "template": "User", "impersonate": "Administrator"},
        "ESC11": {"ca": "EXAMPLE-CA"},
        "CERTIFRIED": {"ca": "EXAMPLE-CA", "dc_fqdn": _DC, "new_computer": "operator_tmp"},
        "GENERIC-ALL": {"pivot": pivot, "target": "svc_sql", "new_computer": "operator_tmp"},
        "FORCE-CHANGE-PASSWORD": {"victim": "svc_sql"},
        "SILVER-TICKET": {"service_host": _DC},
        "DIAMOND-TICKET": {"forged_user": "Administrator"},
        "RBCD": {"new_computer": "operator_tmp"},
        "NTLM-RELAY": {"mode": "smb_sam"},
    }.get(technique, {}).copy()
    if technique in _FORGERS:
        params["domain_sid"] = "S-1-5-21-111111111-222222222-333333333"
    return params


class _CoveragePM(ProcessManager):
    def __init__(self, runner):
        self.runner = runner

    def start(self, argv, *, env=None, cwd=None):
        path = Path(cwd)
        if self.runner.technique in {"ESC8", "ESC11"}:
            (path / "dc.pfx").write_bytes(self.runner.pfx)
        elif self.runner.technique == "UNCONSTRAINED-DELEG":
            (path / "dc$.ccache").write_bytes(self.runner.ticket)
        elif self.runner.technique == "NTLM-RELAY":
            lootdir = Path(argv[argv.index("-l") + 1])
            (lootdir / "dc_samhashes.sam").write_text(self.runner.dump)
        return ProcHandle(id="reveal-listener")

    def read(self, handle):
        return "GOT certificate"

    def poll(self, handle):
        return None

    def stop(self, handle):
        return self.read(handle)


class _CoverageReader(ShareReader):
    def __init__(self, runner):
        self.runner = runner

    def list_shares(self):
        return ["SYSVOL"]

    def list_dir(self, share, path, limit):
        return [_Entry(".env", False, len(self.runner.loot))] if path == "" else []

    def read_file(self, share, path, max_bytes):
        return self.runner.loot[:max_bytes]

    def close(self):
        pass


class _CoverageRunner(CommandRunner):
    def __init__(self, case, variant=0, *, access=True):
        self.case = case
        self.technique = case.partition(":")[0]
        self.access = access
        self.calls = []
        self.nt = ("91" if variant == 0 else "92") * 16
        self.nt2 = ("93" if variant == 0 else "94") * 16
        self.aes = ("95" if variant == 0 else "96") * 32
        self.password = f"ROLLOUT_PASSWORD_{variant}!"
        self.ticket = f"ROLLOUT_CCACHE_{variant}!".encode() + b"\x00\xff"
        self.pfx = f"ROLLOUT_PFX_{variant}!".encode() + b"\x00\xfe"
        self.hash = f"$krb5tgs$23$*svc_sql$EXAMPLE*$ROLLOUT_HASH_{variant}"
        self.token = f"ROLLOUT_TOKEN_{variant}!"
        self.loot = (f'DB_PASSWORD="{self.password}"\nAPI_KEY={self.token}\n'
                     f'OTHER_PASSWORD=SECOND_{self.password}\n').encode()
        self.dump = (f"EXAMPLE\\krbtgt:502:{'00' * 16}:{self.nt}:::\n"
                     f"EXAMPLE\\svc_sql:1100:{'00' * 16}:{self.nt2}:::\n"
                     f"EXAMPLE\\krbtgt:aes256-cts-hmac-sha1-96:{self.aes}\n")

    def configure(self, ctx):
        Path(ctx.output_dir).mkdir(parents=True, exist_ok=True)
        ctx.config.poll_interval_s = 0
        ctx.config.tool_timeout_s = 1
        ctx.config.forge_key = "ab" * 32
        ctx.config.forge_key_kind = "aes"
        ctx.config.forge_key_nt = "cd" * 16
        ctx.proc_manager = _CoveragePM(self)
        ctx.share_reader_factory = lambda *args: _CoverageReader(self)

    @property
    def secrets(self):
        cc = ("ccache_base64", "Administrator", base64.b64encode(self.ticket).decode())
        if self.technique in _TICKETS or self.case == "GENERIC-ALL:rbcd":
            return [cc]
        if self.technique in {"ESC8", "ESC11", "CERTIFRIED"}:
            return [("pfx_base64", "dc$", base64.b64encode(self.pfx).decode()),
                    ("ccache_base64", "dc$", cc[2]), ("nt_hash", "dc$", self.nt)]
        dumps = [("nt_hash", "EXAMPLE\\krbtgt", self.nt),
                 ("nt_hash", "EXAMPLE\\svc_sql", self.nt2),
                 ("aes_key", "EXAMPLE\\krbtgt", self.aes)]
        if self.technique == "UNCONSTRAINED-DELEG":
            return [("ccache_base64", "dc$", cc[2]), *dumps]
        if self.technique == "NTLM-RELAY":
            return dumps
        if self.technique == "SHARE-LOOT":
            path = f"{_DC}/SYSVOL/.env"
            return [("api_token", path, self.token), ("password", path, self.password),
                    ("password", path, "SECOND_" + self.password)]
        if self.technique == "ADCS-ESC1":
            return [("nt_hash", "Administrator", self.nt)]
        if self.technique == "SHADOW-CREDS" or self.case == "GENERIC-ALL:shadow_creds":
            return [("nt_hash", "svc_sql", self.nt)]
        if self.technique == "TARGETED-KERBEROAST" or self.case == "GENERIC-ALL:spn_kerberoast":
            return [("crackable_hash", "svc_sql", self.hash), ("password", "svc_sql", self.password)]
        return [("password", "svc_sql", self.password)]

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-dacledit":
            return RunResult(0, "ACCESS ALLOWED ACE\nTrustee: operator  Rights: GenericAll\n")
        if tool == "bloodyAD":
            if "password" in argv:
                assert argv[-1] == self.password
            return RunResult(0, "Attribute successfully set; password successfully set")
        if tool == "impacket-GetUserSPNs":
            return RunResult(0, self.hash)
        if tool == "hashcat":
            return RunResult(0, self.password if "--show" in argv else "")
        if tool == "certipy-ad":
            if argv[1] == "shadow":
                return RunResult(0, f"Got hash for 'svc_sql': {'00' * 16}:{self.nt}\nSuccessfully restored")
            if argv[1] == "account":
                return RunResult(0, "Successfully created account" if argv[2] == "create"
                                 else "Successfully deleted account")
            if argv[1] == "req":
                (Path(cwd) / "issued.pfx").write_bytes(self.pfx)
                return RunResult(0, "Successfully requested certificate\n"
                                 "Saved certificate and private key to 'issued.pfx'")
            if argv[1] == "auth":
                (Path(cwd) / "dc.ccache").write_bytes(self.ticket)
                principal = "Administrator" if self.technique == "ADCS-ESC1" else "dc$"
                return RunResult(0, "Got TGT\nSaved credential cache to 'dc.ccache'\n"
                                 f"Got hash for '{principal}': {'00' * 16}:{self.nt}")
        if tool == "impacket-addcomputer":
            return RunResult(0, "Successfully deleted computer account" if "-delete" in argv
                             else "Successfully added computer account")
        if tool == "impacket-rbcd":
            action = argv[argv.index("-action") + 1]
            return RunResult(0, {"write": "Delegation rights modified successfully",
                                 "flush": "Delegation rights flushed", "read": "Accounts allowed to act"}[action])
        if tool in {"impacket-getST", "impacket-ticketer"}:
            if self.technique == "BRONZE-BIT" and "-force-forwardable" not in argv:
                return RunResult(1, "KDC_ERR_BADOPTION")
            name = argv[-1] if tool == "impacket-ticketer" else "impersonated"
            (Path(cwd) / f"{name}.ccache").write_bytes(self.ticket)
            return RunResult(0, f"Saving ticket in {name}.ccache")
        if tool == "impacket-secretsdump":
            return RunResult(0, self.dump)
        if tool == "nxc":
            if argv[1] == "ldap":
                return RunResult(0, "LDAP [+] EXAMPLE\\operator\nsAMAccountName: svc_sql\n")
            return RunResult(0, "SMB [+] EXAMPLE\\Administrator from ccache (Pwn3d!)"
                             if self.access else ("SMB [+] EXAMPLE\\Administrator" if self.technique == "S4U2SELF"
                                                  else "SMB [-] access denied"))
        return RunResult(0, "")


@pytest.mark.parametrize("case", _COVERAGE_CASES)
@pytest.mark.parametrize("show", [False, True])
@pytest.mark.parametrize("composed", [False, True])
@pytest.mark.parametrize("proof_exception", [False, True])
def test_rollout_reveal_delivery_and_invariant(case, show, composed, proof_exception, tmp_path,
                                              monkeypatch, dispatch, capsys):
    tokens = []
    technique = case.partition(":")[0]
    for variant in (0, 1):
        runner = _CoverageRunner(case, variant)
        delivered, _ = dispatch(runner)
        if not show:
            monkeypatch.setattr(type(get_executor(technique)), "revealed_secrets",
                                lambda *a: pytest.fail("reveal hook called without opt-in"))
        monkeypatch.setattr("secrets.token_urlsafe", lambda n: runner.password)
        output = tmp_path / str(variant)
        params = _coverage_params(case)
        if proof_exception:
            monkeypatch.setattr(proof, "build_terminal_fact", lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("later proof failed")))
        if composed:
            cfg = ValidationConfig("example.test", "192.0.2.1", username="operator",
                                   password="operator-input", show_flag=show, allow_destructive=True)
            ctx = ExecutorContext(cfg, runner, AuthorizedLabProvider(), output, composed=True,
                                  on_artifact=lambda edge, art: cli.reveal_to_terminal(edge.revealed_secrets(art)))
            runner.configure(ctx)
            edge = get_executor(technique)
            finding = finding_from_inputs(ctx, edge, _DC, params)
            if technique == "GENERIC-ALL":
                ctx.input_caps["control"] = Capability(
                    states.control_for("svc_sql"), CAP_CONTROL,
                    ControlGrant("operator", "svc_sql", "GenericAll", "operator-seed"))
            result = edge.run_composable(ctx, finding, params)
            receipt = result.receipt
            report = engine.ChainReport(states.S_DA, result.complete, False, True,
                                        path=[technique], receipts=[receipt]).to_dict()
            output.mkdir(parents=True, exist_ok=True)
            report_path = output / "chain-report.json"
            report_path.write_text(json.dumps(report, indent=2) + "\n")
            for _, _, secret in runner.secrets:
                assert secret not in repr(report)
                assert secret.encode() not in report_path.read_bytes()
            if result.teardown_obligation:
                edge.teardown(ctx, result.teardown_obligation)
        else:
            args = _args("run", output, show) + ["--allow-destructive", technique, "--target", _DC]
            for key, value in params.items():
                args += ["--param", f"{key}={value}"]
            status = cli.main(args)
            captured = capsys.readouterr()
            receipt = json.loads(captured.out)
            assert status == (0 if receipt.get("complete") else 1), receipt
            for _, _, secret in runner.secrets:
                assert secret not in captured.out + captured.err
        assert delivered == ([SecretReveal(technique, *row) for row in runner.secrets] if show else []), receipt
        assert ("executor_exception" in receipt["errors"]) is proof_exception, receipt
        _assert_clean(receipt, runner.secrets, output / "verification-receipt.json")
        tokens.append((receipt.get("terminal_fact") or {}).get("proof_token"))
        if technique in _FORGERS:
            assert not list(output.glob(".forge-*/*.ccache"))
    assert tokens[0] == tokens[1]
    if not proof_exception:
        assert tokens[0]


@pytest.mark.parametrize("technique", ["BRONZE-BIT", "S4U2SELF", *sorted(_FORGERS)])
def test_ticket_revealed_after_failed_proof_and_cleanup(technique, tmp_path, dispatch, capsys):
    runner = _CoverageRunner(technique, access=False)
    delivered, _ = dispatch(runner)
    args = _args("run", tmp_path) + [technique, "--target", _DC]
    for key, value in _coverage_params(technique).items():
        args += ["--param", f"{key}={value}"]
    assert cli.main(args) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert not receipt["complete"]
    assert delivered == [SecretReveal(technique, *row) for row in runner.secrets]
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")
    if technique in _FORGERS:
        assert not list(tmp_path.glob(".forge-*/*.ccache"))


@pytest.mark.parametrize("technique", ["ADD-MEMBER", "WRITE-DACL", "WRITE-OWNER", "GPO-ABUSE",
                                       "OPENSHARES-WRITE", "COERCION", "SIGNING-RELAY"])
def test_no_secret_primitives_use_default_empty_hook(technique):
    reveal = SecretReveal("trap", "password", "user", "trap")
    assert get_executor(technique).revealed_secrets({"_reveal": [reveal], "password": "trap"}) == []


@pytest.mark.parametrize("technique", sorted({c.partition(":")[0] for c in _COVERAGE_CASES} | set(TECHNIQUES)))
def test_every_reveal_hook_reads_only_private_keys(technique):
    assert get_executor(technique).revealed_secrets({"reveal": ["trap"], "password": "trap"}) == []


@pytest.mark.parametrize("case", ["TARGETED-KERBEROAST", "GENERIC-ALL:spn_kerberoast"])
@pytest.mark.parametrize("denied", [False, True])
def test_rollout_hash_revealed_without_cracking(case, denied, tmp_path, monkeypatch, dispatch, capsys):
    class Uncracked(_CoverageRunner):
        def run(self, argv, **kwargs):
            if argv[0] == "hashcat":
                assert not denied
                return RunResult(0, "")
            return super().run(argv, **kwargs)

    class DenyCrack(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied" if op == "offline_crack" and denied else "not_required"

    runner = Uncracked(case)
    delivered, _ = dispatch(runner, authorizer=DenyCrack())
    technique = runner.technique
    args = _args("run", tmp_path) + [technique, "--target", _DC]
    for key, value in _coverage_params(case).items():
        args += ["--param", f"{key}={value}"]
    assert cli.main(args) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert delivered == [SecretReveal(technique, *runner.secrets[0])]
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")


@pytest.mark.parametrize("technique", ["ESC8", "ESC11", "UNCONSTRAINED-DELEG", "NTLM-RELAY"])
def test_listener_secret_survives_stop_exception(technique, tmp_path, monkeypatch, dispatch, capsys):
    def broken_stop(self, handle):
        raise RuntimeError("listener stop failed")

    monkeypatch.setattr(_CoveragePM, "stop", broken_stop)
    runner = _CoverageRunner(technique)
    delivered, _ = dispatch(runner)
    args = _args("run", tmp_path) + [technique, "--target", _DC]
    for key, value in _coverage_params(technique).items():
        args += ["--param", f"{key}={value}"]
    assert cli.main(args) == 1
    receipt = json.loads(capsys.readouterr().out)
    rows = runner.secrets if technique == "NTLM-RELAY" else runner.secrets[:1]
    assert delivered == [SecretReveal(technique, *row) for row in rows]
    _assert_clean(receipt, runner.secrets, tmp_path / "verification-receipt.json")


def test_rbcd_no_impersonation_ticket_recovers_nothing(tmp_path, dispatch, capsys):
    class NoTicket(_CoverageRunner):
        def run(self, argv, **kwargs):
            if argv[0] == "impacket-getST":
                return RunResult(1, "KDC_ERR_BADOPTION")
            return super().run(argv, **kwargs)

    delivered, _ = dispatch(NoTicket("RBCD"))
    assert cli.main(_args("run", tmp_path) + ["RBCD", "--target", _DC,
                                             "--param", "new_computer=operator_tmp"]) == 1
    receipt = json.loads(capsys.readouterr().out)
    assert delivered == [] and "getST_no_ticket" in receipt["errors"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_share_loot_reveals_all_inspected_values_and_gpp(encoding, tmp_path, dispatch, capsys):
    runner = _CoverageRunner("SHARE-LOOT")
    cpw = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
    private_key = "-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\n-----END PRIVATE KEY-----"
    aws_id = "AKIA" + "A" * 16
    aws_secret = "AWS_SECRET_SENTINEL_1234567890"
    slack = "xoxb-SLACKTOKEN12345678"
    extra = (f'\n<Properties userName="EXAMPLE\\backup" cpassword="{cpw}"/>\n'
             f'{private_key}\n{aws_id}\naws_secret_access_key={aws_secret}\n{slack}\n'
             'Connection String=Data Source=db;pwd=DB_CONNECTION_SENTINEL;\n')
    runner.loot = (runner.loot.decode() + extra).encode(encoding)
    delivered, _ = dispatch(runner)
    assert cli.main(_args("run", tmp_path) + ["SHARE-LOOT", "--target", _DC]) == 0
    receipt = json.loads(capsys.readouterr().out)
    location = f"{_DC}/SYSVOL/.env"
    expected = [
        ("private_key", location, private_key), ("aws_access_key_id", location, aws_id),
        ("slack_token", location, slack), ("gpp_cpassword", location, cpw),
        ("aws_secret_access_key", location, aws_secret), ("api_token", location, runner.token),
        ("password", location, runner.password), ("password", location, "SECOND_" + runner.password),
        ("password", location, "DB_CONNECTION_SENTINEL"),
        ("password", "EXAMPLE\\backup", "GPPstillStandingStrong2k18"),
    ]
    assert delivered == [SecretReveal("SHARE-LOOT", *row) for row in expected]
    _assert_clean(receipt, expected, tmp_path / "verification-receipt.json")
