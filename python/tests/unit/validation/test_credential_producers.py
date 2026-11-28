"""ADR-003 Phase 1: actual recovery, runtime products, routing and dispatch gate."""
from __future__ import annotations

import base64
import gc
import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from purplesploit.validation import cli, engine, proof, states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.engine import ChainEngine
from purplesploit.validation.engine.chain_engine import _StateEntry
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    AuthorizedLabProvider, Capability, Credential, ControlGrant, ExecutorContext,
    SecretReveal, ValidationExecutor, CAP_AES_KEY, CAP_CCACHE, CAP_CONTROL,
    CAP_NT_HASH, CAP_PASSWORD, CAP_PFX, CAP_PRINCIPAL,
)
from purplesploit.validation.inputs import finding_from_inputs
from purplesploit.validation.findings import map_finding
from purplesploit.validation.recommend import ParamValue

# Reuse the reveal rollout's fake tools and independent expected recovered data.
from .test_show_flag import (
    _COVERAGE_CASES, _CoverageRunner, _Runner, _coverage_params, _DC,
    TECHNIQUES, TARGETS, _args, _assert_clean, dispatch,
)


_KINDS = {
    "password": ("password", CAP_PASSWORD),
    "nt_hash": ("nthash", CAP_NT_HASH),
    "aes_key": ("aeskey", CAP_AES_KEY),
    "ccache_base64": ("ccache", CAP_CCACHE),
    "pfx_base64": ("pfx", CAP_PFX),
}
_CASES = [*_COVERAGE_CASES, *TECHNIQUES]


def _setup(case, tmp_path, *, composed=False, success=True, variant=0):
    technique = case.partition(":")[0]
    runner = (_Runner(technique, variant, success=success) if case in TECHNIQUES
              else _CoverageRunner(case, variant, access=success))
    ctx = ExecutorContext(
        ValidationConfig("example.test", "192.0.2.1", username="operator",
                         password="operator-input", allow_destructive=True,
                         poll_interval_s=0, tool_timeout_s=1),
        runner, AuthorizedLabProvider(), tmp_path, composed=composed,
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    if hasattr(runner, "configure"):
        runner.configure(ctx)
    edge = get_executor(technique)
    overrides = _coverage_params(case)
    finding = finding_from_inputs(ctx, edge, TARGETS.get(case, _DC), overrides)
    if technique == "GENERIC-ALL" and composed:
        ctx.input_caps["control"] = Capability(
            states.control_for("svc_sql"), CAP_CONTROL,
            ControlGrant("operator", "svc_sql", "GenericAll", "operator-seed"))
    return edge, ctx, finding, overrides, runner


def _assert_credentials(caps, rows, technique):
    credentials = [c for c in caps if isinstance(c, Credential)]
    expected = [row for row in rows if row[0] in _KINDS]
    assert len(credentials) == len(expected)
    for cap, (kind, principal, secret) in zip(credentials, expected):
        assert isinstance(cap, Capability) and cap.secret
        assert (cap.secret_type, cap.channel) == _KINDS[kind]
        assert cap.principal == principal
        assert cap.state == states.cred_for(principal)
        account = principal.rsplit("\\", 1)[-1].split("@", 1)[0]
        assert cap.is_machine is account.endswith("$")
        assert cap.domain == (principal.rsplit("\\", 1)[0] if "\\" in principal else "example.test")
        assert cap.source_technique == technique and cap.reach_hint == ()
        if kind.endswith("_base64"):
            path = Path(cap.value)
            assert path.read_bytes() == base64.b64decode(secret)
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        else:
            assert cap.value == secret
    return credentials


@pytest.mark.parametrize("case", _CASES)
@pytest.mark.parametrize("composed", [False, True])
@pytest.mark.parametrize("proof_exception", [False, True])
def test_each_recoverer_produces_at_recovery_before_proof(case, composed, proof_exception,
                                                       tmp_path, monkeypatch):
    edge, ctx, finding, overrides, runner = _setup(case, tmp_path, composed=composed)
    if hasattr(runner, "password"):
        monkeypatch.setattr("secrets.token_urlsafe", lambda n: runner.password)
    params = edge._params(ctx, finding, overrides)
    at_proof = []
    original = proof.build_terminal_fact

    def prove(*args, **kwargs):
        # Read the live capture before proof construction succeeds (or raises).
        artifact = ctx._pending_reveal_artifact
        if artifact is None:  # receipt normalization also calls this function
            return original(*args, **kwargs)
        caps = edge.produced(ctx, finding, params, artifact)
        at_proof.extend(c for c in caps if isinstance(c, Credential))
        if proof_exception:
            raise RuntimeError("proof failed after recovery")
        return original(*args, **kwargs)

    monkeypatch.setattr(proof, "build_terminal_fact", prove)
    # Production must not call the display hook, even without --show-flag.
    monkeypatch.setattr(edge, "revealed_secrets", lambda *a: pytest.fail("display hook called"))
    result = edge.run_composable(ctx, finding, overrides)
    assert result.complete is not proof_exception, result.receipt
    creds = _assert_credentials(result.capabilities, runner.secrets, edge.technique)
    assert creds and at_proof == creds
    if proof_exception:
        assert result.capabilities == creds  # no legacy state claim on failed proof
        assert "executor_exception" in result.receipt["errors"]
    for cap in creds:
        assert str(cap.value) not in json.dumps(result.receipt)
    if result.teardown_obligation:
        edge.teardown(ctx, result.teardown_obligation)


@pytest.mark.parametrize("case", [*TECHNIQUES, "BRONZE-BIT", "S4U2SELF", "GOLDEN-TICKET",
                                 "SILVER-TICKET", "DIAMOND-TICKET", "SAPPHIRE-TICKET"])
@pytest.mark.parametrize("composed", [False, True])
def test_recovery_survives_negative_proof(case, composed, tmp_path):
    edge, ctx, finding, overrides, runner = _setup(case, tmp_path, composed=composed, success=False)
    result = edge.run_composable(ctx, finding, overrides)
    assert not result.complete
    _assert_credentials(result.capabilities, runner.secrets, edge.technique)
    assert result.capabilities and all(isinstance(c, Credential) for c in result.capabilities)


@pytest.mark.parametrize("technique", ["ADD-MEMBER", "WRITE-DACL", "WRITE-OWNER", "GPO-ABUSE",
                                      "OPENSHARES-WRITE", "COERCION", "SIGNING-RELAY"])
def test_no_secret_primitives_produce_no_credential(technique, tmp_path):
    runner = _CoverageRunner(technique)
    ctx = ExecutorContext(ValidationConfig("example.test", "192.0.2.1"), runner,
                          AuthorizedLabProvider(), tmp_path)
    edge = get_executor(technique)
    finding = map_finding({"host": _DC, "category": "acl", "severity": "high",
                           "line": "candidate"})
    params = {spec.name: ParamValue(spec, spec.recommended or "", "recommended")
              for spec in edge.param_specs(ctx, finding)}
    caps = edge.produced(ctx, finding, params,
                         {"complete": False, "_reveal": [SecretReveal(technique, "password", "trap", "trap")]})
    assert not any(isinstance(c, Credential) for c in caps)


def test_rbcd_without_ticket_produces_no_credential(tmp_path):
    edge, ctx, finding, overrides, runner = _setup("RBCD", tmp_path)
    original = runner.run

    def no_ticket(argv, **kwargs):
        if argv[0] == "impacket-getST":
            from purplesploit.validation.executors.base import RunResult
            return RunResult(1, "KDC_ERR_BADOPTION")
        return original(argv, **kwargs)

    runner.run = no_ticket
    result = edge.run_composable(ctx, finding, overrides)
    assert not result.complete and result.capabilities == []


def test_credential_metadata_is_optional_and_preserves_channel_validation():
    cap = Capability("state")
    assert (cap.domain, cap.is_machine, cap.secret_type, cap.source_technique, cap.reach_hint) == (
        "", False, "", "", ())
    with pytest.raises(ValueError, match="unknown capability channel"):
        Credential("state", "invalid")
    assert Credential("state", CAP_PFX).secret


@pytest.mark.parametrize("principal,domain,machine", [
    ("svc_sql", "example.test", False),
    ("EXAMPLE\\DC$", "EXAMPLE", True),
    ("DC$@other.test", "other.test", True),
    ("member.example.test\\administrator", "member.example.test", False),
])
def test_identity_metadata_uses_captured_principal(principal, domain, machine, tmp_path):
    edge, ctx, finding, overrides, runner = _setup("LAPS", tmp_path)
    artifact = {"_reveal": [SecretReveal("LAPS", "password", principal, "recovered")]}
    cap, = edge.produced(ctx, finding, {}, artifact)
    assert (cap.principal, cap.domain, cap.is_machine) == (principal, domain, machine)


def test_ticket_snapshot_lifetime_follows_threaded_value(tmp_path):
    edge, ctx, finding, overrides, runner = _setup("RBCD", tmp_path)
    artifact = {"_reveal": [SecretReveal("RBCD", "ccache_base64", "Administrator",
                                        base64.b64encode(b"ticket bytes").decode())]}
    cap, = edge.produced(ctx, finding, {}, artifact)
    assert edge.produced(ctx, finding, {}, artifact)[0] is cap  # stable reads
    copied = replace(cap, provenance=("RBCD",))
    threaded, env = ChainEngine._thread_caps(edge, {cap.state: _StateEntry(copied, "RBCD")})
    path = Path(cap.value)
    assert path.read_bytes() == b"ticket bytes" and env["KRB5CCNAME"] == str(path)
    del cap, copied, artifact
    gc.collect()
    assert Path(threaded["ccache"]).read_bytes() == b"ticket bytes"
    del threaded, env
    gc.collect()
    assert not path.exists()


def test_unqualified_sam_account_uses_relay_target_local_realm(tmp_path):
    edge, ctx, finding, overrides, runner = _setup("NTLM-RELAY", tmp_path)
    runner.dump = f"Administrator:500:{'00' * 16}:{runner.nt}:::\n"
    result = edge.run_composable(ctx, finding, overrides)
    assert result.complete
    cap, = result.capabilities
    assert isinstance(cap, Credential)
    assert (cap.principal, cap.domain, cap.channel, cap.value) == (
        "Administrator", _DC, CAP_NT_HASH, runner.nt)


def test_engine_threads_recovered_password_to_consuming_edge(tmp_path):
    producer, ctx, finding, overrides, runner = _setup("LAPS", tmp_path)
    principal = TARGETS["LAPS"] + "\\administrator"
    cred_state = states.cred_for(principal)
    producer.pre = frozenset({states.S0_USER_CREDS})
    producer.eff = frozenset({cred_state})
    seen = []

    class Consumer(ValidationExecutor):
        technique = "PASSWORD-CONSUMER"
        technique_class = "password_consumer"
        terminal_kind = "authn_success"
        pre = frozenset({cred_state})
        eff = frozenset({states.S_DA})

        def param_specs(self, ctx, finding):
            return []

        def execute(self, ctx, finding, params):
            seen.append(dict(ctx.input_caps))
            assert ctx.input_caps["password"] == runner.secrets[0][2]
            assert ctx.input_caps["principal"] == principal
            return {"complete": True}

    engine = ChainEngine([producer, Consumer()])
    consumer_finding = map_finding({"host": _DC, "category": "smb", "line": "consumer"})
    report = engine.run(ctx, lambda edge: finding if edge is producer else consumer_finding)
    assert report.reached and report.path == ["LAPS", "PASSWORD-CONSUMER"], engine._private_errors
    assert len(seen) == 1 and runner.secrets[0][2] not in json.dumps(report.to_dict())


@pytest.mark.parametrize("channel,key,value", [
    (CAP_PASSWORD, "password", "cleartext"), (CAP_NT_HASH, "nt_hash", "ab" * 16),
    (CAP_AES_KEY, "aes_key", "cd" * 32), (CAP_CCACHE, "ccache", "/runtime/ticket"),
    (CAP_PRINCIPAL, "principal", "svc_sql"),
])
def test_existing_channel_routes_stay_typed(channel, key, value):
    cap = Capability("state", channel, value, "svc_sql")
    inputs, env = ChainEngine._thread_caps(get_executor("DCSYNC"), {"state": _StateEntry(cap, "front")})
    assert inputs[key] == value and inputs["principal"] == "svc_sql"
    assert env == ({"KRB5CCNAME": value} if channel == CAP_CCACHE else {})


_CHAIN_CASES = [*TECHNIQUES, "ESC8", "ESC11", "CERTIFRIED", "RBCD", "SHARE-LOOT",
                "NTLM-RELAY", "UNCONSTRAINED-DELEG"]


@pytest.mark.parametrize("case,mode", [(c, "run") for c in _CASES] + [(c, "chain") for c in _CHAIN_CASES])
def test_produced_values_never_reach_real_dispatch_receipts_or_tokens(case, mode, tmp_path,
                                                                   monkeypatch, dispatch, capsys):
    technique = case.partition(":")[0]
    tokens = []
    for variant in (0, 1):
        edge, ctx, finding, overrides, runner = _setup(case, tmp_path / str(variant), variant=variant)
        dispatch(runner)
        if hasattr(runner, "password"):
            monkeypatch.setattr("secrets.token_urlsafe", lambda n: runner.password)
        produced = []
        original = type(edge)._execute_to_artifact

        def capture(self, ctx, finding, params):
            if mode == "chain" and hasattr(runner, "configure"):
                # Inject the same fake dependencies into the fresh edge context.
                runner.configure(ctx)
            artifact = original(self, ctx, finding, params)
            produced.extend(self.produced(ctx, finding, params, artifact))
            return artifact

        with monkeypatch.context() as patch:
            patch.setattr(type(edge), "_execute_to_artifact", capture)
            args = _args(mode, ctx.output_dir, False) + ["--allow-destructive"]
            if mode == "chain":
                # Bind a single real front so every credential shape can pass
                # through the real engine/report writer without identity re-scope.
                edge.pre = frozenset({states.S0_USER_CREDS})
                edge.eff = frozenset({states.S_DA})
                patch.setattr(cli, "default_edges", lambda: [edge])
                patch.setattr(engine, "default_edges", lambda: [edge])
                args += ["--allow-crack", "--map", f"{technique}={TARGETS.get(case, _DC)}"]
            else:
                args += [technique, "--target", TARGETS.get(case, _DC)]
            for key, value in overrides.items():
                scoped_key = f"{technique}.{key}" if mode == "chain" else key
                args += ["--param", f"{scoped_key}={value}"]
            assert cli.main(args) == 0
        out = capsys.readouterr()
        report = json.loads(out.out)
        receipt = report["receipts"][0] if mode == "chain" else report
        creds = _assert_credentials(produced, runner.secrets, technique)
        rows = [(c.secret_type, c.principal, str(c.value)) for c in creds]
        _assert_clean(receipt, [*runner.secrets, *rows], ctx.output_dir / "credential-receipt.json")
        for path in Path(ctx.output_dir).glob("*receipt*.json"):
            for _, _, value in [*runner.secrets, *rows]:
                assert value.encode() not in path.read_bytes()
        for _, _, value in rows:
            assert value not in out.out + out.err
        if mode == "chain":
            for _, _, value in [*runner.secrets, *rows]:
                assert value.encode() not in (Path(ctx.output_dir) / "chain-report.json").read_bytes()
        tokens.append((receipt.get("terminal_fact") or {}).get("proof_token"))
    assert tokens[0] and tokens[0] == tokens[1]


@pytest.mark.parametrize("case", ["KERBEROAST", "ASREP", "TARGETED-KERBEROAST", "GENERIC-ALL:spn_kerberoast"])
def test_uncracked_roast_is_reveal_only(case, tmp_path):
    edge, ctx, finding, overrides, runner = _setup(case, tmp_path)
    original = runner.run

    def uncracked(argv, **kwargs):
        if argv[0] == "hashcat":
            from purplesploit.validation.executors.base import RunResult
            return RunResult(0, "")
        return original(argv, **kwargs)

    runner.run = uncracked
    result = edge.run_composable(ctx, finding, overrides)
    assert not result.complete and result.capabilities == []


def test_loot_named_password_and_legacy_looted_state_both_produced(tmp_path):
    edge, ctx, finding, overrides, runner = _setup("SHARE-LOOT", tmp_path)
    cpw = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
    runner.loot += f'<Properties userName="EXAMPLE\\backup" cpassword="{cpw}"/>'.encode()
    result = edge.run_composable(ctx, finding, overrides)
    assert result.complete
    legacy = [c for c in result.capabilities if not isinstance(c, Credential)]
    assert len(legacy) == 1 and legacy[0].state == states.S_LOOTED_CREDS
    named = [c for c in result.capabilities if isinstance(c, Credential) and c.principal == "EXAMPLE\\backup"]
    assert len(named) == 1
    assert (named[0].domain, named[0].secret_type, named[0].channel, named[0].value) == (
        "EXAMPLE", "password", CAP_PASSWORD, "GPPstillStandingStrong2k18")
    assert named[0].value == legacy[0].value
