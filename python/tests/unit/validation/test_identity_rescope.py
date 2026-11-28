"""Phase 3: stored identities reach real dispatch through a derived config only."""
from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from purplesploit.validation import cli, discovery, engine, states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.credential_store import CredentialStore
from purplesploit.validation.executors import get_executor
from purplesploit.validation.identity import (
    CredentialScopeError, credential_scope, derive_config, resolve_credential,
)
from purplesploit.validation.inputs import finding_from_inputs
from purplesploit.validation.probes import ProbeResult

from .test_credential_store import _credential
from .test_show_flag import _Runner, TARGETS, _args, dispatch


SECRET = "GAINED_AUTH_SENTINEL!"


def _base(output):
    return ValidationConfig("example.test", "192.0.2.1", username="operator",
                            password="operator-password", nt_hash="operator-hash",
                            aes_key="operator-aes", output_dir=output,
                            extra_targets=["member.example.test"], tool_timeout_s=17,
                            show_flag=True)


def _seed(base, **overrides):
    store = CredentialStore.from_config(base)
    store.upsert([_credential(value=SECRET, **overrides)])
    return store


@pytest.mark.parametrize("kind,field", [("password", "password"), ("nthash", "nt_hash"),
                                       ("aeskey", "aes_key"), ("ccache", None)])
@pytest.mark.parametrize("domain", ["other.test", ""])
def test_derive_config_keeps_base_and_settings(tmp_path, kind, field, domain):
    base = _base(tmp_path)
    before = asdict(base)
    entry = {"principal": "HOST$", "domain": domain, "secret_type": kind, "value": SECRET}
    active = derive_config(base, entry)
    assert active is not base
    assert active.username == "HOST$"
    assert active.domain == (domain or base.domain)
    for name in ("password", "nt_hash", "aes_key"):
        assert getattr(active, name) == (SECRET if name == field else None)
    for name, value in before.items():
        if name not in {"username", "domain", "password", "nt_hash", "aes_key"}:
            assert getattr(active, name) == value
    assert asdict(base) == before
    assert SECRET not in json.dumps(active.redacted())


@pytest.mark.parametrize("selector", ["HOST$", "host$@OTHER.TEST", "0"])
def test_machine_name_qualified_name_and_index(tmp_path, selector):
    base = _base(tmp_path)
    store = _seed(base, principal="HOST$", domain="other.test", is_machine=True)
    entry = resolve_credential(store, selector)
    assert entry["principal"] == "HOST$" and entry["is_machine"] is True
    # Rotations preserve the selected entry's index.
    store.upsert([_credential(principal="new_user"),
                  _credential(principal="HOST$", domain="other.test", value="ROTATED")])
    assert resolve_credential(store, "0")["value"] == "ROTATED"


def test_domain_collision_and_multiple_auth_types_need_disambiguation(tmp_path):
    base = _base(tmp_path)
    store = _seed(base)
    store.upsert([_credential(domain="other.test")])
    with pytest.raises(CredentialScopeError, match="ambiguous"):
        resolve_credential(store, "svc_sql")
    assert resolve_credential(store, "svc_sql@other.test")["domain"] == "other.test"
    store.upsert([_credential(secret_type="nthash")])
    with pytest.raises(CredentialScopeError, match="ambiguous"):
        resolve_credential(store, "svc_sql@example.test")
    assert resolve_credential(store, "2")["secret_type"] == "nthash"


def test_pfx_is_skipped_when_an_auth_credential_has_the_same_name(tmp_path):
    base = _base(tmp_path)
    store = _seed(base)
    entries = store.load()
    store._save([dict(entries[0], secret_type="pfx"), entries[0]])
    assert resolve_credential(store, "svc_sql")["secret_type"] == "password"
    with pytest.raises(CredentialScopeError, match="unsupported_secret_type"):
        resolve_credential(store, "0")


@pytest.mark.parametrize("inherited", [False, True])
@pytest.mark.parametrize("fails", [False, True])
def test_ccache_private_material_environment_and_cleanup(tmp_path, monkeypatch, inherited, fails):
    base = _base(tmp_path)
    store = _seed(base)
    entries = store.load()
    entries[0].update(secret_type="ccache", value=base64.b64encode(SECRET.encode()).decode())
    store._save(entries)
    if inherited:
        monkeypatch.setenv("KRB5CCNAME", "operator-cache")
    else:
        monkeypatch.delenv("KRB5CCNAME", raising=False)
    before = asdict(base)
    cache = None
    try:
        with credential_scope(base, "svc_sql") as (active, entry):
            cache = Path(os.environ["KRB5CCNAME"])
            assert cache.read_bytes() == SECRET.encode()
            assert stat.S_IMODE(cache.stat().st_mode) == 0o600
            assert stat.S_IMODE(cache.parent.stat().st_mode) == 0o700
            assert active.username == "svc_sql"
            assert active.password is active.nt_hash is active.aes_key is None
            if fails:
                raise RuntimeError("fake dispatch failure")
    except RuntimeError:
        assert fails
    assert cache is not None and not cache.exists() and not cache.parent.exists()
    assert os.environ.get("KRB5CCNAME") == ("operator-cache" if inherited else None)
    assert asdict(base) == before


def test_non_cache_scope_unsets_operator_ticket_then_restores(tmp_path, monkeypatch):
    base = _base(tmp_path)
    _seed(base)
    monkeypatch.setenv("KRB5CCNAME", "operator-cache")
    with credential_scope(base, "svc_sql"):
        assert "KRB5CCNAME" not in os.environ
    assert os.environ["KRB5CCNAME"] == "operator-cache"


@pytest.mark.parametrize("failure", ["missing", "ambiguous", "pfx", "malformed", "bad_cache"])
@pytest.mark.parametrize("mode", ["run", "discover", "chain", "pipeline"])
def test_selection_errors_never_dispatch_or_change_base(tmp_path, monkeypatch, capsys, failure, mode):
    base = _base(tmp_path)
    store = _seed(base)
    selector, expected = "unknown", "as_cred_not_found"
    if failure == "ambiguous":
        store.upsert([_credential(domain="other.test")])
        selector, expected = "svc_sql", "as_cred_ambiguous"
    elif failure in ("pfx", "bad_cache"):
        entries = store.load()
        entries[0]["secret_type"] = "pfx" if failure == "pfx" else "ccache"
        store._save(entries)
        selector = "svc_sql"
        expected = "as_cred_unsupported_secret_type" if failure == "pfx" else "as_cred_cache_error"
    elif failure == "malformed":
        store.path.write_text("INVALID JSON " + SECRET)
        expected = "credential_store_error"
    before = asdict(base)
    monkeypatch.setattr(cli, "build_config", lambda args: base)
    monkeypatch.setattr(cli, "ValidationOrchestrator", lambda *a, **k: pytest.fail("dispatched"))
    args = _args(mode, tmp_path, show=False) + ["--as-cred", selector]
    if mode == "run":
        args += ["DCSYNC"]
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert expected in json.loads(captured.out)["errors"][0]
    assert SECRET not in captured.out + captured.err
    assert "now acting as" not in captured.out
    assert asdict(base) == before


def _setup_mode(mode, monkeypatch):
    edge = get_executor("DCSYNC")
    if mode == "chain":
        edge.pre, edge.eff = frozenset({states.S0_USER_CREDS}), frozenset({states.S_DA})
        monkeypatch.setattr(cli, "default_edges", lambda: [edge])
        monkeypatch.setattr(engine, "default_edges", lambda: [edge])
    elif mode == "pipeline":
        monkeypatch.setattr(cli.ValidationOrchestrator, "enumerate", lambda orch: [finding_from_inputs(
            orch.context, edge, TARGETS["DCSYNC"])])
        monkeypatch.setattr("purplesploit.validation.orchestrator.run_probes",
                            lambda ctx, findings: [ProbeResult(viable=True, reason="fake viable")])
    elif mode == "discover":
        monkeypatch.setattr(discovery, "candidate_findings", lambda cfg, hosts: [])


@pytest.mark.parametrize("mode", ["run", "discover", "chain", "pipeline"])
@pytest.mark.parametrize("kind", ["password", "nthash", "aeskey", "ccache"])
def test_real_dispatch_uses_gained_auth_and_keeps_outputs_clean(tmp_path, monkeypatch, dispatch,
                                                             capsys, mode, kind):
    class CapturingRunner(_Runner):
        def __init__(self):
            super().__init__("DCSYNC")
            self.caches = []

        def run(self, argv, **kwargs):
            cache = os.environ.get("KRB5CCNAME")
            self.caches.append(Path(cache).read_bytes() if cache else None)
            return super().run(argv, **kwargs)

    runner = CapturingRunner()
    _, contexts = dispatch(runner)
    _setup_mode(mode, monkeypatch)
    base = _base(tmp_path)
    store = _seed(base, principal="HOST$", is_machine=True)
    entries = store.load()
    entries[0].update(secret_type=kind, value=(base64.b64encode(SECRET.encode()).decode()
                                             if kind == "ccache" else SECRET))
    store._save(entries)
    before = asdict(base)
    monkeypatch.setattr(cli, "build_config", lambda args: base)
    args = _args(mode, tmp_path, show=False) + ["--as-cred", "HOST$"]
    if mode == "run":
        args += ["DCSYNC", "--target", TARGETS["DCSYNC"]]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    banner, body = captured.out.split("\n", 1)
    assert banner == "now acting as HOST$@example.test [source: SHARE-LOOT]"
    report = json.loads(body)
    assert contexts[0].config.username == "HOST$"
    assert asdict(base) == before
    calls = runner.calls
    assert calls
    assert not any("operator" in str(call) for call in calls)
    if mode == "discover":
        ldap = next(call for call in calls if call[:2] == ["nxc", "ldap"])
        assert ldap[ldap.index("-u") + 1] == "HOST$"
        assert "(sAMAccountName=HOST$)" in ldap
    else:
        dump = next(call for call in calls if call[0] == "impacket-secretsdump")
        assert "example.test/HOST$" in dump[-1]
        if kind == "password":
            assert f":{SECRET}@" in dump[-1]
        elif kind in ("nthash", "aeskey"):
            flag = "-hashes" if kind == "nthash" else "-aesKey"
            assert dump[dump.index(flag) + 1] == SECRET
        else:
            assert "-k" in dump and "-no-pass" in dump
    if kind == "ccache":
        assert runner.caches and all(cache == SECRET.encode() for cache in runner.caches)
    for secret in (SECRET, entries[0]["value"], *(s[2] for s in runner.secrets)):
        assert secret not in captured.out + captured.err
        assert secret not in repr(report)
        for path in tmp_path.rglob("*.json"):
            if path != store.path:
                assert secret not in path.read_text()


def test_absent_selector_does_not_load_store_or_derive_config(tmp_path, monkeypatch, dispatch, capsys):
    runner = _Runner("DCSYNC")
    _, contexts = dispatch(runner)
    base = replace(_base(tmp_path), collect_creds=False, show_flag=False)
    monkeypatch.setattr(cli, "build_config", lambda args: base)
    monkeypatch.setattr(CredentialStore, "load", lambda self: pytest.fail("unexpected store read"))
    assert cli.main(_args("run", tmp_path, show=False) +
                    ["DCSYNC", "--target", TARGETS["DCSYNC"]]) == 0
    assert contexts[0].config is base
    assert json.loads(capsys.readouterr().out)["complete"] is True


@pytest.mark.parametrize("mode", ["run", "chain", "pipeline", "discover"])
@pytest.mark.parametrize("kind", ["password", "nthash", "aeskey", "ccache"])
def test_rotating_auth_secret_leaves_public_output_and_proof_tokens_identical(
        tmp_path, monkeypatch, dispatch, capsys, mode, kind):
    runner = _Runner("DCSYNC")
    dispatch(runner)
    _setup_mode(mode, monkeypatch)
    base = replace(_base(tmp_path), show_flag=False)
    store = _seed(base)
    monkeypatch.setattr(cli, "build_config", lambda args: base)
    args = _args(mode, tmp_path, show=False) + ["--as-cred", "svc_sql"]
    if mode == "run":
        args += ["DCSYNC", "--target", TARGETS["DCSYNC"]]
    outputs, receipts = [], []
    for secret in (SECRET, "ROTATED_AUTH_SENTINEL!"):
        entries = store.load()
        entries[0].update(secret_type=kind, value=(base64.b64encode(secret.encode()).decode()
                                                 if kind == "ccache" else secret))
        store._save(entries)
        assert cli.main(args) == 0
        captured = capsys.readouterr()
        assert secret not in captured.out + captured.err
        outputs.append(captured.out)
        receipts.append({str(path): path.read_bytes() for path in tmp_path.rglob("*.json")
                         if path != store.path})
    # Whole output equality also covers receipts embedded in chain/pipeline reports.
    assert outputs[0] == outputs[1]
    assert receipts[0] == receipts[1]
    if mode != "discover":
        report = json.loads(outputs[0].split("\n", 1)[1])
        if mode == "chain":
            receipt = report["receipts"][0]
        elif mode == "pipeline":
            receipt = json.loads(Path(report["executed"][0]["receipt"]).read_text())
        else:
            receipt = report
        assert receipt["terminal_fact"]["proof_token"]


@pytest.mark.parametrize("selector", ["run", "pipeline", "chain", "discover"])
def test_public_selector_equal_to_command_is_not_dispatched(tmp_path, selector):
    args = cli.build_parser().parse_args(_args("discover", tmp_path, show=False) +
                                         ["--as-cred", selector])
    assert args.command == "discover" and args.as_cred == selector
