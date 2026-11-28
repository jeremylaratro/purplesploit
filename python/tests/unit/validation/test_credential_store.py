"""Phase 2: private session persistence and real CLI dispatch with fake tools."""
from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import replace

import pytest

from purplesploit.validation import cli, credential_store, discovery, engine, states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.credential_store import CredentialStore
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    AuthorizedLabProvider, Capability, Credential, ExecutorContext, SecretReveal,
    CAP_AES_KEY, CAP_CCACHE, CAP_NT_HASH, CAP_PASSWORD, CAP_PFX, CAP_PRINCIPAL,
)
from purplesploit.validation.inputs import finding_from_inputs
from purplesploit.validation.probes import ProbeResult

from .test_show_flag import _Runner, TARGETS, _args, dispatch


SENTINEL = "STORED_ONLY_SENTINEL!"


def _credential(**overrides):
    cap = Credential(states.cred_for("svc_sql"), CAP_PASSWORD, SENTINEL, "svc_sql",
                     domain="example.test", secret_type="password", source_technique="SHARE-LOOT")
    return replace(cap, **overrides)


def _store(output):
    return CredentialStore.from_config(ValidationConfig("example.test", "192.0.2.1", output_dir=output))


def test_store_load_upsert_dedup_and_clear(tmp_path):
    store = _store(tmp_path)
    assert store.load() == store.list() == []
    assert not store.path.exists()
    store.upsert([_credential()])
    original, = store.load()
    assert set(original) == {"principal", "domain", "is_machine", "secret_type",
                             "source_technique", "value", "first_seen"}
    assert original["value"] == SENTINEL
    # A fresh instance reads the same session, preserving the original timestamp.
    store = CredentialStore(store.path)
    store.upsert([_credential(value="ROTATED!", source_technique="LAPS")])
    updated, = store.load()
    assert updated == {**original, "value": "ROTATED!", "source_technique": "LAPS"}
    store.upsert([_credential(principal="DC$", is_machine=True),
                  _credential(domain="other.test"),
                  _credential(channel=CAP_NT_HASH, secret_type="nthash")])
    assert len(store.load()) == 4
    assert any(e["is_machine"] for e in store.load())
    store.clear()
    assert CredentialStore(store.path).load() == []


def test_store_only_collects_secret_credentials(tmp_path):
    store = _store(tmp_path)
    store.upsert([Capability("legacy", CAP_PASSWORD, "IGNORE_ME"),
                  _credential(channel=CAP_PRINCIPAL)])
    assert not store.path.exists()


def test_store_uses_exclusive_0600_creation_for_every_write(tmp_path, monkeypatch):
    store = _store(tmp_path)
    real_open = os.open
    writes = []

    def opened(path, flags, mode=0o777):
        writes.append((flags, mode))
        fd = real_open(path, flags, mode)
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        return fd

    monkeypatch.setattr(credential_store.os, "open", opened)
    for action in (lambda: store.upsert([_credential()]),
                   lambda: store.upsert([_credential(value="UPDATED!")]), store.clear):
        action()
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert writes == [(os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)] * 3


def test_exclusive_collision_and_failed_write_preserve_existing_store(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store.upsert([_credential()])
    original = store.path.read_bytes()
    monkeypatch.setattr(credential_store.secrets, "token_hex", lambda n: "collision")
    collision = store.path.with_name(f".{store.path.name}-collision")
    collision.write_text("do not overwrite")
    with pytest.raises(FileExistsError):
        store.upsert([_credential(value="NEW!")])
    assert collision.read_text() == "do not overwrite"
    assert store.path.read_bytes() == original
    collision.unlink()

    def failed(*args, **kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(credential_store.json, "dump", failed)
    with pytest.raises(OSError):
        store.upsert([_credential(value="NEW!")])
    assert store.path.read_bytes() == original
    assert not collision.exists()


@pytest.mark.parametrize("channel,kind", [(CAP_CCACHE, "ccache"), (CAP_PFX, "pfx")])
def test_file_credential_survives_snapshot_removal(tmp_path, channel, kind):
    snapshot = tmp_path / "snapshot"
    snapshot.write_bytes(b"private bearer material")
    store = _store(tmp_path)
    store.upsert([_credential(channel=channel, secret_type=kind, value=str(snapshot))])
    snapshot.unlink()
    entry, = CredentialStore(store.path).load()
    assert base64.b64decode(entry["value"]) == b"private bearer material"


def test_store_config_paths_and_collection_defaults(tmp_path):
    cfg = ValidationConfig("example.test", "192.0.2.1", output_dir=tmp_path)
    assert cfg.collect_creds is True
    assert CredentialStore.from_config(cfg).path == tmp_path / "cred-store" / "creds.json"
    cfg.cred_store_dir = str(tmp_path / "engagement")
    assert CredentialStore.from_config(cfg).path == tmp_path / "engagement" / "creds.json"
    cfg.cred_store_file = str(tmp_path / "override.json")
    assert CredentialStore.from_config(cfg).path == tmp_path / "override.json"
    assert not {"cred_store_dir", "cred_store_file", "collect_creds"} & cfg.redacted().keys()


@pytest.mark.parametrize("show", [False, True])
def test_creds_list_metadata_only_and_terminal_reveal(tmp_path, monkeypatch, capsys, show):
    store = _store(tmp_path)
    store.upsert([_credential()])
    delivered = []
    monkeypatch.setattr(cli, "reveal_to_terminal", delivered.extend)
    assert cli.main(["creds", "list", "--output", str(tmp_path)] +
                    (["--show-flag"] if show else [])) == 0
    captured = capsys.readouterr()
    entry, = json.loads(captured.out)
    assert set(entry) == {"principal", "domain", "secret_type", "source_technique", "first_seen"}
    assert entry == store.list()[0]
    assert entry["principal"] == "svc_sql" and entry["domain"] == "example.test"
    assert SENTINEL not in captured.out + captured.err
    assert delivered == ([SecretReveal("SHARE-LOOT", "password", "svc_sql", SENTINEL)] if show else [])


@pytest.mark.parametrize("channel,kind,reveal_kind", [
    (CAP_NT_HASH, "nthash", "nt_hash"), (CAP_AES_KEY, "aeskey", "aes_key"),
    (CAP_CCACHE, "ccache", "ccache_base64"), (CAP_PFX, "pfx", "pfx_base64"),
])
def test_creds_reveal_all_secret_types(tmp_path, monkeypatch, capsys, channel, kind, reveal_kind):
    value = SENTINEL
    if channel in (CAP_CCACHE, CAP_PFX):
        snapshot = tmp_path / "snapshot"
        snapshot.write_bytes(SENTINEL.encode())
        value = str(snapshot)
    store = _store(tmp_path)
    store.upsert([_credential(channel=channel, secret_type=kind, value=value)])
    delivered = []
    monkeypatch.setattr(cli, "reveal_to_terminal", delivered.extend)
    assert cli.main(["--show-flag", "creds", "--output", str(tmp_path), "list"]) == 0
    captured = capsys.readouterr()
    assert delivered == [SecretReveal("SHARE-LOOT", reveal_kind, "svc_sql", store.load()[0]["value"])]
    assert delivered[0].value not in captured.out + captured.err


@pytest.mark.parametrize("mode", ["run", "chain", "pipeline", "discover"])
@pytest.mark.parametrize("collect", [False, True])
def test_real_dispatch_collects_without_changing_public_outputs(tmp_path, monkeypatch, dispatch,
                                                              capsys, mode, collect):
    runner = _Runner("DCSYNC")
    delivered, contexts = dispatch(runner)
    store = _store(tmp_path)
    store.upsert([_credential()])  # Seeded values must never be read into any run/report.
    args = _args(mode, tmp_path, show=False)
    if not collect:
        args += ["--no-collect-creds"]
    if mode == "run":
        args += ["DCSYNC", "--target", TARGETS["DCSYNC"]]
    elif mode == "chain":
        edge = get_executor("DCSYNC")
        edge.pre, edge.eff = frozenset({states.S0_USER_CREDS}), frozenset({states.S_DA})
        monkeypatch.setattr(cli, "default_edges", lambda: [edge])
        monkeypatch.setattr(engine, "default_edges", lambda: [edge])
    elif mode == "pipeline":
        monkeypatch.setattr(cli.ValidationOrchestrator, "enumerate", lambda orch: [finding_from_inputs(
            orch.context, get_executor("DCSYNC"), TARGETS["DCSYNC"])])
        monkeypatch.setattr("purplesploit.validation.orchestrator.run_probes",
                            lambda ctx, findings: [ProbeResult(viable=True, reason="fake viable")])
    else:
        monkeypatch.setattr(discovery, "candidate_findings", lambda cfg, hosts: [finding_from_inputs(
            ExecutorContext(cfg, runner, AuthorizedLabProvider(), tmp_path),
            get_executor("DCSYNC"), TARGETS["DCSYNC"])])
        monkeypatch.setattr(discovery, "recon", lambda ctx: discovery._Recon(None, None, False, None, False))
        monkeypatch.setattr(discovery.probes_mod, "run_probes",
                            lambda ctx, findings: [ProbeResult(viable=True, reason="fake viable")])
        args += ["--exploit"]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert contexts[0].config.collect_creds is collect
    assert delivered == []
    entries = store.load()
    assert len(entries) == (5 if collect else 1)
    if collect:
        assert {e["value"] for e in entries} == {SENTINEL, *(r[2] for r in runner.secrets)}
    secrets = [SENTINEL, *(r[2] for r in runner.secrets)]
    for secret in secrets:
        assert secret not in captured.out + captured.err
        assert secret not in repr(report)
        for path in tmp_path.rglob("*.json"):
            if path != store.path:
                assert secret not in path.read_text()


def test_real_run_repeat_deduplicates_then_cli_clear(tmp_path, dispatch, capsys):
    dispatch(_Runner("LAPS"))
    args = _args("run", tmp_path, show=False) + ["LAPS", "--target", TARGETS["LAPS"]]
    assert cli.main(args) == 0
    first_output = capsys.readouterr().out
    store = _store(tmp_path)
    original = store.load()
    assert cli.main(args) == 0
    assert capsys.readouterr().out == first_output
    assert store.load() == original and len(original) == 1
    assert cli.main(["creds", "clear", "--output", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"cleared": True}
    assert store.load() == []


def test_collection_opt_out_preserves_receipt_bytes(tmp_path, dispatch, capsys):
    dispatch(_Runner("LAPS"))
    args = _args("run", tmp_path, show=False) + ["LAPS", "--target", TARGETS["LAPS"]]
    assert cli.main(args + ["--no-collect-creds"]) == 0
    disabled = capsys.readouterr().out
    receipt = (tmp_path / "receipts" / "LAPS.json").read_bytes()
    assert not _store(tmp_path).path.exists()
    assert cli.main(args) == 0
    assert capsys.readouterr().out == disabled
    assert (tmp_path / "receipts" / "LAPS.json").read_bytes() == receipt
    assert _store(tmp_path).load()


@pytest.mark.parametrize("action", ["list", "clear"])
def test_store_errors_never_print_exception_values(tmp_path, monkeypatch, capsys, action):
    def failed(*args):
        raise OSError(SENTINEL)

    monkeypatch.setattr(CredentialStore, action, failed)
    assert cli.main(["creds", action, "--output", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"errors": ["credential_store_error"]}
    assert SENTINEL not in captured.out + captured.err


def test_collection_error_leaves_receipt_intact(tmp_path, monkeypatch, dispatch, capsys):
    dispatch(_Runner("LAPS"))

    def failed(*args):
        raise OSError(SENTINEL)

    monkeypatch.setattr(CredentialStore, "upsert", failed)
    assert cli.main(_args("run", tmp_path, show=False) + ["LAPS", "--target", TARGETS["LAPS"]]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["complete"] is True
    assert SENTINEL not in captured.out + captured.err
