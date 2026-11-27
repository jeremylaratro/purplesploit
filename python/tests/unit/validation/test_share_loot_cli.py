"""SHARE-LOOT operator-CLI wiring: `run SHARE-LOOT` dispatch + the SHARE-LOOT flags.

Before this, `run SHARE-LOOT` returned `dispatch_error` -- SHARE-LOOT had no
`inputs.TARGET_PARAM` entry, so the finding binder KeyError'd before any tool; and
`share_protocol` / `share_access_mode` / bounds / loot caps were not CLI flags
(Python-API-only). These tests lock in the operator-ready path.
"""
from __future__ import annotations

from purplesploit.validation.cli import build_parser, build_config
from purplesploit.validation.inputs import finding_from_inputs, TARGET_PARAM
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import ExecutorContext, AuthorizedLabProvider
from purplesploit.validation.config import ValidationConfig


BASE = ["run", "SHARE-LOOT", "--domain", "north.sevenkingdoms.local", "--dc-ip", "10.0.0.11"]


def _args(argv):
    return build_parser().parse_args(argv)


def test_share_loot_has_target_param():
    assert TARGET_PARAM["SHARE-LOOT"] == "hosts"          # the KeyError source is gone


def test_run_share_loot_binds_hosts_not_dispatch_error(tmp_path):
    # RED pre-fix: finding_from_inputs KeyError'd on SHARE-LOOT (-> dispatch_error).
    cfg = ValidationConfig(domain="d", dc_ip="1.2.3.4", username="u", password="p")
    ctx = ExecutorContext(cfg, runner=None, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    edge = get_executor("SHARE-LOOT")
    f = finding_from_inputs(ctx, edge, target="10.0.0.5,10.0.0.6")
    assert f.technique == "SHARE-LOOT" and f.technique_class == "share_loot"
    assert f.host == "10.0.0.5,10.0.0.6"                  # target -> the hosts scope
    assert f._overrides.get("hosts") == "10.0.0.5,10.0.0.6"
    assert f.entity.get("hosts") == "10.0.0.5,10.0.0.6"   # surfaces publicly (safe host list)


def test_build_config_share_loot_defaults_untouched():
    cfg = build_config(_args(BASE))                       # no SHARE-LOOT flags -> config defaults
    assert cfg.share_protocol == "smb" and cfg.share_access_mode == "crawl"
    assert cfg.loot_enabled is True
    assert cfg.share_max_shares == 64 and cfg.share_max_depth == 12
    assert cfg.share_crawl_deadline_s == 300


def test_build_config_share_loot_flags_applied():
    cfg = build_config(_args(BASE + [
        "--share-protocol", "nfs", "--share-access-mode", "mount",
        "--share-max-shares", "8", "--share-max-depth", "3", "--share-max-entries", "100",
        "--share-max-files", "50", "--share-crawl-deadline", "42",
        "--loot-store-dir", "/tmp/sl-store", "--no-loot"]))
    assert cfg.share_protocol == "nfs" and cfg.share_access_mode == "mount"
    assert cfg.share_max_shares == 8 and cfg.share_max_depth == 3
    assert cfg.share_max_entries == 100 and cfg.share_max_files == 50
    assert cfg.share_crawl_deadline_s == 42
    assert cfg.loot_store_dir == "/tmp/sl-store" and cfg.loot_enabled is False


def test_invalid_protocol_flag_rejected_by_argparse():
    import pytest
    with pytest.raises(SystemExit):                       # choices=[smb,nfs] -> argparse rejects
        _args(BASE + ["--share-protocol", "ftp"])


def test_run_dispatch_end_to_end_no_dispatch_error(tmp_path, monkeypatch, capsys):
    # The full `main run SHARE-LOOT` path binds + runs the executor (reader injected,
    # no network) and emits a SHARE-LOOT receipt -- never the old dispatch_error.
    from purplesploit.validation import cli
    from purplesploit.validation.executors.share_loot import ShareReader, _Entry

    class _R(ShareReader):
        def list_shares(self): return ["DATA"]
        def list_dir(self, s, p, limit): return [_Entry("readme.txt", False, 4)] if p == "" else []
        def read_file(self, s, p, n): return b"hi\n"
        def close(self): pass

    orig_init = cli.ValidationOrchestrator.__init__
    def patched_init(self, *a, **k):
        orig_init(self, *a, **k)
        self.context.share_reader_factory = lambda c, host, timeout: _R()
    monkeypatch.setattr(cli.ValidationOrchestrator, "__init__", patched_init)

    status = cli.main(["run", "SHARE-LOOT", "--domain", "north.sevenkingdoms.local",
                       "--dc-ip", "10.0.0.11", "--target", "10.0.0.5", "--user", "u",
                       "--password", "p", "--output", str(tmp_path)])
    import json
    out = json.loads(capsys.readouterr().out)
    assert out.get("technique") == "SHARE-LOOT"
    assert out.get("errors") != ["dispatch_error"]
    assert out["terminal_fact"]["ok"] is True             # the injected share was crawled
