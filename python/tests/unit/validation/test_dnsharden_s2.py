"""DNSHARDEN S2 — Kerberos discovery wiring + persisted resolution diagnostics.

Proves the NEW behavior non-vacuously: Kerberos-mode nxc calls now carry
``--kdcHost`` (so realm→KDC resolution works without a carrier ``/etc/hosts``),
``--dns-server`` stays OPT-IN (carrier path byte-unchanged), NTLM modes get no
discovery flags, and a real resolution failure surfaces a rich, PERSISTED
diagnostic in the receipt.
"""
from __future__ import annotations

from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider)
from purplesploit.validation import netresolve


HOST = "winterfell.north.sevenkingdoms.local"
AES = "deadbeef" * 8


# ======================================================= canonical auth flags

def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11", username="jon.snow")
    base.update(kw)
    return ValidationConfig(**base)


def test_nxc_auth_flags_password_mode_has_no_discovery():
    flags = netresolve.nxc_auth_flags(_cfg(password="pw"))
    assert flags == ["-u", "jon.snow", "-p", "pw"]
    assert "--kdcHost" not in flags            # NTLM -> no KDC discovery


def test_nxc_auth_flags_hash_mode_has_no_discovery():
    flags = netresolve.nxc_auth_flags(_cfg(nt_hash="deadbeef" * 4))
    assert "--kdcHost" not in flags and "-H" in flags


def test_nxc_auth_flags_aeskey_mode_adds_kdchost():
    # implicit Kerberos via --aesKey MUST carry discovery flags (review #1)
    flags = netresolve.nxc_auth_flags(_cfg(aes_key=AES))
    assert "--aesKey" in flags and "--kdcHost" in flags
    assert flags[flags.index("--kdcHost") + 1] == "10.0.0.11"
    assert "--dns-server" not in flags         # opt-in


def test_nxc_auth_flags_aeskey_with_dns_server_opt_in():
    flags = netresolve.nxc_auth_flags(_cfg(aes_key=AES, kdc_host="1.2.3.4", dns_server="5.6.7.8"))
    assert flags[-4:] == ["--kdcHost", "1.2.3.4", "--dns-server", "5.6.7.8"]


# ============================= GOLDEN reauth argv (forge_common wired, r2 #3)

class _ForgeCap(CommandRunner):
    """Captures argv; forges a ccache; nxc returns Pwn3d or a scripted failure."""
    def __init__(self, nxc_out="SMB w 445 WS [+] NORTH\\Administrator from ccache (Pwn3d!)\n"):
        self.nxc_out = nxc_out
        self.calls = []

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        name = Path(argv[0]).name
        if name == "impacket-lookupsid":
            return RunResult(0, stdout="[*] Domain SID is: S-1-5-21-1-2-3\n")
        if name == "impacket-ticketer" and cwd:
            (Path(cwd) / f"{argv[-1]}.ccache").write_bytes(b"CC")
            return RunResult(0, stdout=f"[*] Saving ticket in {argv[-1]}.ccache\n")
        if name == "nxc":
            return RunResult(0, stdout=self.nxc_out)
        return RunResult(0, stdout="")

    def nxc_argv(self):
        return next((c for c in self.calls if Path(c[0]).name == "nxc"), None)


def _golden(cfg, runner, tmp_path, overrides):
    ctx = ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    f = map_finding({"finding_id": "KB", "host": HOST, "category": "kerberos",
                     "severity": "high", "line": "krbtgt"})
    return get_executor("GOLDEN-TICKET").run(ctx, f, overrides)


def test_golden_reauth_has_kdchost_no_dns_server_by_default(tmp_path):
    runner = _ForgeCap()
    r = _golden(_cfg(forge_key=AES, forge_key_kind="aes"), runner, tmp_path,
               {"reauth_target": HOST, "domain_sid": "S-1-5-21-1-2-3", "forged_user": "Administrator"})
    assert r["complete"] is True
    argv = runner.nxc_argv()
    assert "--kdcHost" in argv and argv[argv.index("--kdcHost") + 1] == "10.0.0.11"
    assert "--dns-server" not in argv          # carrier path preserved


def test_golden_reauth_dns_server_opt_in(tmp_path):
    runner = _ForgeCap()
    _golden(_cfg(forge_key=AES, forge_key_kind="aes", dns_server="10.0.0.11"), runner, tmp_path,
            {"reauth_target": HOST, "domain_sid": "S-1-5-21-1-2-3", "forged_user": "Administrator"})
    argv = runner.nxc_argv()
    assert "--dns-server" in argv and argv[argv.index("--dns-server") + 1] == "10.0.0.11"


def test_golden_realm_resolution_failure_surfaces_persisted_diagnostic(tmp_path):
    # reauth fails with a realm/KDC resolution error -> the receipt carries the rich,
    # actionable diagnostic (persisted in `errors`), not just an opaque failure.
    runner = _ForgeCap(nxc_out="[-] Cannot find KDC for realm NORTH.SEVENKINGDOMS.LOCAL\n")
    r = _golden(_cfg(forge_key=AES, forge_key_kind="aes"), runner, tmp_path,
               {"reauth_target": HOST, "domain_sid": "S-1-5-21-1-2-3", "forged_user": "Administrator"})
    assert r["complete"] is False
    errs = r["errors"]
    assert "reauth_failed" in errs
    diag = [e for e in errs if e.startswith("resolution_failed:realm_kdc")]
    assert diag, errs
    assert "cfg.kdc_host" in diag[0] and "kdcHost=10.0.0.11" in diag[0]   # actionable context


# ========================================= wiring guards (non-vacuous presence)

def test_all_kerberos_sites_wire_discovery_flags():
    base = Path(netresolve.__file__).parent / "executors"
    for fn in ("constrained_deleg.py", "generic_all.py", "rbcd.py", "adcs_esc1.py", "forge_common.py"):
        assert "nxc_kerberos_flags" in (base / fn).read_text(), f"{fn} lost its discovery wiring"


def test_all_seven_auth_helpers_delegate_to_canonical():
    root = Path(netresolve.__file__).parent
    for rel in ("executors/add_member.py", "executors/gpo_abuse.py", "executors/roast.py",
                "executors/generic_all.py", "executors/targeted_kerberoast.py",
                "executors/certifried.py", "probes.py"):   # probes.py is the 7th (S2-review r1)
        src = (root / rel).read_text()
        assert "netresolve.nxc_auth_flags(cfg)" in src, f"{rel} did not delegate its auth helper"
        # the old duplicated body must be gone
        assert 'argv += ["--aesKey", cfg.aes_key]' not in src, f"{rel} still has a duplicated helper body"
