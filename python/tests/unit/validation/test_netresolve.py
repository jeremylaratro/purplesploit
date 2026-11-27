"""DNSHARDEN S1 — the netresolve layer (canonical NetBIOS/GC + Kerberos discovery
flags + post-hoc resolution-failure classifier).

Non-vacuous: the NetBIOS consolidation is pinned to the EXACT contract the review
required (`dcsync._krbtgt_target(cfg) == gc_qualify(cfg,"krbtgt")`, not `== netbios`),
`--dns-server` is proven OPT-IN (absent by default, present+exact only when set),
and the classifier is shown to label realm/fqdn failures with actionable context
while returning None on success.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation import netresolve
from purplesploit.validation.executors.dcsync import _krbtgt_target
from purplesploit.validation.executors import forge_common


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11")
    base.update(kw)
    return ValidationConfig(**base)


# ============================================================ NetBIOS / GC (G3)

def test_netbios_first_label_uppercased():
    assert netresolve.netbios(_cfg()) == "NORTH"


def test_netbios_override_wins_and_is_trimmed():
    assert netresolve.netbios(_cfg(netbios_domain="  Custom  ")) == "CUSTOM"


def test_netbios_single_label_domain():
    assert netresolve.netbios(_cfg(domain="corp")) == "CORP"


def test_config_netbios_property_now_honors_override():
    # the old config.netbios property IGNORED netbios_domain -- delegating fixes it
    assert _cfg(netbios_domain="WEIRD").netbios == "WEIRD"
    assert _cfg().netbios == "NORTH"


def test_forge_common_netbios_delegates():
    assert forge_common.netbios(_cfg(netbios_domain="x")) == netresolve.netbios(_cfg(netbios_domain="x")) == "X"


def test_gc_qualify_shape():
    assert netresolve.gc_qualify(_cfg(), "krbtgt") == "NORTH/krbtgt"
    assert netresolve.gc_qualify(_cfg(netbios_domain="ess"), "WINTERFELL$") == "ESS/WINTERFELL$"


def test_dcsync_krbtgt_target_equals_gc_qualify():
    # the CORRECT equivalence contract (review r1 #2): _krbtgt_target == gc_qualify,
    # NOT == netbios. Holds across default + whitespace override.
    for cfg in (_cfg(), _cfg(netbios_domain="  Child  "), _cfg(domain="essos.local")):
        assert _krbtgt_target(cfg) == netresolve.gc_qualify(cfg, "krbtgt")


# ====================================================== Kerberos discovery (G2)

def test_kdc_host_default_is_dc_ip():
    assert netresolve.kdc_host(_cfg()) == "10.0.0.11"


def test_kdc_host_explicit_override():
    assert netresolve.kdc_host(_cfg(kdc_host="10.9.9.9")) == "10.9.9.9"


def test_dns_server_is_opt_in():
    assert netresolve.dns_server(_cfg()) is None
    assert netresolve.dns_server(_cfg(dns_server="10.0.0.11")) == "10.0.0.11"


def test_nxc_kerberos_flags_no_dns_server_by_default():
    # carrier path: --kdcHost only, NO --dns-server (so the tool's system/hosts
    # resolver is preserved). Exact value, no duplicates.
    flags = netresolve.nxc_kerberos_flags(_cfg())
    assert flags == ["--kdcHost", "10.0.0.11"]
    assert "--dns-server" not in flags


def test_nxc_kerberos_flags_with_opt_in_dns_server():
    flags = netresolve.nxc_kerberos_flags(_cfg(kdc_host="1.2.3.4", dns_server="5.6.7.8"))
    assert flags == ["--kdcHost", "1.2.3.4", "--dns-server", "5.6.7.8"]
    assert flags.count("--kdcHost") == 1 and flags.count("--dns-server") == 1


# ================================================= post-hoc classifier (G1/G5)

def test_classify_realm_kdc_failure_is_rich_and_actionable():
    d = netresolve.classify_resolution_failure(
        _cfg(), "winterfell.north.sevenkingdoms.local",
        "[-] Cannot find KDC for realm NORTH.SEVENKINGDOMS.LOCAL")
    assert d is not None and d.startswith("resolution_failed:realm_kdc")
    # actionable context: the realm, the resolver tried, and a fix
    assert "NORTH.SEVENKINGDOMS.LOCAL" in d and "kdcHost=10.0.0.11" in d and "cfg.kdc_host" in d


def test_classify_fqdn_failure_names_target_and_fix():
    d = netresolve.classify_resolution_failure(
        _cfg(), "winterfell.north.sevenkingdoms.local",
        "socket.gaierror: [Errno -3] Temporary failure in name resolution")
    assert d is not None and d.startswith("resolution_failed:fqdn")
    assert "winterfell.north.sevenkingdoms.local" in d and "cfg.dns_server" in d
    assert "system/etc-hosts" in d            # the resolver tried, when dns_server unset


def test_classify_success_returns_none():
    assert netresolve.classify_resolution_failure(
        _cfg(), "winterfell", "SMB  winterfell  445  WS  [+] NORTH\\Administrator (Pwn3d!)") is None


def test_classify_unrelated_failure_returns_none():
    # an AUTH failure is not a resolution failure -> no false diagnostic
    assert netresolve.classify_resolution_failure(
        _cfg(), "winterfell", "[-] STATUS_LOGON_FAILURE") is None


def test_classifier_leaks_no_secrets():
    cfg = _cfg(password="SuperSecret!", nt_hash="deadbeef" * 4)
    d = netresolve.classify_resolution_failure(cfg, "host", "Cannot find KDC for realm X")
    assert d and "SuperSecret!" not in d and "deadbeef" not in d


# ============================================================ import hygiene (#6)

def test_netresolve_imports_nothing_from_package():
    src = Path(netresolve.__file__).read_text()
    # no `from .` / `from ..` / `import purplesploit` -> dependency-free leaf (no cycle)
    for bad in ("from .", "from ..", "import purplesploit"):
        assert bad not in src, f"netresolve must not contain {bad!r}"


def test_cold_import_no_cycle():
    # fresh interpreter: importing netresolve, then config, then the executor
    # registry must all succeed (config -> netresolve one-way; no cycle).
    pkg_root = Path(__file__).resolve().parents[3]   # .../python
    code = (f"import sys; sys.path.insert(0, {str(pkg_root)!r});"
            "import purplesploit.validation.netresolve;"
            "import purplesploit.validation.config;"
            "import purplesploit.validation.executors;"
            "print('OK')")
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True,
                       env={"PYTHONDONTWRITEBYTECODE": "1"})
    assert r.returncode == 0 and "OK" in r.stdout, r.stderr
