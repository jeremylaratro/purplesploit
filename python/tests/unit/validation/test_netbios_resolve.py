"""Active NetBIOS resolution (netresolve.resolve_netbios / ensure_netbios).

Layering (owner request 27NOV2026): ONE main method (rpcclient lsaquery) retried
up to 3 times, then BACKUP methods (querydominfo, lookupsid) once each, then the
deterministic heuristic. Non-vacuous: a network result must WIN over the heuristic
(proven with a domain whose heuristic differs from the network answer), the main
must be retried exactly `attempts` times before a backup is tried, and an operator
override must short-circuit with NO query.
"""
from __future__ import annotations

from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation import netresolve
from purplesploit.validation.executors.base import CommandRunner, RunResult


# domain whose heuristic NetBIOS ("CORP") DIFFERS from the real one ("CONTOSO"),
# so a network answer is distinguishable from the heuristic fallback.
def _cfg(**kw):
    base = dict(domain="corp.contoso.local", dc_ip="10.0.0.11", username="jsmith", password="pw")
    base.update(kw)
    return ValidationConfig(**base)


class _NBRunner(CommandRunner):
    """Scripted per-tool fake. `resp` maps a key to a RunResult or a list consumed
    in call order (exhausted → failure). rpcclient is keyed by its `-c` command."""
    def __init__(self, resp=None):
        self.resp = resp or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        name = Path(argv[0]).name
        key = name
        if name == "rpcclient" and "-c" in argv:
            key = f"rpcclient:{argv[argv.index('-c') + 1]}"
        v = self.resp.get(key)
        if isinstance(v, list):
            return v.pop(0) if v else RunResult(1, stdout="")
        return v if v is not None else RunResult(1, stdout="")

    def count(self, predicate):
        return sum(1 for c in self.calls if predicate(c))


_LSAQUERY_OK = RunResult(0, stdout="Domain Name: CONTOSO\nDomain Sid: S-1-5-21-1-2-3\n")
_QUERYDOMINFO_OK = RunResult(0, stdout="Domain:\t\tCONTOSO\nServer:\t\t\n")
_LOOKUPSID_OK = RunResult(0, stdout="[*] Domain SID is: S-1-5-21-1-2-3\n500: CONTOSO\\Administrator (SidTypeUser)\n")
_FAIL = RunResult(1, stdout="", stderr="NT_STATUS_IO_TIMEOUT")


# ========================================================= the layering

def test_main_lsaquery_wins_on_first_attempt():
    r = _NBRunner({"rpcclient:lsaquery": _LSAQUERY_OK})
    name, method, trail = netresolve.resolve_netbios(_cfg(), r)
    assert name == "CONTOSO" and method == "lsaquery(attempt 1)"   # network, not heuristic "CORP"
    assert r.count(lambda c: "lsaquery" in c) == 1
    assert not r.count(lambda c: "querydominfo" in c)              # backups not reached


def test_main_retried_three_times_then_backup():
    r = _NBRunner({"rpcclient:lsaquery": [_FAIL, _FAIL, _FAIL], "rpcclient:querydominfo": _QUERYDOMINFO_OK})
    name, method, trail = netresolve.resolve_netbios(_cfg(), r)
    assert name == "CONTOSO" and method == "querydominfo"
    assert r.count(lambda c: "lsaquery" in c) == 3                 # main tried exactly 3x
    assert r.count(lambda c: "querydominfo" in c) == 1


def test_falls_through_to_lookupsid():
    r = _NBRunner({"rpcclient:lsaquery": [_FAIL, _FAIL, _FAIL],
                   "rpcclient:querydominfo": _FAIL, "impacket-lookupsid": _LOOKUPSID_OK})
    name, method, _ = netresolve.resolve_netbios(_cfg(), r)
    assert name == "CONTOSO" and method == "lookupsid"


def test_all_methods_fail_falls_back_to_heuristic():
    r = _NBRunner()   # everything fails
    name, method, trail = netresolve.resolve_netbios(_cfg(), r)
    assert method == "heuristic" and name == "CORP"               # the FQDN-first-label guess
    assert r.count(lambda c: "lsaquery" in c) == 3                # main still retried 3x
    assert r.count(lambda c: "impacket-lookupsid" in c) == 1     # both backups attempted


def test_attempts_is_configurable():
    r = _NBRunner()
    netresolve.resolve_netbios(_cfg(), r, attempts=1)
    assert r.count(lambda c: "lsaquery" in c) == 1


def test_override_short_circuits_with_no_query():
    r = _NBRunner({"rpcclient:lsaquery": _LSAQUERY_OK})
    name, method, _ = netresolve.resolve_netbios(_cfg(netbios_domain="FIXED"), r)
    assert name == "FIXED" and method == "override"
    assert r.calls == []                                          # NEVER queried


def test_invalid_or_noise_output_is_rejected():
    # a blank / noise domain must not be accepted as a NetBIOS name
    for bad in (RunResult(0, stdout="Domain Name:\n"), RunResult(0, stdout="Domain Name: Name\n")):
        r = _NBRunner({"rpcclient:lsaquery": [bad, bad, bad]})
        _, method, _ = netresolve.resolve_netbios(_cfg(), r)
        assert method != "lsaquery(attempt 1)"                    # fell through, not accepted


# ========================================================= ensure_netbios caching

def test_ensure_caches_a_network_result():
    cfg = _cfg()
    r = _NBRunner({"rpcclient:lsaquery": _LSAQUERY_OK})
    name, method, _ = netresolve.ensure_netbios(cfg, r)
    assert name == "CONTOSO" and cfg.netbios_domain == "CONTOSO"  # cached onto cfg
    # a second resolve now short-circuits on the override (no new query)
    r2 = _NBRunner({"rpcclient:lsaquery": _LSAQUERY_OK})
    _, m2, _ = netresolve.resolve_netbios(cfg, r2)
    assert m2 == "override" and r2.calls == []


def test_ensure_does_not_cache_the_heuristic():
    cfg = _cfg()
    r = _NBRunner()   # all fail -> heuristic
    name, method, _ = netresolve.ensure_netbios(cfg, r)
    assert method == "heuristic" and cfg.netbios_domain is None   # NOT pinned (transient-safe)


def test_resolver_requires_no_creds_gracefully():
    # Kerberos-only cfg (no password/hash) -> rpc/lookupsid unusable -> heuristic
    r = _NBRunner({"rpcclient:lsaquery": _LSAQUERY_OK})
    cfg = ValidationConfig(domain="corp.contoso.local", dc_ip="10.0.0.11", username="j")
    name, method, _ = netresolve.resolve_netbios(cfg, r)
    assert method == "heuristic"           # no usable cred -> methods decline, never crash
    assert r.calls == []                   # didn't even try (no cred to pass)
