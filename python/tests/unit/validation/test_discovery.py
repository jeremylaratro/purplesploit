"""Capability-discovery mode: probe-all viability report + gated auto-exploit.

Safety is the point (plan-reviewed): discovery is read-only; auto-exploit fires ONLY a
technique that is implemented + verified + probe-viable (not unknown) + has complete target
params + is non-mutating (unless --allow-destructive). Everything else is reported, not fired.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.executors import IMPLEMENTED
from purplesploit.validation.executors.base import (ExecutorContext, CommandRunner, RunResult,
                                                     AuthorizedLabProvider)
from purplesploit.validation.orchestrator import ValidationOrchestrator
from purplesploit.validation.probes import ProbeResult, probe_finding, PreconditionProbe
from purplesploit.validation import discovery


def _cfg(tmp_path, **kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="192.168.56.11",
                username="jon.snow", password="pw", output_dir=tmp_path)
    base.update(kw)
    return ValidationConfig(**base)


class _Runner(CommandRunner):
    """getST -> a saved ticket; nxc -> Pwn3d (so an eligible non-mutating edge completes)."""
    def __init__(self):
        self.calls = []
    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "nxc":
            return RunResult(returncode=0, stdout="SMB h 445 [+] north\\Administrator (Pwn3d!)")
        if tool == "impacket-getST":
            return RunResult(returncode=0, stdout="[*] Saving ticket in admin@cifs.ccache")
        return RunResult(returncode=0, stdout="")


def _ctx(cfg, tmp_path):
    return ExecutorContext(cfg, runner=_Runner(), authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path)


# Craft probe verdicts by technique for build_verdicts (bypasses the live LDAP reads).
def _fake_probes(mapping, default):
    def run(ctx, findings, max_workers=8):
        return [mapping.get(f.technique, default) for f in findings]
    return run


def test_candidate_findings_one_per_technique(tmp_path):
    cands = discovery.candidate_findings(_cfg(tmp_path), ["winterfell"])
    assert {c.technique for c in cands} == set(IMPLEMENTED)      # every technique probed
    assert all(c.entity == {} for c in cands)                   # no self-as-target seeding (review #4)


def test_eligibility_gate(tmp_path, monkeypatch):
    mapping = {
        "S4U2SELF": ProbeResult(viable=True, reason="computer acct"),      # verified, non-mut, complete
        "WRITE-DACL": ProbeResult(viable=True, reason="has write"),        # verified but MUTATING
        "KERBEROAST": ProbeResult(viable=True, reason="roastable"),        # viable but needs principal (missing)
        "BRONZE-BIT": ProbeResult(viable=True, reason="deleg"),            # viable but UNVERIFIED
        "ASREP": ProbeResult(viable=False, reason="preauth on"),          # not viable
        "LAPS": ProbeResult(viable=True, unknown=True, reason="?"),        # unknown
    }
    monkeypatch.setattr(discovery.probes_mod, "run_probes",
                        _fake_probes(mapping, ProbeResult(viable=True, unknown=True, reason="?")))
    v = {x.technique: x for x in discovery.build_verdicts(_ctx(_cfg(tmp_path), tmp_path), ["winterfell"])}
    assert len(v) == len(IMPLEMENTED)                                      # review #3: all present, none dropped
    assert v["S4U2SELF"].eligible_for_autoexploit is True
    assert v["WRITE-DACL"].eligible_for_autoexploit is False and v["WRITE-DACL"].mutating is True  # review #1
    assert v["KERBEROAST"].eligible_for_autoexploit is False and "principal" in v["KERBEROAST"].missing_params
    assert v["BRONZE-BIT"].eligible_for_autoexploit is False and v["BRONZE-BIT"].viable is True     # unverified
    assert v["ASREP"].eligible_for_autoexploit is False and v["ASREP"].viable is False
    assert v["LAPS"].eligible_for_autoexploit is False and v["LAPS"].unknown is True                # review #2


def test_mutating_eligible_only_with_allow_destructive(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery.probes_mod, "run_probes",
                        _fake_probes({"WRITE-DACL": ProbeResult(viable=True, reason="ok")},
                                     ProbeResult(viable=False, reason="n/a")))
    ctx = _ctx(_cfg(tmp_path, allow_destructive=True), tmp_path)
    v = {x.technique: x for x in discovery.build_verdicts(ctx, ["winterfell"], allow_destructive=True)}
    assert v["WRITE-DACL"].eligible_for_autoexploit is True                # mutating allowed now


def test_discover_autoexploit_runs_eligible_skips_mutating(tmp_path, monkeypatch):
    mapping = {"S4U2SELF": ProbeResult(viable=True, reason="computer acct"),
               "WRITE-DACL": ProbeResult(viable=True, reason="has write")}
    monkeypatch.setattr(discovery.probes_mod, "run_probes",
                        _fake_probes(mapping, ProbeResult(viable=False, reason="n/a")))
    runner = _Runner()
    orch = ValidationOrchestrator(_cfg(tmp_path, auto_confirm=True), runner=runner)
    report = orch.discover(["winterfell.north.sevenkingdoms.local"], exploit=True, allow_destructive=False)
    exploited = {e["technique"] for e in report["exploited"]}
    assert "S4U2SELF" in exploited                                         # verified+viable+non-mut -> fired
    assert "WRITE-DACL" not in exploited                                   # mutating, no --allow-destructive
    # WRITE-DACL's tooling was never invoked
    assert not any("dacledit" in " ".join(c).lower() or "bloodyad" in " ".join(c).lower()
                   for c in runner.calls)
    assert report["mode"] == "discover" and report["summary"]["techniques"] == len(IMPLEMENTED)


def test_probe_error_reason_carries_no_secret(tmp_path):
    # review #5: a probe exception carrying credential text must NOT reach the public reason.
    class _Boom(PreconditionProbe):
        technique = "KERBEROAST"
        def check(self, ctx, finding):
            raise RuntimeError("impacket GetUserSPNs north/jon.snow:SuperSecret123 failed")
    ctx = _ctx(_cfg(tmp_path), tmp_path)
    from purplesploit.validation.findings import map_finding
    f = map_finding({"finding_id":"x","host":"h","category":"x","severity":"info","line":"x"})
    import purplesploit.validation.probes as P
    import unittest.mock as mock
    with mock.patch.object(P, "get_probe", return_value=_Boom()):
        res = P.probe_finding(ctx, f)
    assert res.unknown is True
    assert "SuperSecret123" not in res.reason and "RuntimeError" in res.reason   # type only


def test_smart_gate_skips_prereq_absent_without_probing(tmp_path, monkeypatch):
    # conditional gating: an account with NO delegation / NO SPN / no CA / no forge key
    # must SKIP those technique groups WITHOUT running their (expensive) probes.
    from purplesploit.validation.discovery import _Recon
    monkeypatch.setattr(discovery, "recon", lambda ctx: _Recon(
        has_delegation=False, has_spn=False, is_computer=False, has_ca=False, has_forge_key=False))
    probed = []
    def fake(ctx, findings, max_workers=8):
        probed.extend(f.technique for f in findings)
        return [ProbeResult(viable=True, unknown=True, reason="?") for _ in findings]
    monkeypatch.setattr(discovery.probes_mod, "run_probes", fake)
    v = {x.technique: x for x in discovery.build_verdicts(_ctx(_cfg(tmp_path), tmp_path), ["winterfell"])}
    for t in ("CONSTRAINED-DELEG-PT", "BRONZE-BIT", "S4U2SELF", "ESC8", "CERTIFRIED",
              "GOLDEN-TICKET", "SHADOW-CREDS"):
        assert t not in probed                                     # gated out -> never probed
        assert v[t].viable is False and "prerequisite_absent" in v[t].evidence   # explained skip
    assert "KERBEROAST" in probed                                  # no shared prereq -> still probed
    assert len(v) == len(IMPLEMENTED)                              # all still reported


def test_smart_gate_fail_safe_on_unreadable_prereq(tmp_path, monkeypatch):
    # an UNREADABLE prerequisite (None) must NOT skip -- fall through to the probe (fail-safe).
    from purplesploit.validation.discovery import _Recon
    monkeypatch.setattr(discovery, "recon", lambda ctx: _Recon(
        has_delegation=None, has_spn=None, is_computer=False, has_ca=None, has_forge_key=False))
    probed = []
    def fake(ctx, findings, max_workers=8):
        probed.extend(f.technique for f in findings)
        return [ProbeResult(viable=True, reason="ok") for _ in findings]
    monkeypatch.setattr(discovery.probes_mod, "run_probes", fake)
    discovery.build_verdicts(_ctx(_cfg(tmp_path), tmp_path), ["winterfell"])
    assert "CONSTRAINED-DELEG-PT" in probed and "ESC8" in probed   # unknown prereq -> probed, not skipped


def test_recon_reads_delegation_and_ca(tmp_path):
    class _R(CommandRunner):
        def run(self, argv, *, env=None, timeout=None, cwd=None):
            tool = Path(argv[0]).name
            if tool == "nxc":
                return RunResult(returncode=0, stdout=(
                    "LDAP dc 389 WINTERFELL [+] Response for object: CN=jon.snow\n"
                    "LDAP dc 389 WINTERFELL sAMAccountName       jon.snow\n"
                    "LDAP dc 389 WINTERFELL msDS-AllowedToDelegateTo CIFS/winterfell\n"))
            if tool == "certipy-ad":
                return RunResult(returncode=0, stdout="Certificate Authorities\n  0\n    CA Name : north-CA\n")
            return RunResult(returncode=0, stdout="")
    ctx = ExecutorContext(_cfg(tmp_path), runner=_R(), authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    r = discovery.recon(ctx)
    assert r.has_delegation is True and r.has_ca is True and r.has_spn is False


def test_recon_ca_errored_is_unknown_not_absent(tmp_path):
    # review HIGH: a FAILED certipy read must leave has_ca=None (not False), so ADCS is
    # not falsely skipped; a CLEAN no-CA read is a confirmed False.
    def _runner(certipy_out, certipy_rc=0):
        class _R(CommandRunner):
            def run(self, argv, *, env=None, timeout=None, cwd=None):
                if Path(argv[0]).name == "certipy-ad":
                    return RunResult(returncode=certipy_rc, stdout=certipy_out)
                return RunResult(returncode=0, stdout="")   # account read fails -> delegation None
        return _R()

    def _recon(runner):
        return discovery.recon(ExecutorContext(_cfg(tmp_path), runner=runner,
                               authorizer=AuthorizedLabProvider(True), output_dir=tmp_path))

    assert _recon(_runner("[-] Got error: LDAP connection failed", certipy_rc=1)).has_ca is None
    assert _recon(_runner("")).has_ca is None                               # empty -> unknown
    # certipy logs TEMPLATE counts separately -- "0 certificate templates" must NOT mean "no CA"
    assert _recon(_runner("[*] Found 0 certificate templates")).has_ca is None
    assert _recon(_runner("[*] Found 0 certificate authorities")).has_ca is False   # explicit CA absence
    assert _recon(_runner("Certificate Authorities\n  0\n    CA Name : north-CA")).has_ca is True


def test_recon_delegation_requires_genuine_read(tmp_path):
    # an error response that merely ECHOES the sAMAccountName filter must NOT be read as a
    # genuine account read (which would infer has_delegation=False and skip delegation).
    def _runner(nxc_out, nxc_rc=0):
        class _R(CommandRunner):
            def run(self, argv, *, env=None, timeout=None, cwd=None):
                if Path(argv[0]).name == "nxc":
                    return RunResult(returncode=nxc_rc, stdout=nxc_out)
                return RunResult(returncode=0, stdout="")
        return _R()

    def _recon(runner):
        return discovery.recon(ExecutorContext(_cfg(tmp_path), runner=runner,
                               authorizer=AuthorizedLabProvider(True), output_dir=tmp_path))

    # error echoing the filter, NO "Response for object" marker -> unknown, not absent
    echo = "LDAP dc 389 WINTERFELL [-] Error running query (sAMAccountName=jon.snow): timeout"
    assert _recon(_runner(echo, nxc_rc=1)).has_delegation is None
    # a genuine clean read with the delegation attr -> True
    good = ("LDAP dc 389 WINTERFELL [+] Response for object: CN=jon.snow\n"
            "LDAP dc 389 WINTERFELL msDS-AllowedToDelegateTo CIFS/winterfell\n")
    assert _recon(_runner(good)).has_delegation is True
    # a genuine clean read WITHOUT the attr -> confirmed absent (False)
    empty = "LDAP dc 389 WINTERFELL [+] Response for object: CN=jon.snow\nLDAP dc 389 WINTERFELL sAMAccountName jon.snow\n"
    assert _recon(_runner(empty)).has_delegation is False


def test_probe_parse_handles_real_nxc_whitespace_format():
    # Carrier-validation fix: real `nxc ldap --query` is WHITESPACE-separated with a
    # "Response for object" marker (not colon-delimited). The parse must read it -- the
    # old colon-only anchor/extractor silently failed against real GOAD output.
    from purplesploit.validation.probes import _extract_attr, _account_read_ok
    nxc = ("LDAP 192.168.56.11 389 WINTERFELL [+] Response for object: CN=jon.snow,CN=Users,DC=north\n"
           "LDAP 192.168.56.11 389 WINTERFELL sAMAccountName       jon.snow\n"
           "LDAP 192.168.56.11 389 WINTERFELL userAccountControl   16843264\n"
           "LDAP 192.168.56.11 389 WINTERFELL msDS-AllowedToDelegateTo CIFS/winterfell\n")
    assert _account_read_ok(RunResult(returncode=0, stdout=nxc), nxc) is True
    assert _extract_attr(nxc, "userAccountControl") == "16843264"
    assert _extract_attr(nxc, "msDS-AllowedToDelegateTo") == "CIFS/winterfell"
    assert _extract_attr(nxc, "sAMAccountName") == "jon.snow"
    # colon / equals formats (older tools and the existing fakes) still parse
    colon = "sAMAccountName: jon.snow\nuserAccountControl = 512\n"
    assert _extract_attr(colon, "userAccountControl") == "512"
    assert _extract_attr(colon, "sAMAccountName") == "jon.snow"


def test_extract_attr_ignores_status_marker_lines_no_cred_leak():
    # review HIGH: nxc echoes `[+] domain\\user:PASSWORD` in its auth banner. A password
    # that happens to contain an attribute-name substring must NOT be captured as that
    # attribute's value (status-marker lines are excluded from attribute parsing).
    from purplesploit.validation.probes import _extract_attr
    leaky = ("LDAP 1.2.3.4 389 DC [+] north\\jon.snow:msDS-AllowedToDelegateTo CanarySecret!\n"
             "LDAP 1.2.3.4 389 DC [+] Response for object: CN=jon.snow\n"
             "LDAP 1.2.3.4 389 DC sAMAccountName       jon.snow\n")
    assert _extract_attr(leaky, "msDS-AllowedToDelegateTo") is None   # not in a real result row
    assert "CanarySecret" not in str(_extract_attr(leaky, "msDS-AllowedToDelegateTo"))
    assert _extract_attr(leaky, "sAMAccountName") == "jon.snow"        # genuine row still read


def test_discover_cli_read_only(tmp_path, monkeypatch):
    # `discover` without --exploit is read-only (no receipts) and exits 0.
    monkeypatch.setattr(discovery.probes_mod, "run_probes",
                        _fake_probes({}, ProbeResult(viable=True, unknown=True, reason="?")))
    from purplesploit.validation import cli
    orig = cli.ValidationOrchestrator.__init__
    def patched(self, *a, **k):
        k.setdefault("runner", _Runner()); orig(self, *a, **k)
    monkeypatch.setattr(cli.ValidationOrchestrator, "__init__", patched)
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        status = cli.main(["discover", "--domain", "north.sevenkingdoms.local",
                           "--dc-ip", "192.168.56.11", "--user", "jon.snow", "--password", "pw",
                           "--target", "winterfell", "--output", str(tmp_path)])
    out = json.loads(buf.getvalue())
    assert status == 0 and out["mode"] == "discover"
    assert out["exploited"] == [] and len(out["discovery"]) == len(IMPLEMENTED)
