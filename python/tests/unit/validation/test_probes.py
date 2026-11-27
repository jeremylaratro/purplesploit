"""Precondition-probe layer (probes.py) -- ADR-002 D1 ("detect before you fire").

Each of the 8 probes is driven with a scripted fake runner (no lab) and asserted
to return the right :class:`ProbeResult` for three cases:

* **viable**     -- a positive determination it can plausibly work (proceeds).
* **not-viable** -- a positive determination it will NOT work (``viable=False``,
  the ONLY state that skips the technique).
* **unknown**    -- a tool error / unreadable fact (``unknown=True``) that must
  NOT skip the technique (it is attempted anyway with the uncertainty flagged).

The cardinal safety property under test: a tool error or unparseable output
yields ``unknown=True``, NEVER a false ``viable=False`` that would wrongly drop a
real finding. Reads are non-destructive only (no test file is ever written).

Orchestrator-level tests assert the wiring: a finding whose probe is not-viable
is SKIPPED (and recorded in the run report's ``skipped`` list with its reason +
evidence), while viable and unknown findings both proceed (the unknown one
carries its reason into the plan).
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation.orchestrator import (
    ValidationOrchestrator, AranumRunner, AutoConfirm, DeclineAll,
)
from purplesploit.validation import probes
from purplesploit.validation.probes import ProbeResult, get_probe, run_probes


# ----------------------------------------------------------------- fakes
class _Runner(CommandRunner):
    """Return a fixed scripted RunResult for any invocation (records argv)."""

    def __init__(self, result=None, by_tool=None):
        self.result = result if result is not None else RunResult(returncode=0, stdout="")
        self.by_tool = by_tool or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool in self.by_tool:
            return self.by_tool[tool]
        return self.result


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, runner, tmp_path):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=AuthorizedLabProvider(True), output_dir=tmp_path)


# A hard tool failure -> _tool_errored True -> every probe must return unknown.
_ERR = RunResult(returncode=None, error="FileNotFoundError: tool not on PATH")


# ================================================================= KERBEROAST
def _kerb_finding(principal="svc_sql"):
    return map_finding({
        "finding_id": "AR-k1", "host": "dc01.north.sevenkingdoms.local",
        "category": "ad", "severity": "high", "rule_id": "promoted-kerberoast-spn",
        "line": f"Kerberoastable SPN account {principal} : MSSQLSvc/db.north",
    })


def test_kerberoast_viable_rc4(tmp_path):
    out = ("LDAP 10.0.0.11 389 DC sAMAccountName: svc_sql\n"
           "LDAP 10.0.0.11 389 DC msDS-SupportedEncryptionTypes: 4\n")
    pr = get_probe("KERBEROAST").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _kerb_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence == {"is_user": True, "enc_types": 4, "rc4": True}
    assert "13100" in pr.reason


def test_kerberoast_viable_aes_only_is_slow(tmp_path):
    out = ("sAMAccountName: svc_sql\nmsDS-SupportedEncryptionTypes: 24\n")  # 0x18 AES, no RC4
    pr = get_probe("KERBEROAST").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _kerb_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence["aes_only"] is True and pr.evidence["rc4"] is False
    assert "slow" in pr.reason.lower()


def test_kerberoast_not_viable_computer_account(tmp_path):
    # A computer/MSA principal (trailing '$') -> uncrackable -> positive skip; no read.
    runner = _Runner(RunResult(0, stdout="unused"))
    pr = get_probe("KERBEROAST").check(
        _ctx(_cfg(), runner, tmp_path), _kerb_finding(principal="WINTERFELL$"))
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["is_user"] is False
    assert runner.calls == []                       # determined without any read


def test_kerberoast_unknown_on_read_error(tmp_path):
    pr = get_probe("KERBEROAST").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _kerb_finding())
    assert pr.viable is True and pr.unknown is True   # unknown must NOT skip
    assert pr.evidence["enc_types"] is None


# ================================================================= ASREP
def _asrep_finding(principal="brandon.stark"):
    return map_finding({
        "finding_id": "AR-a1", "host": "dc01.north.sevenkingdoms.local",
        "category": "ad", "severity": "high", "rule_id": "promoted-asrep-user",
        "line": f"AS-REP-roastable account {principal} : no pre-auth",
    })


def test_asrep_viable_dont_req_preauth_set(tmp_path):
    out = "sAMAccountName: brandon.stark\nuserAccountControl: 4260352\n"   # 0x410200 has 0x400000
    pr = get_probe("ASREP").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _asrep_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence["uac_dont_req_preauth"] is True


def test_asrep_not_viable_preauth_required(tmp_path):
    out = "sAMAccountName: brandon.stark\nuserAccountControl: 512\n"       # normal account
    pr = get_probe("ASREP").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _asrep_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["uac_dont_req_preauth"] is False
    assert "pre-auth required" in pr.reason


def test_asrep_unknown_on_read_error(tmp_path):
    pr = get_probe("ASREP").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _asrep_finding())
    assert pr.viable is True and pr.unknown is True
    assert pr.evidence["uac_dont_req_preauth"] is None


# ================================================================= LAPS
def _laps_finding(host="srv02.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-l1", "host": host, "category": "smb", "severity": "high",
        "line": f"ms-Mcs-AdmPwd READABLE (LAPSv1) on {host}",
    })


def test_laps_viable_attribute_readable(tmp_path):
    out = "sAMAccountName: SRV02$\nms-Mcs-AdmPwd: Str0ngL@psPw!\n"
    pr = get_probe("LAPS").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _laps_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence["laps_readable"] is True


def test_laps_not_viable_no_attribute(tmp_path):
    # Object read OK (anchor present) but the LAPS attribute is explicitly absent.
    out = "sAMAccountName: SRV02$\nms-Mcs-AdmPwd attribute not found for SRV02$\n"
    pr = get_probe("LAPS").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _laps_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["laps_readable"] is False


def test_laps_unknown_on_read_error(tmp_path):
    pr = get_probe("LAPS").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _laps_finding())
    assert pr.viable is True and pr.unknown is True   # aranum marker passed through
    assert pr.evidence["laps_readable"] is None


# ================================================================= CONSTRAINED-DELEG-PT
def _deleg_finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-d1", "host": host, "category": "delegation", "severity": "high",
        "line": f"msDS-AllowedToDelegateTo cifs/{host} (constrained delegation) on {host}",
    })


def test_deleg_viable_full_protocol_transition(tmp_path):
    # jon.snow (the operator / deleg principal) has a2d set AND TRUSTED_TO_AUTH (0x1000000).
    out = ("sAMAccountName: jon.snow\n"
           "msDS-AllowedToDelegateTo: cifs/winterfell.north.sevenkingdoms.local\n"
           "userAccountControl: 16777728\n")                 # 0x1000200 has 0x1000000
    pr = get_probe("CONSTRAINED-DELEG-PT").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _deleg_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence["protocol_transition"] is True
    assert pr.evidence["target_protected"] is False          # Administrator is RID-500 ok
    assert "full S4U" in pr.reason


def test_deleg_viable_with_caveat_no_protocol_transition(tmp_path):
    out = ("sAMAccountName: jon.snow\n"
           "msDS-AllowedToDelegateTo: cifs/winterfell.north.sevenkingdoms.local\n"
           "userAccountControl: 512\n")                       # a2d set but no PT bit
    pr = get_probe("CONSTRAINED-DELEG-PT").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _deleg_finding())
    assert pr.viable is True and pr.unknown is False          # still viable (with caveat)
    assert pr.evidence["protocol_transition"] is False
    assert "RBCD/coercion pivot" in pr.reason


def test_deleg_not_viable_no_allowed_to_delegate_to(tmp_path):
    # Object read OK but msDS-AllowedToDelegateTo is unset -> no constrained delegation.
    out = "sAMAccountName: jon.snow\nuserAccountControl: 512\n"
    pr = get_probe("CONSTRAINED-DELEG-PT").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _deleg_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["allowed_to_delegate_to"] is None


def test_deleg_unknown_on_read_error(tmp_path):
    pr = get_probe("CONSTRAINED-DELEG-PT").check(
        _ctx(_cfg(), _Runner(_ERR), tmp_path), _deleg_finding())
    assert pr.viable is True and pr.unknown is True


# ================================================================= RBCD
def _rbcd_finding(host="dc01.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-r1", "host": host, "category": "delegation", "severity": "high",
        "line": f"msDS-AllowedToActOnBehalfOfOtherIdentity writable on {host}",
    })


def test_rbcd_viable_maq_and_dfl_ok_but_write_acl_unknown(tmp_path):
    out = "ms-DS-MachineAccountQuota: 10\nmsDS-Behavior-Version: 7\n"      # MAQ>0, DFL 2016
    pr = get_probe("RBCD").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _rbcd_finding())
    assert pr.viable is True
    # The required write-ACL is NOT readable without BloodHound -> flagged unknown,
    # NEVER a false skip.
    assert pr.unknown is True
    assert pr.evidence == {"maq": 10, "dfl": 7}
    assert "WriteAccountRestrictions" in pr.reason


def test_rbcd_not_viable_maq_zero(tmp_path):
    out = "ms-DS-MachineAccountQuota: 0\nmsDS-Behavior-Version: 7\n"
    pr = get_probe("RBCD").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _rbcd_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["maq"] == 0


def test_rbcd_not_viable_dfl_below_2012(tmp_path):
    out = "ms-DS-MachineAccountQuota: 10\nmsDS-Behavior-Version: 4\n"      # DFL 2008R2 < 2012
    pr = get_probe("RBCD").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _rbcd_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["dfl"] == 4


def test_rbcd_unknown_on_read_error(tmp_path):
    pr = get_probe("RBCD").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _rbcd_finding())
    assert pr.viable is True and pr.unknown is True
    assert pr.evidence == {"maq": None, "dfl": None}


# ================================================================= OPENSHARES-WRITE
def _shares_finding(host="srv02.north.sevenkingdoms.local", share="data"):
    return map_finding({
        "finding_id": "AR-s1", "host": host, "category": "smb", "severity": "high",
        "line": f"non-default RW share '{share}' (READ,WRITE) on {host}",
    })


def _shares_table(share, perms):
    return ("SMB 10.0.0.12 445 SRV02 Share           Permissions     Remark\n"
            "SMB 10.0.0.12 445 SRV02 -----           -----------     ------\n"
            f"SMB 10.0.0.12 445 SRV02 {share}            {perms}\n")


def test_openshares_viable_write_permission(tmp_path):
    runner = _Runner(RunResult(0, stdout=_shares_table("data", "READ,WRITE")))
    pr = get_probe("OPENSHARES-WRITE").check(_ctx(_cfg(), runner, tmp_path), _shares_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence["share_rw"] is True
    # Non-destructive: a --shares read only, never a put/write.
    assert all("--shares" in c or Path(c[0]).name != "nxc" for c in runner.calls)
    assert all("put" not in c for c in runner.calls)


def test_openshares_not_viable_read_only(tmp_path):
    runner = _Runner(RunResult(0, stdout=_shares_table("data", "READ")))
    pr = get_probe("OPENSHARES-WRITE").check(_ctx(_cfg(), runner, tmp_path), _shares_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["share_rw"] is False
    assert "READ-only" in pr.reason


def test_openshares_unknown_on_read_error(tmp_path):
    pr = get_probe("OPENSHARES-WRITE").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _shares_finding())
    assert pr.viable is True and pr.unknown is True    # aranum RW marker passed through
    assert pr.evidence["share_rw"] is None


# ================================================================= SHADOW-CREDS
def _shadow_finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-sc1", "host": host, "category": "adcs", "severity": "high",
        "rule_id": "promoted-shadow-creds", "line": f"shadow credentials candidate on {host}",
    })


def test_shadow_viable_pkinit_available_write_acl_unknown(tmp_path):
    out = ("Certipy v5.0.0\n[*] Finding certificate templates\n"
           "Certificate Authorities\n  0\n    CA Name  : NORTH-CA\n    DNS Name : dc01.north\n")
    pr = get_probe("SHADOW-CREDS").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _shadow_finding())
    assert pr.viable is True
    assert pr.unknown is True                          # msDS-KeyCredentialLink write-ACL unreadable
    assert pr.evidence["pkinit_available"] is True


def test_shadow_not_viable_no_ca(tmp_path):
    out = "Certipy v5.0.0\n[-] Could not find any certificate authorities\n"
    pr = get_probe("SHADOW-CREDS").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _shadow_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["pkinit_available"] is False


def test_shadow_unknown_on_read_error(tmp_path):
    pr = get_probe("SHADOW-CREDS").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _shadow_finding())
    assert pr.viable is True and pr.unknown is True
    assert pr.evidence["pkinit_available"] is None


# ================================================================= ADCS-ESC1
def _esc1_finding(host="dc01.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-e1", "host": host, "category": "adcs", "severity": "critical",
        "rule_id": "promoted-adcs-tpl",
        "line": "AD CS template VulnTemplate (ESC1) issued by AD CS CA NORTH-CA",
    })


def test_esc1_viable_template_enrollable(tmp_path):
    out = ("Certipy v5.0.0\n[*] Found 1 vulnerable certificate templates\n"
           "  0\n    Template Name : VulnTemplate\n    [!] Vulnerabilities : ESC1\n")
    pr = get_probe("ADCS-ESC1").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _esc1_finding())
    assert pr.viable is True and pr.unknown is False
    assert pr.evidence == {"esc1_template": "VulnTemplate", "esc1_confirmed": True}


def test_esc1_not_viable_no_vulnerable_template(tmp_path):
    out = "Certipy v5.0.0\n[*] Found 0 vulnerable certificate templates\n"
    pr = get_probe("ADCS-ESC1").check(
        _ctx(_cfg(), _Runner(RunResult(0, stdout=out)), tmp_path), _esc1_finding())
    assert pr.viable is False and pr.unknown is False
    assert pr.evidence["esc1_confirmed"] is False


def test_esc1_unknown_on_read_error(tmp_path):
    pr = get_probe("ADCS-ESC1").check(_ctx(_cfg(), _Runner(_ERR), tmp_path), _esc1_finding())
    assert pr.viable is True and pr.unknown is True
    assert pr.evidence["esc1_template"] == "VulnTemplate"   # aranum entity passed through


# ================================================================= registry / helpers
def test_registry_covers_all_fifteen_techniques():
    assert set(probes.PROBE_REGISTRY) == {
        "KERBEROAST", "ASREP", "LAPS", "CONSTRAINED-DELEG-PT",
        "RBCD", "OPENSHARES-WRITE", "SHADOW-CREDS", "ADCS-ESC1",
        "ESC8", "ESC11", "CERTIFRIED", "DCSYNC",
        "COERCION", "NTLM-RELAY", "UNCONSTRAINED-DELEG",       # PP: listener trio added
        "WRITE-DACL", "WRITE-OWNER", "ADD-MEMBER",
        "TARGETED-KERBEROAST", "FORCE-CHANGE-PASSWORD",
        "GENERIC-ALL", "GPO-ABUSE",                              # T3: ACL edges (all 7)
        "GOLDEN-TICKET", "SILVER-TICKET",                        # T4: Kerberos forging
        "DIAMOND-TICKET", "SAPPHIRE-TICKET",
        "SHARE-LOOT",                                            # SHARELOOT S1: SMB share discovery
        "BRONZE-BIT", "S4U2SELF",                                # T6: delegation extras
        "SIGNING-RELAY"}                                         # SMB/LDAP signing-posture exposure


def test_get_probe_unknown_technique_is_none():
    assert get_probe("BOGUS-TECHNIQUE") is None              # genuinely unregistered
    assert get_probe(None) is None


def test_probe_that_raises_degrades_to_unknown(tmp_path):
    # A probe error must become unknown (attempt anyway), never a false viable=False.
    class _Boom(CommandRunner):
        def run(self, argv, *, env=None, timeout=None, cwd=None):
            raise RuntimeError("boom")
    pr = probes.probe_finding(_ctx(_cfg(), _Boom(), tmp_path), _kerb_finding())
    assert pr is not None and pr.viable is True and pr.unknown is True


def test_run_probes_aligns_results_and_handles_no_probe(tmp_path):
    kerb = _kerb_finding()
    unmapped = map_finding({"finding_id": "AR-x", "host": "h", "category": "web",
                            "line": "nothing validatable here"})
    runner = _Runner(RunResult(0, stdout="sAMAccountName: svc_sql\nmsDS-SupportedEncryptionTypes: 4\n"))
    results = run_probes(_ctx(_cfg(), runner, tmp_path), [kerb, unmapped])
    assert len(results) == 2
    assert isinstance(results[0], ProbeResult) and results[0].viable is True
    assert results[1] is None                          # unmapped finding -> no probe


# ================================================================= orchestrator wiring
class _FakeAranum(AranumRunner):
    """Write a findings.json with the given raw findings and return its path."""

    def __init__(self, raw):
        self.raw = raw

    def findings_path(self, config):
        p = Path(config.output_dir) / "findings.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"findings": self.raw}), encoding="utf-8")
        return p


class _ProbeRouter(CommandRunner):
    """Route a probe read to a scripted response by (tool, subcommand, attributes)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.responses.get(self._key(argv),
                                  RunResult(returncode=None, error="unscripted"))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "certipy-ad":
            return "certipy"
        if tool == "nxc":
            sub = argv[1] if len(argv) > 1 else ""
            if sub == "smb":
                return "nxc-shares"
            if "--query" in argv:
                i = argv.index("--query")
                attrs = argv[i + 2] if len(argv) > i + 2 else ""
                for marker, key in (("msDS-SupportedEncryptionTypes", "kerb"),
                                    ("ms-DS-MachineAccountQuota", "rbcd"),
                                    ("msDS-AllowedToDelegateTo", "deleg"),
                                    ("ms-Mcs-AdmPwd", "laps"),
                                    ("userAccountControl", "asrep")):
                    if marker in attrs:
                        return key
        return tool


# Three findings exercising all three probe outcomes through the pipeline.
_RAW_VIABLE = {"finding_id": "AR-k1", "host": "dc01.north.sevenkingdoms.local",
               "category": "ad", "severity": "high", "rule_id": "promoted-kerberoast-spn",
               "line": "Kerberoastable SPN account svc_sql : MSSQLSvc/db"}
_RAW_NOT_VIABLE = {"finding_id": "AR-a1", "host": "dc01.north.sevenkingdoms.local",
                   "category": "ad", "severity": "high", "rule_id": "promoted-asrep-user",
                   "line": "AS-REP-roastable account brandon.stark : x"}
_RAW_UNKNOWN = {"finding_id": "AR-r1", "host": "dc01.north.sevenkingdoms.local",
                "category": "delegation", "severity": "high",
                "line": "msDS-AllowedToActOnBehalfOfOtherIdentity writable on dc01"}


def _probe_responses():
    return {
        "kerb": RunResult(0, stdout="sAMAccountName: svc_sql\nmsDS-SupportedEncryptionTypes: 4\n"),
        "asrep": RunResult(0, stdout="sAMAccountName: brandon.stark\nuserAccountControl: 512\n"),
        "rbcd": RunResult(returncode=None, error="timeout"),   # -> unknown, proceeds
    }


def test_orchestrator_plan_attaches_probe_and_confirm_skips_not_viable(tmp_path):
    # Short username so the RBCD executor's derived computer name fits sAMAccountName.
    cfg = _cfg(output_dir=tmp_path, auto_confirm=True, username="joe")
    runner = _ProbeRouter(_probe_responses())
    orch = ValidationOrchestrator(cfg, runner=runner, confirmer=AutoConfirm())
    findings = [map_finding(_RAW_VIABLE), map_finding(_RAW_NOT_VIABLE), map_finding(_RAW_UNKNOWN)]
    plans = orch.plan(findings)
    by_tech = {pv.finding.technique: pv for pv in plans}
    assert by_tech["KERBEROAST"].probe.viable is True and by_tech["KERBEROAST"].skipped_by_probe is False
    assert by_tech["ASREP"].probe.viable is False and by_tech["ASREP"].skipped_by_probe is True
    assert by_tech["RBCD"].probe.unknown is True and by_tech["RBCD"].skipped_by_probe is False
    # confirm() drops the not-viable one; viable and unknown both proceed.
    chosen_tech = {pv.finding.technique for pv, _ in orch.confirm(plans)}
    assert chosen_tech == {"KERBEROAST", "RBCD"}


def test_orchestrator_run_report_has_skipped_list_with_reason(tmp_path):
    cfg = _cfg(output_dir=tmp_path, auto_confirm=False, username="joe")  # DeclineAll -> no exec
    runner = _ProbeRouter(_probe_responses())
    orch = ValidationOrchestrator(cfg, runner=runner, confirmer=DeclineAll(),
                                  aranum=_FakeAranum([_RAW_VIABLE, _RAW_NOT_VIABLE, _RAW_UNKNOWN]))
    report = orch.run()
    # The not-viable finding is recorded under "skipped" with its reason + evidence.
    skipped = {s["technique"]: s for s in report["skipped"]}
    assert set(skipped) == {"ASREP"}
    assert skipped["ASREP"]["finding_id"] == "AR-a1"
    assert "pre-auth required" in skipped["ASREP"]["reason"]
    assert skipped["ASREP"]["evidence"]["uac_dont_req_preauth"] is False
    # The viable + unknown findings proceed (appear in "planned", annotated with probe).
    planned = {p["technique"]: p for p in report["planned"]}
    assert set(planned) == {"KERBEROAST", "RBCD"}
    assert planned["RBCD"]["probe"]["unknown"] is True   # uncertainty carried into the plan
    assert planned["KERBEROAST"]["probe"]["viable"] is True


def test_orchestrator_unconstrained_now_probed_and_proceeds(tmp_path):
    # PP: UNCONSTRAINED-DELEG now HAS a probe. With an unscripted router the probe
    # read errors -> unknown (viable=True) -> the finding still proceeds (never a
    # false skip), and plans[0].probe is populated (coverage reached the orchestrator).
    raw = {"finding_id": "AR-u1", "host": "srv01.north.sevenkingdoms.local",
           "category": "delegation", "severity": "high",
           "line": "UNCONSTRAINED DELEGATION on srv01"}
    cfg = _cfg(output_dir=tmp_path, auto_confirm=True)
    orch = ValidationOrchestrator(cfg, runner=_ProbeRouter({}), confirmer=AutoConfirm())
    plans = orch.plan([map_finding(raw)])
    assert len(plans) == 1
    assert plans[0].finding.technique == "UNCONSTRAINED-DELEG"
    assert plans[0].probe is not None and plans[0].probe.unknown is True
    assert plans[0].skipped_by_probe is False


def test_skipped_by_probe_refuses_to_skip_unknown():
    # Defence-in-depth: skip ONLY on a confident not-viable. A probe that (wrongly)
    # set viable=False together with unknown=True must still NOT skip -- the
    # fail-safe cannot depend on a probe honouring "unknown implies viable".
    from purplesploit.validation.orchestrator import PlannedValidation
    mk = lambda pr: PlannedValidation(finding=None, executor=None, plan=None,
                                      implemented=False, probe=pr)
    assert mk(ProbeResult(viable=False, reason="confident")).skipped_by_probe is True
    assert mk(ProbeResult(viable=False, reason="unsure", unknown=True)).skipped_by_probe is False
    assert mk(ProbeResult(viable=True, reason="ok")).skipped_by_probe is False
    assert mk(None).skipped_by_probe is False


# ============================================ PP (25NOV2026) listener-trio probes
def _mk(host, category="ad"):
    f = map_finding({"finding_id": "AR-pp", "host": host, "category": category,
                     "severity": "high", "line": f"x {host}"})
    f.host = host
    return f


# --- COERCION (PP-1): coercer scan surface, non-destructive -----------------
def test_coercion_viable_when_method_reachable(tmp_path):
    out = "[+] [MS-EFSR] EfsRpcOpenFileRaw pipe accessible on dc01\n"
    r = _Runner(by_tool={"coercer": RunResult(0, stdout=out)})
    res = probes.CoercionProbe().check(_ctx(_cfg(), r, tmp_path), _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is False and res.evidence["coercion_methods"] is True


def test_coercion_unknown_when_no_method_positively_seen(tmp_path):
    # HIGH-dir MEDIUM-2: a zero-method scan is NOT a reliable negative (auth/collection
    # failure; DCs are near-universally coercible) -> unknown, never a false skip.
    r = _Runner(by_tool={"coercer": RunResult(0, stdout="[-] No coercion method available")})
    res = probes.CoercionProbe().check(_ctx(_cfg(), r, tmp_path), _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True and res.evidence["coercion_methods"] is None


def test_coercion_unknown_on_tool_error(tmp_path):
    res = probes.CoercionProbe().check(_ctx(_cfg(), _Runner(by_tool={"coercer": _ERR}), tmp_path),
                                       _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True       # fail-safe: never a false skip


# --- NTLM-RELAY (PP-2): relay target signing enforcement --------------------
def test_relay_viable_when_smb_signing_off(tmp_path):
    r = _Runner(by_tool={"nxc": RunResult(0, stdout="SMB srv02 445 SRV02 [*] signing:False SMBv1:False")})
    res = probes.NTLMRelayProbe().check(_ctx(_cfg(), r, tmp_path), _mk("srv02.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is False and res.evidence["smb_signing"] is False


def test_relay_unknown_when_smb_enforced_and_no_ldap_surface(tmp_path):
    # HIGH-1: SMB signing enforced + no positive LDAP surface -> UNKNOWN, never a
    # skip (a DC LDAP / web-enroll relay may still work). Fail-safe.
    r = _Runner(by_tool={"nxc": RunResult(0, stdout="signing:True")})
    res = probes.NTLMRelayProbe().check(_ctx(_cfg(), r, tmp_path), _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True and res.evidence["ldap_relayable"] is None


def test_relay_viable_via_ldap_when_smb_enforced(tmp_path):
    class _Dual(CommandRunner):
        def run(self, argv, *, env=None, timeout=None, cwd=None):
            svc = argv[1] if len(argv) > 1 else ""
            return (RunResult(0, stdout="signing:True") if svc == "smb"
                    else RunResult(0, stdout="LDAP dc01 389 [*] channel binding: None"))
    res = probes.NTLMRelayProbe().check(_ctx(_cfg(), _Dual(), tmp_path),
                                        _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.evidence.get("ldap_relayable") is True


def test_relay_unknown_on_tool_error(tmp_path):
    res = probes.NTLMRelayProbe().check(_ctx(_cfg(), _Runner(by_tool={"nxc": _ERR}), tmp_path),
                                        _mk("srv02.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True


# --- UNCONSTRAINED-DELEG (PP-3): UAC TRUSTED_FOR_DELEGATION 0x80000 ----------
def test_unconstrained_viable_when_trusted_for_deleg(tmp_path):
    out = ("LDAP dc01 389 DC01 sAMAccountName: DC01$\n"
           "LDAP dc01 389 DC01 userAccountControl: 532480")   # 0x82000 = SERVER_TRUST + TRUSTED_FOR_DELEG
    r = _Runner(by_tool={"nxc": RunResult(0, stdout=out)})
    res = probes.UnconstrainedDelegProbe().check(_ctx(_cfg(), r, tmp_path),
                                                 _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True and res.evidence["trusted_for_delegation"] is True


def test_unconstrained_not_viable_without_bit(tmp_path):
    out = ("LDAP ws 389 WS01 sAMAccountName: WS01$\n"
           "LDAP ws 389 WS01 userAccountControl: 4096")       # 0x1000 workstation, no 0x80000
    r = _Runner(by_tool={"nxc": RunResult(0, stdout=out)})
    res = probes.UnconstrainedDelegProbe().check(_ctx(_cfg(), r, tmp_path),
                                                 _mk("ws01.north.sevenkingdoms.local"))
    assert res.viable is False and res.evidence["trusted_for_delegation"] is False


def test_unconstrained_unknown_on_unread(tmp_path):
    res = probes.UnconstrainedDelegProbe().check(_ctx(_cfg(), _Runner(by_tool={"nxc": _ERR}), tmp_path),
                                                 _mk("dc01.north.sevenkingdoms.local"))
    assert res.viable is True and res.unknown is True


def test_pp_probes_registered_all_15_covered():
    from purplesploit.validation.probes import get_probe, PROBE_REGISTRY
    from purplesploit.validation.executors import IMPLEMENTED
    assert type(get_probe("COERCION")).__name__ == "CoercionProbe"
    assert type(get_probe("NTLM-RELAY")).__name__ == "NTLMRelayProbe"
    assert type(get_probe("UNCONSTRAINED-DELEG")).__name__ == "UnconstrainedDelegProbe"
    # every implemented technique now has a detect-before-fire probe.
    assert IMPLEMENTED <= set(PROBE_REGISTRY)
