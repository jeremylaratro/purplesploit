"""T1a executors: KERBEROAST + ASREP (roast.py) and LAPS (laps.py).

Each technique is driven end-to-end with a scripted fake runner (no lab) and the
emitted receipt is asserted to be a well-formed ``adlab.plan003.proof.v1`` with
the shape the harness scorer reads as *proved*: correct schema/technique/class,
the scoring identity the facet keys on (KERBEROAST {domain,principal}, ASREP
{domain}, LAPS {host_id}), all steps ok, a non-negated terminal fact with a
token, and -- critically -- no recovered secret anywhere in the receipt.

Failure/gate paths assert the honest *non*-proved shape: a failed crack/login or
a denied gate yields an incomplete receipt (no positive terminal fact), never a
fabricated proof.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof


# ----------------------------------------------------------------- fake runner
class _FakeRunner(CommandRunner):
    """Return scripted stdout keyed on the tool + a distinguishing flag."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(returncode=0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "hashcat":
            return "hashcat:show" if "--show" in argv else "hashcat:crack"
        if tool == "nxc":
            return "nxc:local" if "--local-auth" in argv else "nxc"
        return tool


def _config(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="hodor", password="hodorhodor",
                host_aliases={"braavos.essos.local": {"host_id": "srv03"}})
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


# ================================================================= KERBEROAST
def _kerb_finding(principal="jon.snow"):
    return map_finding({
        "finding_id": "AR-k1", "host": "", "category": "kerberoast", "severity": "high",
        "rule_id": "promoted-kerberoast-spn",
        "line": f"Kerberoastable SPN account {principal}: MSSQLSvc/db.north",
    })


def _kerb_proved_script():
    return {
        "impacket-GetUserSPNs": RunResult(0, stdout=(
            "ServicePrincipalName  Name      MemberOf  PasswordLastSet\n"
            "$krb5tgs$23$*jon.snow$NORTH$MSSQLSvc*$abcd$ef0011223344556677")),
        "hashcat:crack": RunResult(0, stdout="Recovered........: 1/1 (100.00%)"),
        "hashcat:show": RunResult(0, stdout="Winter2022!"),
        "nxc": RunResult(0, stdout="SMB  10.0.0.11  445  WINTERFELL  [+] north\\jon.snow (Pwn3d!)"),
    }


def test_kerberoast_maps_and_defaults():
    f = _kerb_finding()
    assert f.technique == "KERBEROAST" and f.entity.get("principal") == "jon.snow"
    assert is_implemented("KERBEROAST")
    cfg = _config()
    specs = {s.name: s for s in get_executor("KERBEROAST").param_specs(
        _ctx(cfg, _FakeRunner({}), Path("/tmp")), f)}
    assert specs["principal"].recommended == "jon.snow"
    assert specs["wordlist"].recommended.endswith("rockyou.txt")
    assert specs["reauth_target"].recommended == cfg.dc_ip


def test_kerberoast_emits_proved_shaped_receipt(tmp_path):
    cfg = _config()
    runner = _FakeRunner(_kerb_proved_script())
    receipt = get_executor("KERBEROAST").run(_ctx(cfg, runner, tmp_path), _kerb_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "KERBEROAST" and receipt["class"] == "kerberoast"
    assert receipt["target"] == {"domain": "north.sevenkingdoms.local", "principal": "jon.snow"}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is False           # non-mutating: no rollback needed
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    # roast -> crack -> reauth were all run.
    tools = [Path(c[0]).name for c in runner.calls]
    assert tools.count("hashcat") == 2 and "nxc" in tools


def test_kerberoast_no_cracked_secret_in_receipt(tmp_path):
    cfg = _config()
    receipt = get_executor("KERBEROAST").run(
        _ctx(cfg, _FakeRunner(_kerb_proved_script()), tmp_path), _kerb_finding())
    blob = json.dumps(receipt)
    assert "Winter2022!" not in blob      # cracked plaintext never stored
    assert "hodorhodor" not in blob       # operator password never stored


def test_kerberoast_crack_fails_is_not_proved(tmp_path):
    script = _kerb_proved_script()
    script["hashcat:show"] = RunResult(0, stdout="")   # nothing cracked
    cfg = _config()
    receipt = get_executor("KERBEROAST").run(_ctx(cfg, _FakeRunner(script), tmp_path), _kerb_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None
    assert "crack_failed" in receipt["errors"]
    # a failed step is present -> the scorer reads prereq_unmet (inconclusive), not proved
    assert any(s["name"] == "crack" and s["ok"] is False for s in receipt["steps"])


def test_kerberoast_crack_gate_denied_inconclusive(tmp_path):
    class _Deny(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied" if op == "offline_crack" else "not_required"
    cfg = _config()
    receipt = get_executor("KERBEROAST").run(
        _ctx(cfg, _FakeRunner(_kerb_proved_script()), tmp_path, _Deny(True)), _kerb_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None


# ================================================================= ASREP
def _asrep_finding(principal="brandon.stark"):
    return map_finding({
        "finding_id": "AR-a1", "host": "", "category": "asrep", "severity": "high",
        "rule_id": "promoted-asrep-user",
        "line": f"AS-REP-roastable account {principal}: DONT_REQ_PREAUTH",
    })


def test_asrep_maps_and_scores_on_domain(tmp_path):
    f = _asrep_finding()
    assert f.technique == "ASREP" and f.entity.get("principal") == "brandon.stark"
    cfg = _config()
    script = {
        "impacket-GetNPUsers": RunResult(0, stdout="$krb5asrep$23$brandon.stark@NORTH:aa11$bb22ccdd"),
        "hashcat:crack": RunResult(0, stdout="Recovered: 1/1"),
        "hashcat:show": RunResult(0, stdout="Summer2021!"),
        "nxc": RunResult(0, stdout="SMB  10.0.0.11  445  WINTERFELL  [+] north\\brandon.stark"),
    }
    receipt = get_executor("ASREP").run(_ctx(cfg, _FakeRunner(script), tmp_path), f)
    assert receipt["technique"] == "ASREP" and receipt["class"] == "asrep"
    # ASREP facet keys on {domain}; principal carried for info but match is domain-level.
    assert receipt["target"]["domain"] == "north.sevenkingdoms.local"
    assert receipt["complete"] is True and receipt["terminal_fact"]["ok"] is True
    assert "Summer2021!" not in json.dumps(receipt)


# ================================================================= LAPS
def _laps_finding(host="braavos.essos.local"):
    return map_finding({
        "finding_id": "AR-l1", "host": host, "category": "laps", "severity": "high",
        "line": f"ms-Mcs-AdmPwd READABLE (LAPSv1) on {host}",
    })


def test_laps_maps_and_defaults(tmp_path):
    f = _laps_finding()
    assert f.technique == "LAPS" and f.host == "braavos.essos.local"
    assert is_implemented("LAPS")
    cfg = _config()
    specs = {s.name: s for s in get_executor("LAPS").param_specs(_ctx(cfg, _FakeRunner({}), tmp_path), f)}
    assert specs["target_host"].recommended == "braavos.essos.local"
    assert specs["local_admin"].recommended == "administrator"


def test_laps_proved_shape_when_login_succeeds(tmp_path):
    # In GOAD the login is a lab quirk (inconclusive); the framework path is
    # exercised with a runner where login succeeds -> proved against srv03.
    cfg = _config()
    script = {
        "impacket-GetLAPSPassword": RunResult(0, stdout=(
            "Computer       Username       Password\n"
            "braavos$       administrator  Summ3rIsC0ming!")),
        "nxc:local": RunResult(0, stdout="SMB  braavos  445  BRAAVOS  [+] braavos\\administrator (Pwn3d!)"),
    }
    receipt = get_executor("LAPS").run(_ctx(cfg, _FakeRunner(script), tmp_path), _laps_finding())
    assert receipt["technique"] == "LAPS" and receipt["class"] == "laps"
    assert receipt["target"].get("host_id") == "srv03"       # resolved via host_aliases
    assert receipt["complete"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    assert "Summ3rIsC0ming!" not in json.dumps(receipt)      # LAPS secret never stored


def test_laps_login_fails_is_not_proved(tmp_path):
    # The real GOAD quirk: read works, login fails -> honest not-proved.
    cfg = _config()
    script = {
        "impacket-GetLAPSPassword": RunResult(0, stdout=(
            "Computer       Username       Password\n"
            "braavos$       administrator  Summ3rIsC0ming!")),
        "nxc:local": RunResult(0, stdout="SMB  braavos  445  BRAAVOS  [-] braavos\\administrator STATUS_LOGON_FAILURE"),
    }
    receipt = get_executor("LAPS").run(_ctx(cfg, _FakeRunner(script), tmp_path), _laps_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"]["ok"] is False           # negated predicate, not absent
    assert "local_login_failed" in receipt["errors"]


def test_laps_read_gate_denied_inconclusive(tmp_path):
    class _Deny(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied" if op == "laps_read" else "not_required"
    cfg = _config()
    script = {"impacket-GetLAPSPassword": RunResult(0, stdout="braavos$ administrator Summ3rIsC0ming!")}
    receipt = get_executor("LAPS").run(_ctx(cfg, _FakeRunner(script), tmp_path, _Deny(True)), _laps_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
