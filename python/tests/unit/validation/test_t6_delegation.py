"""T6 delegation extras: BRONZE-BIT (bronze_bit.py) + S4U2SELF (s4u2self.py).

Both drive impacket getST as a compromised service/machine account then prove the
ticket with nxc. Driven end-to-end with a scripted fake runner (no lab):
- BRONZE-BIT CLASSIFIES the target (exit 0 is never proof): exploited / kdc_patched
  (KRB_AP_ERR_MODIFIED, CVE-2020-17049 enforced) / not_delegatable (KDC_ERR_BADOPTION).
- S4U2SELF requires (Pwn3d!) for the local-admin claim -- a plain [+] is NOT admin.
- Secret-safety: the service key never reaches the receipt; the ccache is engine-only
  and only surfaces as a CAP_CCACHE capability from produced() on success.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (ExecutorContext, CommandRunner,
                                                     RunResult, AuthorizedLabProvider, CAP_CCACHE)
from purplesploit.validation import states
from purplesploit.validation.executors import _s4u_common as s4u


FAKE_AES = "a" * 64                         # a fake service-account AES key (secret)
TICKET_LINE = "[*] Saving ticket in Administrator@cifs_castelblack.ccache"


class _FakeRunner(CommandRunner):
    def __init__(self, getst="", nxc=""):
        self.getst, self.nxc = getst, nxc
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "nxc":
            return RunResult(returncode=0, stdout=self.nxc)
        return RunResult(returncode=0, stdout=self.getst)

    def getst_argv(self):
        return next(c for c in self.calls if Path(c[0]).name == "impacket-getST")


def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="192.168.56.11",
                username="CASTELBLACK$", aes_key=FAKE_AES)
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, runner, tmp_path):
    return ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _finding(host="castelblack.north.sevenkingdoms.local"):
    return map_finding({"finding_id": "T6", "host": host, "category": "delegation",
                        "severity": "info", "line": f"delegation on {host}"})


# ============================================================= _s4u_common key handling
def test_key_flags_prefer_aes_and_normalize_nt():
    assert s4u.getst_key_flags(_cfg(aes_key=FAKE_AES)) == ["-aesKey", FAKE_AES]
    # bare NT hash -> empty-LM:NT (impacket requires the colon form)
    flags = s4u.getst_key_flags(_cfg(aes_key=None, nt_hash="b" * 32))
    assert flags == ["-hashes", "aad3b435b51404eeaad3b435b51404ee:" + "b" * 32]
    # already LM:NT -> unchanged
    assert s4u.getst_key_flags(_cfg(aes_key=None, nt_hash="c" * 32 + ":" + "d" * 32))[1] == "c" * 32 + ":" + "d" * 32
    # AES preferred when both present (an NT hash can't decrypt an AES S4U ticket)
    assert s4u.getst_key_flags(_cfg(aes_key=FAKE_AES, nt_hash="e" * 32))[0] == "-aesKey"


def test_classify_kerberos_failure():
    assert s4u.classify_kerberos_failure("Kerberos SessionError: KRB_AP_ERR_MODIFIED") == "kdc_patched"
    assert s4u.classify_kerberos_failure("KDC_ERR_BADOPTION(...)") == "not_delegatable"
    assert s4u.classify_kerberos_failure("all good") is None


# ===================================================================== S4U2SELF
def test_s4u2self_local_admin_pwned(tmp_path):
    r = _FakeRunner(getst=TICKET_LINE, nxc="SMB castelblack 445 [+] north\\Administrator (Pwn3d!)")
    res = get_executor("S4U2SELF").run(_ctx(_cfg(), r, tmp_path), _finding())
    tf = res["terminal_fact"]
    assert tf["ok"] is True and res["complete"] is True
    assert tf["classification"] == "local_admin"
    argv = r.getst_argv()
    assert "-self" in argv and "-altservice" in argv            # the S4U2self recipe
    blob = json.dumps(res)
    assert FAKE_AES not in blob and ".ccache" not in blob        # key + ticket never in the receipt


def test_s4u2self_authenticated_is_not_local_admin(tmp_path):
    # review HIGH: a plain [+] authentication is NOT local admin -> ok=False.
    r = _FakeRunner(getst=TICKET_LINE, nxc="SMB castelblack 445 [+] north\\svc (authenticated)")
    res = get_executor("S4U2SELF").run(_ctx(_cfg(), r, tmp_path), _finding())
    assert res["terminal_fact"]["ok"] is False
    assert res["terminal_fact"]["classification"] == "authenticated_not_admin"
    assert "authenticated_not_admin" in res["errors"]


def test_s4u2self_produces_local_admin_capability_not_in_receipt(tmp_path):
    r = _FakeRunner(getst=TICKET_LINE, nxc="(Pwn3d!)")
    cr = get_executor("S4U2SELF").run_composable(_ctx(_cfg(), r, tmp_path), _finding())
    caps = cr.capabilities
    assert caps and caps[0].state == states.local_admin_for("castelblack.north.sevenkingdoms.local")
    assert caps[0].channel == CAP_CCACHE and caps[0].secret is True   # ccache is a secret channel
    assert FAKE_AES not in json.dumps(cr.receipt)


def test_s4u2self_no_ticket_classified_not_fabricated(tmp_path):
    r = _FakeRunner(getst="[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN", nxc="")
    res = get_executor("S4U2SELF").run(_ctx(_cfg(), r, tmp_path), _finding())
    assert res["terminal_fact"]["ok"] is False and res["complete"] is False
    assert "principal_unknown" in res["errors"]
    assert not any(Path(c[0]).name == "nxc" for c in r.calls)    # never reached the proof step


# ===================================================================== BRONZE-BIT
def test_bronze_bit_exploited(tmp_path):
    r = _FakeRunner(getst=TICKET_LINE, nxc="SMB winterfell 445 [+] north\\Administrator (Pwn3d!)")
    res = get_executor("BRONZE-BIT").run(_ctx(_cfg(), r, tmp_path), _finding("winterfell.north.sevenkingdoms.local"))
    tf = res["terminal_fact"]
    assert tf["ok"] is True and tf["classification"] == "exploited"
    assert "-force-forwardable" in r.getst_argv()               # the CVE exploit flag
    assert FAKE_AES not in json.dumps(res)


def test_bronze_bit_kdc_patched_is_detected(tmp_path):
    # the GOAD reality: an enforcing KDC rejects the forged ticket -> correctly classified.
    r = _FakeRunner(getst="[*]\tForcing the service ticket to be forwardable\n"
                          "[-] Kerberos SessionError: KRB_AP_ERR_MODIFIED(Message stream modified)")
    res = get_executor("BRONZE-BIT").run(_ctx(_cfg(), r, tmp_path), _finding("winterfell.north.sevenkingdoms.local"))
    tf = res["terminal_fact"]
    assert tf["ok"] is False and tf["classification"] == "kdc_patched"
    assert "kdc_patched" in res["errors"] and "kdc_patched" in tf["predicate"]
    assert not any(Path(c[0]).name == "nxc" for c in r.calls)    # no ticket -> no proof attempt


def test_bronze_bit_not_delegatable(tmp_path):
    r = _FakeRunner(getst="[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)")
    res = get_executor("BRONZE-BIT").run(_ctx(_cfg(), r, tmp_path), _finding("winterfell.north.sevenkingdoms.local"))
    assert res["terminal_fact"]["classification"] == "not_delegatable"
    assert res["terminal_fact"]["ok"] is False


def test_bronze_bit_produces_impersonation_tgt_only_when_exploited(tmp_path):
    exploited = _FakeRunner(getst=TICKET_LINE, nxc="(Pwn3d!)")
    cr = get_executor("BRONZE-BIT").run_composable(_ctx(_cfg(), exploited, tmp_path),
                                                   _finding("winterfell.north.sevenkingdoms.local"))
    assert cr.capabilities and cr.capabilities[0].state == states.S_IMPERSONATION_TGT
    patched = _FakeRunner(getst="KRB_AP_ERR_MODIFIED")
    cr2 = get_executor("BRONZE-BIT").run_composable(_ctx(_cfg(), patched, tmp_path),
                                                    _finding("winterfell.north.sevenkingdoms.local"))
    assert cr2.capabilities == []                                # patched -> no capability produced


# ===================================================================== CLI dispatch
def test_run_dispatch_binds_both(tmp_path):
    from purplesploit.validation.inputs import finding_from_inputs, TARGET_PARAM
    assert TARGET_PARAM["BRONZE-BIT"] == "target_host" and TARGET_PARAM["S4U2SELF"] == "self_host"
    ctx = _ctx(_cfg(), _FakeRunner(), tmp_path)
    for t, host in (("BRONZE-BIT", "winterfell"), ("S4U2SELF", "castelblack")):
        f = finding_from_inputs(ctx, get_executor(t), target=host)   # no KeyError/dispatch_error
        assert f.technique == t and f.host == host
