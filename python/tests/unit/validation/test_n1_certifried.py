"""N1 Certifried executor (certifried.py) -- CVE-2022-26923, synchronous.

Driven end-to-end with a scripted fake runner keyed on the certipy SUBCOMMAND
(account create / account delete / req / auth) plus nxc for the LDAP read-back.
Asserts the proved shape and -- critically (H1) -- that ``target_identity`` emits
the CA host (host_id=srv03 + essos.local), NOT the impersonated DC, so the facet
matches. The H2 rollback is asserted to be NON-VACUOUS: it passes only on a
positive read-back (bind-ok AND the created computer absent); a computer still
present OR a transport-failed read must NOT verify.
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


# ----------------------------------------------------------------- fakes
class _CertipyRunner(CommandRunner):
    """Scripted stdout keyed on the certipy subcommand (account:create/delete,
    req, auth) and nxc (the LDAP read-back)."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(returncode=0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "certipy-ad":
            sub = argv[1] if len(argv) > 1 else ""
            if sub == "account":
                return f"account:{argv[2] if len(argv) > 2 else ''}"
            return sub
        if tool == "nxc":
            return "nxc"
        return tool


class _Deny(AuthorizedLabProvider):
    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _cfg(host_aliases=None, **kw) -> ValidationConfig:
    base = dict(domain="essos.local", dc_ip="10.0.1.10",
                username="khal", password="h0rsel0rd",
                host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


_CA_HOST = "braavos.essos.local"
_ALIAS = {_CA_HOST: {"host_id": "srv03"}}
_NEW = "khal_cmp_certifried"
_DC_FQDN = "meereen.essos.local"
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _certifried_finding(host=_CA_HOST):
    return map_finding({"finding_id": "AR-cf", "host": host, "category": "adcs",
                        "severity": "critical", "rule_id": "promoted-adcs-ca",
                        "line": f"AD CS CA ESSOS-CA on {host}"})


def _script(nxc_out=None, **over):
    base = {
        "account:create": RunResult(0, stdout="[*] Successfully created account "
                                              f"'{_NEW}$' with password ..."),
        "req": RunResult(0, stdout="[*] Successfully requested certificate\n"
                                   "[*] Saved certificate and private key to 'certifried.pfx'\n"),
        "auth": RunResult(0, stdout="[*] Got TGT\n"
                                    "[*] Saved credential cache to 'certifried.ccache'\n"
                                    f"[*] Got hash for 'meereen$': {_FAKE_NT_HASH}\n"),
        "account:delete": RunResult(0, stdout=f"[*] Successfully deleted account '{_NEW}$'"),
        "nxc": RunResult(0, stdout=(nxc_out if nxc_out is not None else
                                    "LDAP  10.0.1.10  389  MEEREEN  [+] essos.local\\khal\n"
                                    "sAMAccountName: meereen$\n")),
    }
    base.update(over)
    return base


def _issued(tmp_path):
    (tmp_path / "certifried.pfx").write_bytes(b"PFX")
    (tmp_path / "certifried.ccache").write_bytes(b"CC")


def _run(cfg, tmp_path, runner, authorizer=None, overrides=None):
    ov = {"dc_fqdn": _DC_FQDN}
    if overrides:
        ov.update(overrides)
    return get_executor("CERTIFRIED").run(
        _ctx(cfg, runner, tmp_path, authorizer), _certifried_finding(), overrides=ov)


# ================================================================= defaults
def test_certifried_maps_and_defaults(tmp_path):
    f = _certifried_finding()
    assert is_implemented("CERTIFRIED")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("CERTIFRIED").param_specs(
        _ctx(cfg, _CertipyRunner({}), tmp_path), f)}
    assert specs["ca_host"].recommended == f.host
    assert specs["ca"].recommended == "ESSOS-CA"
    assert specs["new_computer"].recommended == _NEW         # <base>_cmp_certifried
    assert specs["dc_fqdn"].required is False


# ================================================================= proved + H1 CA-host key
def test_certifried_proved_shaped_receipt_keys_on_ca_host(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    runner = _CertipyRunner(_script())
    receipt = _run(cfg, tmp_path, runner)
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "CERTIFRIED" and receipt["class"] == "adcs"
    # H1: the proof is keyed on the CA host (srv03 + essos.local), NOT the DC.
    assert receipt["target"].get("host_id") == "srv03"
    assert receipt["target"].get("domain") == "essos.local"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert [s["name"] for s in receipt["steps"]] == [
        "account_create", "cert_request", "cert_auth",
        "rollback_delete_computer", "rollback_verify_read", "destroy_key_material"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "rollback_unverified" not in receipt["errors"]
    assert not (tmp_path / "certifried.pfx").exists()        # issued key material destroyed
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "cert_issued_and_used" and tf["ok"] is True and tf["proof_token"]
    assert tf["impersonated"] == "meereen$"                  # impersonated DC (not the key)
    # certipy was invoked as: account create, req, auth, account delete (in order).
    subs = [c[1] for c in runner.calls if Path(c[0]).name == "certipy-ad"]
    assert subs == ["account", "req", "auth", "account"]
    acct_ops = [c[2] for c in runner.calls
                if Path(c[0]).name == "certipy-ad" and c[1] == "account"]
    assert acct_ops == ["create", "delete"]


def test_certifried_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, password="Kh@l3esi2024!")
    _issued(tmp_path)
    receipt = _run(cfg, tmp_path, _CertipyRunner(_script()))
    blob = json.dumps(receipt)
    assert "Kh@l3esi2024!" not in blob                       # operator password never stored
    assert _FAKE_NT_HASH not in blob                         # recovered NT hash never stored
    assert "certifried.pfx" not in blob and "certifried.ccache" not in blob  # key material paths


# ================================================================= H2 non-vacuous rollback
def test_certifried_unverified_when_computer_still_present(tmp_path):
    # The read-back shows the created computer STILL present -> deletion not
    # confirmed -> rollback NOT verified (positive-confirmation).
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    nxc_out = ("LDAP  10.0.1.10  389  MEEREEN  [+] essos.local\\khal\n"
               f"sAMAccountName: {_NEW}$\n")
    receipt = _run(cfg, tmp_path, _CertipyRunner(_script(nxc_out=nxc_out)))
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
    assert any(s["name"] == "rollback_verify_read" and s["ok"] is False
               for s in receipt["steps"])


def test_certifried_vacuous_read_does_not_verify(tmp_path):
    # A transport-FAILED read (no bind-ok marker) must NOT pass as "deleted" even
    # though the computer name is absent from the (empty/errored) output.
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    nxc_out = "LDAP  10.0.1.10  389  MEEREEN  [-] connection reset\n"
    receipt = _run(cfg, tmp_path, _CertipyRunner(_script(nxc_out=nxc_out)))
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
    assert any(s["name"] == "rollback_verify_read" and s["ok"] is False
               for s in receipt["steps"])


# ================================================================= honest non-proved shapes
def test_certifried_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    runner = _CertipyRunner(_script())
    receipt = _run(cfg, tmp_path, runner, authorizer=_Deny("certifried_account_create"))
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"] is False
    assert runner.calls == []                                 # certipy never run


def test_certifried_account_create_fails_is_not_proved(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    script = _script(**{"account:create": RunResult(1, stdout="[-] Could not create account: MAQ reached")})
    runner = _CertipyRunner(script)
    receipt = _run(cfg, tmp_path, runner)
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "account_create_failed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is False            # nothing to roll back
    # req/auth never ran.
    assert not any(c[1] in ("req", "auth") for c in runner.calls if Path(c[0]).name == "certipy-ad")


def test_certifried_req_fails_cleans_up_and_not_proved(tmp_path):
    # Computer created but the cert request failed -> not proved, and the created
    # computer is still deleted (the rollback runs).
    cfg = _cfg(host_aliases=_ALIAS)
    script = _script(req=RunResult(1, stdout="[-] Request failed: template denied"))
    runner = _CertipyRunner(script)
    receipt = _run(cfg, tmp_path, runner)
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "cert_request_failed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert any(c[1] == "account" and c[2] == "delete"
               for c in runner.calls if Path(c[0]).name == "certipy-ad")
    assert not any(c[1] == "auth" for c in runner.calls if Path(c[0]).name == "certipy-ad")
